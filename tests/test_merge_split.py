"""devices.split_from: added by the column migration on a fresh DB, an older DB and a newer-schema DB."""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from leasewatch import db as dbmod  # noqa: E402
from leasewatch.db import AlreadyADevice, Database  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.connectors import Batch  # noqa: E402
from leasewatch.connectors.merge import MergeState, merge  # noqa: E402
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from test_merge import NOW, S, row  # noqa: E402

A, B = "02:00:00:00:00:01", "00:00:5e:00:53:02"
WITHOUT = [m for m in dbmod.MIGRATIONS if m[1] != "split_from"]


def cols(path: str) -> dict[str, tuple]:
    conn = sqlite3.connect(path)
    try:
        return {r[1]: r for r in conn.execute("PRAGMA table_info(devices)")}
    finally:
        conn.close()


class SplitFromTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "t.db")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def seed(self) -> None:
        conn = sqlite3.connect(self.path)
        conn.execute("INSERT INTO devices (mac, first_seen, last_seen, ip) VALUES (?, 100, 200, '10.0.0.1')", (A,))
        conn.execute("INSERT INTO devices (mac, first_seen, last_seen, ip) VALUES (?, 110, 210, '10.0.0.2')", (B,))
        conn.commit()
        conn.close()

    def test_fresh_db_has_null_column(self) -> None:
        Database(self.path).close()
        c = cols(self.path)["split_from"]
        self.assertEqual(c[2].upper(), "TEXT")
        self.assertEqual(c[3], 0)  # nullable
        self.assertIsNone(c[4])  # no default: NULL

    def test_older_db_gets_column_rows_untouched(self) -> None:
        with mock.patch.object(dbmod, "MIGRATIONS", WITHOUT):
            Database(self.path).close()
        self.assertNotIn("split_from", cols(self.path))
        self.seed()
        conn = sqlite3.connect(self.path)
        before = conn.execute("SELECT * FROM devices ORDER BY mac").fetchall()
        conn.close()
        Database(self.path).close()
        self.assertIn("split_from", cols(self.path))
        conn = sqlite3.connect(self.path)
        after = conn.execute("SELECT * FROM devices ORDER BY mac").fetchall()
        conn.close()
        self.assertEqual([r[:len(before[0])] for r in after], before)
        self.assertEqual([r[-1] for r in after], [None, None])
        Database(self.path).close()  # a second open does not add it again

    def test_rows_and_detail_carry_none(self) -> None:
        Database(self.path).close()
        self.seed()
        db = Database(self.path)
        self.addCleanup(db.close)
        rows = db.devices()
        self.assertEqual(len(rows), 2)
        for r in rows:
            self.assertIn("split_from", r)
            self.assertIsNone(r["split_from"])
        self.assertIsNone(db.device_detail(A)["device"]["split_from"])

    def test_newer_schema_still_adds_column(self) -> None:
        with mock.patch.object(dbmod, "MIGRATIONS", WITHOUT):
            Database(self.path).close()
        conn = sqlite3.connect(self.path)
        conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        conn.commit()
        conn.close()
        Database(self.path).close()
        self.assertIn("split_from", cols(self.path))
        conn = sqlite3.connect(self.path)
        self.assertEqual(conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0], "99")
        conn.close()


DEV, AL, AL2 = "02:00:00:00:20:01", "06:00:00:00:20:02", "0a:00:00:00:20:03"
CID = "ff00000000000002"
MERGED = 1_700_000_000


class SplitAliasTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.db = Database(os.path.join(self.dir, "t.db"))
        self.addCleanup(self.db.close)
        with self.db.tx() as c:
            c.execute("INSERT INTO devices (mac, first_seen, last_seen, ip, hostname, client_id, sources, online, name) "
                      "VALUES (?, 100, 900, '10.0.0.1', 'alex', ?, 'fw1', 1, 'Alex')", (DEV, CID))
            c.execute("INSERT INTO devices (mac, first_seen, last_seen) VALUES ('00:00:5e:00:53:09', 1, 2)")
            c.execute("INSERT INTO aliases VALUES (?, ?, 'client-id', ?, ?, 777)", (AL, DEV, CID, MERGED))
            c.execute("INSERT INTO aliases VALUES (?, ?, 'hostname', 'alex', ?, 778)", (AL2, DEV, MERGED))
            c.execute("INSERT INTO history (mac, ts, ip, hostname, vlan, lease_type) VALUES (?, 1, '10.0.0.1', 'alex', '', '')", (DEV,))
            c.execute("INSERT INTO events (ts, mac, kind, detail) VALUES (5, ?, 'merged', 'x')", (DEV,))
            c.execute("INSERT INTO seen (mac, source, last_seen, last_present) VALUES (?, 'fw1', 2, 2)", (DEV,))

    def counts(self) -> list[int]:
        return [self.db.q(f"SELECT COUNT(*) FROM {t} WHERE mac=?", (DEV,))[0][0] for t in ("history", "events", "seen")]

    def test_client_id_split(self) -> None:
        before, dev_before = self.counts(), self.db.device(DEV)
        t0 = int(time.time())
        out = self.db.split_alias(DEV, AL)
        assert out is not None
        dev, new = out
        day = time.strftime("%Y-%m-%d", time.localtime(MERGED))
        self.assertIsNone(self.db.q("SELECT 1 FROM aliases WHERE mac=?", (AL,)) or None)
        self.assertEqual(dev["aliases"], [AL2])
        self.assertEqual(new["aliases"], [])
        self.assertGreaterEqual(new["first_seen"], t0)
        want = {"mac": AL, "last_seen": 777, "last_online": None, "online": 0, "ip": "", "hostname": "", "vendor": "", "vlan": "",
                "iface": "", "lease_type": "", "sources": "", "client_id": CID, "baseline": 0, "acked": 0, "name": "",
                "note": "", "split_from": DEV}
        for k, v in want.items():
            self.assertEqual(new[k], v, k)
        self.assertEqual(self.db.device(AL)["split_from"], DEV)
        self.assertEqual(self.counts()[0::2], before[0::2])  # history, seen
        self.assertEqual(self.counts()[1], before[1] + 1)  # events: only the split event
        self.assertEqual({k: v for k, v in self.db.device(DEV).items()}, dev_before)
        self.assertEqual({k: v for k, v in dev.items() if k != "aliases"}, dev_before)
        ev = {r["mac"]: r for r in self.db.q("SELECT * FROM events WHERE kind='split'")}
        self.assertEqual(ev[DEV]["detail"], f"{AL} split off (merged by client-id {CID} on {day})")
        self.assertEqual(ev[AL]["detail"], f"split from {DEV}")
        self.assertEqual(ev[DEV]["ts"], ev[AL]["ts"])
        self.assertEqual(len(ev), 2)
        self.assertIsNone(self.db.split_alias(DEV, AL))  # second click

    def test_hostname_split_has_no_client_id(self) -> None:
        out = self.db.split_alias(AL2, AL2)  # the path may be the alias itself
        assert out is not None
        self.assertEqual(out[0]["mac"], DEV)
        self.assertEqual(out[1]["client_id"], "")
        d = [r["detail"] for r in self.db.q("SELECT detail FROM events WHERE mac=? AND kind='split'", (DEV,))]
        self.assertTrue(d[0].startswith(f"{AL2} split off (merged by hostname alex on "))

    def test_not_an_alias_of_this_device(self) -> None:
        other = "00:00:5e:00:53:09"
        with self.db.tx() as c:
            c.execute("INSERT INTO aliases VALUES ('0e:00:00:00:20:04', ?, 'hostname', 'b', 1, 1)", (other,))
        self.assertIsNone(self.db.split_alias(DEV, "0e:00:00:00:20:04"))
        self.assertIsNone(self.db.split_alias(DEV, "02:00:00:00:99:99"))
        self.assertIsNone(self.db.split_alias("02:00:00:00:99:98", AL))
        self.assertEqual(len(self.db.aliases(other)), 1)

    def test_already_a_device(self) -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO devices (mac, first_seen, last_seen) VALUES (?, 1, 2)", (AL,))
        before = self.counts()
        with self.assertRaises(AlreadyADevice):
            self.db.split_alias(DEV, AL)
        self.assertEqual(len(self.db.aliases(DEV)), 2)
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.db.q("SELECT COUNT(*) FROM events WHERE kind='split'")[0][0], 0)


class FirstListingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(restore, self._env)

    def run_merge(self, prev: dict, sightings: list):
        return merge(prev, {"fw1": Batch(sightings=sightings, attachments=[])}, Config(), NOW, MergeState())

    def test_first_listing_writes_history_but_no_field_events(self) -> None:
        split = row(AL, ip="", hostname="", vendor="", vlan="", iface="", lease_type="", sources="", online=0,
                    last_online=None, split_from=DEV)
        other = row(DEV)
        res = self.run_merge({AL: split, DEV: other}, [S(AL, "10.0.0.7", "alex-pc"), S(DEV, "10.0.0.5")])
        mine = [e for e in res.events if e[0] == AL]
        self.assertEqual(mine, [])
        self.assertEqual([h for h in res.history if h[0] == AL][0][1]["ip"], "10.0.0.7")
        self.assertEqual(len([h for h in res.history if h[0] == AL]), 1)
        self.assertTrue(res.rows[AL]["sources"])
        self.assertEqual(res.rows[AL]["hostname"], "alex-pc")
        # the second listing is an ordinary one
        res2 = self.run_merge(res.rows, [S(AL, "10.0.0.8", "alex-pc"), S(DEV, "10.0.0.5")])
        self.assertIn((AL, "ip", "10.0.0.7 -> 10.0.0.8"), res2.events)

    def test_listed_row_still_writes_events(self) -> None:
        res = self.run_merge({DEV: row(DEV)}, [S(DEV, "10.0.0.9")])
        self.assertIn((DEV, "ip", "10.0.0.5 -> 10.0.0.9"), res.events)


if __name__ == "__main__":
    unittest.main()
