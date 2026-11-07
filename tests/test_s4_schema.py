"""Schema v3 (S4): device columns client_id, archived_ts, mail_queued and the aliases table, migrated one-way."""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_collector import SCHEMA_1_0  # noqa: E402

from leasewatch.db import Database  # noqa: E402

# the columns db.py added to devices up to v2 (git show 6890972:leasewatch/db.py, MIGRATIONS), copied so the test
# keeps building a real v2 file when db.py moves on
V2_COLUMNS = [
    ("sw_port", "TEXT NOT NULL DEFAULT ''"), ("sw_via", "TEXT NOT NULL DEFAULT ''"),
    ("wifi_ssid", "TEXT NOT NULL DEFAULT ''"), ("wifi_ap", "TEXT NOT NULL DEFAULT ''"),
    ("wifi_signal", "INTEGER"), ("wifi_radio", "TEXT NOT NULL DEFAULT ''"),
    ("wifi_alias", "TEXT NOT NULL DEFAULT ''"), ("link", "TEXT NOT NULL DEFAULT ''"),
    ("loc_source", "TEXT NOT NULL DEFAULT ''"),
]
V2_SEEN = "CREATE TABLE IF NOT EXISTS seen (mac TEXT, source TEXT, last_seen INTEGER NOT NULL, last_present INTEGER, PRIMARY KEY(mac, source))"
NEW_COLUMNS = {"client_id": "", "archived_ts": None, "mail_queued": None, "split_from": None, "label": ""}
ALIAS_COLUMNS = ["mac", "device", "reason", "detail", "merged_ts", "last_seen"]

A, B = "02:00:00:00:00:01", "aa:bb:cc:00:00:02"


def fill(conn: sqlite3.Connection, v2: bool) -> None:
    """Synthetic devices, history, events (and seen rows for v2) as a running 1.0/1.1 install leaves them."""
    if v2:
        conn.execute("INSERT INTO devices(mac,first_seen,last_seen,last_online,ip,hostname,vlan,acked,acked_at,name,note,"
                     "sw_port,wifi_ssid,wifi_signal,loc_source) VALUES(?,100,200,190,'10.0.0.5','alexs-ipad','HomeNet',1,"
                     "150,?,'den',  'ge-0/1','HomeNet',-61,'fw1')", (A, "Alex's iPad"))
        conn.execute("INSERT INTO devices(mac,first_seen,last_seen,ip,baseline) VALUES(?,110,210,'10.0.0.6',1)", (B,))
        conn.executemany("INSERT INTO seen(mac,source,last_seen,last_present) VALUES(?,?,?,?)",
                         [(A, "fw1", 200, 190), (A, "ap-hall", 180, None), (B, "fw1", 210, 205)])
    else:
        conn.execute("INSERT INTO devices(mac,first_seen,last_seen,ip,hostname,name) VALUES(?,100,200,'10.0.0.5','pc',?)",
                     (A, "Alex's iPad"))
    conn.executemany("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                     [(A, 100, "10.0.0.4", "alexs-ipad", "HomeNet", "dynamic"), (A, 160, "10.0.0.5", "alexs-ipad", "HomeNet", "dynamic")])
    conn.executemany("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)",
                     [(100, A, "new", ""), (160, A, "ip", "10.0.0.4 -> 10.0.0.5"), (150, A, "acked", "")])
    conn.execute("INSERT INTO meta(key,value) VALUES('first_run_done','1')")


def dump(conn: sqlite3.Connection) -> dict:
    """Every row of the pre-v3 tables, the devices rows without the v3 columns, and meta without schema_version."""
    conn.row_factory = sqlite3.Row
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    out = {}
    for t in ("devices", "history", "events", "seen", "meta"):
        if t in tables:
            rows = [dict(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY rowid")]
            for r in rows:
                for col in NEW_COLUMNS:
                    r.pop(col, None)
            out[t] = [r for r in rows if r.get("key") != "schema_version"]
    return out


class SchemaV3Test(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "t.db")

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def build(self, version: int) -> dict:
        """A populated v1 or v2 file built with raw SQL; returns its rows."""
        conn = sqlite3.connect(self.path)
        try:
            conn.executescript(SCHEMA_1_0)
            if version == 2:
                for col, decl in V2_COLUMNS:
                    conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {decl}")
                conn.execute(V2_SEEN)
                conn.execute("INSERT INTO meta(key,value) VALUES('schema_version','2')")
            fill(conn, version == 2)
            conn.commit()
            return dump(conn)
        finally:
            conn.close()

    def open(self) -> tuple[Database, list[str]]:
        """Open the file and record every schema_version the open writes."""
        versions: list[str] = []
        orig = Database.set_meta

        def spy(db: Database, key: str, value: str, conn: sqlite3.Connection | None = None) -> None:
            if key == "schema_version":
                versions.append(value)
            return orig(db, key, value, conn)
        with mock.patch.object(Database, "set_meta", spy):
            db = Database(self.path)
        self.addCleanup(db._conn.close)
        return db, versions

    def assert_v3(self, db: Database) -> None:
        self.assertEqual(db.get_meta("schema_version"), "4")
        cols = {r[1] for r in db.q("PRAGMA table_info(devices)")}
        self.assertLessEqual(set(NEW_COLUMNS), cols)
        self.assertEqual([r[1] for r in db.q("PRAGMA table_info(aliases)")], ALIAS_COLUMNS)
        self.assertEqual(db.q("SELECT * FROM aliases"), [])

    def assert_defaults(self, db: Database) -> None:
        for r in db.q("SELECT client_id, archived_ts, mail_queued, split_from, label FROM devices"):
            self.assertEqual(dict(r), NEW_COLUMNS)

    def test_fresh_file_is_v3(self) -> None:
        db, versions = self.open()
        self.assert_v3(db)
        self.assertEqual(versions, ["1", "2", "3", "4"])
        db.q("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,1)", (A,))
        self.assert_defaults(db)

    def test_v2_with_data_migrates_and_keeps_every_row(self) -> None:
        before = self.build(2)
        db, versions = self.open()
        self.assertEqual(versions, ["3", "4"])  # steps 3 and 4 run on a v2 file
        self.assert_v3(db)
        self.assert_defaults(db)
        self.assertEqual(len(db.q("SELECT 1 FROM devices")), 2)
        self.assertEqual(dump(db._conn), before)
        self.assertEqual(db.device(A)["name"], "Alex's iPad")  # the app's own row_factory sees the same values

    def test_v1_with_data_migrates_through_v2(self) -> None:
        before = self.build(1)
        db, versions = self.open()
        self.assertEqual(versions, ["1", "2", "3", "4"])
        self.assert_v3(db)
        self.assert_defaults(db)
        after = dump(db._conn)
        self.assertEqual(after["seen"], [])
        for r in after["devices"]:  # the v2 columns arrive at their defaults next to the 1.0 values
            for col, _ in V2_COLUMNS:
                self.assertIn(r.pop(col), ("", None))
        self.assertEqual({k: v for k, v in after.items() if k != "seen"}, before)

    def test_second_open_is_a_no_op(self) -> None:
        self.build(2)
        db, _ = self.open()
        first = dump(db._conn)
        db._conn.close()
        db, versions = self.open()
        self.assertEqual(versions, [])
        self.assert_v3(db)
        self.assertEqual(dump(db._conn), first)

    def test_crash_after_the_alters_before_the_version_write_reruns_safely(self) -> None:
        # columns and table already there, version still 2: what a crash between the ALTERs and step 3 leaves
        before = self.build(2)
        conn = sqlite3.connect(self.path)
        conn.execute("ALTER TABLE devices ADD COLUMN client_id TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE devices ADD COLUMN archived_ts INTEGER")
        conn.commit(); conn.close()
        db, versions = self.open()
        self.assertEqual(versions, ["3", "4"])
        self.assert_v3(db)
        self.assert_defaults(db)
        self.assertEqual(dump(db._conn), before)

    def test_newer_version_without_aliases_creates_it_and_keeps_the_version(self) -> None:
        self.build(2)
        conn = sqlite3.connect(self.path)
        conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        conn.commit(); conn.close()
        with self.assertLogs("leasewatch.db", "WARNING") as logs:
            db, versions = self.open()
        self.assertIn("WARNING:leasewatch.db:database schema 99 lacks table aliases; creating it", logs.output)
        self.assertEqual((versions, db.get_meta("schema_version")), ([], "99"))
        self.assertEqual(db.q("SELECT * FROM aliases"), [])
        self.assert_defaults(db)


if __name__ == "__main__":
    unittest.main()
