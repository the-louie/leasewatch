"""Schema v4: the wifi_presence table, its migration from v3, and the per-device and all-device reads."""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock


from leasewatch import db as dbmod
from leasewatch.db import Database

A, B, C = "02:00:00:00:00:01", "02:00:00:00:00:02", "00:00:5e:00:53:03"
COLS = ["mac", "ssid", "first_seen", "last_seen", "seconds_seen", "polls_seen", "last_ap"]


def digest(conn: sqlite3.Connection) -> str:
    """One hash over every row of the tables that exist before v4."""
    h = hashlib.sha256()
    for t in ("devices", "events", "aliases", "history", "seen", "meta"):
        for r in conn.execute(f"SELECT * FROM {t} ORDER BY rowid"):
            if t == "meta" and r[0] == "schema_version":
                continue
            h.update(repr(tuple(r)).encode())
    return h.hexdigest()


class WifiDbTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "t.db")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def open(self) -> Database:
        db = Database(self.path)
        self.addCleanup(db._conn.close)
        return db

    def put(self, db: Database, mac: str, ssid: str, last: int, first: int = 1, ap: str = "ap1") -> None:
        db.q("INSERT INTO wifi_presence VALUES(?,?,?,?,?,?,?)", (mac, ssid, first, last, 60, 2, ap))

    def test_fresh_db_is_v4_with_the_table(self) -> None:
        db = self.open()
        self.assertEqual(db.get_meta("schema_version"), "4")
        self.assertEqual([r[1] for r in db.q("PRAGMA table_info(wifi_presence)")], COLS)
        self.assertEqual(db.q("SELECT * FROM wifi_presence"), [])

    def test_v3_migrates_to_v4_and_keeps_every_row(self) -> None:
        steps = {k: v for k, v in dbmod.VERSION_STEPS.items() if k <= 3}
        with mock.patch.object(dbmod, "SCHEMA_VERSION", 3), mock.patch.object(dbmod, "VERSION_STEPS", steps):
            old = Database(self.path)
            self.assertEqual(old.get_meta("schema_version"), "3")
            old.q("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,2)", (A,))
            old.q("INSERT INTO events(ts,mac,kind,detail) VALUES(5,?,'new','x')", (A,))
            old.q("INSERT INTO aliases(mac,device,reason,merged_ts,last_seen) VALUES(?,?,'r',3,4)", (B, A))
            before = digest(old._conn)
            self.assertEqual(old.q("SELECT name FROM sqlite_master WHERE name='wifi_presence'"), [])
            old._conn.close()
        db = self.open()
        self.assertEqual(db.get_meta("schema_version"), "4")
        self.assertEqual(db.wifi_presence(A), [])
        self.assertEqual(digest(db._conn), before)

    def test_newer_schema_without_the_table_gets_it_and_keeps_the_version(self) -> None:
        self.open()._conn.close()
        conn = sqlite3.connect(self.path)
        conn.execute("DROP TABLE wifi_presence")
        conn.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        conn.commit(); conn.close()
        with self.assertLogs("leasewatch.db", "WARNING"):
            db = self.open()
        self.assertEqual(db.get_meta("schema_version"), "99")
        self.assertEqual(db.wifi_presence(A), [])

    def test_wifi_presence_orders_newest_first_and_is_empty_without_rows(self) -> None:
        db = self.open()
        self.assertEqual(db.wifi_presence(A), [])
        self.put(db, A, "old", 10)
        self.put(db, A, "b-new", 30)
        self.put(db, A, "a-new", 30)
        self.put(db, B, "other", 99)
        rows = db.wifi_presence(A)
        self.assertEqual([r["ssid"] for r in rows], ["a-new", "b-new", "old"])
        self.assertEqual(rows[0], {"ssid": "a-new", "first_seen": 1, "last_seen": 30, "seconds_seen": 60,
                                   "polls_seen": 2, "last_ap": "ap1"})

    def test_wifi_presence_all_groups_by_mac_in_one_statement(self) -> None:
        db = self.open()
        self.put(db, A, "x", 10)
        self.put(db, A, "y", 20)
        self.put(db, B, "x", 5)
        self.put(db, C, "z", 7)
        seen: list[str] = []
        db._conn.set_trace_callback(seen.append)
        got = db.wifi_presence_all()
        db._conn.set_trace_callback(None)
        self.assertEqual(len(seen), 1)
        self.assertEqual(set(got), {A, B, C})
        self.assertEqual([r["ssid"] for r in got[A]], ["y", "x"])
        self.assertEqual(got[A], db.wifi_presence(A))
        self.assertNotIn("mac", got[B][0])
        self.assertEqual(Database.wifi_presence_all(self.open()), got)

    def test_device_detail_carries_wifi_presence(self) -> None:
        db = self.open()
        db.q("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,2)", (A,))
        db.q("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,2)", (B,))
        db.q("INSERT INTO aliases(mac,device,reason,merged_ts,last_seen) VALUES(?,?,'r',3,4)", (C, A))
        self.assertEqual(db.device_detail(B)["wifi_presence"], [])
        self.put(db, A, "home", 10)
        self.assertEqual(db.device_detail(A)["wifi_presence"], db.wifi_presence(A))
        self.assertEqual(db.device_detail(C)["wifi_presence"][0]["ssid"], "home")  # an alias opens its device


if __name__ == "__main__":
    unittest.main()
