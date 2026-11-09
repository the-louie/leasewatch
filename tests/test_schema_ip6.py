"""Columns devices.ip6_stable and history.ip6: added to an older file on open, and an older binary still works."""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import unittest

from _case import EnvTmpCase
from _fixtures import FakeClient, S
from test_collector import SCHEMA_1_0

from leasewatch.collector import Collector
from leasewatch.config import Config
from leasewatch.db import Database

A = "02:00:00:00:00:01"
# the history SELECT and INSERT of the build before these columns
OLD_SELECT = "SELECT ts, ip, hostname, vlan, lease_type FROM history WHERE mac=? ORDER BY ts DESC, id DESC LIMIT ?"
OLD_INSERT = "INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)"


class Ip6ColumnsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "t.db")
        self.addCleanup(shutil.rmtree, self.dir, True)
        conn = sqlite3.connect(self.path)
        try:
            conn.executescript(SCHEMA_1_0)
            for col, decl in [("sw_port", "TEXT NOT NULL DEFAULT ''"), ("tags", "TEXT NOT NULL DEFAULT ''"),
                              ("ip6", "TEXT NOT NULL DEFAULT ''")]:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {decl}")
            conn.execute("INSERT INTO devices(mac,first_seen,last_seen,ip,hostname,ip6) VALUES(?,100,200,'10.0.0.5','pc','2001:db8::5')", (A,))
            conn.executemany(OLD_INSERT,
                             [(A, 100, "10.0.0.4", "pc", "HomeNet", "dynamic"), (A, 160, "10.0.0.5", "pc", "HomeNet", "dynamic")])
            conn.commit()
        finally:
            conn.close()

    def test_old_file_gets_both_columns_and_keeps_rows(self) -> None:
        db = Database(self.path)
        self.addCleanup(db._conn.close)
        dev = {r[1]: r for r in db.q("PRAGMA table_info(devices)")}
        hist = {r[1]: r for r in db.q("PRAGMA table_info(history)")}
        self.assertEqual((dev["ip6_stable"][4], hist["ip6"][4]), ("''", "''"))
        self.assertEqual(db.device(A)["ip6_stable"], "")
        self.assertEqual(db.device(A)["ip6"], "2001:db8::5")
        rows = db.history(A)
        self.assertEqual([(r["ts"], r["ip"], r["ip6"]) for r in rows], [(160, "10.0.0.5", ""), (100, "10.0.0.4", "")])

    def test_old_binary_statements_work_on_the_migrated_file(self) -> None:
        db = Database(self.path)
        self.addCleanup(db._conn.close)
        self.assertEqual(len(db.q(OLD_SELECT, (A, 10))), 2)
        db.q(OLD_INSERT, (A, 170, "10.0.0.6", "pc", "HomeNet", "dynamic"))
        self.assertEqual(db.q("SELECT ip6 FROM history WHERE ts=170")[0][0], "")
        self.assertEqual(len(db.q(OLD_SELECT, (A, 10))), 3)


class Ip6CollectorTest(EnvTmpCase):
    def test_collector_history_row_has_empty_ip6(self) -> None:
        db = Database(Config().db_path)
        self.addCleanup(db._conn.close)
        c = FakeClient([S("02:00:00:00:00:01", "10.0.0.5", "pc")])
        col = Collector(Config(), db, c)
        col.run_once()
        c.sightings_data[0] = S("02:00:00:00:00:01", "10.0.0.6", "pc")
        col.run_once()
        rows = db.history("02:00:00:00:00:01")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["ip6"] == "" for r in rows))
        self.assertEqual(db.device("02:00:00:00:00:01")["ip6_stable"], "")


if __name__ == "__main__":
    unittest.main()
