"""Indexes for the per-poll restored-events query and the aliases lookup."""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from leasewatch.db import Database

RESTORED_SQL = "SELECT mac, MAX(ts) ts FROM events WHERE kind='restored' GROUP BY mac"
ALIASES_SQL = "SELECT mac, reason, detail, merged_ts, last_seen FROM aliases WHERE device=? ORDER BY merged_ts DESC, mac"
NAMES = {"events_restored", "aliases_device"}


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "t.db")

    def open(self) -> Database:
        db = Database(self.path)
        self.addCleanup(db._conn.close)
        return db

    def index_names(self, db: Database) -> set:
        return {r[0] for r in db._conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}

    def plan(self, db: Database, sql: str, params: tuple = ()) -> str:
        return " | ".join(r[3] for r in db._conn.execute("EXPLAIN QUERY PLAN " + sql, params))

    def test_restored_query_uses_partial_index(self):
        p = self.plan(self.open(), RESTORED_SQL)
        self.assertIn("events_restored", p)

    def test_aliases_query_uses_index(self):
        p = self.plan(self.open(), ALIASES_SQL, ("02:00:00:00:00:01",))
        self.assertIn("aliases_device", p)

    def test_reopen_current_schema_has_indexes(self):
        self.open()._conn.close()
        db = self.open()
        self.assertEqual(db.get_meta("schema_version"), "3")
        self.assertTrue(NAMES <= self.index_names(db))

    def test_newer_schema_gets_indexes_and_keeps_version(self):
        db = self.open()
        db.set_meta("schema_version", "99")
        db._conn.execute("DROP INDEX events_restored")
        db._conn.execute("DROP INDEX aliases_device")
        db._conn.close()
        db = self.open()
        self.assertEqual(db.get_meta("schema_version"), "99")
        self.assertTrue(NAMES <= self.index_names(db))


if __name__ == "__main__":
    unittest.main()
