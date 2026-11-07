"""Indexes for the per-poll restored-events query and the aliases lookup."""
from __future__ import annotations

import os
import logging
import shutil
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

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


class CloseTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "t.db")
        self.db = Database(self.path)
        self.addCleanup(self.db.close)

    def fill(self, n: int = 2000) -> None:
        with self.db.tx() as c:
            for i in range(n):
                c.execute("INSERT INTO devices(mac, first_seen, last_seen) VALUES(?,?,?)", (f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}", 1, 1))
                c.execute("INSERT INTO events(mac, ts, kind, detail) VALUES(?,?,?,?)", (f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}", i, "new", "x" * 40))

    def test_close_merges_the_wal_into_the_main_file(self):
        self.fill()
        wal = self.path + "-wal"
        before = os.path.getsize(wal)
        self.assertGreater(before, 0)
        self.assertTrue(self.db.close())
        after = os.path.getsize(wal) if os.path.exists(wal) else 0
        self.assertEqual(after, 0)
        alone = os.path.join(self.dir, "copy.db")
        shutil.copyfile(self.path, alone)
        c = sqlite3.connect(alone)
        try:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 2000)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM events").fetchone()[0], 2000)
        finally:
            c.close()

    def test_close_twice_and_use_after_close(self):
        self.assertTrue(self.db.close())
        self.assertTrue(self.db.close())
        with self.assertRaises(sqlite3.ProgrammingError):
            self.db.q("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            with self.db.tx():
                pass
        with self.assertRaises(sqlite3.ProgrammingError):
            self.db.set_meta("k", "v")

    def test_busy_lock_is_reported_and_the_connection_survives(self):
        held, done = threading.Event(), threading.Event()

        def hold():
            with self.db._lock:
                held.set()
                done.wait(5)
        t = threading.Thread(target=hold)
        t.start()
        self.addCleanup(t.join)
        self.addCleanup(done.set)
        held.wait(5)
        with self.assertLogs("leasewatch.db", "WARNING") as cm:
            self.assertFalse(self.db.close(timeout=0.2))
        self.assertIn("database busy at shutdown", cm.output[0])
        done.set()
        t.join()
        self.assertEqual(self.db.q("SELECT 1 AS x")[0]["x"], 1)
        self.assertTrue(self.db.close())

    def test_poll_cut_off_by_shutdown_logs_no_error(self):
        from leasewatch.collector import Collector
        col = Collector.__new__(Collector)
        col.cfg = mock.Mock(poll_seconds=0)
        col.db = self.db
        stop = threading.Event()

        def run_once():
            stop.set()
            raise sqlite3.ProgrammingError("database is closed")
        col.run_once = run_once
        col._fail = mock.Mock(side_effect=AssertionError("must not record a failed poll"))
        with self.assertLogs("leasewatch", "DEBUG") as cm:
            logging.getLogger("leasewatch").debug("start")
            col.loop(stop)
        self.assertFalse([r for r in cm.records if r.levelno >= logging.ERROR], cm.output)
        self.assertIn("poll cut off by shutdown", "\n".join(cm.output))


if __name__ == "__main__":
    unittest.main()
