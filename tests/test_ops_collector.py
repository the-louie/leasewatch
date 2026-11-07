"""Collector.loop: clear last_error text for database errors, one traceback per failed spell, a line on recovery."""
from __future__ import annotations

import os
import sqlite3
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from test_instances import FW1, Base  # noqa: E402
from leasewatch.db import db_error_text  # noqa: E402


def sqlite_error(cls, text: str, code: int, name: str) -> sqlite3.Error:
    e = cls(text)
    e.sqlite_errorcode, e.sqlite_errorname = code, name
    return e


class Steps(threading.Event):
    """A stop event that ends the loop after n waits (one wait per poll)."""

    def __init__(self, n: int):
        super().__init__()
        self.n = n

    def wait(self, timeout=None):
        self.n -= 1
        if self.n <= 0:
            self.set()
        return self.is_set()


class TextTests(unittest.TestCase):
    def test_codes(self):
        for code, name, text in ((13, "SQLITE_FULL", "database full (disk or size limit)"),
                                 (5, "SQLITE_BUSY", "database locked by another process"),
                                 (6, "SQLITE_LOCKED", "database locked by another process"),
                                 (10, "SQLITE_IOERR", "database I/O error"),
                                 (8, "SQLITE_READONLY", "database is read-only (check DATA_DIR permissions)"),
                                 (11, "SQLITE_CORRUPT", "database file is damaged (restore a backup)"),
                                 (26, "SQLITE_NOTADB", "database file is damaged (restore a backup)"),
                                 (13 | (2 << 8), "SQLITE_FULL_X", "database full (disk or size limit)")):
            self.assertEqual(db_error_text(sqlite_error(sqlite3.OperationalError, "x", code, name)), text)

    def test_other_and_no_code(self):
        self.assertEqual(db_error_text(sqlite_error(sqlite3.OperationalError, "x", 1, "SQLITE_ERROR")),
                         "database error (SQLITE_ERROR)")
        self.assertEqual(db_error_text(sqlite3.OperationalError("x")), "database error (OperationalError)")


class LoopTests(Base):
    def run_loop(self, col, effects, polls=None):
        with mock.patch.object(col, "run_once", side_effect=effects):
            with self.assertLogs("leasewatch.collector", "DEBUG") as cm:
                col.loop(Steps(polls or len(effects)))
        return cm

    def test_full_disk_one_traceback_then_recovery(self):
        col, db = self.collector(FW1)
        full = sqlite_error(sqlite3.OperationalError, "database or disk is full", 13, "SQLITE_FULL")
        cm = self.run_loop(col, [full, full, full, {"ok": True}])
        self.assertEqual(db.get_meta("last_error"), "database full (disk or size limit)")
        errors = [r for r in cm.records if r.levelname == "ERROR"]
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].exc_info)
        self.assertEqual(sum(1 for r in cm.records if r.exc_info), 1)
        self.assertEqual([r.getMessage() for r in cm.records if r.levelname == "INFO"],
                         ["polls work again after 3 failed poll(s)"])

    def test_locked(self):
        col, db = self.collector(FW1)
        self.run_loop(col, [sqlite_error(sqlite3.OperationalError, "database is locked", 5, "SQLITE_BUSY")])
        self.assertEqual(db.get_meta("last_error"), "database locked by another process")

    def test_other_error_keeps_the_old_text(self):
        col, db = self.collector(FW1)
        self.run_loop(col, [ValueError("boom")])
        self.assertEqual(db.get_meta("last_error"), "internal error in collector (see logs)")

    def test_new_cause_in_the_same_spell_logs_again(self):
        col, db = self.collector(FW1)
        full = sqlite_error(sqlite3.OperationalError, "full", 13, "SQLITE_FULL")
        busy = sqlite_error(sqlite3.OperationalError, "busy", 5, "SQLITE_BUSY")
        cm = self.run_loop(col, [full, busy, busy])
        self.assertEqual(sum(1 for r in cm.records if r.exc_info), 2)

    def test_real_full_disk(self):
        col, db = self.collector(FW1)
        db._conn.execute("PRAGMA max_page_count=%d" % db._conn.execute("PRAGMA page_count").fetchone()[0])

        def fill(*a, **k):
            with db.tx() as c:
                c.execute("CREATE TABLE junk(x)")
                for _ in range(2000):
                    c.execute("INSERT INTO junk VALUES(zeroblob(4096))")

        cm = self.run_loop(col, [sqlite_error(sqlite3.OperationalError, "x", 13, "SQLITE_FULL")])
        self.assertEqual(db.get_meta("last_error"), "database full (disk or size limit)")
        with self.assertRaises(sqlite3.OperationalError) as r:
            fill()
        self.assertEqual(db_error_text(r.exception), "database full (disk or size limit)")
        self.assertTrue(cm.records)

    def test_unrecordable_failure_warns_once_without_traceback(self):
        col, db = self.collector(FW1)
        full = sqlite_error(sqlite3.OperationalError, "full", 13, "SQLITE_FULL")
        with mock.patch.object(col, "_fail", side_effect=full):
            cm = self.run_loop(col, [full, full, full])
        warns = [r for r in cm.records if r.levelname == "WARNING"]
        self.assertEqual(len(warns), 1)
        self.assertFalse(warns[0].exc_info)
        self.assertIn("cannot record the failed poll: database full", warns[0].getMessage())

    def test_shutdown_still_breaks_quietly(self):
        col, db = self.collector(FW1)
        stop = threading.Event()

        def boom():
            stop.set()
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")

        with mock.patch.object(col, "run_once", side_effect=boom):
            with self.assertLogs("leasewatch.collector", "DEBUG") as cm:
                col.loop(stop)
        self.assertFalse([r for r in cm.records if r.levelno >= 30])


if __name__ == "__main__":
    unittest.main()
