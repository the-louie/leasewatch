"""Collector.loop: clear last_error text for database errors, one traceback per failed spell, a line on recovery."""
from __future__ import annotations

import sqlite3
import threading
import time
import unittest
from unittest import mock

from test_instances import FW1, Base, arp
from leasewatch.db import db_error_text


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

    def test_returned_failure_does_not_end_the_spell(self):
        col, db = self.collector(FW1)
        boom = RuntimeError("x")
        cm = self.run_loop(col, [boom, boom, {"ok": False}, {"ok": False}, {"ok": True}])
        info = [r.getMessage() for r in cm.records if r.levelname == "INFO"]
        self.assertEqual(info, ["polls work again after 2 failed poll(s)"])  # once, after the ok poll; count unchanged

    def test_returned_failure_alone_logs_no_recovery(self):
        col, db = self.collector(FW1)
        cm = self.run_loop(col, [RuntimeError("x"), {"ok": False}])
        self.assertEqual([r for r in cm.records if r.levelname == "INFO"], [])

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


class PruneClockTests(Base):
    """PRUNE_DAYS goes by the clamped prune clock, not the wall clock."""
    DAY = 86400

    def offline_device(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1, "PRUNE_DAYS": "30"})
        col.run_once()  # the baseline
        t0 = int(time.time())
        db.q("UPDATE devices SET online=0, last_online=? WHERE mac=?", (t0 - 3600, "02:00:00:00:00:01"))
        self.client.rows = [arp("02:00:00:00:00:09", "10.0.0.9")]  # another device keeps the poll non-empty
        return col, db, t0

    def poll_at(self, col, wall, mono):
        with mock.patch("time.time", return_value=wall), mock.patch("time.monotonic", return_value=mono):
            r = col.run_once()
            self.assertTrue(r["ok"], r)

    def test_forward_clock_step_archives_nothing(self):
        col, db, t0 = self.offline_device()
        self.poll_at(col, t0 + 100 * self.DAY, time.monotonic() + 5)
        self.assertIsNone(db.q("SELECT archived_ts FROM devices WHERE mac='02:00:00:00:00:01'")[0]["archived_ts"])
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events WHERE kind='archived'")[0]["n"], 0)

    def test_real_ageing_archives_with_the_clamped_age(self):
        col, db, t0 = self.offline_device()
        m0 = time.monotonic()
        for days in (10, 20):
            self.poll_at(col, t0 + days * self.DAY, m0 + days * self.DAY)
            self.assertIsNone(db.q("SELECT archived_ts FROM devices WHERE mac='02:00:00:00:00:01'")[0]["archived_ts"])
        self.poll_at(col, t0 + 31 * self.DAY, m0 + 31 * self.DAY)
        self.assertEqual(db.q("SELECT archived_ts FROM devices WHERE mac='02:00:00:00:00:01'")[0]["archived_ts"], t0 + 31 * self.DAY)
        self.assertEqual([r["detail"] for r in db.q("SELECT detail FROM events WHERE kind='archived'")],
                         ["auto: not online for 31 days"])


if __name__ == "__main__":
    unittest.main()
