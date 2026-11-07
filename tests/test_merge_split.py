"""devices.split_from: added by the column migration on a fresh DB, an older DB and a newer-schema DB."""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from leasewatch import db as dbmod  # noqa: E402
from leasewatch.db import Database  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
