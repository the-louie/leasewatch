"""The ETag follows writes from this connection (total_changes) and from another one (data_version)."""
from __future__ import annotations

import time
import unittest

import test_web_edge_cases as QW
from leasewatch.db import Database


class EtagVersionTests(QW.Base):
    def setUp(self) -> None:
        super().setUp()
        self.db.set_meta("last_poll_ts", str(int(time.time())))  # fresh data: meta.stale is false
        self.add_device(hostname="laptop")

    def tag(self, path: str = "/api/devices") -> str:
        h = self.handler(path=path)
        h.do_GET()
        head = h.wfile.getvalue().partition(b"\r\n\r\n")[0].decode().split("\r\n")
        return next(ln.partition(": ")[2] for ln in head if ln.lower().startswith("etag:"))

    def other(self) -> Database:
        o = Database(self.cfg.db_path)
        self.addCleanup(o._conn.close)
        return o

    def test_external_name_write_changes_devices_tag(self) -> None:
        before = self.tag()
        self.other().q("UPDATE devices SET name='x'")
        self.assertNotEqual(self.tag(), before)

    def test_own_write_changes_tag(self) -> None:
        before = self.tag()
        self.db.q("UPDATE devices SET name='y'")
        self.assertNotEqual(self.tag(), before)

    def test_idle_reads_same_tag(self) -> None:
        self.assertEqual(self.tag(), self.tag())

    def test_external_event_insert_changes_events_tag(self) -> None:
        before = self.tag("/api/events")
        self.other().q("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (int(time.time()), "", "note", "x"))
        self.assertNotEqual(self.tag("/api/events"), before)


if __name__ == "__main__":
    unittest.main()
