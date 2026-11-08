"""gzip on /api/devices, /api/events and /api/status: only when asked for, only above 1 KiB, never on files."""
from __future__ import annotations

import gzip
import json
import os
import sys
import unittest
from unittest import mock

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_web_edge_cases as QW  # noqa: E402


class GzipTests(QW.Base):
    def seed(self, n: int) -> None:
        self.db._conn.executemany("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,1)",
                                  [(f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}",) for i in range(n)])
        self.db._conn.commit()

    def get(self, path: str, enc: str | None = None, command: str = "GET") -> tuple[dict, bytes]:
        hdr = b"Host: 127.0.0.1\r\n"
        if enc is not None:
            hdr += b"Accept-Encoding: " + enc.encode() + b"\r\n"
        h = self.handler(command=command, path=path, headers=hdr)
        h.do_GET()
        head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")[1:]
        return {k.lower(): v for k, _, v in (ln.partition(": ") for ln in lines)}, body

    def test_gzip_when_accepted(self) -> None:
        self.seed(2000)
        h, body = self.get("/api/devices", "gzip")
        self.assertEqual(h["content-encoding"], "gzip")
        self.assertEqual(h["vary"], "Accept-Encoding")
        self.assertEqual(int(h["content-length"]), len(body))
        self.assertEqual(len(json.loads(gzip.decompress(body))["devices"]), 2000)

    def test_identity_without_header(self) -> None:
        self.seed(2000)
        h, body = self.get("/api/devices")
        self.assertNotIn("content-encoding", h)
        self.assertEqual(h["vary"], "Accept-Encoding")
        self.assertEqual(int(h["content-length"]), len(body))
        self.assertEqual(len(json.loads(body)["devices"]), 2000)

    def test_q_values_and_wildcard(self) -> None:
        self.seed(2000)
        for enc, want in [("gzip;q=0", False), ("gzip; q=0.0, identity", False), ("identity", False),
                          ("*", True), ("*;q=0.5", True), ("gzip;q=0, *", False), ("deflate, gzip;q=0.5", True),
                          ("GZIP", True), ("gzip;q=x", False)]:
            h, _ = self.get("/api/devices", enc)
            self.assertEqual("content-encoding" in h, want, enc)
            self.assertEqual(h["vary"], "Accept-Encoding")

    def test_small_body_is_identity(self) -> None:
        h, body = self.get("/api/devices", "gzip")
        self.assertLessEqual(len(body), 1024)
        self.assertNotIn("content-encoding", h)
        self.assertEqual(h["vary"], "Accept-Encoding")
        json.loads(body)

    def test_other_routes_have_vary(self) -> None:
        for path in ("/api/status", "/api/events"):
            h, _ = self.get(path, "gzip")
            self.assertEqual(h["vary"], "Accept-Encoding", path)

    def test_csv_and_static_not_compressed(self) -> None:
        self.seed(200)
        for path in ("/api/devices.csv", "/static/app.js"):
            h, body = self.get(path, "gzip")
            self.assertNotIn("content-encoding", h, path)
            self.assertNotIn("vary", h, path)
            self.assertGreater(len(body), 1024, path)

    def test_head_has_headers_and_no_body(self) -> None:
        self.seed(2000)
        # Clock frozen: the body carries the time, so the two gzip lengths differ across a second boundary.
        with mock.patch("leasewatch.web.time.time", return_value=1_800_000_000.0):
            gh, gbody = self.get("/api/devices", "gzip")
            h, body = self.get("/api/devices", "gzip", command="HEAD")
        self.assertEqual(body, b"")
        self.assertEqual(h["content-encoding"], "gzip")
        self.assertEqual(h["vary"], "Accept-Encoding")
        self.assertEqual(h["content-length"], str(len(gbody)))

    def test_security_headers_kept(self) -> None:
        self.seed(2000)
        h, _ = self.get("/api/devices", "gzip")
        self.assertEqual(h["cache-control"], "no-store")
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertIn("content-security-policy", h)


if __name__ == "__main__":
    unittest.main()
