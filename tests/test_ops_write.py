"""Write protection (READ_ONLY, WRITE_ALLOW) on POST and in the meta, and the /metrics route."""
from __future__ import annotations

import base64
import gzip
import io
import json
import unittest
from unittest import mock

import test_web_edge_cases as QW
from test_ops_metrics import parse as parse_metrics
from leasewatch import auth, metrics, web

PASSWORD = "correct horse battery"
HASH = auth.make_hash(PASSWORD, 100_000)
CREDS = "Basic " + base64.b64encode(f"alex:{PASSWORD}".encode()).decode()
REFUSED = {"error": "writes are not allowed from this address"}


class _Base(QW.Base):
    def setUp(self) -> None:
        super().setUp()
        self.add_device(hostname="laptop")

    @staticmethod
    def parse(h: object) -> tuple[int, dict, bytes]:
        head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        return int(lines[0].split()[1]), {k.lower(): v for k, _, v in (ln.partition(": ") for ln in lines[1:])}, body

    def post(self, client: str = "127.0.0.1", path: str = f"/api/devices/{QW.MAC}", body: dict | None = None,
             extra: bytes = b"") -> tuple[int, dict, bytes]:
        raw = json.dumps(body if body is not None else {"name": "renamed"}).encode()
        hdr = (b"Host: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: " + str(len(raw)).encode() + b"\r\n"
               + extra)
        h = self.handler(command="POST", path=path, headers=hdr, rfile=io.BytesIO(raw))
        h.client_address = (client, 40000)
        h.do_POST()
        return self.parse(h)

    def get(self, path: str = "/api/devices", client: str = "127.0.0.1", command: str = "GET",
            extra: bytes = b"") -> tuple[int, dict, bytes]:
        h = self.handler(command=command, path=path, headers=b"Host: 127.0.0.1\r\n" + extra)
        h.client_address = (client, 40000)
        h.do_GET()
        return self.parse(h)

    def meta(self, client: str = "127.0.0.1") -> dict:
        return json.loads(self.get(client=client)[2])["meta"]


class ReadOnlyTests(_Base):
    env = {"READ_ONLY": "1"}

    def test_post_refused_get_served(self) -> None:
        with self.assertLogs("leasewatch.web", "DEBUG") as cm:
            st, h, body = self.post()
        self.assertEqual((st, json.loads(body)), (403, {"error": "read-only"}))
        self.assertEqual(h["content-security-policy"], web.CSP)
        self.assertFalse([r for r in cm.records if r.levelname != "DEBUG"])  # expected, so not a warning
        self.assertEqual(self.db.device_detail(QW.MAC)["device"]["name"], "")
        st, _, body = self.get()
        self.assertEqual(st, 200)
        m = json.loads(body)["meta"]
        self.assertIs(m["read_only"], True)
        self.assertIs(m["can_write"], False)

    def test_read_only_wins_over_write_allow(self) -> None:
        with mock.patch.object(self.cfg, "write_allow", "10.0.1.0/24"):
            st, _, body = self.post(client="10.0.1.7")
        self.assertEqual((st, json.loads(body)), (403, {"error": "read-only"}))


class WriteAllowTests(_Base):
    env = {"WRITE_ALLOW": "10.0.1.0/24"}

    def tearDown(self) -> None:
        t = self.H.write_refusals._timer
        if t is not None:
            t.cancel()
        super().tearDown()

    def test_inside_may_write(self) -> None:
        st, _, body = self.post(client="10.0.1.7")
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["device"]["name"], "renamed")

    def test_outside_refused_without_echo(self) -> None:
        with self.assertLogs("leasewatch.web", "WARNING"):
            st, _, body = self.post(client="10.0.9.9")
        self.assertEqual((st, json.loads(body)), (403, REFUSED))
        self.assertNotIn(b"10.0.9.9", body)
        self.assertEqual(self.db.device_detail(QW.MAC)["device"]["name"], "")

    def test_forwarded_for_is_ignored(self) -> None:
        with self.assertLogs("leasewatch.web", "WARNING"):
            st, _, _ = self.post(client="10.0.9.9", extra=b"X-Forwarded-For: 10.0.1.7\r\nX-Real-IP: 10.0.1.7\r\n")
        self.assertEqual(st, 403)

    def test_refused_before_routing(self) -> None:
        with self.assertLogs("leasewatch.web", "WARNING"):
            st, _, body = self.post(client="10.0.9.9", path="/nope")
        self.assertEqual((st, json.loads(body)), (403, REFUSED))
        self.assertEqual(self.post(client="10.0.1.7", path="/nope")[0], 404)

    def test_meta_per_client(self) -> None:
        self.assertEqual({k: self.meta("10.0.1.7")[k] for k in ("read_only", "can_write")},
                         {"read_only": False, "can_write": True})
        self.assertEqual({k: self.meta("10.0.9.9")[k] for k in ("read_only", "can_write")},
                         {"read_only": False, "can_write": False})

    def test_refusals_logged_once_a_minute_with_count(self) -> None:
        with mock.patch("leasewatch.web.time.monotonic", return_value=5000.0) as now:
            with self.assertLogs("leasewatch.web", "WARNING") as cm:
                self.post(client="10.0.9.9")
            self.assertEqual(cm.output, ["WARNING:leasewatch.web:refused 1 write(s) outside WRITE_ALLOW (last from 10.0.9.9)"])
            now.return_value = 5010.0
            with self.assertNoLogs("leasewatch.web", "WARNING"):
                self.post(client="10.0.9.9")
                self.post(client="10.0.9.8")
            now.return_value = 5061.0
            with self.assertLogs("leasewatch.web", "WARNING") as cm:
                self.post(client="10.0.9.7")
            self.assertEqual(cm.output, ["WARNING:leasewatch.web:refused 3 write(s) outside WRITE_ALLOW (last from 10.0.9.7)"])
            # a burst that ends inside the window: the timer's report brings it to the log
            now.return_value = 5070.0
            with self.assertNoLogs("leasewatch.web", "WARNING"):
                self.post(client="10.0.9.6")
            self.assertIsNotNone(self.H.write_refusals._timer)
            now.return_value = 5122.0
            with self.assertLogs("leasewatch.web", "WARNING") as cm:
                self.H.write_refusals._report()
            self.assertEqual(cm.output, ["WARNING:leasewatch.web:refused 1 write(s) outside WRITE_ALLOW (last from 10.0.9.6)"])

    def test_allowed_post_not_counted(self) -> None:
        with self.assertNoLogs("leasewatch.web", "WARNING"):
            self.post(client="10.0.1.7")


class LoginAndWriteAllowTests(_Base):
    env = {"WRITE_ALLOW": "10.0.1.0/24", "AUTH_USER": "alex", "AUTH_PASSWORD_HASH": HASH}

    def test_401_before_the_write_check(self) -> None:
        st, h, body = self.post(client="10.0.9.9")
        self.assertEqual((st, json.loads(body)), (401, {"error": "authentication required"}))
        self.assertIn("www-authenticate", h)
        with self.assertLogs("leasewatch.web", "WARNING"):
            st, _, body = self.post(client="10.0.9.9", extra=f"Authorization: {CREDS}\r\n".encode())
        self.assertEqual((st, json.loads(body)), (403, REFUSED))
        st, _, _ = self.post(client="10.0.1.7", extra=f"Authorization: {CREDS}\r\n".encode())
        self.assertEqual(st, 200)

    def test_metrics_needs_login(self) -> None:
        st, _, body = self.get("/metrics")
        self.assertEqual((st, json.loads(body)), (401, {"error": "authentication required"}))
        st, h, _ = self.get("/metrics", extra=f"Authorization: {CREDS}\r\n".encode())
        self.assertEqual((st, h["content-type"]), (200, metrics.CONTENT_TYPE))


class MetricsRouteTests(_Base):
    def test_text_parses_with_headers(self) -> None:
        st, h, body = self.get("/metrics")
        self.assertEqual(st, 200)
        self.assertEqual(h["content-type"], "text/plain; version=0.0.4; charset=utf-8")
        self.assertEqual(h["cache-control"], "no-store")
        self.assertEqual(h["vary"], "Accept-Encoding")
        self.assertEqual(h["content-security-policy"], web.CSP)
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertNotIn("etag", h)
        self.assertNotIn("content-encoding", h)
        m = parse_metrics(body.decode())
        self.assertEqual(m["leasewatch_build_info"], [({"version": "9.9.9"}, 1.0)])
        self.assertEqual(m["leasewatch_devices_archived"], [({}, 0.0)])

    def test_gzip_when_accepted(self) -> None:
        _, plain, raw = self.get("/metrics")
        self.assertGreater(len(raw), 1024)  # over the size _encode compresses from
        st, h, body = self.get("/metrics", extra=b"Accept-Encoding: gzip\r\n")
        self.assertEqual((st, h["content-encoding"], h["vary"]), (200, "gzip", "Accept-Encoding"))
        parse_metrics(gzip.decompress(body).decode())

    def test_head(self) -> None:
        st, h, body = self.get("/metrics", command="HEAD")
        self.assertEqual((st, body, h["content-type"]), (200, b"", metrics.CONTENT_TYPE))
        self.assertNotIn("etag", h)

    def test_if_none_match_gets_200(self) -> None:
        st, h, _ = self.get("/metrics", extra=b"If-None-Match: *\r\n")
        self.assertEqual(st, 200)
        self.assertNotIn("etag", h)


if __name__ == "__main__":
    unittest.main()
