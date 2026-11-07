"""The connection cap (a 503 instead of a thread) and the request-read deadline, on a real server on loopback."""
from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from leasewatch import auth, web  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.db import Database  # noqa: E402

ENV = {**FW1_ENV, "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0"}
MAC = "aa:bb:cc:dd:ee:01"


def headers_of(raw: bytes) -> dict[str, str]:
    head = raw.partition(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")[1:]
    return {k: v for k, _, v in (ln.partition(": ") for ln in head)}


def wait_until(cond, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


class ServerTests(unittest.TestCase):
    max_connections = 64
    read_seconds = 15.0
    extra_env: dict = {}

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = clean_env(dict(ENV, DATA_DIR=self.tmp.name, **self.extra_env))
        self.cfg = Config()
        self.db = Database(self.cfg.db_path)
        self.db.q("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,1)", (MAC,))
        patches = [mock.patch.object(web.Server, "MAX_CONNECTIONS", self.max_connections),
                   mock.patch.object(web.Handler, "REQUEST_READ_SECONDS", self.read_seconds)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.base_threads = threading.active_count()
        self.srv = web.serve(self.cfg, self.db, "9.9.9")
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.socks: list[socket.socket] = []

    def tearDown(self) -> None:
        for s in self.socks:
            s.close()
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)
        # the handler threads end once their clients are gone; the database is closed after them
        wait_until(lambda: threading.active_count() <= self.base_threads)
        self.db._conn.close()
        self.tmp.cleanup()
        restore(self._saved)

    def stalled(self, n: int) -> list[socket.socket]:
        new = [socket.create_connection(("127.0.0.1", self.port), timeout=5) for _ in range(n)]
        self.socks += new
        return new

    def req(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            return r.status, r.headers, r.read()
        finally:
            conn.close()

    def raw_get(self) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"GET /api/status HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            return recv_all(s)


def recv_all(s: socket.socket) -> bytes:
    chunks = []
    while True:
        c = s.recv(65536)
        if not c:
            return b"".join(chunks)
        chunks.append(c)


class ConnectionCapTests(ServerTests):
    max_connections = 4

    def test_over_the_limit_gets_503_then_200_after(self) -> None:
        with self.assertLogs("leasewatch.web", "INFO") as logs:
            self.stalled(4)
            self.assertTrue(wait_until(lambda: threading.active_count() >= self.base_threads + 1 + 4))
            raw = self.raw_get()
            self.assertTrue(raw.startswith(b"HTTP/1.0 503 "), raw[:80])
            h = headers_of(raw)
            self.assertEqual((h["Retry-After"], h["Connection"]), ("5", "close"))
            self.assertTrue(h["Content-Type"].startswith("application/json"))
            for k, v in web._SECURITY_HEADERS.items():
                self.assertEqual(h[k], v, k)
            self.assertEqual(json.loads(raw.partition(b"\r\n\r\n")[2]), {"error": "busy"})
            for s in self.socks:
                s.close()
            self.socks.clear()
            self.assertTrue(wait_until(lambda: threading.active_count() <= self.base_threads + 1))
            self.assertEqual(self.req("GET", "/api/status")[0], 200)
        out = "\n".join(logs.output)
        self.assertIn("WARNING:leasewatch.web:connection limit (4) reached; refusing connections", out)
        self.assertIn("INFO:leasewatch.web:connections accepted again (1 refused)", out)

    def test_refusal_carries_the_same_security_headers(self) -> None:
        status, hdrs, _ = self.req("GET", "/api/status")
        self.assertEqual(status, 200)
        normal = {(k, v) for k, v in hdrs.items() if k in web._SECURITY_HEADERS}
        busy = headers_of(web._BUSY_RESPONSE)
        refusal = {(k, v) for k, v in busy.items() if k not in ("Content-Type", "Content-Length", "Retry-After", "Connection")}
        self.assertEqual(refusal, normal)
        self.assertEqual(normal, set(web._SECURITY_HEADERS.items()))


class ReadDeadlineTests(ServerTests):
    read_seconds = 1.0

    def test_stalled_connections_are_closed_at_the_deadline(self) -> None:
        socks = self.stalled(10)
        t0 = time.monotonic()
        for s in socks:
            self.assertEqual(s.recv(1), b"")  # closed by the server, nothing sent
        self.assertLess(time.monotonic() - t0, 2.5)
        self.assertEqual(self.req("GET", "/api/status")[0], 200)

    def test_threads_stay_bounded_and_the_rest_are_refused(self) -> None:
        with self.assertLogs("leasewatch.web", "WARNING"):
            socks = self.stalled(70)
            self.assertTrue(wait_until(lambda: threading.active_count() >= self.base_threads + 1 + 64, 3))
            self.assertLessEqual(threading.active_count(), self.base_threads + 1 + 64)
            refused = [s for s in socks if recv_all(s).startswith(b"HTTP/1.0 503 ")]
        self.assertEqual(len(refused), 6)

    def test_a_trickling_client_is_cut_at_the_deadline(self) -> None:
        s = self.stalled(1)[0]
        s.sendall(b"GET /api/status HTTP/1.0\r\nX-Slow: ")
        stop = threading.Event()

        def trickle() -> None:
            while not stop.wait(0.3):
                try:
                    s.send(b"a")
                except OSError:
                    return

        t = threading.Thread(target=trickle, daemon=True)
        t.start()
        t0 = time.monotonic()
        try:
            data = s.recv(65536)
        except ConnectionResetError:
            data = b""
        elapsed = time.monotonic() - t0
        stop.set()
        t.join(2)
        self.assertEqual(data, b"")
        self.assertGreater(elapsed, 0.7)
        self.assertLess(elapsed, 1.8)

    def test_get_head_and_post_still_work(self) -> None:
        self.assertEqual(self.req("GET", "/api/status")[0], 200)
        status, _, body = self.req("HEAD", "/api/status")
        self.assertEqual((status, body), (200, b""))
        status, _, body = self.req("POST", f"/api/devices/{MAC}", json.dumps({"acked": True}).encode(),
                                   {"Content-Type": "application/json"})
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["device"]["acked"])

    def test_the_write_timeout_is_back_after_the_read(self) -> None:
        # a response written after the read deadline still gets the handler's full write timeout
        orig, seen = web.Handler._api_status, []

        def slow(h: web.Handler) -> None:
            time.sleep(1.3)
            seen.append(h.connection.gettimeout())
            orig(h)

        with mock.patch.object(web.Handler, "_api_status", slow):
            self.assertEqual(self.req("GET", "/api/status")[0], 200)
        self.assertEqual(seen, [web.Handler.timeout])

class SlowAuthTests(ServerTests):
    """The server's own password check must not use up the time the body has to arrive."""
    read_seconds = 1.0
    extra_env = {"AUTH_USER": "alex", "AUTH_PASSWORD_HASH": auth.make_hash("pw-for-the-test", 100_000)}

    def test_post_with_its_body_is_answered_after_a_slow_check(self) -> None:
        import base64
        real = auth.Verifier.check

        def slow(v, header, client=""):
            time.sleep(1.5)  # past REQUEST_READ_SECONDS
            return real(v, header, client)

        body = json.dumps({"acked": True}).encode()
        cred = base64.b64encode(b"alex:pw-for-the-test").decode()
        raw = (f"POST /api/devices/{MAC} HTTP/1.0\r\nHost: 127.0.0.1\r\nAuthorization: Basic {cred}\r\n"
               f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
        with mock.patch.object(auth.Verifier, "check", slow):
            with socket.create_connection(("127.0.0.1", self.port), timeout=8) as s:
                s.sendall(raw)
                out = recv_all(s)
        self.assertTrue(out.startswith(b"HTTP/1.0 200 "), out[:80])
        self.assertTrue(json.loads(out.partition(b"\r\n\r\n")[2])["device"]["acked"])


if __name__ == "__main__":
    unittest.main()
