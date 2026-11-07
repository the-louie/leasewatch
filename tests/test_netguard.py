"""S6 T-01: the network guard. Importing this module installs it for the whole `unittest discover` run (every
module is imported before the first test runs); the tests prove that it blocks and fails non-loopback attempts,
including swallowed ones, and leaves loopback alone."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _netguard  # noqa: E402
from _netguard import NetworkBlocked, expect_blocked  # noqa: E402

_netguard.install()

DOC_IP = "192.0.2.1"  # RFC 5737 documentation address: never routed


class GuardBlocksTest(unittest.TestCase):
    def test_installed(self) -> None:
        self.assertTrue(_netguard.installed())

    def test_connect_to_documentation_address_fails_loudly(self) -> None:
        with expect_blocked() as caught, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            with self.assertRaises(NetworkBlocked) as cm:
                s.connect((DOC_IP, 80))
            with self.assertRaises(NetworkBlocked):
                s.connect_ex((DOC_IP, 80))
        self.assertIn("network guard", str(cm.exception))
        self.assertIn(DOC_IP, str(cm.exception))
        self.assertIn("must not reach the network", str(cm.exception))
        self.assertEqual(len(caught), 2)

    def test_create_connection_fails_loudly(self) -> None:
        with expect_blocked() as caught, self.assertRaises(NetworkBlocked):
            socket.create_connection((DOC_IP, 443), timeout=1)
        self.assertEqual(len(caught), 1)

    def test_getaddrinfo_of_a_public_name_fails_loudly(self) -> None:
        with expect_blocked() as caught, self.assertRaises(NetworkBlocked) as cm:
            socket.getaddrinfo("api.mailgun.net", 443)
        self.assertIn("network guard: a test tried to resolve 'api.mailgun.net' port 443", str(cm.exception))
        self.assertEqual(len(caught), 1)

    def test_blocked_error_is_an_oserror(self) -> None:
        # clients wrap OSError into their own exception type: the code under test takes its normal failure path
        self.assertTrue(issubclass(NetworkBlocked, OSError))

    def test_swallowed_attempt_still_fails_the_test(self) -> None:
        def swallow() -> None:
            try:
                socket.create_connection((DOC_IP, 80), timeout=1)
            except OSError:
                pass  # what a client wrapping the error into its own type looks like from the test

        inner = unittest.FunctionTestCase(swallow)
        result = unittest.TestResult()
        with expect_blocked():
            inner.run(result)
        self.assertEqual(len(result.failures), 1, result.errors)
        self.assertIn("network guard", result.failures[0][1])
        self.assertIn(DOC_IP, result.failures[0][1])

    def test_host_allowed(self) -> None:
        for host in (None, "", "localhost", "LOCALHOST", "127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1",
                     "0.0.0.0", "::", b"127.0.0.1"):
            with self.subTest(host=host):
                self.assertTrue(_netguard.host_allowed(host))
        for host in (DOC_IP, "10.0.0.2", "2001:db8::1", "fw1.example.lan", "api.mailgun.net", b"example.com",
                     "localhost.example.com"):
            with self.subTest(host=host):
                self.assertFalse(_netguard.host_allowed(host))


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a: object) -> None:
        pass


class GuardAllowsLoopbackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = HTTPServer(("127.0.0.1", 0), _Ok)
        self.addCleanup(self.srv.server_close)
        t = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(self.srv.shutdown)
        self.port = self.srv.server_address[1]

    def test_loopback_connections_work(self) -> None:
        for host in ("127.0.0.1", "localhost"):
            with self.subTest(host=host), socket.create_connection((host, self.port), timeout=5) as s:
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                self.assertTrue(s.recv(64).startswith(b"HTTP/1.0 204"))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            self.assertEqual(s.connect_ex(("127.0.0.1", self.port)), 0)
        self.assertTrue(socket.getaddrinfo("localhost", self.port))

    def test_unix_socket_works(self) -> None:
        with tempfile.TemporaryDirectory() as d, socket.socket(socket.AF_UNIX) as srv, socket.socket(socket.AF_UNIX) as c:
            path = os.path.join(d, "s")
            srv.bind(path)
            srv.listen(1)
            c.connect(path)
            conn, _ = srv.accept()
            conn.close()


class ChildGuardTest(unittest.TestCase):
    """child_argv() (used for the contrib package suites) runs `unittest discover` with the guard installed."""

    def test_child_suite_fails_on_a_swallowed_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "tests"))
            with open(os.path.join(d, "tests", "test_leak.py"), "w", encoding="utf-8") as f:
                f.write("import socket, unittest\n"
                        "class T(unittest.TestCase):\n"
                        "    def test_leak(self):\n"
                        "        try:\n"
                        f"            socket.create_connection(({DOC_IP!r}, 80), timeout=1)\n"
                        "        except OSError:\n"
                        "            pass\n")
            r = subprocess.run(_netguard.child_argv("discover", "-s", "tests"), cwd=d, capture_output=True, text=True,
                               timeout=60)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("network guard", r.stderr)
        self.assertIn("FAILED (failures=1)", r.stderr)


if __name__ == "__main__":
    unittest.main()
