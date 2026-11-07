"""S5 T-02: optional HTTP basic auth (AUTH_USER + AUTH_PASSWORD_HASH), the hash format, the request check with its
success cache and CPU cap, `python -m leasewatch hash-password`, and the Docker healthcheck that accepts 401."""
import base64
import hashlib
import hmac
import io
import json
import logging
import os
import re
import subprocess
import sys
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..")
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)
import test_web  # noqa: E402
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from test_web import CSP, MAC2, WebTestCase  # noqa: E402
from leasewatch import __main__ as cli  # noqa: E402
from leasewatch import auth  # noqa: E402
from leasewatch.config import Config  # noqa: E402

USER = "alex"
PASSWORD = "correct horse battery"  # a known string the log and the CLI output must never carry
HASH = auth.make_hash(PASSWORD, 100_000)  # the lowest accepted count: each web test's first login stays fast
HASH_MSG = "AUTH_PASSWORD_HASH is not a valid hash (make one with python -m leasewatch hash-password)"
FAST = (1000, b"s" * 16, hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), b"s" * 16, 1000))  # Verifier only


def basic(user: str, pw: str, scheme: str = "Basic") -> str:
    return f"{scheme} " + base64.b64encode(f"{user}:{pw}".encode()).decode()


GOOD = basic(USER, PASSWORD)


def b64(n: int) -> str:
    return base64.urlsafe_b64encode(b"x" * n).rstrip(b"=").decode()


class HashTests(unittest.TestCase):
    def test_round_trip(self):
        h = auth.make_hash("pw")
        scheme, it, salt, dk = h.split(":")
        self.assertEqual((scheme, it), ("pbkdf2_sha256", "600000"))
        self.assertNotRegex(h, r"[$/+=]")  # safe in env files, shells and Compose
        parsed = auth.parse_hash(h)
        self.assertEqual(parsed[0], 600_000)
        self.assertEqual(len(parsed[1]), 16)
        self.assertEqual(parsed[2], hashlib.pbkdf2_hmac("sha256", b"pw", parsed[1], 600_000))
        self.assertNotEqual(auth.make_hash("pw"), h)  # random salt

    def test_iteration_bounds(self):
        self.assertIsNotNone(auth.parse_hash(f"pbkdf2_sha256:100000:{b64(16)}:{b64(32)}"))
        self.assertIsNotNone(auth.parse_hash(f"pbkdf2_sha256:10000000:{b64(8)}:{b64(32)}"))
        with self.assertRaises(ValueError):
            auth.make_hash("pw", 99_999)

    def test_malformed(self):
        for s in ("", "x", f"pbkdf2_sha1:600000:{b64(16)}:{b64(32)}", f"pbkdf2_sha256:0:{b64(16)}:{b64(32)}",
                  f"pbkdf2_sha256:99999:{b64(16)}:{b64(32)}", f"pbkdf2_sha256:100000000:{b64(16)}:{b64(32)}",
                  f"pbkdf2_sha256:+600000:{b64(16)}:{b64(32)}", f"pbkdf2_sha256:６00000:{b64(16)}:{b64(32)}",
                  f"pbkdf2_sha256:600000:{b64(7)}:{b64(32)}", f"pbkdf2_sha256:600000:{b64(16)}:{b64(31)}",
                  f"pbkdf2_sha256:600000:{b64(16)}:{b64(33)}", f"pbkdf2_sha256:600000:a$b!:{b64(32)}",
                  f"pbkdf2_sha256:600000:{b64(16)}:{b64(32)}=", f"pbkdf2_sha256:600000:{b64(16)}:{b64(32)}:x",
                  f"pbkdf2_sha256:600000:{b64(16)}:{b64(32)[:-1]}"):
            self.assertIsNone(auth.parse_hash(s), s)


class ParseBasicTests(unittest.TestCase):
    def test_cases(self):
        enc = lambda raw: "Basic " + base64.b64encode(raw).decode()  # noqa: E731
        self.assertEqual(auth.parse_basic(GOOD), (USER, PASSWORD))
        self.assertEqual(auth.parse_basic(basic(USER, PASSWORD, "bAsIc")), (USER, PASSWORD))
        self.assertEqual(auth.parse_basic(basic("u", "a:b:c")), ("u", "a:b:c"))  # split on the first colon
        self.assertEqual(auth.parse_basic(basic("", "")), ("", ""))
        for h in (None, "", "Basic", "Basic ", "Bearer abc", "Digest " + GOOD[6:], "Basic !!!!", "Basic YWJj=",
                  enc(b"\xff\xfe:pw"), enc(b"no-colon"), "Basic " + "QUFB" * 1300, "Basi̇c " + GOOD[6:],
                  "Basic " + GOOD[6:] + "é"):
            self.assertIsNone(auth.parse_basic(h), h and h[:40])


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.v = auth.Verifier(USER, FAST)
        logging.disable(logging.NOTSET)

    def test_check(self):
        self.assertTrue(self.v.check(GOOD))
        self.assertFalse(self.v.check(basic("alex2", PASSWORD)))
        self.assertFalse(self.v.check(basic(USER, PASSWORD + "x")))
        self.assertFalse(self.v.check(None))

    def test_constant_time_compare_and_pbkdf2_on_wrong_user(self):
        with mock.patch("hmac.compare_digest", wraps=hmac.compare_digest) as cd, \
                mock.patch("hashlib.pbkdf2_hmac", wraps=hashlib.pbkdf2_hmac) as kdf:
            self.assertFalse(self.v.check(basic("bob", PASSWORD)))
        self.assertEqual(kdf.call_count, 1)  # computed even for a wrong user: no timing hint about the name
        self.assertEqual(cd.call_count, 2)  # the user and the derived key
        self.assertIn(mock.call(b"bob", USER.encode()), cd.call_args_list)

    def test_success_cached_failure_not(self):
        with mock.patch("hashlib.pbkdf2_hmac", wraps=hashlib.pbkdf2_hmac) as kdf:
            self.assertTrue(self.v.check(GOOD))
            self.assertTrue(self.v.check(GOOD))
            self.assertEqual(kdf.call_count, 1)
            bad = basic(USER, "nope")
            self.assertFalse(self.v.check(bad))
            self.assertFalse(self.v.check(bad))
            self.assertEqual(kdf.call_count, 3)

    def test_cache_expires_after_ten_minutes(self):
        with mock.patch("hashlib.pbkdf2_hmac", wraps=hashlib.pbkdf2_hmac) as kdf, \
                mock.patch("leasewatch.auth.time.monotonic", return_value=1000.0) as now:
            self.v.check(GOOD)
            now.return_value = 1000.0 + 599
            self.v.check(GOOD)
            self.assertEqual(kdf.call_count, 1)
            now.return_value = 1000.0 + 601
            self.assertTrue(self.v.check(GOOD))
            self.assertEqual(kdf.call_count, 2)

    def test_cache_keeps_32_newest(self):
        token = GOOD.split(" ", 1)[1]
        headers = [f"Basic{' ' * n}{token}" for n in range(1, 41)]  # 40 headers, the same credentials
        for h in headers:
            self.assertTrue(self.v.check(h))
        self.assertEqual(len(self.v._cache), 32)
        self.assertNotIn(token.encode(), b"".join(self.v._cache))  # keyed by an HMAC, not the header
        with mock.patch("hashlib.pbkdf2_hmac", wraps=hashlib.pbkdf2_hmac) as kdf:
            self.v.check(headers[-1])
            self.assertEqual(kdf.call_count, 0)
            self.v.check(headers[0])  # the oldest was dropped
            self.assertEqual(kdf.call_count, 1)

    def test_busy(self):
        self.v._sem.acquire()
        self.v._sem.acquire()
        try:
            with mock.patch.object(auth, "BUSY_TIMEOUT", 0.05), self.assertRaises(auth.Busy):
                self.v.check(GOOD)
        finally:
            self.v._sem.release()
            self.v._sem.release()
        self.assertTrue(self.v.check(GOOD))

    def test_failure_log_has_no_credentials_and_is_rate_limited(self):
        with mock.patch("leasewatch.auth.time.monotonic", return_value=5000.0) as now:
            with self.assertLogs("leasewatch.auth", "WARNING") as cm:
                self.v.check(basic("mallory", PASSWORD), "10.0.0.9")
            text = "\n".join(cm.output)
            self.assertIn("10.0.0.9", text)
            for secret in ("mallory", PASSWORD, GOOD[6:]):
                self.assertNotIn(secret, text)
            now.return_value = 5030.0
            with self.assertNoLogs("leasewatch.auth", "WARNING"):
                self.v.check(basic(USER, "x"), "10.0.0.8")
                self.v.check("Basic !!", "10.0.0.7")
            now.return_value = 5061.0
            with self.assertLogs("leasewatch.auth", "WARNING") as cm:
                self.v.check(basic(USER, "y"), "10.0.0.6")
            self.assertIn("3 failed", cm.output[0])
            self.assertIn("10.0.0.6", cm.output[0])
            with self.assertNoLogs("leasewatch.auth", "WARNING"):
                self.v.check(None, "10.0.0.5")  # no credentials sent: the browser's first request, not an attempt


class ReviewS5Tests(unittest.TestCase):
    """S5 review: non-ASCII blanks in the header, a burst that ends inside the log window."""

    def setUp(self):
        self.v = auth.Verifier(USER, FAST)

    def test_non_ascii_blank_is_a_failed_login(self):
        # str.strip() drops 0xA0 and 0x85 (http.server decodes headers as latin-1); check() then raised
        for h in (GOOD + "\xa0", "\x85" + GOOD, "Basic \xa0" + GOOD[6:], GOOD + "\xe4"):
            with self.subTest(h=h):
                self.assertIsNone(auth.parse_basic(h))
                with self.assertLogs("leasewatch.auth", "WARNING"):
                    self.v._fail_logged = float("-inf")
                    self.assertFalse(self.v.check(h, "10.0.0.1"))

    def test_burst_inside_the_window_is_reported_later(self):
        reported = threading.Event()
        lines = []

        class H(logging.Handler):
            def emit(self, record):
                lines.append(record.getMessage())
                reported.set()

        h = H()
        logging.getLogger("leasewatch.auth").addHandler(h)
        try:
            with mock.patch.object(auth, "FAIL_LOG_EVERY", 0.3):
                self.v._failed("10.0.0.1")
                self.assertEqual(len(lines), 1)
                reported.clear()
                for _ in range(5):
                    self.v._failed("10.0.0.2")
                self.assertTrue(reported.wait(5), "the held-back attempts never reached the log")
        finally:
            logging.getLogger("leasewatch.auth").removeHandler(h)
        self.assertIn("5 failed attempts", lines[1])
        self.assertIn("10.0.0.2", lines[1])
        self.assertEqual(self.v._fails, 0)


class ShutdownFlushTests(unittest.TestCase):
    """Held-back failed logins reach the log when the server stops (the daemon timer dies with the process)."""

    def test_flush_reports_held_back_count_once(self):
        v = auth.Verifier(USER, FAST)
        with self.assertLogs("leasewatch.auth", "WARNING") as logs:
            for _ in range(301):
                v._failed("192.0.2.7")
            timer = v._fail_timer
            v.flush()
            v.flush()  # idempotent: nothing pending, no second line
        self.assertEqual(len(logs.output), 2, logs.output)
        self.assertIn("300 failed attempts", logs.output[1])
        self.assertIn("192.0.2.7", logs.output[1])
        self.assertEqual(v._fails, 0)
        timer.join(1)  # cancelled: no thread left behind
        self.assertFalse(timer.is_alive())

    def test_main_flushes_the_verifier_on_shutdown(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        saved = clean_env({**FW1_ENV, "DATA_DIR": tmp.name})
        self.addCleanup(restore, saved)
        verifier = mock.Mock()
        srv = mock.Mock()
        srv.RequestHandlerClass.verifier = verifier
        with mock.patch.object(cli, "serve", return_value=srv), mock.patch.object(cli, "Collector"), \
                mock.patch.object(cli.signal, "signal"), mock.patch.object(cli, "startup_line", return_value=""), \
                mock.patch.object(cli, "types_line", return_value=""), self.assertLogs("leasewatch", "INFO"):
            self.assertEqual(cli.main([]), 0)
        verifier.flush.assert_called_once_with()


class ConfigTests(unittest.TestCase):
    def cfg(self, **env):
        saved = clean_env({**FW1_ENV, **env})
        try:
            return Config()
        finally:
            restore(saved)

    def auth_problems(self, **env):
        return [p for p in self.cfg(**env).validate() if "AUTH" in p]

    def test_off_by_default(self):
        c = self.cfg()
        self.assertFalse(c.auth_enabled)
        self.assertEqual(self.auth_problems(), [])

    def test_on(self):
        c = self.cfg(AUTH_USER=USER, AUTH_PASSWORD_HASH=HASH)
        self.assertTrue(c.auth_enabled)
        self.assertEqual(self.auth_problems(AUTH_USER=USER, AUTH_PASSWORD_HASH=HASH), [])
        self.assertNotIn(HASH, repr(c))

    def test_both_or_neither(self):
        msg = ["AUTH_USER and AUTH_PASSWORD_HASH must be set together"]
        self.assertEqual(self.auth_problems(AUTH_USER=USER), msg)
        self.assertEqual(self.auth_problems(AUTH_PASSWORD_HASH=HASH), msg)
        self.assertFalse(self.cfg(AUTH_USER=USER).auth_enabled)

    def test_bad_hash_not_echoed(self):
        bad = "pbkdf2_sha256:99999:" + HASH.split(":", 2)[2]
        problems = self.auth_problems(AUTH_USER=USER, AUTH_PASSWORD_HASH=bad)
        self.assertEqual(problems, [HASH_MSG])
        self.assertNotIn(bad.split(":")[2], "".join(problems))

    def test_bad_user(self):
        # a surrogate: a Latin-1 env file read as UTF-8 (the hash check would raise UnicodeEncodeError)
        for u in ("a:b", "a\x01b", "a\x7fb", "a\x85b", "Bj\udcf6rn"):
            self.assertEqual(self.auth_problems(AUTH_USER=u, AUTH_PASSWORD_HASH=HASH),
                             ["AUTH_USER must not contain ':' or control characters"], repr(u))


class AuthWebTests(WebTestCase):
    """The HTTP suite's server with auth on."""

    def setUp(self):
        with mock.patch.dict(test_web.ENV, AUTH_USER=USER, AUTH_PASSWORD_HASH=HASH):
            super().setUp()

    def creds(self, headers=None, auth_header=GOOD):
        return {**(headers or {}), "Authorization": auth_header}

    ROUTES = ("/", "/static/app.js", "/static/style.css", "/healthz", "/api/devices", "/api/devices.csv",
              "/api/status", "/api/stats", "/api/events", f"/api/devices/{MAC2}")

    def assert_401(self, status, headers, body):
        self.assertEqual(status, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Basic realm="leasewatch", charset="UTF-8"')
        self.assertEqual(headers["Content-Security-Policy"], CSP)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(json.loads(body), {"error": "authentication required"})

    def test_every_route_needs_credentials(self):
        for path in self.ROUTES + ("/nope", "/static/../x"):
            for h in ({}, self.creds(auth_header=basic("bob", PASSWORD)), self.creds(auth_header=basic(USER, "x")),
                      self.creds(auth_header="Bearer x")):
                with self.subTest(path=path, h=h):
                    self.assert_401(*self.req("GET", path, headers=h))
        st, hd, body = self.req("HEAD", "/api/stats")
        self.assertEqual((st, body), (401, b""))

    def test_non_ascii_blank_gets_401(self):
        import socket
        token = GOOD[6:].encode()
        for raw in (b"Basic " + token + b"\xa0", b"\x85Basic " + token, b"Basic \xa0" + token):
            for method in (b"GET", b"POST"):
                with self.subTest(raw=raw, method=method), socket.create_connection(("127.0.0.1", self.port), 10) as s:
                    s.sendall(method + b" /api/devices/" + MAC2.encode() + b" HTTP/1.0\r\nHost: 127.0.0.1\r\n"
                              b"Content-Length: 0\r\nAuthorization: " + raw + b"\r\n\r\n")
                    reply = b""
                    while chunk := s.recv(65536):
                        reply += chunk
                    self.assertRegex(reply, rb"^HTTP/1\.[01] 401 ")

    def test_right_credentials(self):
        for path in self.ROUTES:
            with self.subTest(path=path):
                st, hd, body = self.req("GET", path, headers=self.creds())
                self.assertIn(st, (200, 503) if path == "/healthz" else (200,), body[:200])
                self.assertNotIn("WWW-Authenticate", hd)
                self.assertEqual(hd["Content-Security-Policy"], CSP)
        st, _, body = self.req("GET", "/healthz", headers=self.creds())
        self.assertIn("last_error", json.loads(body))

    def test_post(self):
        body = json.dumps({"note": "hi"}).encode()
        ct = {"Content-Type": "application/json"}
        self.assert_401(*self.req("POST", f"/api/devices/{MAC2}", body=body, headers=ct))
        st, _, data = self.req("POST", f"/api/devices/{MAC2}", body=body, headers=self.creds(ct))
        self.assertEqual(st, 200, data)
        self.assertEqual(json.loads(data)["device"]["note"], "hi")
        st, _, _ = self.req("POST", f"/api/devices/{MAC2}", body=body, headers=self.creds({**ct, "Sec-Fetch-Site": "cross-site"}))
        self.assertEqual(st, 403)
        self.assert_401(*self.req("POST", "/nope", body=body, headers=ct))  # 401 before routing

    def test_host_check_first(self):
        st, hd, _ = self.req("GET", "/api/stats", headers={"Host": "evil.example.com"})
        self.assertEqual(st, 421)
        self.assertNotIn("WWW-Authenticate", hd)
        st, _, _ = self.req("GET", "/api/stats", headers=self.creds({"Host": "evil.example.com"}))
        self.assertEqual(st, 421)

    def test_method_not_allowed_stays_open(self):
        st, hd, _ = self.req("PUT", "/api/stats")
        self.assertEqual(st, 405)
        self.assertNotIn("WWW-Authenticate", hd)

    def test_busy_gives_503(self):
        v = self.srv.RequestHandlerClass.verifier
        v._sem.acquire()
        v._sem.acquire()
        try:
            with mock.patch.object(auth, "BUSY_TIMEOUT", 0.05):
                st, hd, body = self.req("GET", "/api/stats", headers=self.creds())
        finally:
            v._sem.release()
            v._sem.release()
        self.assertEqual((st, json.loads(body)), (503, {"error": "busy"}))
        self.assertEqual(hd["Retry-After"], "5")
        self.assertEqual(hd["Content-Security-Policy"], CSP)

    def test_second_request_uses_cache(self):
        self.assertEqual(self.req("GET", "/api/stats", headers=self.creds())[0], 200)
        with mock.patch("hashlib.pbkdf2_hmac", wraps=hashlib.pbkdf2_hmac) as kdf:
            self.assertEqual(self.req("GET", "/api/stats", headers=self.creds())[0], 200)
        self.assertEqual(kdf.call_count, 0)


class AuthOffWebTests(WebTestCase):
    def test_no_credentials_needed(self):
        self.assertIsNone(self.srv.RequestHandlerClass.verifier)
        st, hd, _ = self.req("GET", "/api/stats")
        self.assertEqual(st, 200)
        self.assertNotIn("WWW-Authenticate", hd)


class HashPasswordCliTests(unittest.TestCase):
    def run_cli(self, argv, stdin, getpass_values=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", out), \
                mock.patch.object(sys, "stderr", err), \
                mock.patch("getpass.getpass", side_effect=getpass_values or []) as gp:
            rc = cli.main(["hash-password", *argv])
        return rc, out.getvalue(), err.getvalue(), gp

    def test_stdin(self):
        for text in (PASSWORD, PASSWORD + "\n", PASSWORD + "\r\n"):
            rc, out, err, gp = self.run_cli(["--iterations", "100000"], io.StringIO(text))
            self.assertEqual(rc, 0, err)
            self.assertEqual(out.count("\n"), 1)
            parsed = auth.parse_hash(out.strip())
            self.assertEqual(parsed[0], 100_000)
            self.assertTrue(auth.Verifier(USER, parsed).check(GOOD))
            self.assertNotIn(PASSWORD, out + err)
            gp.assert_not_called()

    def test_empty_refused(self):
        for text in ("", "\n"):
            rc, out, err, _ = self.run_cli([], io.StringIO(text))
            self.assertEqual((rc, out), (1, ""))
            self.assertIn("empty", err)

    def test_short_warns(self):
        rc, out, err, _ = self.run_cli(["--iterations", "100000"], io.StringIO("short"))
        self.assertEqual(rc, 0)
        self.assertIn("12", err)
        self.assertIsNotNone(auth.parse_hash(out.strip()))

    def test_iterations_bounds(self):
        for n in ("99999", "10000001", "x"):
            rc, out, _, _ = self.run_cli(["--iterations", n], io.StringIO(PASSWORD))
            self.assertEqual((rc, out), (1 if n != "x" else 2, ""), n)

    def test_tty(self):
        tty = mock.Mock(isatty=lambda: True)
        rc, out, err, gp = self.run_cli(["--iterations", "100000"], tty, [PASSWORD, PASSWORD])
        self.assertEqual(rc, 0, err)
        self.assertEqual(gp.call_count, 2)
        self.assertTrue(auth.Verifier(USER, auth.parse_hash(out.strip())).check(GOOD))
        rc, out, err, _ = self.run_cli([], tty, [PASSWORD, PASSWORD + "x"])
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("do not match", err)

    def test_undecodable_byte_is_refused(self):
        # a C/C.UTF-8 locale (the image's) reads a non-UTF-8 byte as a surrogate instead of raising
        rc, out, err, _ = self.run_cli(["--iterations", "100000"], io.StringIO("abc\udcffdefghijklm\n"))
        self.assertEqual((rc, out), (1, ""))
        self.assertEqual(err, "cannot read the password\n")

    def test_stdout_closed(self):
        err = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(PASSWORD)), mock.patch.object(sys, "stdout", None), \
                mock.patch.object(sys, "stderr", err):
            self.assertEqual(cli.main(["hash-password", "--iterations", "100000"]), 1)
        self.assertNotIn("Traceback", err.getvalue())

    def test_stdout_closed_keeps_a_set_exit_code(self):
        # argparse's usage error (2) stays 2 when there is no stdout to flush
        with mock.patch.object(sys, "stdout", None), mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(cli.main(["check", "--bogus"]), 2)

    def test_real_process(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONWARNINGS"}
        r = subprocess.run([sys.executable, "-m", "leasewatch", "hash-password", "--iterations", "100000"], cwd=REPO,
                           input=PASSWORD, capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"^pbkdf2_sha256:100000:[A-Za-z0-9_-]{22}:[A-Za-z0-9_-]{43}\n$")
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)


class HealthcheckTests(WebTestCase):
    """The Dockerfile's HEALTHCHECK command, run against the test server: 200 or 401 is alive."""

    def code(self):
        with open(os.path.join(REPO, "Dockerfile"), encoding="utf-8") as f:
            line = next(x for x in f if x.startswith("HEALTHCHECK"))
        argv = json.loads(line.split(" CMD ", 1)[1])
        self.assertEqual(argv[:2], ["python", "-c"])
        self.assertIn("http://127.0.0.1:8080/", argv[2])
        return argv[2]

    def run_code(self, port):
        code = self.code().replace(":8080/", f":{port}/")
        return subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=30).returncode

    def test_alive_without_auth(self):
        self.assertEqual(self.run_code(self.port), 0)

    def test_alive_with_auth(self):
        self.tearDown()
        with mock.patch.dict(test_web.ENV, AUTH_USER=USER, AUTH_PASSWORD_HASH=HASH):
            self.setUp()
        self.assertEqual(self.req("GET", "/api/stats")[0], 401)
        self.assertEqual(self.run_code(self.port), 0)

    def test_down(self):
        with socketserver_port() as port:
            self.assertEqual(self.run_code(port), 1)


class socketserver_port:
    """A local port with nothing listening on it."""

    def __enter__(self):
        import socket
        self.s = socket.socket()
        self.s.bind(("127.0.0.1", 0))
        return self.s.getsockname()[1]

    def __exit__(self, *exc):
        self.s.close()


if __name__ == "__main__":
    unittest.main()
