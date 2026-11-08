"""UniFi client: one session kept across polls (classic and UniFi OS), once-only re-login on 401, re-login pacing,
UniFi OS detection, CSRF header handling and rotation, logout on close(), and no secret in errors or logs.

A local ThreadingHTTPServer (port 0) emulates both controller kinds; nothing reaches the network.
"""
from __future__ import annotations

import base64
import json
import secrets
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import _env  # noqa: F401  # the repo root on the path and the network guard, also when this module runs on its own
from leasewatch import unifi
from leasewatch.connectors import ConnectorError, HostContext
from leasewatch.connectors.unifi import UnifiConnector, _UnifiCfg
from leasewatch.unifi import UnifiClient

USER, PASSWORD = "ro-viewer", "pw-Sekret-9137"
OS_STA, OS_DEV = "/proxy/network/api/s/default/stat/sta", "/proxy/network/api/s/default/stat/device"
CL_STA, CL_DEV = "/api/s/default/stat/sta", "/api/s/default/stat/device"
STA_ROW = {"mac": "02:00:00:00:00:06", "essid": "HomeNet", "ap_mac": "02:00:00:00:00:aa", "signal": -60}
DEV_ROW = {"mac": "02:00:00:00:00:aa", "name": "ap-hall"}
LOGIN_REQUIRED = {"meta": {"rc": "error", "msg": "api.err.LoginRequired"}, "data": []}


def b64url(o: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")


class Controller:
    """mode: "classic302" (/ redirects to /manage), "classic_base" (/ is a 200 page with <base href="/manage/">)
    or "os" (/ is a plain 200 page). Counts logins, GETs and logouts; records every request with its headers."""

    def __init__(self, mode: str = "classic302", csrf_in_header: bool = True, jwt_ok: bool = True) -> None:
        self.mode, self.csrf_in_header, self.jwt_ok = mode, csrf_in_header, jwt_ok
        self.sessions: set[str] = set()
        self.csrf = ""
        self.rotate_next = False          # the next stat reply sends x-updated-csrf-token
        self.reject_stats = False         # every stat GET answers 401
        self.stat_status = 0              # nonzero: every stat GET answers this status
        self.root_status = 0              # nonzero: GET / answers this status
        self.login_redirect = ""          # nonzero: the login answers 302 to this URL
        self.jwt_csrf: str | None = None  # set: the csrfToken claim the TOKEN JWT carries instead of a random one
        self.stall = 0.0                  # seconds the stat GETs wait before answering
        self.requests: list[tuple[str, str, dict, bytes]] = []
        self.lock = threading.Lock()
        ctl = self

        class H(BaseHTTPRequestHandler):
            def _send(self, status: int, body: bytes = b"{}", headers: dict | None = None) -> None:
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):  # the client gave up (the timeout test)
                    pass

            def _cookie(self, name: str) -> str:
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == name:
                        return v
                return ""

            def _answer(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                with ctl.lock:
                    ctl.requests.append((self.command, self.path, dict(self.headers), body))
                ctl.handle(self, body)
            do_GET = do_POST = _answer

            def log_message(self, *a: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def os(self) -> bool:
        return self.mode == "os"

    def handle(self, h, body: bytes) -> None:
        path, cmd = h.path.split("?")[0], h.command
        js = lambda o, status=200, headers=None: h._send(status, json.dumps(o).encode(),
                                                          {"Content-Type": "application/json", **(headers or {})})
        if path == "/" and cmd == "GET":
            if self.root_status:
                return h._send(self.root_status, b"")
            if self.mode == "classic302":
                return h._send(302, b"", {"Location": "/manage"})
            page = b'<html><head><BASE  href="/manage/"></head></html>' if self.mode == "classic_base" else b"<html>UniFi OS</html>"
            return h._send(200, page, {"Content-Type": "text/html"})
        login = "/api/auth/login" if self.os else "/api/login"
        if cmd == "POST" and path in ("/api/login", "/api/auth/login"):
            if self.login_redirect:
                return h._send(302, b"", {"Location": self.login_redirect})
            if path != login:
                return js({}, 401 if self.os else 404)  # the cross-endpoint replies of [5]
            creds = json.loads(body or b"{}")
            if (creds.get("username"), creds.get("password")) != (USER, PASSWORD):
                return js({"meta": {"rc": "error", "msg": "api.err.Invalid"}}, 400 if not self.os else 401)
            sid = secrets.token_hex(8)
            self.sessions.add(sid)
            if not self.os:
                return js({"meta": {"rc": "ok"}, "data": []}, headers={"Set-Cookie": f"unifises={sid}; Path=/"})
            self.csrf = secrets.token_hex(8) if self.jwt_csrf is None else self.jwt_csrf
            token = (f"{b64url({'alg': 'none'})}.{b64url({'csrfToken': self.csrf, 'sid': sid})}.sig" if self.jwt_ok
                     else f"{sid}.%%%not-base64.sig")
            if not self.jwt_ok:
                self.sessions.add(token)
            extra = {"Set-Cookie": f"TOKEN={token}; Path=/"}
            if self.csrf_in_header:
                extra["x-csrf-token"] = self.csrf  # lower case: the client must read headers case-insensitively
            return js({"username": USER}, headers=extra)
        if cmd == "POST" and path in ("/api/logout", "/api/auth/logout"):
            if self.os:
                if path != "/api/auth/logout" or not self.csrf or h.headers.get("X-CSRF-Token") != self.csrf:
                    return js({}, 403)
            self.sessions.clear()
            return js({"meta": {"rc": "ok"}})
        if cmd == "GET" and path in ((OS_STA, OS_DEV) if self.os else (CL_STA, CL_DEV)):
            if self.stall:
                time.sleep(self.stall)
            sid = self._sid(h)
            if self.reject_stats or sid not in self.sessions:
                return js(LOGIN_REQUIRED, 401)
            if self.stat_status:
                return js({}, self.stat_status)
            extra = {}
            if self.rotate_next:
                self.rotate_next = False
                self.csrf = secrets.token_hex(8)
                extra["x-updated-csrf-token"] = self.csrf
            return js({"meta": {"rc": "ok"}, "data": [STA_ROW if path.endswith("sta") else DEV_ROW]}, headers=extra)
        return js({}, 404)

    def _sid(self, h) -> str:
        if not self.os:
            return h._cookie("unifises")
        token = h._cookie("TOKEN")
        if not self.jwt_ok:
            return token
        try:
            payload = token.split(".")[1]
            return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["sid"]
        except Exception:
            return ""

    def invalidate(self) -> None:
        self.sessions.clear()

    def count(self, method: str, path: str) -> int:
        return sum(1 for m, p, _, _ in self.requests if m == method and p == path)

    def stats(self) -> int:
        return sum(1 for m, p, _, _ in self.requests if m == "GET" and "/stat/" in p)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        p = mock.patch.object(unifi, "_monotonic", self.clock)
        p.start()
        self.addCleanup(p.stop)

    def ctl(self, *a: object, **kw: object) -> Controller:
        c = Controller(*a, **kw)
        self.addCleanup(c.close)
        return c

    def client(self, ctl: Controller, platform: str = "auto", password: str = PASSWORD) -> UnifiClient:
        c = UnifiClient(_UnifiCfg(unifi_url=ctl.url, unifi_site="default", unifi_user=USER, unifi_password=password,
                                  unifi_verify_tls=False, platform=platform))
        self.addCleanup(c.close)
        return c

    def assert_ok(self, out: dict) -> None:
        self.assertEqual(out["02:00:00:00:00:06"].ap, "ap-hall")


class SessionReuseClassic(Base):
    """One login per session on a classic controller, logout on close."""

    def test_five_polls_one_login_then_logout_on_close(self) -> None:
        ctl = self.ctl("classic302")
        c = self.client(ctl, "classic")
        for _ in range(5):
            self.assert_ok(c.clients())
            self.clock.t += 120
        self.assertEqual((ctl.count("POST", "/api/login"), ctl.stats(), ctl.count("POST", "/api/logout")), (1, 10, 0))
        c.close()
        self.assertEqual(ctl.count("POST", "/api/logout"), 1)
        c.close()  # a second close() has no session left: no request
        self.assertEqual(ctl.count("POST", "/api/logout"), 1)

    def test_expired_session_logs_in_once_more(self) -> None:
        ctl = self.ctl("classic302")
        c = self.client(ctl, "classic")
        for _ in range(2):
            self.assert_ok(c.clients())
            self.clock.t += 120
        ctl.invalidate()
        self.assert_ok(c.clients())
        self.assertEqual(ctl.count("POST", "/api/login"), 2)

    def test_login_required_in_a_200_body_counts_as_expiry(self) -> None:
        ctl = self.ctl("classic302")
        c = self.client(ctl, "classic")
        self.assert_ok(c.clients())
        self.clock.t += 120
        real = ctl.handle
        state = {"n": 0}

        def once_200(h, body):  # the first stat GET after the login answers HTTP 200 with LoginRequired
            if "/stat/" in h.path and state["n"] == 0:
                state["n"] = 1
                return h._send(200, json.dumps(LOGIN_REQUIRED).encode(), {"Content-Type": "application/json"})
            return real(h, body)
        ctl.handle = once_200
        self.assert_ok(c.clients())
        self.assertEqual(ctl.count("POST", "/api/login"), 2)

    def test_401_right_after_a_fresh_login_is_an_error_not_a_loop(self) -> None:
        ctl = self.ctl("classic302")
        ctl.reject_stats = True
        c = self.client(ctl, "classic")
        with self.assertRaises(RuntimeError) as cm:
            c.clients()
        self.assertEqual(str(cm.exception), "unifi: HTTP 401")
        self.assertEqual(ctl.count("POST", "/api/login"), 1)

    def test_relogin_inside_60_s_is_deferred(self) -> None:
        ctl = self.ctl("classic302")
        c = self.client(ctl, "classic")
        self.assert_ok(c.clients())
        ctl.invalidate()
        self.clock.t += 30
        with self.assertRaises(RuntimeError) as cm:
            c.clients()
        self.assertEqual(str(cm.exception), "unifi: session expired, re-login deferred")
        self.assertEqual(ctl.count("POST", "/api/login"), 1)
        self.clock.t += 20  # still inside the window: no session, still no login
        with self.assertRaisesRegex(RuntimeError, "re-login deferred"):
            c.clients()
        self.assertEqual(ctl.count("POST", "/api/login"), 1)
        self.clock.t += 11
        self.assert_ok(c.clients())
        self.assertEqual(ctl.count("POST", "/api/login"), 2)

    def test_401_after_every_fresh_login_stays_http_401_and_is_not_paced(self) -> None:
        # a login whose session never read must not count as an expired session
        ctl = self.ctl("classic302")
        ctl.reject_stats = True
        c = self.client(ctl, "classic")
        with self.assertNoLogs("leasewatch.unifi", "INFO"):
            for _ in range(3):
                with self.assertRaises(RuntimeError) as cm:
                    c.clients()
                self.assertEqual(str(cm.exception), "unifi: HTTP 401")
                self.clock.t += 30
        self.assertEqual(ctl.count("POST", "/api/login"), 3)

    def test_failed_login_is_not_paced(self) -> None:
        ctl = self.ctl("classic302")
        c = self.client(ctl, "classic", password="wrong-pass-123")
        for _ in range(2):
            with self.assertRaises(RuntimeError) as cm:
                c.clients()
            self.assertEqual(str(cm.exception), "unifi: login failed (HTTP 400)")
        self.assertEqual(ctl.count("POST", "/api/login"), 2)

    def test_login_rate_limited(self) -> None:
        ctl = self.ctl("classic302")
        ctl.handle = lambda h, body: h._send(429, b"{}")
        with self.assertRaises(RuntimeError) as cm:
            self.client(ctl, "classic").clients()
        self.assertEqual(str(cm.exception), "unifi: login rate-limited (HTTP 429)")

    def test_login_redirect_is_not_followed(self) -> None:
        for mode, platform in (("classic302", "classic"), ("os", "unifi_os")):
            target = self.ctl(mode)
            ctl = self.ctl(mode)
            ctl.login_redirect = target.url + ("/api/auth/login" if mode == "os" else "/api/login")
            with self.assertRaises(RuntimeError) as cm:
                self.client(ctl, platform).clients()
            self.assertEqual(str(cm.exception), "unifi: HTTP 302")
            self.assertEqual(target.requests, [])

    def test_timeout_keeps_the_session(self) -> None:
        ctl = self.ctl("classic302")
        c = self.client(ctl, "classic")
        self.assert_ok(c.clients())
        ctl.stall = 0.6
        with mock.patch.object(unifi, "TIMEOUT", 0.2):
            with self.assertRaises(RuntimeError):
                c.clients()
        ctl.stall = 0
        self.clock.t += 120
        self.assert_ok(c.clients())
        self.assertEqual(ctl.count("POST", "/api/login"), 1)

    def test_server_error_keeps_the_session(self) -> None:
        ctl = self.ctl("classic302")
        c = self.client(ctl, "classic")
        self.assert_ok(c.clients())
        ctl.stat_status = 500
        with self.assertRaises(RuntimeError) as cm:
            c.clients()
        self.assertEqual(str(cm.exception), "unifi: HTTP 500")
        ctl.stat_status = 0
        self.assert_ok(c.clients())
        self.assertEqual(ctl.count("POST", "/api/login"), 1)


class UnifiOs(Base):
    """UniFi OS detection and its login path."""

    def test_detection(self) -> None:
        for mode, login in (("classic302", "/api/login"), ("classic_base", "/api/login"), ("os", "/api/auth/login")):
            ctl = self.ctl(mode)
            self.assert_ok(self.client(ctl).clients())
            self.assertEqual(ctl.count("GET", "/"), 1, mode)
            self.assertEqual(ctl.count("POST", login), 1, mode)
            self.assertEqual(ctl.count("POST", "/api/auth/login" if login == "/api/login" else "/api/login"), 0, mode)

    def test_detection_error_names_platform(self) -> None:
        ctl = self.ctl("os")
        ctl.root_status = 500
        with self.assertRaises(RuntimeError) as cm:
            self.client(ctl).clients()
        self.assertEqual(str(cm.exception), "unifi: cannot detect the controller type (HTTP 500); set PLATFORM")

    def test_five_polls_one_login_csrf_sent_logout_on_close(self) -> None:
        ctl = self.ctl("os")
        c = self.client(ctl)
        for _ in range(5):
            self.assert_ok(c.clients())
            self.clock.t += 120
        self.assertEqual((ctl.count("POST", "/api/auth/login"), ctl.stats(), ctl.count("GET", "/")), (1, 10, 1))
        sent = [hd.get("X-Csrf-Token") for m, p, hd, _ in ctl.requests if "/stat/" in p]
        self.assertEqual(sent, [ctl.csrf] * 10)
        c.close()
        self.assertEqual(ctl.count("POST", "/api/auth/logout"), 1)
        self.assertEqual(ctl.sessions, set())  # the fixture answers 403 (and keeps the session) without the CSRF header

    def test_forced_expiry_relogs_once_and_detects_again(self) -> None:
        ctl = self.ctl("os")
        c = self.client(ctl)
        self.assert_ok(c.clients())
        ctl.invalidate()
        self.clock.t += 120
        self.assert_ok(c.clients())
        self.assertEqual((ctl.count("POST", "/api/auth/login"), ctl.count("GET", "/")), (2, 2))

    def test_csrf_from_jwt_only(self) -> None:
        ctl = self.ctl("os", csrf_in_header=False)
        c = self.client(ctl)
        self.assert_ok(c.clients())
        self.assertEqual([hd.get("X-Csrf-Token") for m, p, hd, _ in ctl.requests if "/stat/" in p], [ctl.csrf] * 2)
        c.close()
        self.assertEqual(ctl.sessions, set())

    def test_malformed_jwt_still_reads(self) -> None:
        ctl = self.ctl("os", csrf_in_header=False, jwt_ok=False)
        c = self.client(ctl)
        self.assert_ok(c.clients())
        self.assertEqual([hd.get("X-Csrf-Token") for m, p, hd, _ in ctl.requests if "/stat/" in p], [None, None])

    def test_unusable_jwt_csrf_is_not_sent(self) -> None:
        # a csrfToken claim that cannot be a header value is ignored, so the reads (which work without
        # CSRF) still succeed instead of failing every poll on a kept session
        for bad in ("a\r\nX", "a\nb", "\u20ac", "a b", "", "x" * 513):
            ctl = self.ctl("os", csrf_in_header=False)
            ctl.jwt_csrf = bad
            c = self.client(ctl)
            for _ in range(2):
                self.assert_ok(c.clients())
            self.assertEqual([hd.get("X-Csrf-Token") for m, p, hd, _ in ctl.requests if "/stat/" in p], [None] * 4, bad)
            self.assertEqual(ctl.count("POST", "/api/auth/login"), 1)

    def test_csrf_rotation(self) -> None:
        ctl = self.ctl("os")
        c = self.client(ctl)
        self.assert_ok(c.clients())
        first = ctl.csrf
        ctl.rotate_next = True
        self.assert_ok(c.clients())  # the sta reply rotates; the device GET must carry the new value
        self.assertNotEqual(first, ctl.csrf)
        sent = [hd.get("X-Csrf-Token") for m, p, hd, _ in ctl.requests if "/stat/" in p]
        self.assertEqual(sent, [first, first, first, ctl.csrf])
        c.close()
        self.assertEqual(ctl.sessions, set())

    def test_platform_override(self) -> None:
        ctl = self.ctl("os")
        with self.assertRaises(RuntimeError) as cm:
            self.client(ctl, "classic").clients()
        self.assertEqual(str(cm.exception), "unifi: login failed (HTTP 401)")
        self.assertEqual(ctl.count("GET", "/"), 0)
        ctl = self.ctl("os")
        self.assert_ok(self.client(ctl, "unifi_os").clients())
        self.assertEqual(ctl.count("GET", "/"), 0)
        ctl = self.ctl("classic302")
        with self.assertRaises(RuntimeError) as cm:
            self.client(ctl, "unifi_os").clients()
        self.assertEqual(str(cm.exception), "unifi: login failed (HTTP 404); check PLATFORM")

    def test_403_names_network_access(self) -> None:
        ctl = self.ctl("os")
        ctl.stat_status = 403
        with self.assertRaises(RuntimeError) as cm:
            self.client(ctl).clients()
        self.assertEqual(str(cm.exception), "unifi: HTTP 403 (user lacks Network access?)")


class Connector(Base):
    def conn(self, ctl_url: str, **kw: str) -> UnifiConnector:
        c = UnifiConnector("unifi", {"url": ctl_url, "user": USER, "password": PASSWORD, "verify_tls": "0", **kw},
                           HostContext(now=lambda: 1700000000))
        self.addCleanup(c.close)
        return c

    def test_platform_setting(self) -> None:
        self.assertEqual(UnifiConnector.describe().version, "1.2")
        self.assertEqual(self.conn("https://unifi.example.lan").client.cfg.platform, "auto")
        for v in ("auto", "classic", "unifi_os"):
            c = self.conn("https://unifi.example.lan", platform=v)
            self.assertEqual((c.validate(), c.client.cfg.platform), ([], v))
        for v in ("foo", "", "UniFi_OS"):
            self.assertIn("connector unifi (unifi): PLATFORM must be one of auto, classic, unifi_os",
                          self.conn("https://unifi.example.lan", platform=v).validate(), v)

    def test_close_logs_out_and_tolerates_a_client_without_close(self) -> None:
        ctl = self.ctl("os")
        c = self.conn(ctl.url)
        c.check()
        c.collect()
        self.assertEqual(ctl.count("POST", "/api/auth/login"), 1)
        c.close()
        self.assertEqual(ctl.count("POST", "/api/auth/logout"), 1)
        UnifiConnector("unifi", {"url": "https://unifi.example.lan", "user": "u", "password": "p"},
                       client=type("U", (), {"clients": lambda self: {}})()).close()

    def test_no_secret_in_errors_or_logs(self) -> None:
        ctl = self.ctl("os")
        cases = []
        with self.assertLogs("leasewatch.unifi", "DEBUG") as logs:
            c = self.conn(ctl.url)
            c.collect()
            secret_values = [PASSWORD, ctl.csrf] + [hd.get("Cookie", "").partition("=")[2] for m, p, hd, _ in ctl.requests
                                                    if "/stat/" in p]
            ctl.invalidate()
            ctl.reject_stats = True
            self.clock.t += 120
            for _ in range(2):
                with self.assertRaises(ConnectorError) as cm:
                    c.collect()
                cases.append(str(cm.exception))
            secret_values.append(ctl.csrf)
            c.close()
            for kw in ({"platform": "classic"}, {"password": "wrong-pass-123"}, {"root": "500"}):
                if kw.pop("root", None):
                    ctl.root_status = 500
                with self.assertRaises(ConnectorError) as cm:
                    self.conn(ctl.url, **kw).check()
                cases.append(str(cm.exception))
            ctl.close()
            with self.assertRaises(ConnectorError) as cm:  # connection refused
                self.conn(ctl.url).check()
            cases.append(str(cm.exception))
        self.assertEqual(cases[:2], ["unifi: HTTP 401", "unifi: session expired, re-login deferred"])
        host, port = ctl.url.split("//")[1].split(":")
        for text in cases + logs.output:
            for s in [x for x in secret_values if x] + [USER, "wrong-pass-123", port]:
                self.assertNotIn(s, text)
            self.assertNotIn(host, text)


if __name__ == "__main__":
    unittest.main()
