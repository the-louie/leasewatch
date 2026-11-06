"""Tests for the mikrotik connector: the pure parser, the HTTP calls against a fake RouterOS on an ephemeral port,
error texts (no host, no secrets), settings and the Batch shape. Synthetic data only; no network."""
from __future__ import annotations

import base64
import io
import json
import os
import socket
import ssl
import sys
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

from leasewatch.connectors import API_VERSION, Batch, ConnectorError, HostContext, Sighting  # noqa: E402
from leasewatch_mikrotik import connector as mc  # noqa: E402
from leasewatch_mikrotik.connector import MikrotikConnector, flag, parse  # noqa: E402

NOW = 1_800_000_000
USER = "lw-reader"
PASSWORD = "s3cr3t-Pa55word"
SERVERS = [{".id": "*1", "name": "dhcp-lan", "interface": "bridge-lan"},
           {".id": "*2", "name": "dhcp-iot", "interface": "vlan20-iot"}]


def lease(**kw: str) -> dict:
    row = {".id": "*A", "address": "10.0.0.10", "mac-address": "02:00:00:00:00:01", "server": "dhcp-lan",
           "status": "bound", "dynamic": "true", "disabled": "false", "host-name": "alex-ipad"}
    row.update(kw)
    return {k: v for k, v in row.items() if v is not None}


def arp(**kw: str) -> dict:
    row = {".id": "*B", "address": "10.0.0.20", "mac-address": "02:00:00:00:00:02", "interface": "bridge-lan",
           "complete": "true", "invalid": "false", "disabled": "false", "published": "false", "dynamic": "true",
           "status": "reachable"}
    row.update(kw)
    return {k: v for k, v in row.items() if v is not None}


def make(url: str = "https://router.example.lan", ctx: HostContext | None = None, **settings: str) -> MikrotikConnector:
    return MikrotikConnector("mt1", {"url": url, "user": USER, "password": PASSWORD, **settings},
                             ctx or HostContext(now=lambda: NOW))


class ParseTest(unittest.TestCase):
    def test_bound_dynamic_lease(self) -> None:
        sightings, dropped = parse(SERVERS, [lease()], [], NOW)
        self.assertEqual(dropped, 0)
        self.assertEqual(sightings, [Sighting(mac="02:00:00:00:00:01", source="", kind="dhcp", presence=False,
                                              observed_at=NOW, ip="10.0.0.10", hostname="alex-ipad",
                                              network="bridge-lan", iface="bridge-lan", lease_type="dynamic")])

    def test_static_lease(self) -> None:
        s = parse(SERVERS, [lease(dynamic="false")], [], NOW)[0][0]
        self.assertEqual(s.lease_type, "static")

    def test_missing_dynamic_reads_as_dynamic(self) -> None:
        s = parse(SERVERS, [lease(dynamic=None)], [], NOW)[0][0]
        self.assertEqual(s.lease_type, "dynamic")

    def test_non_bound_and_disabled_leases_skipped(self) -> None:
        rows = [lease(status="waiting", dynamic="false"), lease(status="offered"), lease(status="testing"),
                lease(status=None), lease(disabled="true")]
        self.assertEqual(parse(SERVERS, rows, [], NOW), ([], 0))

    def test_missing_optional_lease_fields(self) -> None:
        row = {"mac-address": "02:00:00:00:00:03", "status": "bound"}
        s = parse([], [row], [], NOW)[0][0]
        self.assertEqual((s.ip, s.hostname, s.network, s.iface, s.lease_type, s.client_id),
                         ("", "", "", "", "dynamic", ""))

    def test_active_values_take_precedence(self) -> None:
        row = lease(**{"active-address": "10.0.0.99", "active-mac-address": "02:00:00:00:00:09",
                       "client-id": "1:2:0:0:0:0:1", "active-client-id": "1:2:0:0:0:0:9"})
        s = parse(SERVERS, [row], [], NOW)[0][0]
        self.assertEqual((s.ip, s.mac, s.client_id), ("10.0.0.99", "02:00:00:00:00:09", "1:2:0:0:0:0:9"))
        empty = lease(**{"active-address": "", "active-mac-address": ""})
        s = parse(SERVERS, [empty], [], NOW)[0][0]
        self.assertEqual((s.ip, s.mac), ("10.0.0.10", "02:00:00:00:00:01"))

    def test_lease_without_mac_skipped(self) -> None:
        self.assertEqual(parse(SERVERS, [lease(**{"mac-address": None})], [], NOW), ([], 0))

    def test_server_to_interface_mapping(self) -> None:
        rows = [lease(server="dhcp-iot"), lease(server="gone"), lease(server=None)]
        self.assertEqual([(s.network, s.iface) for s in parse(SERVERS, rows, [], NOW)[0]],
                         [("vlan20-iot", "vlan20-iot"), ("", ""), ("", "")])

    def test_malformed_server_rows_ignored(self) -> None:
        servers = ["x", {"interface": "ether9"}, {"name": "dhcp-lan", "interface": "bridge-lan"}]
        self.assertEqual(parse(servers, [lease()], [], NOW)[0][0].network, "bridge-lan")

    def test_arp_complete_entry(self) -> None:
        sightings, dropped = parse([], [], [arp()], NOW)
        self.assertEqual((sightings, dropped), ([Sighting(mac="02:00:00:00:00:02", source="", kind="arp", presence=True,
                                                          observed_at=NOW, ip="10.0.0.20", network="bridge-lan",
                                                          iface="bridge-lan")], 0))

    def test_arp_incomplete_invalid_disabled_published_permanent_skipped(self) -> None:
        rows = [arp(complete="false", status="incomplete", **{"mac-address": None}), arp(complete="false", status="failed"),
                arp(invalid="true"), arp(disabled="true"), arp(published="true"),
                arp(status="permanent", dynamic="false")]
        self.assertEqual(parse([], [], rows, NOW), ([], 0))

    def test_arp_without_complete_uses_status(self) -> None:
        rows = [arp(complete=None, status="stale"), arp(complete=None, status="failed"), arp(complete=None, status=None)]
        self.assertEqual([s.ip for s in parse([], [], rows, NOW)[0]], ["10.0.0.20"])

    def test_arp_missing_optional_flags(self) -> None:
        row = {"address": "10.0.0.21", "mac-address": "02:00:00:00:00:05", "complete": "true"}
        s = parse([], [], [row], NOW)[0][0]
        self.assertEqual((s.ip, s.network, s.presence), ("10.0.0.21", "", True))

    def test_ignore_interfaces(self) -> None:
        ignore = frozenset({"vlan20-iot", "ether1"})
        leases = [lease(), lease(server="dhcp-iot")]
        arps = [arp(), arp(interface="ether1"), arp(interface="ETHER1")]
        sightings = parse(SERVERS, leases, arps, NOW, ignore)[0]
        self.assertEqual([(s.kind, s.iface) for s in sightings], [("dhcp", "bridge-lan"), ("arp", "bridge-lan")])

    def test_ignore_by_server_name(self) -> None:
        self.assertEqual(parse(SERVERS, [lease()], [], NOW, frozenset({"dhcp-lan"})), ([], 0))

    def test_strict_flags(self) -> None:
        self.assertEqual([flag({"k": v}, "k") for v in ("true", "false", "", None, True, False)],
                         [True, False, None, None, True, False])
        for v in ("yes", "no", "True", "1", "0"):
            with self.assertRaises(ValueError):
                flag({"k": v}, "k")

    def test_bad_flag_and_non_object_rows_dropped(self) -> None:
        rows_l = [lease(dynamic="yes"), "x", None, lease()]
        rows_a = [arp(complete="1"), 7, arp()]
        sightings, dropped = parse(SERVERS, rows_l, rows_a, NOW)
        self.assertEqual((len(sightings), dropped), (2, 5))

    def test_non_string_values_do_not_raise(self) -> None:
        row = lease(address=5)
        row["host-name"] = None
        s = parse(SERVERS, [row], [], NOW)[0][0]
        self.assertEqual((s.ip, s.hostname), ("5", ""))

    def test_non_string_active_value_does_not_shadow_configured(self) -> None:
        # a list, object or boolean is not a value: it must fall back to the configured one, not become "[]"
        for junk in ([], {}, False, True, [1]):
            row = lease(**{"active-mac-address": junk, "active-address": junk, "active-client-id": junk,
                           "client-id": "1:2:0:0:0:0:1"})
            s = parse(SERVERS, [row], [], NOW)[0][0]
            self.assertEqual((s.mac, s.ip, s.client_id), ("02:00:00:00:00:01", "10.0.0.10", "1:2:0:0:0:0:1"), junk)


class FakeRouter:
    """A RouterOS stand-in on 127.0.0.1:0. routes: path -> (status, body bytes, extra headers)."""

    def __init__(self) -> None:
        self.routes: dict[str, tuple[int, bytes, dict[str, str]]] = {}
        self.requests: list[tuple[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.requests.append((self.path, self.headers.get("Authorization", "")))
                status, body, headers = outer.routes.get(self.path.split("?", 1)[0], (404, b'{"error":404,"message":"Not Found"}', {}))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True)
        self.thread.start()

    def json(self, path: str, value: object, status: int = 200) -> None:
        self.routes[path] = (status, json.dumps(value).encode(), {"Content-Type": "application/json"})

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class HttpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.router = FakeRouter()
        self.addCleanup(self.router.close)
        self.conn = make(self.router.url)

    def error(self, call: str = "check") -> str:
        with self.assertRaises(ConnectorError) as cm:
            getattr(self.conn, call)()
        text = str(cm.exception)
        self.assert_no_secret(text)
        self.assertIsNone(cm.exception.__cause__)
        return text

    def assert_no_secret(self, text: str) -> None:
        token = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        for s in (PASSWORD, token, "Pa55word"):
            self.assertNotIn(s, text)

    def test_collect(self) -> None:
        self.router.json("/rest/ip/dhcp-server", SERVERS)
        self.router.json("/rest/ip/dhcp-server/lease", [lease(), lease(status="waiting")])
        self.router.json("/rest/ip/arp", [arp(), arp(complete="false", status="failed")])
        b = self.conn.collect()
        self.assertIsInstance(b, Batch)
        self.assertEqual([(s.kind, s.mac, s.network) for s in b.sightings],
                         [("dhcp", "02:00:00:00:00:01", "bridge-lan"), ("arp", "02:00:00:00:00:02", "bridge-lan")])
        self.assertEqual(b.stats, {"leases": 2, "arp": 2, "dropped": 0})
        paths = [p for p, _ in self.router.requests]
        self.assertTrue(all("?.proplist=" in p for p in paths))
        self.assertEqual([p.split("?")[0] for p in paths], ["/rest/ip/dhcp-server", "/rest/ip/dhcp-server/lease", "/rest/ip/arp"])
        self.assertIn("host-name", paths[1])
        auth = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        self.assertTrue(all(a == auth for _, a in self.router.requests))

    def test_check_ok(self) -> None:
        self.router.json("/rest/system/resource", {"version": "7.16 (stable)"})
        self.conn.check()
        self.assertEqual(self.router.requests[0][0], "/rest/system/resource?.proplist=version")

    def test_401_with_routeros_error_json(self) -> None:
        self.router.json("/rest/system/resource", {"error": 401, "message": "Unauthorized"}, status=401)
        self.assertEqual(self.error(), "mikrotik /rest/system/resource: HTTP 401 (wrong USER or PASSWORD): Unauthorized")

    def test_403(self) -> None:
        self.router.json("/rest/system/resource", {"error": 403, "message": "Forbidden"}, status=403)
        self.assertIn("read and rest-api policies", self.error())

    def test_400_with_detail(self) -> None:
        self.router.json("/rest/system/resource", {"detail": "no such command\nor directory", "error": 400,
                                                   "message": "Bad Request"}, status=400)
        self.assertEqual(self.error(), "mikrotik /rest/system/resource: HTTP 400: Bad Request; no such command or directory")

    def test_error_body_not_json(self) -> None:
        self.router.routes["/rest/system/resource"] = (500, b"<html>oops</html>", {})
        self.assertEqual(self.error(), "mikrotik /rest/system/resource: HTTP 500")

    def test_error_detail_echoing_password_is_redacted(self) -> None:
        self.router.json("/rest/system/resource", {"error": 400, "message": "Bad Request", "detail": f"bad {PASSWORD}"},
                         status=400)
        self.assertIn("bad ***", self.error())

    def test_redirect_not_followed(self) -> None:
        self.router.routes["/rest/system/resource"] = (302, b"", {"Location": self.router.url + "/elsewhere"})
        self.assertEqual(self.error(), "mikrotik /rest/system/resource: HTTP 302")
        self.assertEqual([p.split("?")[0] for p, _ in self.router.requests], ["/rest/system/resource"])

    def test_non_json_200(self) -> None:
        self.router.routes["/rest/system/resource"] = (200, b"<html>webfig</html>", {"Content-Type": "text/html"})
        self.assertIn("response is not JSON", self.error())

    def test_list_endpoint_not_a_list(self) -> None:
        self.router.json("/rest/ip/dhcp-server", {"error": "x"})
        self.assertEqual(self.error("collect"), "mikrotik /rest/ip/dhcp-server: unexpected response shape (not a list)")

    def test_oversized_body_capped(self) -> None:
        self.router.json("/rest/system/resource", {"version": "x" * 200})
        with mock.patch.object(mc, "MAX_BODY", 100):
            self.assertIn("response larger than", self.error())

    def test_connection_refused(self) -> None:
        with socket.socket() as sock:  # a port nothing listens on once this socket is closed
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.conn = make(f"http://127.0.0.1:{port}")
        self.assertIn("connection refused", self.error())


class StubOpener:
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def open(self, req: object, timeout: float = 0) -> object:
        raise self.exc


class StubTest(unittest.TestCase):
    def conn_raising(self, exc: BaseException, **settings: str) -> tuple[MikrotikConnector, list[dict]]:
        calls: list[dict] = []

        def factory(**kw: bool) -> StubOpener:
            calls.append(kw)
            return StubOpener(exc)
        return make(ctx=HostContext(now=lambda: NOW, opener_factory=factory), **settings), calls

    def error(self, conn: MikrotikConnector) -> str:
        with self.assertRaises(ConnectorError) as cm:
            conn.check()
        return str(cm.exception)

    def test_tls_failure_message_redacted(self) -> None:
        e = ssl.SSLCertVerificationError(1, "certificate verify failed")
        e.verify_message = "Hostname mismatch, certificate is not valid for 'router.example.lan'."
        conn, _ = self.conn_raising(urllib.error.URLError(e))
        text = self.error(conn)
        self.assertNotIn("router.example.lan", text)
        self.assertIn("certificate is not valid for '<host>'", text)
        self.assertIn("VERIFY_TLS=0", text)

    def test_host_masked_whole_occurrences_only(self) -> None:
        mask = mc.make_host_mask("https://10.0.0.1")
        self.assertEqual(mask("10.0.0.1 and 10.0.0.15 and 10.0.0.1:443"), "<host> and 10.0.0.15 and <host>:443")
        mask6 = mc.make_host_mask("https://[fd00::1]")
        self.assertEqual(mask6("fd00::1 fd00::1:5 fd00:0000:0000:0000:0000:0000:0000:0001"),
                         "<host> fd00::1:5 <host>")
        self.assertEqual(mc.make_host_mask("https://ROUTER.example.lan.")("router.EXAMPLE.lan"), "<host>")

    def test_generic_tls_error(self) -> None:
        conn, _ = self.conn_raising(ssl.SSLError(1, "[SSL] wrong version number"))
        self.assertTrue(self.error(conn).startswith("mikrotik /rest/system/resource: TLS error"))

    def test_timeout(self) -> None:
        conn, _ = self.conn_raising(urllib.error.URLError(TimeoutError("timed out")))
        self.assertEqual(self.error(conn), "mikrotik /rest/system/resource: timed out")
        conn, _ = self.conn_raising(socket.timeout("timed out"))
        self.assertEqual(self.error(conn), "mikrotik /rest/system/resource: timed out")

    def test_name_not_resolved(self) -> None:
        conn, _ = self.conn_raising(urllib.error.URLError(socket.gaierror(-2, "Name or service not known")))
        self.assertEqual(self.error(conn), "mikrotik /rest/system/resource: host name not resolved")

    def test_opener_flags(self) -> None:
        conn, calls = self.conn_raising(TimeoutError())
        self.assertRaises(ConnectorError, conn.check)
        conn2, calls2 = self.conn_raising(TimeoutError(), verify_tls="0", proxy="1")
        self.assertRaises(ConnectorError, conn2.check)
        self.assertEqual((calls, calls2), ([{"verify_tls": True, "use_env_proxy": False}],
                                           [{"verify_tls": False, "use_env_proxy": True}]))

    def test_host_redactor_applied(self) -> None:
        e = urllib.error.URLError(OSError(5, "other-instance-secret here"))
        ctx = HostContext(redact=lambda t: t.replace("other-instance-secret", "***"),
                          opener_factory=lambda **kw: StubOpener(e))
        self.assertEqual(self.error(make(ctx=ctx)), "mikrotik /rest/system/resource: *** here")


class ErrorTextTest(unittest.TestCase):
    """The error pipeline: secrets redacted first, then the host masked, then the text cleaned and cut."""

    def http_error(self, detail: str, url: str = "https://router.example.lan", password: str = PASSWORD,
                   redact: object = None) -> str:
        body = json.dumps({"error": 400, "message": "Bad Request", "detail": detail}).encode()

        def factory(**kw: bool) -> StubOpener:
            return StubOpener(urllib.error.HTTPError(url + "/rest/x", 400, "Bad", {}, io.BytesIO(body)))
        ctx = HostContext(now=lambda: NOW, opener_factory=factory, **({"redact": redact} if redact else {}))
        conn = MikrotikConnector("mt1", {"url": url, "user": USER, "password": password}, ctx)
        with self.assertRaises(ConnectorError) as cm:
            conn.check()
        return str(cm.exception)

    def test_secret_containing_the_host_is_redacted_whole(self) -> None:
        pw = "router.example.lan#2024"
        text = self.http_error(f'invalid value "{pw}"', password=pw)
        self.assertIn('invalid value "***"', text)
        self.assertNotIn("2024", text)
        text = self.http_error("invalid value 10.0.0.1!secret9", url="https://10.0.0.1", password="10.0.0.1!secret9")
        self.assertNotIn("secret9", text)
        # another instance's secret (the host's redactor) is also matched before the host is masked
        other = "router.example.lan/other-77"
        text = self.http_error(f"x {other}", redact=lambda t: t.replace(other, "***"))
        self.assertNotIn("other-77", text)

    def test_cut_never_leaves_part_of_a_secret_or_host(self) -> None:
        for n in range(90, 420, 7):  # the secret or host at every position around the cut
            text = self.http_error("x" * n + " " + PASSWORD)
            self.assertNotIn(PASSWORD[:6], text, n)
            text = self.http_error("y" * n + " router.example.lan")
            self.assertNotIn("router.ex", text, n)

    def test_long_host_in_tls_message_masked(self) -> None:
        host = "edge-router-01." + "site-north." * 6 + "example.lan"  # longer than the old 120-character cut
        e = ssl.SSLCertVerificationError(1, "certificate verify failed")
        e.verify_message = f"Hostname mismatch, certificate is not valid for '{host}'."
        conn = MikrotikConnector("mt1", {"url": "https://" + host, "user": USER, "password": PASSWORD},
                                 HostContext(opener_factory=lambda **kw: StubOpener(urllib.error.URLError(e))))
        with self.assertRaises(ConnectorError) as cm:
            conn.check()
        self.assertNotIn("edge-router", str(cm.exception))
        self.assertIn("'<host>'", str(cm.exception))
        self.assertIn("VERIFY_TLS=0", str(cm.exception))

    def test_unicode_line_and_bidi_controls_removed(self) -> None:
        for ch in "\u2028\u2029\u202a\u202e\u2066\u2069\u200e\u200f\u061c\u200b\ufeff":
            self.assertEqual(mc._clean(f"a{ch}b"), "a b", repr(ch))
        self.assertNotIn("\u202e", self.http_error("a\u2028b\u202ec"))

    def test_idna_error_wrapped(self) -> None:
        for exc in (UnicodeError("label too long"), UnicodeEncodeError("idna", "x", 0, 1, "label empty")):
            conn = make(ctx=HostContext(opener_factory=lambda **kw: StubOpener(exc)))
            with self.assertRaises(ConnectorError) as cm:
                conn.check()
            self.assertEqual(str(cm.exception), "mikrotik /rest/system/resource: bad URL (host name not valid)")
            self.assertIsNone(cm.exception.__cause__)


class SettingsTest(unittest.TestCase):
    def test_describe(self) -> None:
        info = MikrotikConnector.describe()
        self.assertEqual((info.type, info.api_version, info.produces), ("mikrotik", API_VERSION, frozenset({"sighting"})))
        self.assertEqual([s.key for s in info.settings if s.secret], ["password"])
        self.assertEqual([s.key for s in info.settings],
                         ["url", "user", "password", "verify_tls", "ignore_interfaces", "proxy"])

    def test_valid(self) -> None:
        self.assertEqual(make().validate(), [])

    def test_required(self) -> None:
        problems = MikrotikConnector("mt1", {}, HostContext()).validate()
        self.assertEqual(len([p for p in problems if "is required" in p]), 3)

    def test_url_checks(self) -> None:
        self.assertEqual(make("http://router.example.lan").validate(),
                         ["url must start with https:// (the www-ssl service)"])
        self.assertIn("url must not contain credentials", make(f"https://{USER}:{PASSWORD}@router.example.lan").validate())
        self.assertIn("url must be a URL (https://<router>)", make("router.example.lan").validate())
        # every request path is appended to the URL: a query or fragment would swallow it
        for url in ("https://router.example.lan?x=1", "https://router.example.lan/?x=1", "https://router.example.lan#a",
                    "https://router.example.lan?"):
            self.assertEqual(make(url).validate(), ["url must not contain a query (?) or fragment (#)"], url)
        for url in ("https://router.example.lan/", "https://router.example.lan:8443", "https://10.0.0.1/mt"):
            self.assertEqual(make(url).validate(), [], url)

    def test_bool_and_user_checks(self) -> None:
        conn = MikrotikConnector("mt1", {"url": "https://router.example.lan", "user": "a:b", "password": PASSWORD,
                                         "verify_tls": "maybe", "proxy": "2"}, HostContext())
        self.assertEqual(conn.validate(), ["user must not contain ':' (HTTP Basic auth cannot carry it)",
                                           "verify_tls must be a boolean (1/0, true/false, yes/no, on/off)",
                                           "proxy must be a boolean (1/0, true/false, yes/no, on/off)"])

    def test_ignore_interfaces_parsed(self) -> None:
        self.assertEqual(make(ignore_interfaces=" Ether1, ,lo").ignore, frozenset({"ether1", "lo"}))
        self.assertEqual(make().ignore, frozenset())

    def test_secret_absent_from_repr(self) -> None:
        conn = make()
        self.assertNotIn(PASSWORD, repr(conn))
        self.assertIn(USER, repr(conn))

    def test_no_io_before_check(self) -> None:
        def factory(**kw: bool) -> object:
            raise AssertionError("I/O before check")
        conn = make(ctx=HostContext(opener_factory=factory))
        conn.validate()
        conn.close()


if __name__ == "__main__":
    unittest.main()
