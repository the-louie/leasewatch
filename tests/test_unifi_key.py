"""parse_integration_clients: Integration API client and device lists to the WifiInfo map."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leasewatch.unifi import parse_integration_clients  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "unifi_integration")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)["data"]


class ParseIntegrationClients(unittest.TestCase):
    def setUp(self):
        self.devices = load("devices.json")

    def test_two_pages(self):
        out = parse_integration_clients(load("clients_p1.json") + load("clients_p2.json"), self.devices)
        self.assertEqual(set(out), {"02:00:00:00:00:21", "02:00:00:00:00:22", "02:00:00:00:00:23", "02:00:00:00:00:0a"})
        a = out["02:00:00:00:00:21"]
        self.assertEqual((a.alias, a.ap, a.wired, a.ssid, a.signal, a.radio, a.channel),
                         ("alex-laptop", "ap-hall", False, "", None, "", None))
        self.assertEqual(out["02:00:00:00:00:22"].alias, "")
        p = out["02:00:00:00:00:23"]
        self.assertTrue(p.wired)
        self.assertEqual(p.ap, "")
        g = out["02:00:00:00:00:0a"]
        self.assertEqual((g.ap, g.alias), ("", "guest-tablet"))

    def test_odd_page(self):
        out = parse_integration_clients(load("clients_odd.json"), self.devices)
        self.assertEqual(list(out), ["02:00:00:00:00:34"])
        self.assertEqual(out["02:00:00:00:00:34"].ap, "ap-hall")

    def test_bad_input_does_not_raise(self):
        self.assertEqual(parse_integration_clients(["x", None, 3], None), {})
        self.assertEqual(parse_integration_clients(None, None), {})
        out = parse_integration_clients([{"type": "WIRELESS", "name": "a", "macAddress": "02:00:00:00:00:01",
                                          "uplinkDeviceId": ["x"]}], ["junk", {"id": 5}, {"id": "d"}])
        self.assertEqual(out["02:00:00:00:00:01"].ap, "")

    def test_duplicate_mac_later_row_wins(self):
        row = {"type": "WIRELESS", "macAddress": "02:00:00:00:00:77", "uplinkDeviceId": "00000000-0000-4000-8000-000000000011"}
        out = parse_integration_clients([dict(row, name="first"), dict(row, name="second", macAddress="02:00:00:00:00:77".upper())],
                                        self.devices)
        self.assertEqual(len(out), 1)
        self.assertEqual(out["02:00:00:00:00:77"].alias, "second")


# --- UnifiKeyClient against a local stub console (ThreadingHTTPServer on 127.0.0.1, port 0) ---

import logging  # noqa: E402
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402
from unittest import mock  # noqa: E402
from urllib.parse import parse_qs, urlsplit  # noqa: E402

from leasewatch import unifi  # noqa: E402
from leasewatch.unifi import UnifiKeyClient  # noqa: E402

KEY = "k3y-Sekret-4471"
API = "/proxy/network/integration/v1"
DEFAULT_ID, LAB_ID = "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"


def raw(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


class Console:
    """Serves the fixture files by path. sites: the site rows; split: the client list comes as clients_p1 + clients_p2
    (else one page of both); status: path (without query) -> status for every request to it; once: path -> status
    for the next request only; handle(h) may be replaced. Records (method, path, headers) of every request."""

    def __init__(self):
        self.sites = raw("sites.json")["data"]
        self.split = True
        self.status: dict[str, int] = {}
        self.once: dict[str, int] = {}
        self.requests: list[tuple[str, str, dict]] = []
        self.lock = threading.Lock()
        con = self

        class H(BaseHTTPRequestHandler):
            def send(self, status, body=b"{}", headers=None):
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def js(self, o, status=200):
                self.send(status, json.dumps(o).encode(), {"Content-Type": "application/json"})

            def do_GET(self):
                with con.lock:
                    con.requests.append((self.command, self.path, dict(self.headers)))
                con.handle(self)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def handle(self, h):
        u = urlsplit(h.path)
        path, q = u.path, parse_qs(u.query)
        offset = int(q.get("offset", ["0"])[0])
        status = self.once.pop(path, 0) or self.status.get(path, 0)
        if status:
            return h.send(status, json.dumps(raw("error_401.json")).encode() if status == 401 else b"{}",
                          {"Location": "http://127.0.0.1:1/elsewhere"} if 300 <= status < 400 else None)
        if path == API + "/sites":
            return h.js({"offset": 0, "limit": 200, "count": len(self.sites), "totalCount": len(self.sites), "data": self.sites})
        for sid in {s["id"] for s in self.sites} | {DEFAULT_ID}:
            if path == f"{API}/sites/{sid}/devices":
                return h.js(raw("devices.json"))
            if path == f"{API}/sites/{sid}/clients":
                if not self.split:
                    rows = raw("clients_p1.json")["data"] + raw("clients_p2.json")["data"]
                    return h.js({"offset": 0, "limit": 200, "count": 6, "totalCount": 6, "data": rows})
                return h.js(raw("clients_p1.json" if offset == 0 else "clients_p2.json"))
        return h.js({}, 404)

    def paths(self):
        return [urlsplit(p).path for _, p, _ in self.requests]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


WANT = {"02:00:00:00:00:21", "02:00:00:00:00:22", "02:00:00:00:00:23", "02:00:00:00:00:0a"}


class KeyBase(unittest.TestCase):
    def setUp(self):
        self.con = Console()
        self.addCleanup(self.con.close)

    def client(self, site="default", key=KEY):
        c = UnifiKeyClient(self.con.url, site, key, verify_tls=False, proxy=False, timeout=5)
        self.addCleanup(c.close)
        return c

    def fails(self, c):
        with self.assertRaises(RuntimeError) as cm:
            c.clients()
        return str(cm.exception)


class KeyClientRead(KeyBase):
    def test_two_pages_and_headers(self):
        out = self.client().clients()
        self.assertEqual(set(out), WANT)
        self.assertEqual((out["02:00:00:00:00:21"].alias, out["02:00:00:00:00:21"].ap), ("alex-laptop", "ap-hall"))
        self.assertTrue(out["02:00:00:00:00:23"].wired)
        self.assertEqual(out["02:00:00:00:00:0a"].ap, "")
        clients = [p for _, p, _ in self.con.requests if p.startswith(f"{API}/sites/{DEFAULT_ID}/clients")]
        self.assertEqual(clients, [f"{API}/sites/{DEFAULT_ID}/clients?offset=0&limit=200",
                                   f"{API}/sites/{DEFAULT_ID}/clients?offset=3&limit=200"])
        for _, _, headers in self.con.requests:
            h = {k.lower(): v for k, v in headers.items()}
            self.assertEqual(h.get("x-api-key"), KEY)
            self.assertEqual(h.get("accept"), "application/json")
            self.assertNotIn("cookie", h)
            self.assertNotIn("x-csrf-token", h)

    def test_site_by_uuid_skips_sites(self):
        self.assertEqual(set(self.client(LAB_ID).clients()), WANT)
        self.assertNotIn(API + "/sites", self.con.paths())
        self.assertIn(f"{API}/sites/{LAB_ID}/clients", self.con.paths())

    def test_site_by_internal_reference_and_name(self):
        self.client("default").clients()
        self.assertIn(f"{API}/sites/{DEFAULT_ID}/clients", self.con.paths())
        self.client("lab").clients()
        self.assertIn(f"{API}/sites/{LAB_ID}/clients", self.con.paths())

    def test_site_name_case_insensitive_fallback(self):
        self.con.sites = [{"id": LAB_ID, "internalReference": "x1", "name": "Lab Floor"}]
        self.client("lab floor").clients()
        self.assertIn(f"{API}/sites/{LAB_ID}/clients", self.con.paths())

    def test_site_id_is_cached(self):
        c = self.client()
        c.clients()
        c.clients()
        self.assertEqual(self.con.paths().count(API + "/sites"), 1)

    def test_unknown_site(self):
        msg = self.fails(self.client("nowhere"))
        self.assertEqual(msg, "unifi: site nowhere not found (use the site's internal reference, name or id)")
        self.assertNotIn("00000000", msg)

    def test_ambiguous_site_name(self):
        self.con.sites = [{"id": DEFAULT_ID, "internalReference": "a", "name": "Home"},
                          {"id": LAB_ID, "internalReference": "b", "name": "Home"}]
        self.assertEqual(self.fails(self.client("Home")), "unifi: site name Home is ambiguous, use its id")

    def test_404_on_cached_site_resolves_once_more(self):
        c = self.client()
        c.clients()
        self.con.once[f"{API}/sites/{DEFAULT_ID}/clients"] = 404
        self.assertEqual(set(c.clients()), WANT)
        self.assertEqual(self.con.paths().count(API + "/sites"), 2)

    def test_404_right_after_resolving_is_an_error(self):
        self.con.status[f"{API}/sites/{DEFAULT_ID}/clients"] = 404
        self.assertEqual(self.fails(self.client()), f"unifi: HTTP 404 on /v1/sites/{DEFAULT_ID}/clients")
        self.assertEqual(self.con.paths().count(API + "/sites"), 1)

    def test_close_is_harmless(self):
        c = self.client()
        c.close()
        c.close()
        self.assertEqual(set(c.clients()), WANT)  # close() kept nothing from working


class KeyClientErrors(KeyBase):
    def test_401_hides_the_key(self):
        self.con.status[API + "/sites"] = 401
        c = self.client()
        with self.assertLogs("leasewatch.unifi", "DEBUG") as logs:
            logging.getLogger("leasewatch.unifi").debug("marker")  # assertLogs needs one record
            msg = self.fails(c)
        self.assertEqual(msg, "unifi: API key rejected (HTTP 401)")
        self.assertNotIn(KEY, msg)
        self.assertNotIn(KEY, repr(c))
        self.assertNotIn(KEY, "\n".join(logs.output))
        self.assertNotIn("Missing credentials", msg)  # the error body is never echoed

    def test_403(self):
        self.con.status[API + "/sites"] = 403
        self.assertEqual(self.fails(self.client()), "unifi: API key rejected (HTTP 403)")

    def test_404_on_sites_means_no_integration_api(self):
        self.con.status[API + "/sites"] = 404
        self.assertEqual(self.fails(self.client()), "unifi: no Integration API at this URL (UniFi OS console needed)")

    def test_other_status_names_the_path(self):
        self.con.status[f"{API}/sites/{DEFAULT_ID}/devices"] = 500
        self.assertEqual(self.fails(self.client()), f"unifi: HTTP 500 on /v1/sites/{DEFAULT_ID}/devices")

    def test_redirect_not_followed(self):
        self.con.status[API + "/sites"] = 302
        self.assertEqual(self.fails(self.client()), "unifi: HTTP 302 on /v1/sites")
        self.assertEqual(len(self.con.requests), 1)

    def test_oversized_body(self):
        with mock.patch.object(unifi, "MAX_BODY", 32):
            self.assertEqual(self.fails(self.client()), "unifi: response too large")

    def test_invalid_json_and_shape(self):
        self.con.handle = lambda h: h.send(200, b"not json")
        self.assertTrue(self.fails(self.client()).startswith("unifi: Expecting value"))
        self.con.handle = lambda h: h.js([1, 2])
        self.assertEqual(self.fails(self.client()), "unifi: unexpected response shape")
        self.con.handle = lambda h: h.js({"count": 1, "totalCount": 1, "data": {"x": 1}})
        self.assertEqual(self.fails(self.client()), "unifi: unexpected response shape")

    def test_malformed_key_not_echoed(self):
        bad = KEY + "\r\nX-Evil: 1"
        c = self.client(key=bad)
        msg = self.fails(c)
        self.assertEqual(msg, "unifi: unexpected response")
        self.assertNotIn(KEY, msg)
        self.assertNotIn(KEY, repr(c))

    def test_unreachable(self):
        port = self.con.server.server_address[1]
        self.con.close()  # nothing listens on the port now (the cleanup's second close is a no-op)
        c = UnifiKeyClient(f"http://127.0.0.1:{port}", "default", KEY, timeout=2)
        msg = self.fails(c)
        self.assertTrue(msg.startswith("unifi: "))
        self.assertNotIn(KEY, msg)

    def test_page_cap(self):
        def endless(h):
            h.js({"offset": 0, "limit": 200, "count": 1, "totalCount": 10 ** 6,
                  "data": [{"id": LAB_ID, "internalReference": "lab", "name": "lab"}]})
        self.con.handle = endless
        c = self.client()
        with self.assertLogs("leasewatch.unifi", "WARNING") as logs:
            rows = c._page("/v1/sites")
        self.assertEqual(len(rows), 50)
        self.assertEqual(len(self.con.requests), 50)
        self.assertIn("more than 50 pages", "\n".join(logs.output))


class KeyConnector(KeyBase):
    def conn(self, **kw):
        from leasewatch.connectors import HostContext
        from leasewatch.connectors.unifi import UnifiConnector
        s = {"url": self.con.url, "auth": "apikey", "api_key": KEY, "verify_tls": "0", "platform": "unifi_os", **kw}
        c = UnifiConnector("unifi", s, HostContext(now=lambda: 1762400000))
        self.addCleanup(c.close)
        return c

    def test_check_and_collect(self):
        c = self.conn()
        self.assertEqual(c.validate(), [])
        c.check()
        b = c.collect()
        self.assertEqual(b.stats, {"clients": 4, "ssid_unavailable": 1})
        got = {a.mac: a for a in b.attachments}
        self.assertEqual(set(got), WANT)
        self.assertEqual(got["02:00:00:00:00:21"].link, "wifi")
        self.assertEqual(got["02:00:00:00:00:23"].link, "wired")
        self.assertEqual(got["02:00:00:00:00:21"].alias, "alex-laptop")
        self.assertEqual(got["02:00:00:00:00:22"].alias, "")
        for a in b.attachments:
            self.assertEqual((a.ssid, a.signal, a.present, a.source, a.observed_at), ("", None, True, "unifi", 1762400000))
        self.assertTrue(all({k.lower(): v for k, v in h.items()}.get("x-api-key") == KEY for _, _, h in self.con.requests))
        c.close()

    def test_401_text_is_masked(self):
        from leasewatch.connectors import ConnectorError
        self.con.status[API + "/sites"] = 401
        host, port = self.con.url.split("//")[1].split(":")
        for call in ("check", "collect"):
            with self.assertLogs("leasewatch.unifi", "DEBUG") as logs:
                logging.getLogger("leasewatch.unifi").debug("marker")
                with self.assertRaises(ConnectorError) as cm:
                    getattr(self.conn(), call)()
            for text in [str(cm.exception)] + logs.output:
                for s in (KEY, host, port):
                    self.assertNotIn(s, text)
            self.assertEqual(str(cm.exception), "unifi: API key rejected (HTTP 401)")


if __name__ == "__main__":
    unittest.main()
