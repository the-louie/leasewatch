"""HTTP-level tests for leasewatch.web: real ThreadingHTTPServer on an ephemeral port, temp SQLite, fake fw1."""
import http.client
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore  # noqa: E402
from leasewatch.collector import Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.db import Database  # noqa: E402
from leasewatch.fw1 import Fw1Error, Sighting  # noqa: E402
from leasewatch.connectors import InstanceSpec  # noqa: E402
from leasewatch.web import MAX_BODY, serve  # noqa: E402

MAC1 = "aa:bb:cc:dd:ee:01"  # baseline device (present at first poll)
MAC2 = "aa:bb:cc:dd:ee:02"  # new device, DHCP, VLAN IOT
MAC3 = "aa:bb:cc:dd:ee:03"  # new device, ARP only, non-ASCII hostname/vendor
UNKNOWN = "02:11:22:33:44:55"
SITE = "Hemnät Test"
VERSION = "9.9.9-test"
ENV = {"FW1_KEY": "k", "FW1_SECRET": "s", "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0",
       "SITE_NAME": SITE, "MAILGUN_KEY": "", "MAILGUN_DOMAIN": "", "MAIL_TO": "", "POLL_SECONDS": "120"}


class FakeClient:
    def __init__(self, sightings):
        self.sightings_data = sightings
        self.fail = False

    def sightings(self, ignore=()):
        if self.fail:
            raise Fw1Error("boom")
        return list(self.sightings_data), {"leases": 1, "arp": 1}


def S(mac, ip, host="", src="dhcp", vlan="Clients", lt="dynamic", online=True, vendor="Acme"):
    return Sighting(mac=mac, ip=ip, hostname=host, vendor=vendor, vlan=vlan, iface="opt3", source=src,
                    lease_type=lt if src == "dhcp" else "", online=online)


class WebTestCase(unittest.TestCase):
    """Each test gets its own DB and server, so POSTs never leak between tests."""

    @classmethod
    def setUpClass(cls):
        logging.disable(logging.CRITICAL)  # the app logs failed polls / handler errors; keep test output clean

    @classmethod
    def tearDownClass(cls):
        logging.disable(logging.NOTSET)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved_env = clean_env(dict(ENV, DATA_DIR=self.tmp.name))
        self.cfg = Config()
        self.db = Database(self.cfg.db_path)
        self.client = FakeClient([S(MAC1, "10.0.0.5", "phone")])
        self.collector = Collector(self.cfg, self.db, self.client)
        self.collector.run_once()  # first poll: MAC1 becomes baseline
        self.client.sightings_data += [S(MAC2, "10.0.0.9", "newbie", vlan="IOT"),
                                       S(MAC3, "10.0.0.77", "Kök-TV", src="arp", vendor="Köksbolaget")]
        self.collector.run_once()  # second poll: MAC2 + MAC3 are real newcomers
        # both polls happen within the same second; push the baseline device back so ordering is deterministic
        self.db.q("UPDATE devices SET first_seen=first_seen-864000 WHERE mac=?", (MAC1,))
        self.srv = serve(self.cfg, self.db, VERSION)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)
        self.db._conn.close()
        self.tmp.cleanup()
        restore(self._saved_env)

    # --- helpers -------------------------------------------------------------
    def req(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            return r.status, r.headers, r.read()
        finally:
            conn.close()

    def get_json(self, path, expect=200):
        status, headers, body = self.req("GET", path)
        self.assertEqual(status, expect, body[:300])
        self.assertTrue(headers["Content-Type"].startswith("application/json"), headers["Content-Type"])
        return json.loads(body.decode("utf-8")), headers

    def post(self, mac, payload, ctype="application/json", raw=None):
        body = raw if raw is not None else json.dumps(payload).encode()
        headers = {"Content-Type": ctype} if ctype is not None else {}
        status, hdrs, data = self.req("POST", f"/api/devices/{mac}", body=body, headers=headers)
        try:
            parsed = json.loads(data.decode("utf-8")) if data else None
        except ValueError:
            parsed = None
        return status, parsed, hdrs

    def raw_request(self, text: bytes) -> bytes:
        """Send bytes on a plain socket and return everything the server answers (b'' if it just hangs up)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(text)
            chunks = []
            try:
                while True:
                    c = s.recv(65536)
                    if not c:
                        break
                    chunks.append(c)
            except (ConnectionResetError, socket.timeout):
                pass
            return b"".join(chunks)


# ----------------------------------------------------------------------------
class StaticTests(WebTestCase):
    def test_index_substitutes_site_name_and_version(self):
        status, headers, body = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        html = body.decode("utf-8")
        self.assertIn("<!doctype html>", html.lower())
        self.assertIn(f"<title>{SITE}</title>", html)
        self.assertIn(VERSION, html)
        self.assertNotIn("{{", html)
        self.assertNotIn("}}", html)

    def test_index_with_query_string(self):
        status, _, body = self.req("GET", "/?filter=new")
        self.assertEqual(status, 200)
        self.assertIn(SITE.encode(), body)

    def test_static_assets_have_sensible_content_types(self):
        status, headers, body = self.req("GET", "/static/style.css")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/css; charset=utf-8")
        self.assertGreater(len(body), 100)

        status, headers, body = self.req("GET", "/static/app.js")
        self.assertEqual(status, 200)
        self.assertIn(headers["Content-Type"], ("text/javascript; charset=utf-8", "application/javascript; charset=utf-8"))
        self.assertGreater(len(body), 100)

        status, headers, body = self.req("GET", "/static/favicon.svg")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "image/svg+xml")
        self.assertIn(b"<svg", body)

    def test_static_content_length_matches_body(self):
        for path in ("/", "/static/style.css", "/static/app.js", "/static/favicon.svg"):
            status, headers, body = self.req("GET", path)
            self.assertEqual(status, 200, path)
            self.assertEqual(int(headers["Content-Length"]), len(body), path)

    def test_unknown_static_and_paths_are_404_json(self):
        for path in ("/static/nope.css", "/static/", "/static", "/index.html", "/favicon.ico", "/api", "/api/", "/api/devices/", "/nothing"):
            status, headers, body = self.req("GET", path)
            self.assertEqual(status, 404, path)
            self.assertTrue(headers["Content-Type"].startswith("application/json"), path)
            self.assertEqual(json.loads(body)["error"], "not found", path)

    def test_static_directory_is_not_served(self):
        # a directory under static (none exists today) and STATIC_DIR itself must never be listed
        status, _, body = self.req("GET", "/static/.")
        self.assertEqual(status, 404)
        self.assertNotIn(b"style.css", body)

    def test_path_traversal_is_404_and_leaks_nothing(self):
        attempts = [
            "/static/../db.py",
            "/static/../web.py",
            "/static/../../tests/test_web.py",
            "/static/../../../../../../etc/passwd",
            "/static/%2e%2e/db.py",
            "/static/..%2fdb.py",
            "/static/%2e%2e%2fdb.py",
            "/static/..%2F..%2Fetc%2Fpasswd",
            "/static/%2e%2e/%2e%2e/etc/passwd",
            "/static//etc/passwd",
            "/static///etc/passwd",
            "/static/./../db.py",
            "/static/style.css/../../db.py",
            "/static/..\\db.py",
            "/static/..%5cdb.py",
            "/static/../static/../db.py",
        ]
        markers = (b"sqlite3", b"import ", b"CREATE TABLE", b"root:", b"def ", b"ThreadingHTTPServer")
        for path in attempts:
            status, headers, body = self.req("GET", path)
            self.assertEqual(status, 404, f"{path} -> {status} {body[:120]!r}")
            self.assertTrue(headers["Content-Type"].startswith("application/json"), path)
            for m in markers:
                self.assertNotIn(m, body, f"{path} leaked {m!r}")
            self.assertLess(len(body), 200, path)

    def test_static_index_html_is_not_served_twice(self):
        status, _, body = self.req("GET", "/static/index.html")
        self.assertEqual(status, 404)


# ----------------------------------------------------------------------------
class ApiReadTests(WebTestCase):
    def test_devices_lists_all_newest_first_with_meta(self):
        data, headers = self.get_json("/api/devices")
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        macs = [d["mac"] for d in data["devices"]]
        self.assertEqual(macs, [MAC2, MAC3, MAC1])
        by = {d["mac"]: d for d in data["devices"]}
        self.assertEqual(by[MAC1]["baseline"], 1)
        self.assertEqual(by[MAC2]["baseline"], 0)
        self.assertEqual(by[MAC2]["vlan"], "IOT")
        self.assertEqual(by[MAC2]["acked"], 0)
        self.assertIsNone(by[MAC2]["acked_at"])
        self.assertEqual(by[MAC3]["hostname"], "Kök-TV")
        self.assertEqual(by[MAC3]["vendor"], "Köksbolaget")
        self.assertEqual(by[MAC3]["sources"], "arp")
        self.assertEqual(by[MAC3]["lease_type"], "")
        meta = data["meta"]
        for key in ("now", "last_poll_ts", "last_poll_age", "last_poll_ok", "last_error", "stale", "poll_seconds",
                    "new_days", "site_name", "version", "mail", "baseline_ts", "last_raw"):
            self.assertIn(key, meta)
        self.assertEqual(meta["site_name"], SITE)
        self.assertEqual(meta["version"], VERSION)
        self.assertTrue(meta["last_poll_ok"])
        self.assertFalse(meta["stale"])
        self.assertFalse(meta["mail"])
        self.assertEqual(meta["last_raw"], "1 leases, 1 arp")

    def test_devices_json_is_utf8_not_ascii_escaped(self):
        _, _, body = self.req("GET", "/api/devices")
        self.assertIn("Kök-TV".encode("utf-8"), body)
        self.assertNotIn(b"\\u00c5", body)

    def test_stats(self):
        data, _ = self.get_json("/api/stats")
        st = data["stats"]
        self.assertEqual(st["total"], 3)
        self.assertEqual(st["online"], 3)
        self.assertEqual(st["new"], 2)
        self.assertEqual(st["unacked"], 2)
        vlans = {v["vlan"]: v for v in st["vlans"]}
        self.assertEqual(vlans["Clients"]["n"], 2)
        self.assertEqual(vlans["IOT"]["n"], 1)
        self.assertEqual(len(st["new_recent"]), 2)
        self.assertIn("meta", data)

    def test_events(self):
        data, _ = self.get_json("/api/events")
        ev = data["events"]
        self.assertEqual(sorted(e["mac"] for e in ev if e["kind"] == "new"), [MAC2, MAC3])
        for e in ev:
            for key in ("ts", "mac", "kind", "detail", "name", "hostname", "vlan"):
                self.assertIn(key, e)
        new2 = next(e for e in ev if e["mac"] == MAC2)
        self.assertIn("10.0.0.9", new2["detail"])
        self.assertEqual(new2["hostname"], "newbie")

    def test_device_known(self):
        data, _ = self.get_json(f"/api/devices/{MAC2}")
        self.assertEqual(data["device"]["mac"], MAC2)
        self.assertEqual(data["device"]["ip"], "10.0.0.9")
        self.assertEqual(len(data["history"]), 1)
        self.assertEqual(data["history"][0]["ip"], "10.0.0.9")
        self.assertEqual([e["kind"] for e in data["events"]], ["new"])

    def test_device_unknown_mac_is_404(self):
        data, _ = self.get_json(f"/api/devices/{UNKNOWN}", expect=404)
        self.assertEqual(data["error"], "unknown device")

    def test_device_bad_mac_formats_are_404_not_500(self):
        bad = [
            "aa:bb:cc:dd:ee",            # too short
            "aa:bb:cc:dd:ee:01:02",      # too long
            "aa-bb-cc-dd-ee-01",         # dashes
            "aabbccddee01",              # no separators
            "aa:bb:cc:dd:ee:0g",         # non-hex
            "aa:bb:cc:dd:ee:01/",        # trailing slash
            "aabbccddeeff:::::",         # 17 chars of [0-9a-f:] but not a MAC
            "::::::::::::::::::",
            "%61a:bb:cc:dd:ee:01",       # url-encoded
            "'%20OR%201=1--",
        ]
        for mac in bad:
            status, headers, body = self.req("GET", f"/api/devices/{mac}")
            self.assertIn(status, (400, 404), mac)  # 17 chars of [0-9a-f:] that is not a MAC -> 400, others 404
            self.assertTrue(headers["Content-Type"].startswith("application/json"), mac)
            self.assertIn("error", json.loads(body))

    def test_device_uppercase_mac_is_not_found(self):
        # the API is strictly lowercase (regex in web.py); uppercase must be rejected cleanly, not 500
        status, _, body = self.req("GET", f"/api/devices/{MAC2.upper()}")
        self.assertEqual(status, 404, body)
        self.assertIn("error", json.loads(body))
        status, parsed, _ = self.post(MAC2.upper(), {"acked": True})
        self.assertEqual(status, 404)
        self.assertEqual(self.db.device(MAC2)["acked"], 0)

    def test_csv_export(self):
        status, headers, body = self.req("GET", "/api/devices.csv")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn('filename="leasewatch-devices.csv"', headers["Content-Disposition"])
        self.assertTrue(body.startswith(b"\xef\xbb\xbf"), "missing UTF-8 BOM")
        text = body.decode("utf-8-sig")
        lines = text.splitlines()
        self.assertEqual(lines[0], "mac,ip,name,hostname,vendor,vlan,lease_type,sources,online,link,switch_port,via,wifi_ssid,wifi_ap,wifi_signal,first_seen,last_online,last_listed,acked,note")
        self.assertEqual([l.split(",")[0] for l in lines[1:]], [MAC2, MAC3, MAC1])
        self.assertIn("Kök-TV", text)
        self.assertIn("Köksbolaget", text)
        # timestamps are rendered, not epoch
        self.assertRegex(lines[1], r",\d{4}-\d{2}-\d{2}T\d{2}:\d{2}[+-]\d{4},\d{4}-\d{2}-\d{2}T\d{2}:\d{2}[+-]\d{4},")

    def test_csv_quotes_commas_and_newlines_in_user_fields(self):
        self.post(MAC2, {"name": 'TV, "vardagsrum"', "note": "line1\nline2"})
        _, _, body = self.req("GET", "/api/devices.csv")
        import csv, io
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        self.assertEqual(len(rows), 4)
        r2 = next(r for r in rows if r[0] == MAC2)
        self.assertEqual(r2[2], 'TV, "vardagsrum"')
        self.assertEqual(r2[-1], "line1\nline2")

    def test_healthz_ok_after_fresh_successful_poll(self):
        data, _ = self.get_json("/healthz", expect=200)
        self.assertTrue(data["ok"])
        self.assertFalse(data["stale"])
        self.assertTrue(data["last_poll_ok"])
        self.assertLessEqual(data["last_poll_age"], 5)

    def test_healthz_503_when_last_poll_failed(self):
        self.client.fail = True
        self.collector.run_once()
        data, _ = self.get_json("/healthz", expect=503)
        self.assertFalse(data["ok"])
        self.assertFalse(data["last_poll_ok"])
        self.assertIn("boom", data["last_error"])
        self.assertIsNotNone(data["last_error_ts"])
        # devices are still served while the poll is failing
        data, _ = self.get_json("/api/devices")
        self.assertEqual(len(data["devices"]), 3)

    def test_healthz_503_when_last_poll_is_stale(self):
        self.db.set_meta("last_poll_ts", str(int(time.time()) - self.cfg.poll_seconds * 3 - 1))
        data, _ = self.get_json("/healthz", expect=503)
        self.assertFalse(data["ok"])
        self.assertTrue(data["stale"])
        self.assertTrue(data["last_poll_ok"])  # the last poll itself was fine, it is just too old

    def test_healthz_200_at_edge_of_staleness(self):
        self.db.set_meta("last_poll_ts", str(int(time.time()) - self.cfg.poll_seconds * 3 + 20))
        self.get_json("/healthz", expect=200)

    def test_healthz_503_when_never_polled(self):
        self.db.q("DELETE FROM meta")
        data, _ = self.get_json("/healthz", expect=503)
        self.assertFalse(data["ok"])
        self.assertTrue(data["stale"])
        self.assertEqual(data["last_poll_ts"], 0)
        self.assertIsNone(data["last_poll_age"])


# ----------------------------------------------------------------------------
class ApiWriteTests(WebTestCase):
    def test_ack_sets_acked_at_and_creates_event(self):
        before = int(time.time())
        status, data, _ = self.post(MAC2, {"acked": True})
        self.assertEqual(status, 200)
        d = data["device"]
        self.assertEqual(d["mac"], MAC2)
        self.assertEqual(d["acked"], 1)
        self.assertGreaterEqual(d["acked_at"], before)
        self.assertLessEqual(d["acked_at"], int(time.time()))
        # persisted + visible through the read endpoints
        self.assertEqual(self.db.device(MAC2)["acked"], 1)
        detail, _ = self.get_json(f"/api/devices/{MAC2}")
        self.assertEqual([e["kind"] for e in detail["events"]], ["acked", "new"])
        all_events, _ = self.get_json("/api/events")
        self.assertEqual(all_events["events"][0]["kind"], "acked")
        self.assertEqual(all_events["events"][0]["mac"], MAC2)
        stats, _ = self.get_json("/api/stats")
        self.assertEqual(stats["stats"]["unacked"], 1)

    def test_ack_twice_creates_one_event_and_unack_clears_acked_at(self):
        self.post(MAC2, {"acked": True})
        self.post(MAC2, {"acked": True})
        detail, _ = self.get_json(f"/api/devices/{MAC2}")
        self.assertEqual([e["kind"] for e in detail["events"]].count("acked"), 1)
        status, data, _ = self.post(MAC2, {"acked": False})
        self.assertEqual(status, 200)
        self.assertEqual(data["device"]["acked"], 0)
        self.assertIsNone(data["device"]["acked_at"])
        detail, _ = self.get_json(f"/api/devices/{MAC2}")
        self.assertEqual([e["kind"] for e in detail["events"]], ["unacked", "acked", "new"])

    def test_name_and_note_are_stored_and_stripped(self):
        status, data, _ = self.post(MAC1, {"name": "  Kitchen TV ", "note": "\n behind the fridge \t"})
        self.assertEqual(status, 200)
        self.assertEqual(data["device"]["name"], "Kitchen TV")
        self.assertEqual(data["device"]["note"], "behind the fridge")
        self.assertEqual(data["device"]["acked"], 0)  # untouched
        row = self.db.device(MAC1)
        self.assertEqual(row["name"], "Kitchen TV")
        self.assertEqual(row["note"], "behind the fridge")

    def test_partial_updates_keep_other_fields(self):
        self.post(MAC1, {"name": "A", "note": "B", "acked": True})
        status, data, _ = self.post(MAC1, {"note": "C"})
        self.assertEqual(status, 200)
        self.assertEqual((data["device"]["name"], data["device"]["note"], data["device"]["acked"]), ("A", "C", 1))

    def test_empty_object_is_noop_200(self):
        status, data, _ = self.post(MAC1, {})
        self.assertEqual(status, 200)
        self.assertEqual(data["device"]["mac"], MAC1)

    def test_null_fields_are_treated_as_absent(self):
        self.post(MAC1, {"name": "keep"})
        status, data, _ = self.post(MAC1, {"name": None, "acked": None, "note": None})
        self.assertEqual(status, 200)
        self.assertEqual(data["device"]["name"], "keep")

    def test_unknown_fields_are_ignored(self):
        status, data, _ = self.post(MAC1, {"acked": True, "mac": UNKNOWN, "baseline": 0, "foo": {"x": 1}, "first_seen": 1})
        self.assertEqual(status, 200)
        self.assertEqual(data["device"]["acked"], 1)
        self.assertEqual(data["device"]["mac"], MAC1)
        self.assertEqual(data["device"]["baseline"], 1)
        self.assertNotEqual(data["device"]["first_seen"], 1)
        self.assertIsNone(self.db.device(UNKNOWN))

    def test_name_truncated_to_80_and_note_to_1000(self):
        status, data, _ = self.post(MAC1, {"name": "n" * 200, "note": "x" * 5000})
        self.assertEqual(status, 200)
        self.assertEqual(len(data["device"]["name"]), 80)
        self.assertEqual(len(data["device"]["note"]), 1000)
        self.assertEqual(len(self.db.device(MAC1)["name"]), 80)
        self.assertEqual(len(self.db.device(MAC1)["note"]), 1000)
        # exactly at the limit is kept whole
        status, data, _ = self.post(MAC1, {"name": "m" * 80, "note": "y" * 1000})
        self.assertEqual(len(data["device"]["name"]), 80)
        self.assertEqual(len(data["device"]["note"]), 1000)

    def test_html_in_name_stored_verbatim_and_json_escaped_in_response(self):
        evil = '<script>alert("x")</script><img src=x onerror="alert(1)">'
        status, data, hdrs = self.post(MAC1, {"name": evil, "note": "a\\b\"c\n<b>"})
        self.assertEqual(status, 200)
        self.assertEqual(data["device"]["name"], evil)
        self.assertEqual(data["device"]["note"], "a\\b\"c\n<b>")
        self.assertEqual(self.db.device(MAC1)["name"], evil)  # verbatim in the DB
        # the raw body is valid JSON with the quotes/backslashes/newline escaped and served as JSON, never as HTML
        _, headers, raw = self.req("GET", f"/api/devices/{MAC1}")
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn(b'alert(\\"x\\")', raw)
        self.assertIn(b'a\\\\b\\"c\\n<b>', raw)
        self.assertEqual(json.loads(raw)["device"]["name"], evil)

    def test_wrong_types_are_400(self):
        for payload, msg in [
            ({"acked": "yes"}, "acked must be boolean"),
            ({"acked": 1}, "acked must be boolean"),
            ({"acked": 0}, "acked must be boolean"),
            ({"name": 5}, "name must be a string"),
            ({"name": ["a"]}, "name must be a string"),
            ({"note": {"a": 1}}, "note must be a string"),
            ({"note": 1.5}, "note must be a string"),
            ({"acked": True, "name": 1}, "name must be a string"),
        ]:
            status, data, _ = self.post(MAC1, payload)
            self.assertEqual(status, 400, payload)
            self.assertEqual(data["error"], msg, payload)
        self.assertEqual(self.db.device(MAC1)["acked"], 0)
        self.assertEqual(self.db.device(MAC1)["name"], "")

    def test_non_object_json_is_400(self):
        for raw in (b"[1,2]", b'"str"', b"1", b"true", b"null"):
            status, data, _ = self.post(MAC1, None, raw=raw)
            self.assertEqual(status, 400, raw)
            self.assertEqual(data["error"], "bad json", raw)

    def test_invalid_json_is_400(self):
        for raw in (b"{", b"{'acked': true}", b"acked=true", b"\xff\xfe{}", b"{\"acked\": tru}"):
            status, data, _ = self.post(MAC1, None, raw=raw)
            self.assertEqual(status, 400, raw)
            self.assertEqual(data["error"], "bad json", raw)

    def test_empty_body_is_400(self):
        status, data, _ = self.post(MAC1, None, raw=b"")
        self.assertEqual(status, 400)
        self.assertEqual(data["error"], "bad body")
        status, hdrs, body = self.req("POST", f"/api/devices/{MAC1}", body=None, headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)

    def test_non_json_content_type_is_415(self):
        for ctype in ("text/plain", "application/x-www-form-urlencoded", "application/xml", "text/json"):
            status, data, _ = self.post(MAC1, None, ctype=ctype, raw=b'{"acked": true}')
            self.assertEqual(status, 415, ctype)
            self.assertEqual(data["error"], "json only")
        status, data, _ = self.post(MAC1, None, ctype=None, raw=b'{"acked": true}')
        self.assertEqual(status, 415, "missing Content-Type")
        self.assertEqual(self.db.device(MAC1)["acked"], 0)

    def test_json_content_type_with_charset_is_accepted(self):
        status, data, _ = self.post(MAC1, None, ctype="application/json; charset=utf-8", raw=b'{"acked": true}')
        self.assertEqual(status, 200)
        self.assertEqual(data["device"]["acked"], 1)

    def test_body_over_16k_is_400_and_exactly_16k_is_accepted(self):
        big = json.dumps({"acked": True, "pad": "x" * (MAX_BODY + 1)}).encode()
        self.assertGreater(len(big), MAX_BODY)
        status, data, _ = self.post(MAC1, None, raw=big)
        self.assertEqual(status, 400)
        self.assertEqual(data["error"], "bad body")
        self.assertEqual(self.db.device(MAC1)["acked"], 0)

        prefix = b'{"acked": true, "pad": "'
        suffix = b'"}'
        exact = prefix + b"y" * (MAX_BODY - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(exact), MAX_BODY)
        status, data, _ = self.post(MAC1, None, raw=exact)
        self.assertEqual(status, 200)
        self.assertEqual(data["device"]["acked"], 1)

    def test_unknown_mac_is_404(self):
        status, data, _ = self.post(UNKNOWN, {"acked": True})
        self.assertEqual(status, 404)
        self.assertEqual(data["error"], "unknown device")
        self.assertIsNone(self.db.device(UNKNOWN))

    def test_bad_mac_formats(self):
        # 17 chars of [0-9a-f:] but not a MAC: passes the route regex, fails MAC_RE -> 400
        status, data, _ = self.post("aabbccddeeff:::::", {"acked": True})
        self.assertEqual(status, 400)
        self.assertEqual(data["error"], "bad mac")
        for mac in ("aa:bb:cc:dd:ee", "aa-bb-cc-dd-ee-01", "aabbccddee01", "aa:bb:cc:dd:ee:0g", "x"):
            status, data, _ = self.post(mac, {"acked": True})
            self.assertEqual(status, 404, mac)
        self.assertEqual(sum(d["acked"] for d in self.db.devices()), 0)

    def test_post_to_other_paths_is_404(self):
        for path in ("/", "/api/devices", "/api/stats", "/api/events", "/healthz", "/static/app.js", "/api/devices.csv"):
            status, headers, body = self.req("POST", path, body=b'{"acked": true}', headers={"Content-Type": "application/json"})
            self.assertEqual(status, 404, path)
            self.assertEqual(json.loads(body)["error"], "not found", path)

    def test_non_numeric_content_length_is_400(self):
        raw = (f"POST /api/devices/{MAC1} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
               f"Content-Length: abc\r\n\r\n").encode()
        resp = self.raw_request(raw)
        self.assertTrue(resp.startswith(b"HTTP/1."), f"server dropped the connection without a response: {resp[:80]!r}")
        self.assertIn(b" 400 ", resp.split(b"\r\n", 1)[0])
        self.assertEqual(self.db.device(MAC1)["acked"], 0)

    def test_negative_content_length_is_400(self):
        raw = (f"POST /api/devices/{MAC1} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
               f"Content-Length: -5\r\n\r\n").encode()
        resp = self.raw_request(raw)
        self.assertIn(b" 400 ", resp.split(b"\r\n", 1)[0])

    def test_unsupported_methods_are_405_with_allow(self):
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            for path in ("/api/devices", f"/api/devices/{MAC1}"):
                status, hdrs, _ = self.req(method, path, body=b"{}", headers={"Content-Type": "application/json"})
                self.assertEqual(status, 405, (method, path)); self.assertEqual(hdrs.get("Allow"), "GET, HEAD, POST", (method, path))
            self.assertEqual(self.db.device(MAC1)["acked"], 0)


# ----------------------------------------------------------------------------
class HeaderTests(WebTestCase):
    def test_head_root_has_headers_and_no_body(self):
        g_status, g_headers, g_body = self.req("GET", "/")
        status, headers, body = self.req("HEAD", "/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(int(headers["Content-Length"]), len(g_body))
        self.assertEqual(headers["Content-Type"], g_headers["Content-Type"])

    def test_head_api_and_404(self):
        status, headers, body = self.req("HEAD", "/api/devices")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertGreater(int(headers["Content-Length"]), 2)
        status, headers, body = self.req("HEAD", "/api/devices.csv")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        status, _, body = self.req("HEAD", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body, b"")

    def test_security_headers_on_every_response(self):
        for path, expect in (("/", 200), ("/static/app.js", 200), ("/api/devices", 200), ("/api/stats", 200),
                             ("/api/events", 200), ("/api/devices.csv", 200), ("/healthz", 200),
                             (f"/api/devices/{MAC1}", 200), (f"/api/devices/{UNKNOWN}", 404), ("/nope", 404)):
            status, headers, _ = self.req("GET", path)
            self.assertEqual(status, expect, path)
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff", path)
            self.assertEqual(headers["X-Frame-Options"], "DENY", path)
            self.assertEqual(headers["Referrer-Policy"], "no-referrer", path)
        status, headers, _ = self.req("POST", f"/api/devices/{MAC1}", body=b'{"acked": true}', headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_api_responses_are_no_store(self):
        for path in ("/api/devices", "/api/stats", "/api/events", "/api/devices.csv", "/healthz", f"/api/devices/{MAC1}", "/nope"):
            _, headers, _ = self.req("GET", path)
            values = headers.get_all("Cache-Control")
            self.assertEqual(values, ["no-store"], f"{path}: {values}")

    def test_static_responses_have_a_single_cache_control_header(self):
        for path in ("/", "/static/style.css", "/static/app.js", "/static/favicon.svg"):
            _, headers, _ = self.req("GET", path)
            values = headers.get_all("Cache-Control")
            self.assertEqual(len(values), 1, f"{path}: duplicate Cache-Control headers {values}")
            self.assertIn(values[0], ("no-cache", "no-store"), path)

    def test_server_header_does_not_leak_python_version(self):
        _, headers, _ = self.req("GET", "/")
        self.assertEqual(headers["Server"].strip(), "leasewatch")


# ----------------------------------------------------------------------------
class ConcurrencyTests(WebTestCase):
    def test_parallel_reads_and_acks_produce_no_500s(self):
        results = []
        errors = []
        lock = threading.Lock()
        start = threading.Barrier(25)

        def reader(n):
            start.wait()
            for _ in range(n):
                try:
                    status, _, body = self.req("GET", "/api/devices")
                    json.loads(body)
                    with lock:
                        results.append(status)
                except Exception as e:  # noqa: BLE001
                    with lock:
                        errors.append(repr(e))

        def acker(mac, n):
            start.wait()
            for i in range(n):
                try:
                    status, _, body = self.req("POST", f"/api/devices/{mac}", body=json.dumps({"acked": i % 2 == 0, "note": f"n{i}"}).encode(),
                                               headers={"Content-Type": "application/json"})
                    json.loads(body)
                    with lock:
                        results.append(status)
                except Exception as e:  # noqa: BLE001
                    with lock:
                        errors.append(repr(e))

        threads = [threading.Thread(target=reader, args=(15,)) for _ in range(20)]
        threads += [threading.Thread(target=acker, args=((MAC1, MAC2, MAC3)[i % 3], 10)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 20 * 15 + 5 * 10)
        self.assertEqual([s for s in results if s >= 500], [])
        self.assertEqual(set(results), {200})
        # the DB is consistent afterwards and still answers
        data, _ = self.get_json("/api/devices")
        self.assertEqual(len(data["devices"]), 3)
        acked_events = [e for e in self.db.events(limit=1000) if e["kind"] in ("acked", "unacked")]
        self.assertGreater(len(acked_events), 0)


# ----------------------------------------------------------------------------
class BugRegressionTests(unittest.TestCase):
    """Regression tests for fixed server bugs (STATIC_DIR normalisation, listen backlog)."""

    def test_static_dir_is_normalised(self):
        # web.STATIC_DIR is built with realpath. Imported through a path such as "<repo>/tests/../leasewatch" a plain
        # join would keep the "/../", and _static()'s guard `normpath(join(STATIC_DIR, name)).startswith(STATIC_DIR + os.sep)`
        # would then be false for every file -> "/", /static/style.css, /static/app.js, /static/favicon.svg all 404.
        code = ("import os, sys\n"
                "sys.path.insert(0, os.path.join('tests', '..'))\n"
                "from leasewatch import web\n"
                "p = os.path.normpath(os.path.join(web.STATIC_DIR, 'style.css'))\n"
                "print(web.STATIC_DIR)\n"
                "print(int(p.startswith(web.STATIC_DIR + os.sep)))\n")
        out = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        static_dir, guard_ok = out.stdout.strip().splitlines()
        self.assertEqual(static_dir, os.path.normpath(static_dir), "web.STATIC_DIR is not normalised (contains /../)")
        self.assertEqual(guard_ok, "1", f"_static() guard rejects its own static dir {static_dir}")

    def test_listen_backlog_absorbs_a_burst_of_clients(self):
        # web.Server sets request_queue_size = 128. With socketserver's default listen(2) backlog of 5, only backlog+1
        # handshakes complete while the accept loop is busy; the rest are dropped by the kernel (TcpExt ListenOverflows)
        # and a bursty client sees ECONNRESET or a SYN-retransmit stall. Deterministic check: the accept loop is
        # deliberately not started, 16 clients connect with a short timeout, and all must complete the handshake.
        tmp = tempfile.TemporaryDirectory()
        saved = dict(os.environ)
        try:
            os.environ.update(ENV)
            os.environ["DATA_DIR"] = tmp.name
            cfg = Config()
            db = Database(cfg.db_path)
            srv = serve(cfg, db, VERSION)
            port = srv.server_address[1]
            socks, connected = [], 0
            try:
                for _ in range(16):
                    s = socket.socket()
                    s.settimeout(0.25)
                    socks.append(s)
                    try:
                        s.connect(("127.0.0.1", port))
                        connected += 1
                    except OSError:
                        pass
            finally:
                for s in socks:
                    s.close()
                srv.server_close()
                db._conn.close()
            self.assertEqual(connected, 16,
                             f"only {connected}/16 clients could connect: listen backlog is {srv.request_queue_size}")
        finally:
            os.environ.clear()
            os.environ.update(saved)
            tmp.cleanup()


class ReleaseReviewTests(WebTestCase):
    def test_text_plain_with_json_suffix_is_rejected(self):
        st, body, _ = self.post(MAC2, {"note": "x"}, ctype="text/plain;application/json")
        self.assertEqual(st, 415, body)

    def test_cross_site_fetch_is_rejected(self):
        st, _, data = self.req("POST", f"/api/devices/{MAC2}", body=b'{"note":"x"}', headers={"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(st, 403, data)
        st, _, _ = self.req("POST", f"/api/devices/{MAC2}", body=b'{"note":"x"}', headers={"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(st, 200)

    def test_control_and_bidi_characters_are_stripped(self):
        st, body, _ = self.post(MAC2, {"name": "a\u0000b\u202ec", "note": "l1\nl2\u0007"})
        self.assertEqual(st, 200, body)
        self.assertEqual(body["device"]["name"], "abc"); self.assertEqual(body["device"]["note"], "l1\nl2")

    def test_unknown_host_header_is_421(self):
        # DNS rebinding: a browser page at evil.example whose name now resolves to this server sends Host: evil.example
        for path, method, body in (("/api/devices", "GET", None), (f"/api/devices/{MAC2}", "POST", b'{"acked":true}'), ("/", "GET", None)):
            st, hdrs, data = self.req(method, path, body=body, headers={"Host": "evil.example", "Content-Type": "application/json"})
            self.assertEqual(st, 421, (path, data)); self.assertEqual(json.loads(data)["error"][:12], "unknown Host")
        self.assertEqual(self.db.device(MAC2)["acked"], 0)
        for host in ("127.0.0.1:%d" % self.port, "localhost", "[::1]:8080"):
            st, _, _ = self.req("GET", "/api/stats", headers={"Host": host}); self.assertEqual(st, 200, host)
        self.cfg.allowed_hosts = ("leases.example.lan",)
        st, _, _ = self.req("GET", "/api/stats", headers={"Host": "leases.example.lan"}); self.assertEqual(st, 200)
        st, _, _ = self.req("GET", "/api/stats", headers={"Host": "other.example.lan"}); self.assertEqual(st, 421)



class QaFixTests(WebTestCase):
    def test_deeply_nested_json_is_400(self):
        status, data, _ = self.post(MAC1, None, raw=b"[" * 16000)
        self.assertEqual(status, 400); self.assertEqual(data["error"], "bad json")

    def test_lone_surrogate_name_is_400(self):
        for field in ("name", "note"):
            status, data, _ = self.post(MAC1, None, raw=('{"%s": "\\ud800"}' % field).encode())
            self.assertEqual(status, 400, field); self.assertEqual(data["error"], "bad json", field)
        self.assertEqual(self.db.device(MAC1)["name"], "")

    def test_stdlib_errors_are_json_with_security_headers(self):
        raw = self.raw_request(b"TRACE / HTTP/1.0\r\n\r\n")
        head, _, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.0 501"), head)
        self.assertIn(b"X-Content-Type-Options: nosniff", head); self.assertIn(b"X-Frame-Options: DENY", head)
        self.assertIn(b"Content-Type: application/json", head)
        self.assertIn("error", json.loads(body))

    def test_site_name_with_version_placeholder_stays_literal(self):
        self.cfg.site_name = "A{{VERSION}}B"
        st, _, body = self.req("GET", "/")
        self.assertEqual(st, 200); self.assertIn(b"A{{VERSION}}B", body)

    def test_connector_labels(self):
        # legacy variables: the switch's SNMP_NAME and "Wi-Fi" as dot text, the instance name stays in "name"
        self.cfg.snmp_host, self.cfg.snmp_auth_key, self.cfg.snmp_priv_key, self.cfg.snmp_name = "10.0.0.2", "a" * 8, "p" * 8, "sw-rack"
        self.cfg.unifi_url, self.cfg.unifi_user, self.cfg.unifi_password = "https://unifi.example.lan", "ro", "pw"
        conns = self.get_json("/api/status")[0]["meta"]["connectors"]
        self.assertEqual([(c["name"], c["label"]) for c in conns], [("fw1", "fw1"), ("switch", "sw-rack"), ("unifi", "Wi-Fi")])
        # LW_CONNECTORS: NAME when set, else the instance name
        self.cfg.connector_specs = [InstanceSpec("fw2", "opnsense", {}), InstanceSpec("sw-a", "snmp_switch", {"name": "ap-hall-sw"}),
                                    InstanceSpec("sw-b", "snmp_switch", {}), InstanceSpec("wifi", "unifi", {})]
        conns = self.get_json("/api/status")[0]["meta"]["connectors"]
        self.assertEqual([(c["name"], c["label"]) for c in conns],
                         [("fw2", "fw2"), ("sw-a", "ap-hall-sw"), ("sw-b", "sw-b"), ("wifi", "Wi-Fi")])

    def test_port_in_use_exits_2_without_traceback(self):
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 0)); busy.listen(1)
            env = dict(os.environ, LISTEN_PORT=str(busy.getsockname()[1]), FW1_URL="http://127.0.0.1:9", DATA_DIR=self.tmp.name,
                       PYTHONPATH=REPO)
            out = subprocess.run([sys.executable, "-m", "leasewatch"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("cannot listen", out.stderr); self.assertNotIn("Traceback", out.stderr)

if __name__ == "__main__":
    unittest.main()
