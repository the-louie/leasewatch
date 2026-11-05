import json, os, socket, sys, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore
from leasewatch import fw1, notify, unifi
from leasewatch.config import Config
from leasewatch.fw1 import Fw1Client, Fw1Error, kea_leases
from leasewatch.unifi import UnifiClient, parse_clients


class Stub:
    """A local HTTP server; `routes` maps a path to (status, headers, body bytes). Records every request."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requests = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def _answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                stub.requests.append((self.command, self.path, dict(self.headers), self.rfile.read(n)))
                status, headers, body = stub.routes.get(self.path.split("?")[0], (404, {}, b"{}"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = _answer

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


LEASES = "/api/dhcpv4/leases/searchLease"
ARP = "/api/diagnostics/interface/get_arp"


def js(o):
    return (200, {"Content-Type": "application/json"}, json.dumps(o).encode())


class StubCase(unittest.TestCase):
    def setUp(self):
        self.stubs = []
        # Config(...) still reads every field not passed explicitly from the environment
        self._env = clean_env()

    def tearDown(self):
        for s in self.stubs:
            s.close()
        restore(self._env)

    def stub(self, routes=None):
        s = Stub(routes)
        self.stubs.append(s)
        return s


class Fw1HttpTests(StubCase):
    def client(self, stub):
        return Fw1Client(stub.url, "k", "s", verify_tls=False, timeout=5)

    def test_redirect_is_not_followed(self):
        target = self.stub({LEASES: js({"rows": []})})
        fw = self.stub({LEASES: (302, {"Location": target.url + LEASES}, b"")})
        with self.assertRaises(Fw1Error) as cm:
            self.client(fw).leases_raw()
        self.assertIn("HTTP 302", str(cm.exception))
        self.assertEqual(target.requests, [])  # the auth header never left for the redirect target

    def test_bad_fw1_url_is_fw1error(self):
        with self.assertRaises(Fw1Error) as cm:
            Fw1Client("https://[fe80::1", "k", "s", verify_tls=False, timeout=5).arp_raw()
        self.assertIn("bad FW1_URL", str(cm.exception))

    def test_non_utf8_body_is_fw1error(self):
        fw = self.stub({ARP: (200, {}, b"\xff\xfe[]")})
        with self.assertRaises(Fw1Error):
            self.client(fw).arp_raw()

    def test_deeply_nested_json_is_fw1error(self):
        fw = self.stub({ARP: (200, {}, b"[" * 200_000)})
        with self.assertRaises(Fw1Error):
            self.client(fw).arp_raw()

    def test_oversized_body_is_fw1error(self):
        fw = self.stub({ARP: (200, {}, b"[" + b" " * 64 + b"]")})
        with mock.patch.object(fw1, "MAX_BODY", 32):
            with self.assertRaises(Fw1Error) as cm:
                self.client(fw).arp_raw()
        self.assertIn("too large", str(cm.exception))

    def test_odd_field_types_do_not_crash(self):
        leases = {"rows": [
            {"mac": "02:00:00:00:00:01", "address": "10.0.1.5", "hostname": None, "man": None, "if": "opt1", "if_descr": 123,
             "type": "dynamic", "status": "online"},
            "not-a-row",
            {"mac": "02:00:00:00:00:02", "address": "10.0.1.6", "hostname": "ap-hall", "if": "opt1", "if_descr": "HomeNet"},
        ]}
        arp = [42, {"mac": "02:00:00:00:00:03", "ip": "10.0.1.7", "intf": "igc1", "intf_description": None, "hostname": None}]
        fw = self.stub({LEASES: js(leases), ARP: js(arp)})
        out, stats = self.client(fw).sightings(ignore_interfaces=(7, "wan"))
        by = {s.mac: s for s in out}
        self.assertEqual(sorted(by), ["02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"])
        self.assertEqual(by["02:00:00:00:00:01"].vlan, "123")
        self.assertEqual(by["02:00:00:00:00:01"].hostname, "")
        self.assertEqual(by["02:00:00:00:00:02"].hostname, "ap-hall")
        self.assertEqual(by["02:00:00:00:00:03"].vlan, "igc1")
        self.assertEqual(stats, {"leases": 3, "arp": 2})

    def test_remaining_type_errors_become_fw1error(self):
        # _s covers the known fields; simulate a type error it does not cover to check the safety net
        fw = self.stub({LEASES: js({"rows": []}), ARP: js([{"mac": "02:00:00:00:00:09"}])})
        with mock.patch.object(fw1, "_s", side_effect=TypeError("boom")):
            with self.assertRaises(Fw1Error) as cm:
                self.client(fw).sightings()
        self.assertIn("unexpected field type", str(cm.exception))

    def test_lease_type_is_normalised(self):
        leases = {"rows": [
            {"mac": "02:00:00:00:00:0a", "address": "10.0.1.10", "if": "opt1", "if_descr": "HomeNet", "type": "Static"},
            {"mac": "02:00:00:00:00:0b", "address": "10.0.1.11", "if": "opt1", "if_descr": "HomeNet", "type": "weird"},
        ]}
        fw = self.stub({LEASES: js(leases), ARP: js([])})
        by = {s.mac: s for s in self.client(fw).sightings()[0]}
        self.assertEqual(by["02:00:00:00:00:0a"].lease_type, "static")
        self.assertEqual(by["02:00:00:00:00:0b"].lease_type, "dynamic")

    def test_kea_null_state_is_not_active(self):
        self.assertEqual(kea_leases([{"hwaddr": "02:00:00:00:00:04", "state": None}]), [])
        self.assertEqual(len(kea_leases([{"hwaddr": "02:00:00:00:00:04", "state": 0, "if_descr": 5}])), 1)


def unifi_cfg(url):
    return Config(unifi_url=url, unifi_user="ro", unifi_password="pw", unifi_verify_tls=False)


STA = "/api/s/default/stat/sta"
DEV = "/api/s/default/stat/device"
OK = {"meta": {"rc": "ok"}, "data": []}


class UnifiTests(StubCase):
    def test_login_redirect_is_not_followed(self):
        target = self.stub({"/api/login": js(OK)})
        ctl = self.stub({"/api/login": (302, {"Location": target.url + "/api/login"}, b"")})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: HTTP 302")
        self.assertEqual(target.requests, [])

    def test_device_without_mac_does_not_name_every_ap(self):
        sta = [{"mac": "02:00:00:00:00:05", "essid": "HomeNet", "ap_mac": ""}]
        devices = [{"mac": "", "name": "ap-hall"}, {"mac": "02:00:00:00:00:aa", "name": "ap-kitchen"}]
        self.assertEqual(parse_clients(sta, devices)["02:00:00:00:00:05"].ap, "")

    def test_api_error_rc(self):
        ctl = self.stub({"/api/login": js(OK), STA: js({"meta": {"rc": "error", "msg": "api.err.NoSiteContext"}, "data": []})})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: api.err.NoSiteContext")

    def test_data_not_a_list(self):
        ctl = self.stub({"/api/login": js(OK), STA: js({"meta": {"rc": "ok"}, "data": {"x": 1}})})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: unexpected response shape")

    def test_odd_rows_become_runtimeerror(self):
        ctl = self.stub({"/api/login": js(OK), STA: js({"data": ["not-a-dict"]}), DEV: js(OK)})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: unexpected response")

    def test_invalid_url_does_not_echo_credentials(self):
        cfg = unifi_cfg("http://admin:hunter2@127.0.0.1:notaport")
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(cfg).clients()
        self.assertNotIn("hunter2", str(cm.exception))

    def test_deeply_nested_json_is_runtimeerror(self):
        ctl = self.stub({"/api/login": js(OK), STA: (200, {}, b"[" * 200_000)})
        with self.assertRaises(RuntimeError) as cm:
            UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: unexpected response")

    def test_oversized_body_is_runtimeerror(self):
        ctl = self.stub({"/api/login": js(OK), STA: (200, {}, b'{"data": []' + b" " * 64 + b"}")})
        with mock.patch.object(unifi, "MAX_BODY", 32):
            with self.assertRaises(RuntimeError) as cm:
                UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(str(cm.exception), "unifi: response too large")

    def test_happy_path(self):
        sta = {"data": [{"mac": "02:00:00:00:00:06", "essid": "HomeNet", "ap_mac": "02:00:00:00:00:aa", "signal": -60}]}
        ctl = self.stub({"/api/login": js(OK), STA: js(sta), DEV: js({"data": [{"mac": "02:00:00:00:00:aa", "name": "ap-hall"}]})})
        out = UnifiClient(unifi_cfg(ctl.url)).clients()
        self.assertEqual(out["02:00:00:00:00:06"].ap, "ap-hall")


DEVICE = {"ip": "10.0.1.8", "mac": "02:00:00:00:00:07", "hostname": "evil\r\nBcc: x@example.com", "vendor": "",
          "vlan": "HomeNet", "lease_type": "dynamic"}


def mail_cfg(base):
    return Config(mailgun_key="key", mailgun_domain="mg.example.com", mail_to="you@example.com", mailgun_api_base=base)


class NotifyTests(StubCase):
    def test_http_error_is_mailerror(self):
        mg = self.stub({"/v3/mg.example.com/messages": (401, {}, b"Forbidden")})
        with self.assertRaises(notify.MailError) as cm:
            notify.new_devices(mail_cfg(mg.url), [DEVICE])
        self.assertEqual(str(cm.exception), "mailgun: HTTP 401")

    def test_connection_error_is_mailerror(self):
        mg = self.stub()
        url = mg.url
        mg.close(); self.stubs.remove(mg)
        with self.assertRaises(notify.MailError):
            notify.new_devices(mail_cfg(url), [DEVICE])

    def test_malformed_status_line_is_mailerror(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        self.addCleanup(srv.close)

        def answer():
            conn, _ = srv.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(b"garbage\r\n\r\n")
        t = threading.Thread(target=answer, daemon=True); t.start()
        with self.assertRaises(notify.MailError) as cm:
            notify.new_devices(mail_cfg(f"http://127.0.0.1:{srv.getsockname()[1]}"), [DEVICE])
        t.join(5)
        self.assertEqual(str(cm.exception), "mailgun: bad response")

    def test_bad_api_base_is_mailerror_without_url(self):
        with self.assertRaises(notify.MailError) as cm:
            notify.new_devices(mail_cfg("api.eu.mailgun.net"), [DEVICE])
        self.assertEqual(str(cm.exception), "mailgun: bad MAILGUN_API_BASE")

    def test_subject_is_sanitised_and_base_url_used(self):
        mg = self.stub({"/v3/mg.example.com/messages": js({"id": "x"})})
        notify.new_devices(mail_cfg(mg.url), [DEVICE])
        self.assertEqual(len(mg.requests), 1)
        from urllib.parse import parse_qs
        form = parse_qs(mg.requests[0][3].decode())
        subject = form["subject"][0]
        self.assertNotIn("\r", subject); self.assertNotIn("\n", subject)
        self.assertIn("evil  Bcc: x@example.com", subject)


class ProxyTests(StubCase):
    """LAN clients must not send the firewall/UniFi credentials through an http(s)_proxy unless PROXY_FOR_LAN is set."""
    PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY")

    def setUp(self):
        super().setUp()
        for k in self.PROXY_VARS:
            os.environ.pop(k, None)
        self.fw = self.stub({LEASES: js({"rows": [], "total": 0})})
        self.proxy = self.stub()
        # urllib reads the proxy settings when the opener is built, so they are set before the client exists
        os.environ["http_proxy"] = os.environ["https_proxy"] = self.proxy.url

    def test_fw1_ignores_env_proxy_by_default(self):
        Fw1Client(self.fw.url, "k", "s", timeout=5).leases_raw()
        self.assertEqual(self.proxy.requests, [])
        self.assertEqual([r[1] for r in self.fw.requests], [LEASES])

    def test_fw1_uses_env_proxy_when_asked(self):
        with self.assertRaises(Fw1Error):  # the proxy stub answers 404
            Fw1Client(self.fw.url, "k", "s", timeout=5, use_env_proxy=True).leases_raw()
        self.assertEqual(self.fw.requests, [])
        self.assertEqual([r[1] for r in self.proxy.requests], [self.fw.url + LEASES])

    def test_unifi_ignores_env_proxy_by_default(self):
        ctl = self.stub({"/api/login": js(OK), STA: js(OK), DEV: js(OK)})
        self.assertEqual(UnifiClient(unifi_cfg(ctl.url)).clients(), {})
        self.assertEqual(self.proxy.requests, [])


if __name__ == "__main__":
    unittest.main()
