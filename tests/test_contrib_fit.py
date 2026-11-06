"""The contrib connectors (dnsmasq_leases, mikrotik) inside the real Collector, web handler included.

Each test sets LW_CONNECTORS_DIR to the repository's contrib/ directory, so the real loader imports both packages
through the entry points in their pyproject.toml; nothing patches the registry. Synthetic data only; the RouterOS
REST API is a local stub on port 0, reached over plain HTTP through the host's opener_factory hook.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _contrib import CONTRIB  # noqa: E402
from _env import FW1_ENV, clean_env, restore  # noqa: E402

from leasewatch.collector import Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.connectors import _reset_registry, load_problems, registry, type_origins  # noqa: E402
from leasewatch.db import Database  # noqa: E402
from leasewatch.fw1 import Sighting as Fw1Sighting  # noqa: E402
from leasewatch.web import serve  # noqa: E402

MAC_FW = "02:00:00:00:00:01"      # on the firewall's ARP table and in the leases file
MAC_LEASE = "02:00:00:00:00:02"   # only in the leases file
MAC_MT = "02:00:00:00:00:03"      # MikroTik: static lease and ARP entry
MAC_MT_DYN = "02:00:00:00:00:04"  # MikroTik: dynamic lease, not in ARP
USER, PASSWORD = "lw-reader", "s3cr3t-Pa55word"
MAIL = {"MAILGUN_KEY": "mg-key", "MAILGUN_DOMAIN": "example.com", "MAIL_TO": "ops@example.com"}


class FakeFwClient:
    """The firewall client the opnsense connector wraps: one ARP row."""

    def sightings(self, ignore=()):
        row = Fw1Sighting(mac=MAC_FW, ip="10.0.0.5", hostname="", vendor="", vlan="LAN", iface="lan", source="arp",
                          lease_type="", online=True)
        return [row], {"leases": 0, "arp": 1}


class _PlainHttps(urllib.request.HTTPHandler):
    """Sends an https:// request over plain HTTP: the stub router has no TLS, the connector insists on https."""

    def https_open(self, req):
        return self.do_open(http.client.HTTPConnection, req)

    https_request = urllib.request.AbstractHTTPHandler.do_request_


def plain_opener(verify_tls: bool = True, use_env_proxy: bool = False) -> urllib.request.OpenerDirector:
    o = urllib.request.OpenerDirector()
    for h in (_PlainHttps(), urllib.request.HTTPErrorProcessor(), urllib.request.HTTPDefaultErrorHandler()):
        o.add_handler(h)
    return o


class RouterStub:
    """A RouterOS 7 REST API on 127.0.0.1:<port 0>. `data` is read per request; `deny` answers 401 to everything,
    with an error body that echoes the password and the router's address."""

    def __init__(self) -> None:
        self.deny = False
        self.data = {
            "/rest/ip/dhcp-server": [{"name": "dhcp-lan", "interface": "bridge-lan"}],
            "/rest/ip/dhcp-server/lease": [
                {"address": "10.0.0.10", "mac-address": MAC_MT.upper(), "server": "dhcp-lan", "status": "bound",
                 "dynamic": "false", "disabled": "false", "host-name": "alex-ipad"},
                {"address": "10.0.0.20", "mac-address": MAC_MT_DYN, "server": "dhcp-lan", "status": "bound",
                 "dynamic": "true", "host-name": "printer"}],
            "/rest/ip/arp": [{"address": "10.0.0.10", "mac-address": MAC_MT.upper(), "interface": "bridge-lan",
                              "complete": "true", "invalid": "false", "disabled": "false", "status": "reachable"}],
            "/rest/system/resource": {"version": "7.16"},
        }
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                token = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
                if stub.deny or self.headers.get("Authorization") != f"Basic {token}":
                    body = {"error": 401, "message": "Unauthorized",
                            "detail": f"login {PASSWORD} from 127.0.0.1:{stub.port} refused"}
                    return self._send(401, body)
                if path not in stub.data:
                    return self._send(404, {"error": 404, "message": "Not Found"})
                return self._send(200, stub.data[path])

            def _send(self, code: int, obj: object) -> None:
                raw = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args: object) -> None:
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(5)


class ContribFitBase(unittest.TestCase):
    def setUp(self) -> None:
        # LW_CONNECTORS_DIR stays set for the whole test: the collector looks the types up in registry() on every
        # poll, and a changed value rebuilds it. The environment and the registry (a process global, whose
        # contrib modules sit in sys.modules) are restored in the cleanup.
        saved = clean_env({"LW_CONNECTORS_DIR": CONTRIB})
        self.addCleanup(_reset_registry)
        self.addCleanup(restore, saved)
        self.assertEqual(load_problems(), [])
        reg = registry()
        self.assertEqual((reg["dnsmasq_leases"].__module__, reg["mikrotik"].__module__),
                         ("leasewatch_dnsmasq.connector", "leasewatch_mikrotik.connector"))
        self.assertEqual({t: (o.kind, o.entry) for t, o in type_origins().items() if t in ("dnsmasq_leases", "mikrotik")},
                         {"dnsmasq_leases": ("LW_CONNECTORS_DIR", "leasewatch-dnsmasq"),
                          "mikrotik": ("LW_CONNECTORS_DIR", "leasewatch-mikrotik")})
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.leases = os.path.join(self.tmp, "dnsmasq.leases")
        self.router: RouterStub | None = None

    def stub(self) -> RouterStub:
        self.router = RouterStub()
        self.addCleanup(self.router.close)
        return self.router

    def dnsmasq_env(self) -> dict:
        return {"LW_CONNECTOR__DHCP1__TYPE": "dnsmasq_leases", "LW_CONNECTOR__DHCP1__PATH": self.leases,
                "LW_CONNECTOR__DHCP1__NETWORK": "LAN"}

    def mikrotik_env(self) -> dict:
        return {"LW_CONNECTOR__MT1__TYPE": "mikrotik", "LW_CONNECTOR__MT1__URL": self.router.url,
                "LW_CONNECTOR__MT1__USER": USER, "LW_CONNECTOR__MT1__PASSWORD": PASSWORD}

    def collector(self, env: dict) -> tuple[Collector, Database]:
        saved = clean_env({"DATA_DIR": self.tmp, "POLL_SECONDS": "15", "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0",
                           "LW_CONNECTORS_DIR": CONTRIB, **env})
        try:
            cfg = Config()
        finally:
            restore(saved)
        # port 0 (an ephemeral port for the web test) is the one setting the startup check refuses
        self.assertEqual([p for p in cfg.validate() if p != "LISTEN_PORT must be 1-65535"], [])
        db = Database(cfg.db_path)
        self.addCleanup(db._conn.close)
        col = Collector(cfg, db, FakeFwClient() if "fw1" in [s.name for s in cfg.instances] else None)
        if "mt1" in col._connectors:
            conn = col._connectors["mt1"]
            conn.ctx = replace(conn.ctx, opener_factory=plain_opener)
        return col, db

    def write_leases(self) -> None:
        exp = int(time.time()) + 86400
        with open(self.leases, "w") as f:
            f.write(f"{exp} {MAC_FW} 10.0.0.5 alex-laptop 01:{MAC_FW}\n"
                    f"0 {MAC_LEASE.upper()} 10.0.0.6 alex-phone *\n")

    @staticmethod
    def device(db: Database, mac: str) -> dict:
        return dict(db.q("SELECT * FROM devices WHERE mac=?", (mac,))[0])


class DnsmasqWithFirewallTest(ContribFitBase):
    def test_baseline_waits_for_the_leases_file(self) -> None:
        col, db = self.collector({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **self.dnsmasq_env(), **MAIL})
        with mock.patch("leasewatch.collector.notify.new_devices") as mail:
            with self.assertLogs("leasewatch.collector", "WARNING") as logs:
                r = col.run_once()
            self.assertTrue(r["ok"])
            self.assertTrue(any("baseline held back until dhcp1" in line for line in logs.output))
            self.assertEqual(db.get_meta("conn.dhcp1.error"), "check failed: PATH: not found")
            self.assertNotIn(self.tmp, db.get_meta("conn.dhcp1.error"))
            self.assertNotEqual(db.get_meta("first_run_done", ""), "1")
            self.assertEqual(self.device(db, MAC_FW)["baseline"], 1)

            col._runs["dhcp1"].retry_at = 0  # the check backoff has passed
            with self.assertNoLogs("leasewatch.collector", "WARNING"):  # held back again, not logged again
                col.run_once()
            self.assertNotEqual(db.get_meta("first_run_done", ""), "1")

            self.write_leases()
            col._runs["dhcp1"].retry_at = 0
            r = col.run_once()
            self.assertTrue(r["ok"])
            self.assertEqual(db.get_meta("conn.dhcp1.ok"), "1")
            self.assertEqual(db.get_meta("first_run_done"), "1")
            self.assertTrue(db.get_meta("baseline_ts"))
            # a later poll without changes: still nothing to mail
            col.run_once()
        mail.assert_not_called()
        # no "new" event; the late leases still add hostname/lease_type change events to the baseline row of fw1's device
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events WHERE kind='new'")[0]["n"], 0)

        both, lease_only = self.device(db, MAC_FW), self.device(db, MAC_LEASE)
        self.assertEqual((both["online"], both["hostname"], both["ip"], both["baseline"]), (1, "alex-laptop", "10.0.0.5", 1))
        self.assertEqual((lease_only["online"], lease_only["last_online"], lease_only["hostname"], lease_only["ip"],
                          lease_only["vlan"], lease_only["lease_type"], lease_only["baseline"], lease_only["sources"]),
                         (0, None, "alex-phone", "10.0.0.6", "LAN", "dynamic", 1, "dhcp"))
        self.assertEqual({(r["source"], r["last_present"] is None) for r in db.seen(MAC_LEASE)}, {("dhcp1", True)})
        self.assertEqual({(r["source"], r["last_present"] is None) for r in db.seen(MAC_FW)},
                         {("dhcp1", True), ("fw1", False)})


class MikrotikOnlyTest(ContribFitBase):
    def test_arp_lease_types_and_ip_change(self) -> None:
        router = self.stub()
        col, db = self.collector({"LW_CONNECTORS": "mt1", **self.mikrotik_env()})
        r = col.run_once()
        self.assertTrue(r["ok"], r)
        self.assertEqual(db.get_meta("first_run_done"), "1")
        self.assertEqual((db.get_meta("conn.mt1.ok"), db.get_meta("conn.mt1.type"), db.get_meta("conn.mt1.count")),
                         ("1", "mikrotik", "3"))
        self.assertEqual(db.get_meta("last_raw"), "2 leases, 1 arp")
        mt, dyn = self.device(db, MAC_MT), self.device(db, MAC_MT_DYN)
        self.assertEqual((mt["online"], mt["ip"], mt["hostname"], mt["lease_type"], mt["vlan"], mt["sources"]),
                         (1, "10.0.0.10", "alex-ipad", "static", "bridge-lan", "arp,dhcp"))
        self.assertEqual((dyn["online"], dyn["ip"], dyn["hostname"], dyn["lease_type"]), (0, "10.0.0.20", "printer", "dynamic"))
        self.assertEqual(db.q("SELECT kind FROM events"), [])

        router.data["/rest/ip/dhcp-server/lease"][0]["address"] = "10.0.0.11"
        router.data["/rest/ip/arp"][0]["address"] = "10.0.0.11"
        r = col.run_once()
        self.assertEqual((r["ok"], r["changed"], r["new"]), (True, 1, 0))
        self.assertEqual([(e["kind"], e["detail"]) for e in db.events(MAC_MT)], [("ip", "10.0.0.10 -> 10.0.0.11")])
        self.assertEqual([h["ip"] for h in db.q("SELECT ip FROM history WHERE mac=? ORDER BY id", (MAC_MT,))],
                         ["10.0.0.10", "10.0.0.11"])
        self.assertEqual(self.device(db, MAC_MT)["ip"], "10.0.0.11")


class MikrotikDeniedTest(ContribFitBase):
    def test_401_is_redacted_and_the_poll_stays_ok(self) -> None:
        router = self.stub()
        router.deny = True
        col, db = self.collector({**FW1_ENV, "LW_CONNECTORS": "fw1,mt1", **self.mikrotik_env()})
        with self.assertLogs("leasewatch.collector", "WARNING") as logs:
            r = col.run_once()
        self.assertNotIn(PASSWORD, "\n".join(logs.output))
        self.assertTrue(r["ok"], r)
        self.assertEqual(db.get_meta("last_poll_ok"), "1")
        err = db.get_meta("conn.mt1.error")
        self.assertTrue(err.startswith("check failed: mikrotik /rest/system/resource: HTTP 401 (wrong USER or PASSWORD)"), err)
        for leak in (PASSWORD, "127.0.0.1"):  # the port alone is kept, as the built-in clients keep it
            self.assertNotIn(leak, err)
            self.assertNotIn(leak, json.dumps(db.all_meta()))
        self.assertEqual(db.get_meta("conn.mt1.ok"), "0")
        self.assertEqual(self.device(db, MAC_FW)["online"], 1)


class WebTest(ContribFitBase):
    def get(self, srv, path: str) -> dict:
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            return json.loads(resp.read())
        finally:
            conn.close()

    def test_api_shows_contrib_sources(self) -> None:
        self.stub()
        self.write_leases()
        col, db = self.collector({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1,mt1", **self.dnsmasq_env(),
                                  **self.mikrotik_env()})
        self.assertTrue(col.run_once()["ok"])
        srv = serve(col.cfg, db, "9.9.9-test")
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            listing = self.get(srv, "/api/devices")
            lease_only = self.get(srv, f"/api/devices/{MAC_LEASE}")
            mt = self.get(srv, f"/api/devices/{MAC_MT}")
            fw = self.get(srv, f"/api/devices/{MAC_FW}")
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(5)
        conns = listing["meta"]["connectors"]
        self.assertEqual([(c["name"], c["label"], c["type"], c["ok"]) for c in conns],
                         [("fw1", "fw1", "opnsense", True), ("dhcp1", "dhcp1", "dnsmasq_leases", True),
                          ("mt1", "mt1", "mikrotik", True)])
        devs = {d["mac"]: d for d in listing["devices"]}
        self.assertEqual(set(devs), {MAC_FW, MAC_LEASE, MAC_MT, MAC_MT_DYN})
        for d in devs.values():  # no attachment producer: nobody places a device
            self.assertEqual((d["loc_source"], d["link"], d["sw_port"], d["wifi_ssid"]), ("", "", "", ""))
        self.assertEqual((devs[MAC_LEASE]["online"], devs[MAC_LEASE]["hostname"], devs[MAC_LEASE]["sources"]),
                         (0, "alex-phone", "dhcp"))
        seen = lambda detail: {r["source"]: r["last_present"] is not None for r in detail["seen"]}
        self.assertEqual(seen(lease_only), {"dhcp1": False})
        self.assertEqual(seen(mt), {"mt1": True})
        self.assertEqual(seen(fw), {"fw1": True, "dhcp1": False})
        self.assertNotIn(PASSWORD, json.dumps(listing))


if __name__ == "__main__":
    unittest.main()
