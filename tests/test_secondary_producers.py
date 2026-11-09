"""Secondary sighting producers (role "controller" or "names"): their sightings count, but their failure does not fail
the poll, hold the baseline back or hold merges back. Fake connector types and synthetic data only."""
import http.client
import json
import threading
import unittest
from dataclasses import replace
from unittest import mock

from _env import UNIFI_ENV, swap_client
from test_instances import FW1, Base, Fake
from test_merge_private_mac import MAIL
from leasewatch.connectors import Batch, ConnectorError, Sighting, registry
from leasewatch.fw1 import Sighting as Fw1Sighting
from leasewatch.unifi import WifiInfo
from leasewatch.web import serve

DEV = "00:00:5e:00:53:01"
NEW = "00:00:5e:00:53:02"
PRIV = "06:00:00:00:10:02"
PRIV2 = "06:00:00:00:10:03"
CID = "ff00000000000001"
WEB = {"LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0"}


class FakeNames(Fake):
    """A listen-only name source: sightings of kind scan, no presence."""
    INFO = replace(Fake.INFO, type="fakenames", produces=frozenset({"sighting"}), roles=frozenset({"names"}))


class FakeFw2(Fake):
    INFO = replace(Fake.INFO, type="fakefw2", produces=frozenset({"sighting"}))


def lease(mac, ip, cid=""):
    return Fw1Sighting(mac=mac, ip=ip, hostname="", vendor="", vlan="LAN", iface="lan", source="dhcp",
                       lease_type="dynamic", online=True, client_id=cid)


def boom():
    raise ConnectorError("unreachable")


class Secondary(Base):
    def setUp(self):
        super().setUp()
        self.reg2 = mock.patch.dict(registry(), {"fakenames": FakeNames, "fakefw2": FakeFw2})
        self.reg2.start()
        self.addCleanup(self.reg2.stop)

    def build(self, kind, extra=None, rows=None):
        """fw1 plus one secondary instance: "unifi" (role controller) or "names" (role names)."""
        if kind == "unifi":
            env = {"LW_CONNECTORS": "fw1,unifi", **FW1, **UNIFI_ENV}
        else:
            env = {"LW_CONNECTORS": "fw1,names", **FW1, "LW_CONNECTOR__NAMES__TYPE": "fakenames"}
        col, db = self.collector({**env, **(extra or {})}, rows=rows)
        self.sec = None
        if kind == "unifi":
            self.wifi = lambda: {DEV: WifiInfo(ssid="HomeNet", hostname="laptop", oui="Acme")}
            swap_client(col, "unifi", type("U", (), {"clients": lambda s: self.wifi()})())
        else:
            self.sec = col._connectors["names"]
            self.sec.on_collect = lambda: Batch(sightings=[Sighting(
                mac=DEV, source="", kind="scan", presence=False, observed_at=0, ip="10.0.0.5", hostname="printer",
                label="Hall printer")])
        return col, db

    def fail_secondary(self, kind):
        if kind == "unifi":
            self.wifi = boom
        else:
            self.sec.on_collect = boom

    def healthz(self, col, db):
        srv = serve(col.cfg, db, "9.9.9-test")
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            return resp.status
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(5)

    def firewall_down(self, kind):
        col, db = self.build(kind, WEB, rows=[lease(DEV, "10.0.0.5")])
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(self.healthz(col, db), 200)
        self.client.fail = True
        res = col.run_once()
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "boom")  # the firewall's error alone
        self.assertEqual(db.get_meta("last_poll_ok"), "0")
        self.assertEqual(self.healthz(col, db), 503)

    def test_firewall_down_fails_the_poll_while_the_controller_answers(self):
        self.firewall_down("unifi")

    def test_firewall_down_fails_the_poll_while_the_name_source_answers(self):
        self.firewall_down("names")

    def baseline(self, kind, extra=None):
        col, db = self.build(kind, {**MAIL, **(extra or {})}, rows=[lease(DEV, "10.0.0.5")])
        self.fail_secondary(kind)
        self.assertTrue(col.run_once()["first_run"])
        self.assertEqual(db.get_meta("first_run_done"), "1")
        self.client.rows = [lease(DEV, "10.0.0.5"), lease(NEW, "10.0.0.6")]
        with mock.patch("leasewatch.collector.notify.new_devices") as mail:
            res = col.run_once()
        self.assertEqual((res["ok"], res["first_run"], res["new"]), (True, False, 1))
        self.assertEqual([d["mac"] for d in mail.call_args[0][1]], [NEW])

    def test_unreachable_controller_does_not_hold_the_baseline(self):
        self.baseline("unifi")

    def test_unreachable_controller_without_hostnames_does_not_hold_the_baseline(self):
        self.baseline("unifi", {"LW_CONNECTOR__UNIFI__HOSTNAMES": "0"})

    def test_unreachable_name_source_does_not_hold_the_baseline(self):
        self.baseline("names")

    def test_unreachable_primary_still_holds_the_baseline(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,fw2", **FW1, "LW_CONNECTOR__FW2__TYPE": "fakefw2"},
                                 rows=[lease(DEV, "10.0.0.5")])
        col._connectors["fw2"].on_collect = boom
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.get_meta("first_run_done"), "")

    def test_failed_name_source_keeps_the_label_it_supplied(self):
        col, db = self.build("names", rows=[lease(DEV, "10.0.0.5")])
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.device(DEV)["label"], "Hall printer")
        self.fail_secondary("names")
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.device(DEV)["label"], "Hall printer")
        self.sec.on_collect = lambda: Batch()
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.device(DEV)["label"], "")

    def test_mac_only_the_controller_lists_gets_no_row_until_the_firewall_does(self):
        col, db = self.build("unifi", rows=[lease(DEV, "10.0.0.5")])
        self.assertTrue(col.run_once()["ok"])  # the baseline
        self.wifi = lambda: {DEV: WifiInfo(ssid="HomeNet", hostname="laptop", oui="Acme"),
                             NEW: WifiInfo(ssid="HomeNet", hostname="tablet", oui="Acme")}
        res = col.run_once()
        self.assertEqual((res["ok"], res["new"]), (True, 0))
        self.assertIsNone(db.device(NEW))
        self.assertEqual(db.q("SELECT kind FROM events WHERE mac=?", (NEW,)), [])
        self.client.rows = [lease(DEV, "10.0.0.5"), lease(NEW, "10.0.0.6")]
        res = col.run_once()
        self.assertEqual((res["ok"], res["new"]), (True, 1))
        self.assertEqual(db.device(NEW)["hostname"], "tablet")  # the controller's name as the fallback
        self.assertEqual([r["kind"] for r in db.q("SELECT kind FROM events WHERE mac=?", (NEW,))], ["new"])

    def test_mac_only_the_name_source_lists_gets_no_row(self):
        col, db = self.build("names", rows=[lease(DEV, "10.0.0.5")])
        self.assertTrue(col.run_once()["ok"])
        self.sec.on_collect = lambda: Batch(sightings=[Sighting(
            mac=NEW, source="", kind="scan", presence=False, observed_at=0, ip="10.0.0.6", hostname="printer")])
        self.assertEqual(col.run_once()["new"], 0)
        self.assertIsNone(db.device(NEW))

    def test_arp_name_stays_when_the_controller_names_the_device_otherwise(self):
        arp = Fw1Sighting(mac=DEV, ip="10.0.0.5", hostname="pc-arp", vendor="", vlan="LAN", iface="lan", source="arp",
                          lease_type="", online=True)
        col, db = self.build("unifi", rows=[arp])
        self.wifi = lambda: {}  # as before the controller named clients: the firewall's name is stored
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.device(DEV)["hostname"], "pc-arp")
        self.wifi = lambda: {DEV: WifiInfo(ssid="HomeNet", hostname="laptop", oui="Acme")}
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.device(DEV)["hostname"], "pc-arp")
        self.assertEqual(db.q("SELECT kind FROM events WHERE mac=? AND kind='hostname'", (DEV,)), [])

    def test_disabled_primary_next_to_an_answering_secondary(self):
        # fw2's PORT is out of range, so the instance is disabled at startup: the name source carries the poll
        col, db = self.collector({"LW_CONNECTORS": "fw2,names", "LW_CONNECTOR__FW2__TYPE": "fakefw2",
                                  "LW_CONNECTOR__FW2__PORT": "0", "LW_CONNECTOR__NAMES__TYPE": "fakenames"})
        self.assertTrue(col._runs["fw2"].disabled)
        col._connectors["names"].on_collect = lambda: Batch(sightings=[Sighting(
            mac=DEV, source="", kind="scan", presence=False, observed_at=0, ip="10.0.0.5", hostname="printer")])
        res = col.run_once()
        self.assertTrue(res["ok"], res)
        self.assertEqual(db.device(DEV)["hostname"], "printer")

    def test_no_enabled_producer_fails_the_poll(self):
        col, db = self.collector({"LW_CONNECTORS": "fw2", "LW_CONNECTOR__FW2__TYPE": "fakefw2",
                                  "LW_CONNECTOR__FW2__PORT": "0"})
        res = col.run_once()
        self.assertEqual((res["ok"], res["error"]), (False, "no sighting connector is enabled"))

    def test_a_secondary_connector_alone_is_refused(self):
        msg = ("LW_CONNECTORS: at least one connector must produce sightings and not be a controller or a name source "
               "(e.g. type opnsense)")
        self.assertIn(msg, self.cfg({"LW_CONNECTORS": "unifi", **UNIFI_ENV}).validate())
        self.assertIn(msg, self.cfg({"LW_CONNECTORS": "names", "LW_CONNECTOR__NAMES__TYPE": "fakenames"}).validate())
        self.assertNotIn(msg, self.cfg({"LW_CONNECTORS": "fw1,names", **FW1,
                                        "LW_CONNECTOR__NAMES__TYPE": "fakenames"}).validate())

    def test_instance_added_later_is_a_suspect_until_it_answers(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1}, rows=[lease(DEV, "10.0.0.5", CID)])
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(json.loads(db.get_meta("lease_holders")), {"holders": ["fw1"], "answered": ["fw1"]})
        # fw2 is added (same database) and fails from its first poll: a new private MAC with the device's client-id
        # is held back, as fw2 may hold its lease
        col, db = self.collector({"LW_CONNECTORS": "fw1,fw2", **FW1, "LW_CONNECTOR__FW2__TYPE": "fakefw2"},
                                 rows=[lease(DEV, "10.0.0.5", CID), lease(PRIV, "10.0.0.7", CID)])
        fw2 = col._connectors["fw2"]
        fw2.on_collect = boom
        self.assertTrue(col.run_once()["ok"])
        self.assertIsNone(db.device(PRIV))
        self.assertEqual(db.q("SELECT mac FROM aliases"), [])
        # fw2 answers once without a lease: it has answered and is no holder
        fw2.on_collect = lambda: Batch(sightings=[Sighting(mac=DEV, source="", kind="arp", presence=True,
                                                           observed_at=0, ip="10.0.0.5")])
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(json.loads(db.get_meta("lease_holders")), {"holders": ["fw1"], "answered": ["fw1", "fw2"]})
        # so its next failure holds nothing: another new private MAC with the client-id merges at once
        fw2.on_collect = boom
        self.client.rows = [lease(DEV, "10.0.0.5", CID), lease(PRIV2, "10.0.0.8", CID)]
        self.assertTrue(col.run_once()["ok"])
        self.assertIn(PRIV2, [r["mac"] for r in db.q("SELECT mac FROM aliases")])


if __name__ == "__main__":
    unittest.main()
