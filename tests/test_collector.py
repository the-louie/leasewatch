import os, sys, tempfile, time, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leasewatch.collector import Collector, merge
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.fw1 import Sighting, Fw1Error


class FakeClient:
    def __init__(self, sightings): self.sightings_data = sightings; self.fail = False
    def sightings(self, ignore=()):
        if self.fail: raise Fw1Error("boom")
        return list(self.sightings_data), {"leases": 1, "arp": 1}


def S(mac, ip, host="", src="dhcp", vlan="Clients", lt="dynamic", online=True, vendor="Acme"):
    return Sighting(mac=mac, ip=ip, hostname=host, vendor=vendor, vlan=vlan, iface="opt3", source=src, lease_type=lt if src == "dhcp" else "", online=online)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ.update({"FW1_KEY": "k", "FW1_SECRET": "s", "DATA_DIR": self.tmp.name})
        self.cfg = Config(); self.db = Database(self.cfg.db_path)

    def tearDown(self): self.tmp.cleanup()

    def test_merge_prefers_dhcp_hostname_and_arp_online(self):
        m = merge([S("aa:bb:cc:dd:ee:01", "10.0.0.5", host="phone", online=False), S("aa:bb:cc:dd:ee:01", "10.0.0.5", host="", src="arp")])
        d = m["aa:bb:cc:dd:ee:01"]
        self.assertEqual(d.hostname, "phone"); self.assertTrue(d.online); self.assertEqual(d.sources, {"dhcp", "arp"}); self.assertEqual(d.lease_type, "dynamic")

    def test_first_run_is_baseline_then_new_devices_and_changes(self):
        c = FakeClient([S("aa:bb:cc:dd:ee:01", "10.0.0.5", "phone")])
        col = Collector(self.cfg, self.db, c)
        r = col.run_once(); self.assertTrue(r["first_run"]); self.assertEqual(r["new"], 0)
        self.assertEqual(self.db.device("aa:bb:cc:dd:ee:01")["baseline"], 1)
        c.sightings_data.append(S("aa:bb:cc:dd:ee:02", "10.0.0.9", "newbie", vlan="IOT"))
        r = col.run_once(); self.assertEqual(r["new"], 1)
        d = self.db.device("aa:bb:cc:dd:ee:02"); self.assertEqual(d["baseline"], 0); self.assertEqual(d["vlan"], "IOT")
        self.assertEqual([e["kind"] for e in self.db.events("aa:bb:cc:dd:ee:02")], ["new"])
        # IP change -> history + event; offline when missing
        c.sightings_data[1] = S("aa:bb:cc:dd:ee:02", "10.0.0.10", "newbie", vlan="IOT")
        col.run_once(); self.assertEqual(len(self.db.history("aa:bb:cc:dd:ee:02")), 2)
        self.assertIn("ip", [e["kind"] for e in self.db.events("aa:bb:cc:dd:ee:02")])
        c.sightings_data.pop(1); col.run_once(); self.assertEqual(self.db.device("aa:bb:cc:dd:ee:02")["online"], 1)  # grace period
        self.db._conn.execute("UPDATE devices SET last_seen=last_seen-700 WHERE mac=?", ("aa:bb:cc:dd:ee:02",)); col.run_once(); self.assertEqual(self.db.device("aa:bb:cc:dd:ee:02")["online"], 0)
        st = self.db.stats(7); self.assertEqual(st["total"], 2); self.assertEqual(st["new"], 1); self.assertEqual(st["unacked"], 1)

    def test_failed_poll_keeps_data_and_records_error(self):
        c = FakeClient([S("aa:bb:cc:dd:ee:01", "10.0.0.5")]); col = Collector(self.cfg, self.db, c); col.run_once()
        c.fail = True; r = col.run_once(); self.assertFalse(r["ok"])
        self.assertEqual(self.db.get_meta("last_poll_ok"), "0"); self.assertIn("boom", self.db.get_meta("last_error"))
        self.assertEqual(len(self.db.devices()), 1)

    def test_user_fields(self):
        c = FakeClient([S("aa:bb:cc:dd:ee:01", "10.0.0.5")]); Collector(self.cfg, self.db, c).run_once()
        d = self.db.update_user_fields("aa:bb:cc:dd:ee:01", True, "  Kitchen TV ", "x" * 2000)
        self.assertEqual(d["acked"], 1); self.assertEqual(d["name"], "Kitchen TV"); self.assertEqual(len(d["note"]), 1000)
        self.assertIsNone(self.db.update_user_fields("00:00:00:00:00:00", True, None, None))



class CollectorRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ.update({"FW1_KEY": "k", "FW1_SECRET": "s", "DATA_DIR": self.tmp.name, "ONLINE_GRACE_MINUTES": "10"})
        self.cfg = Config(); self.db = Database(self.cfg.db_path)

    def tearDown(self): self.tmp.cleanup()

    def test_grace_period_keeps_device_online_when_missing_from_one_poll(self):
        c = FakeClient([S("aa:bb:cc:dd:ee:01", "10.0.0.5", src="arp")]); col = Collector(self.cfg, self.db, c); col.run_once()
        c.sightings_data = []; col.run_once()
        self.assertEqual(self.db.device("aa:bb:cc:dd:ee:01")["online"], 1, "still within the grace period")
        self.db._conn.execute("UPDATE devices SET last_seen=last_seen-700"); col.run_once()
        self.assertEqual(self.db.device("aa:bb:cc:dd:ee:01")["online"], 0)

    def test_empty_first_poll_is_not_a_baseline(self):
        c = FakeClient([]); col = Collector(self.cfg, self.db, c)
        r = col.run_once(); self.assertFalse(r["ok"]); self.assertEqual(self.db.get_meta("first_run_done"), "")
        c.sightings_data = [S("aa:bb:cc:dd:ee:01", "10.0.0.5")]; r = col.run_once()
        self.assertTrue(r["first_run"]); self.assertEqual(r["new"], 0); self.assertEqual(self.db.device("aa:bb:cc:dd:ee:01")["baseline"], 1)

    def test_merge_is_order_independent_and_follows_the_wire(self):
        rows = [S("aa:bb:cc:dd:ee:01", "10.0.0.5", "pc", vlan="Clients", online=False), S("aa:bb:cc:dd:ee:01", "10.0.0.5", src="arp", vlan="Clients"), S("aa:bb:cc:dd:ee:01", "10.0.1.5", src="arp", vlan="Servers")]
        import itertools
        results = {(m["aa:bb:cc:dd:ee:01"].ip, m["aa:bb:cc:dd:ee:01"].vlan) for m in (merge(list(p)) for p in itertools.permutations(rows))}
        self.assertEqual(results, {("10.0.0.5", "Clients")})
        moved = merge([S("aa:bb:cc:dd:ee:01", "10.0.0.5", "pc", vlan="Clients", online=False), S("aa:bb:cc:dd:ee:01", "10.0.1.9", src="arp", vlan="Servers")])["aa:bb:cc:dd:ee:01"]
        self.assertEqual((moved.ip, moved.vlan, moved.hostname), ("10.0.1.9", "Servers", "pc"))

    def test_failed_poll_ages_online_and_unexpected_exceptions_are_recorded(self):
        c = FakeClient([S("aa:bb:cc:dd:ee:01", "10.0.0.5", src="arp")]); col = Collector(self.cfg, self.db, c); col.run_once()
        self.db._conn.execute("UPDATE devices SET last_seen=last_seen-700")
        c.sightings = lambda ignore=(): (_ for _ in ()).throw(RuntimeError("weird"))
        r = col.run_once(); self.assertFalse(r["ok"]); self.assertIn("weird", self.db.get_meta("last_error"))
        self.assertEqual(self.db.device("aa:bb:cc:dd:ee:01")["online"], 0)


class FixRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ.update({"FW1_KEY": "k", "FW1_SECRET": "s", "DATA_DIR": self.tmp.name})
        self.cfg = Config(); self.db = Database(self.cfg.db_path)

    def tearDown(self): self.db._conn.close(); self.tmp.cleanup()

    def test_wifi_device_seen_wired_later_drops_wifi_details(self):
        from leasewatch.unifi import WifiInfo
        from leasewatch.switch import build_snapshot
        mac = "aa:bb:cc:dd:ee:01"
        col = Collector(self.cfg, self.db, FakeClient([S(mac, "10.0.0.5", src="arp")]))
        wifi = {mac: WifiInfo(ssid="HomeNet", ap="ap-hall", signal=-50, radio="5 GHz")}
        col._unifi = type("U", (), {"clients": lambda self: wifi})()
        col._switch = type("W", (), {"snapshot": lambda self: build_snapshot([("1.170.187.204.221.238.1", 5)], [("5", 5)], [("5", "GigabitEthernet1/0/5")], [])})()
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["link"], d["wifi_ssid"]), ("wifi", "HomeNet"))
        wifi[mac] = WifiInfo(wired=True, alias="laptop")
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["link"], d["wifi_ssid"], d["wifi_ap"], d["wifi_signal"], d["wifi_radio"], d["wifi_alias"]), ("wired", "", "", None, "", "laptop"))

    def test_bad_log_level_falls_back_to_info(self):
        import subprocess
        env = dict(os.environ, LOG_LEVEL="verbose", FW1_URL="", PYTHONPATH=os.path.join(os.path.dirname(__file__), ".."))
        out = subprocess.run([sys.executable, "-m", "leasewatch"], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotIn("Traceback", out.stderr)
        self.assertIn("not a log level", out.stderr)
        self.assertEqual(out.returncode, 2)  # stops at the (deliberately) missing FW1_URL, not at the log level

    def test_dhcp_backend_is_validated(self):
        os.environ["DHCP_BACKEND"] = "dnsmasq"
        try:
            self.assertIn("DHCP_BACKEND must be isc or kea", Config().validate())
        finally:
            del os.environ["DHCP_BACKEND"]


if __name__ == "__main__":
    unittest.main()
