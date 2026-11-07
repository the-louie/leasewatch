import os, sys, tempfile, time, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore, sources, swap_client
from leasewatch.collector import Collector, merge
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.fw1 import Sighting, Fw1Error


class FakeClient:
    def __init__(self, sightings): self.sightings_data = sightings; self.fail = False
    def arp_raw(self): return []  # what the opnsense connector's check() calls; `fail` breaks collect() only
    def sightings(self, ignore=()):
        if self.fail: raise Fw1Error("boom")
        return list(self.sightings_data), {"leases": 1, "arp": 1}


def S(mac, ip, host="", src="dhcp", vlan="Clients", lt="dynamic", online=True, vendor="Acme"):
    return Sighting(mac=mac, ip=ip, hostname=host, vendor=vendor, vlan=vlan, iface="opt3", source=src, lease_type=lt if src == "dhcp" else "", online=online)


def cfg_with(*names):
    """Config with the instances "switch"/"unifi" (in that order after fw1) configured; the test swaps in their fakes."""
    os.environ.update(sources(*names))  # the test's tearDown restores the environment
    return Config()


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        self.cfg = Config(); self.db = Database(self.cfg.db_path)

    def tearDown(self): self.db._conn.close(); self.tmp.cleanup(); restore(self._env)

    def test_merge_prefers_dhcp_hostname_and_arp_online(self):
        m = merge([S("aa:bb:cc:dd:ee:01", "10.0.0.5", host="phone", online=False), S("aa:bb:cc:dd:ee:01", "10.0.0.5", host="", src="arp")])
        d = m["aa:bb:cc:dd:ee:01"]
        self.assertEqual(d.hostname, "phone"); self.assertTrue(d.online); self.assertEqual(d.sources, {"dhcp", "arp"}); self.assertEqual(d.lease_type, "dynamic")

    # B-08.3: an injected client is not a reason to skip check(); the connector's check() runs against it
    def test_injected_client_is_checked(self):
        c = FakeClient([S("aa:bb:cc:dd:ee:01", "10.0.0.5")])
        calls = []
        c.arp_raw = lambda: calls.append(1) or []
        col = Collector(self.cfg, self.db, client=c)
        self.assertTrue(col.run_once()["ok"])
        col.run_once()
        self.assertEqual(len(calls), 1)  # once, then collect() only

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
        self.db._conn.execute("UPDATE devices SET last_seen=last_seen-700, last_online=last_online-700 WHERE mac=?", ("aa:bb:cc:dd:ee:02",)); col.run_once(); self.assertEqual(self.db.device("aa:bb:cc:dd:ee:02")["online"], 0)
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
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name, "ONLINE_GRACE_MINUTES": "10"})
        self.cfg = Config(); self.db = Database(self.cfg.db_path)

    def tearDown(self): self.db._conn.close(); self.tmp.cleanup(); restore(self._env)

    def test_grace_period_keeps_device_online_when_missing_from_one_poll(self):
        c = FakeClient([S("aa:bb:cc:dd:ee:01", "10.0.0.5", src="arp")]); col = Collector(self.cfg, self.db, c); col.run_once()
        c.sightings_data = []; col.run_once()
        self.assertEqual(self.db.device("aa:bb:cc:dd:ee:01")["online"], 1, "still within the grace period")
        self.db._conn.execute("UPDATE devices SET last_seen=last_seen-700, last_online=last_online-700"); col.run_once()
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
        self.db._conn.execute("UPDATE devices SET last_seen=last_seen-700, last_online=last_online-700")
        c.sightings = lambda ignore=(): (_ for _ in ()).throw(RuntimeError("weird"))
        r = col.run_once(); self.assertFalse(r["ok"]); self.assertEqual(self.db.get_meta("last_error"), "RuntimeError")  # not a ConnectorError: type name only
        self.assertEqual(self.db.device("aa:bb:cc:dd:ee:01")["online"], 0)


class FixRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        self.cfg = Config(); self.db = Database(self.cfg.db_path)

    def tearDown(self): self.db._conn.close(); self.tmp.cleanup(); restore(self._env)

    def test_wifi_device_seen_wired_later_drops_wifi_details(self):
        from leasewatch.unifi import WifiInfo
        from leasewatch.switch import build_snapshot
        mac = "aa:bb:cc:dd:ee:01"
        col = Collector(cfg_with("switch", "unifi"), self.db, FakeClient([S(mac, "10.0.0.5", src="arp")]))
        wifi = {mac: WifiInfo(ssid="HomeNet", ap="ap-hall", signal=-50, radio="5 GHz")}
        swap_client(col, "unifi", type("U", (), {"clients": lambda self: wifi})())
        swap_client(col, "switch", type("W", (), {"snapshot": lambda self: build_snapshot([("1.170.187.204.221.238.1", 5)], [("5", 5)], [("5", "GigabitEthernet1/0/5")], [])})())
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["link"], d["wifi_ssid"]), ("wifi", "HomeNet"))
        wifi[mac] = WifiInfo(wired=True, alias="laptop")
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["link"], d["wifi_ssid"], d["wifi_ap"], d["wifi_signal"], d["wifi_radio"], d["wifi_alias"]), ("wired", "", "", None, "", "laptop"))

    def test_bad_log_level_falls_back_to_info(self):
        import subprocess
        env = dict(os.environ, LOG_LEVEL="verbose", LW_CONNECTOR__FW1__URL="", PYTHONPATH=os.path.join(os.path.dirname(__file__), ".."))
        out = subprocess.run([sys.executable, "-m", "leasewatch"], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotIn("Traceback", out.stderr)
        self.assertIn("not a log level", out.stderr)
        self.assertEqual(out.returncode, 2)  # stops at the (deliberately) empty firewall URL, not at the log level

    def test_dhcp_device_leaving_arp_keeps_online_during_grace(self):
        mac = "aa:bb:cc:dd:ee:01"
        c = FakeClient([S(mac, "10.0.0.5", "pc"), S(mac, "10.0.0.5", src="arp")]); col = Collector(self.cfg, self.db, c); col.run_once()
        c.sightings_data = [S(mac, "10.0.0.5", "pc", online=False)]  # lease still listed, gone from ARP
        col.run_once(); self.assertEqual(self.db.device(mac)["online"], 1)
        self.db.q("UPDATE devices SET last_online=last_online-700"); col.run_once()
        self.assertEqual(self.db.device(mac)["online"], 0)

    def test_wifi_device_drops_old_switch_port(self):
        from leasewatch.unifi import WifiInfo
        from leasewatch.switch import build_snapshot
        mac = "aa:bb:cc:dd:ee:01"
        col = Collector(cfg_with("switch", "unifi"), self.db, FakeClient([S(mac, "10.0.0.5", src="arp")]))
        wifi = {}
        swap_client(col, "unifi", type("U", (), {"clients": lambda self: wifi})())
        swap_client(col, "switch", type("W", (), {"snapshot": lambda self: build_snapshot([("1.170.187.204.221.238.1", 5)], [("5", 5)], [("5", "GigabitEthernet1/0/5")], [])})())
        col.run_once(); self.assertEqual((self.db.device(mac)["sw_port"], self.db.device(mac)["link"]), ("GE1/0/5", "wired"))
        wifi[mac] = WifiInfo(ssid="HomeNet", ap="ap-hall")
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["sw_port"], d["sw_via"], d["link"], d["wifi_ssid"]), ("", "", "wifi", "HomeNet"))

    def test_config_validation(self):
        sw = sources("switch")
        for env, msg in [({"LW_CONNECTOR__FW1__URL": "httpfoo"}, "connector fw1 (opnsense): url must be a URL"), ({"NEW_DAYS": "0"}, "NEW_DAYS"),
                         ({"ONLINE_GRACE_MINUTES": "-1"}, "ONLINE_GRACE"), ({"PUBLIC_URL": "leases.example"}, "PUBLIC_URL"),
                         ({**sw, "LW_CONNECTOR__SWITCH__AUTH": "MD5"}, "connector switch (snmp_switch): AUTH must be one of SHA, SHA256")]:
            os.environ.update({"LW_CONNECTOR__FW1__URL": "https://fw"}); os.environ.update(env)
            self.assertTrue(any(msg in p for p in Config().validate()), (env, Config().validate()))
            for k in env: os.environ.pop(k)
            os.environ.update(FW1_ENV)
        self.assertEqual(Config().validate(), [])

    def test_host_allowed(self):
        os.environ.update({"PUBLIC_URL": "https://leases.example.lan/"})
        cfg = Config()
        for h in ("leases.example.lan", "LEASES.example.lan:443", "10.0.0.5:8080", "[::1]:8080", "localhost", ""):
            self.assertTrue(cfg.host_allowed(h), h)
        for h in ("evil.example", "evil.example:8080", "leases.example.lan.evil.example"):
            self.assertFalse(cfg.host_allowed(h), h)
        os.environ["ALLOWED_HOSTS"] = "a.example.lan, b.example.lan"
        self.assertTrue(Config().host_allowed("b.example.lan")); self.assertFalse(Config().host_allowed("leases.example.lan"))
        os.environ["ALLOWED_HOSTS"] = "*"
        self.assertTrue(Config().host_allowed("evil.example"))

    def test_mail_text(self):
        from leasewatch import notify
        from unittest import mock
        sent = []
        # patched only inside this block, so later tests get the real _send back
        with mock.patch.object(notify, "_send", lambda cfg, subject, text: sent.append((subject, text))):
            devs = [{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.5", "hostname": "pc", "vendor": "Acme", "vlan": "LAN", "lease_type": "dynamic"}]
            notify.new_devices(self.cfg, devs)
            self.assertEqual(sent[-1][0], "New device: pc (10.0.0.5, LAN)"); self.assertNotIn("acknowledge", sent[-1][1])  # no PUBLIC_URL: no link
            os.environ["PUBLIC_URL"] = "https://leases.example.lan"
            notify.new_devices(Config(), devs + devs)
            self.assertEqual(sent[-1][0], "2 new devices on the network"); self.assertIn("https://leases.example.lan/?filter=unacked", sent[-1][1])
        self.assertEqual(notify._send.__name__, "_send")

    def test_dhcp_backend_is_validated(self):
        os.environ["LW_CONNECTOR__FW1__DHCP_BACKEND"] = "dhcpd"
        self.assertIn("connector fw1 (opnsense): DHCP_BACKEND must be one of isc, kea, dnsmasq", Config().validate())
        os.environ["LW_CONNECTOR__FW1__DHCP_BACKEND"] = "dnsmasq"
        self.assertFalse([p for p in Config().validate() if "DHCP_BACKEND" in p])


class ReviewFixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        self.cfg = Config(); self.db = Database(self.cfg.db_path)

    def tearDown(self): self.db._conn.close(); self.tmp.cleanup(); restore(self._env)

    def _same_over_permutations(self, rows):
        import itertools
        mac = rows[0].mac
        first = merge(rows)[mac]
        for p in itertools.permutations(rows):
            self.assertEqual(merge(list(p))[mac], first, p)
        return first

    def test_merge_ties_do_not_depend_on_row_order(self):
        mac = "02:00:00:00:00:01"
        m = self._same_over_permutations([S(mac, "10.0.0.5", "pc-a", src="arp"), S(mac, "10.0.0.5", "pc-b", src="arp")])
        self.assertEqual(m.hostname, "pc-a")
        m = self._same_over_permutations([S(mac, "10.0.0.5", "pc-d", lt="dynamic"), S(mac, "10.0.0.5", "pc-s", lt="static")])
        self.assertEqual((m.lease_type, m.hostname), ("static", "pc-s"))
        m = self._same_over_permutations([S(mac, "", "ghost"), S(mac, "10.0.0.7", "pc")])
        self.assertEqual((m.ip, m.hostname), ("10.0.0.7", "pc"))  # the empty-IP lease loses

    def test_wifi_device_no_longer_listed_by_unifi_falls_back_to_switch(self):
        from leasewatch.unifi import WifiInfo
        from leasewatch.switch import build_snapshot
        mac = "02:00:00:00:00:01"
        col = Collector(cfg_with("switch", "unifi"), self.db, FakeClient([S(mac, "10.0.0.5", src="arp")]))
        wifi = {mac: WifiInfo(ssid="HomeNet", ap="ap-hall", signal=-50, radio="5 GHz", alias="laptop")}
        swap_client(col, "unifi", type("U", (), {"clients": lambda self: wifi})())
        swap_client(col, "switch", type("W", (), {"snapshot": lambda self: build_snapshot([("1.2.0.0.0.0.1", 5)], [("5", 5)], [("5", "GigabitEthernet1/0/5")], [])})())
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["link"], d["wifi_ssid"], d["sw_port"]), ("wifi", "HomeNet", ""))
        wifi.clear()  # UniFi answers, but no longer lists the device
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["link"], d["wifi_ssid"], d["wifi_ap"], d["wifi_signal"], d["wifi_radio"], d["wifi_alias"], d["sw_port"]),
                         ("wired", "", "", None, "", "laptop", "GE1/0/5"))

    def test_departing_wifi_device_keeps_its_last_ssid(self):
        from leasewatch.unifi import WifiInfo
        from leasewatch.switch import build_snapshot
        mac = "02:00:00:00:00:01"
        c = FakeClient([S(mac, "10.0.0.5", src="arp"), S("02:00:00:00:00:09", "10.0.0.9", src="arp")])
        col = Collector(cfg_with("switch", "unifi"), self.db, c)
        wifi = {mac: WifiInfo(ssid="HomeNet", ap="ap-hall", signal=-50, radio="5 GHz")}
        swap_client(col, "unifi", type("U", (), {"clients": lambda self: wifi})())
        # the FDB keeps the phone on port 5, the AP uplink, after it has left
        swap_client(col, "switch", type("W", (), {"snapshot": lambda self: build_snapshot([("1.2.0.0.0.0.1", 5)], [("5", 5)], [("5", "GigabitEthernet1/0/5")], [])})())
        col.run_once()
        wifi.clear(); c.sightings_data = [S("02:00:00:00:00:09", "10.0.0.9", src="arp")]  # gone from ARP and UniFi
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["online"], d["link"], d["wifi_ssid"], d["wifi_ap"], d["sw_port"]), (1, "wifi", "HomeNet", "ap-hall", ""))

    def test_unifi_failure_does_not_write_ap_port_on_wifi_devices(self):
        from leasewatch.unifi import WifiInfo
        from leasewatch.switch import build_snapshot
        mac = "02:00:00:00:00:01"
        col = Collector(cfg_with("switch", "unifi"), self.db, FakeClient([S(mac, "10.0.0.5", src="arp")]))
        state = {"down": False}
        def clients(_self):
            if state["down"]:
                raise TimeoutError()
            return {mac: WifiInfo(ssid="HomeNet", ap="ap-hall", signal=-50, radio="5 GHz")}
        swap_client(col, "unifi", type("U", (), {"clients": clients})())
        # port 5 is the AP uplink: the FDB lists the Wi-Fi device there
        swap_client(col, "switch", type("W", (), {"snapshot": lambda self: build_snapshot([("1.2.0.0.0.0.1", 5)], [("5", 5)], [("5", "GigabitEthernet1/0/5")], [])})())
        col.run_once()
        state["down"] = True
        col.run_once(); d = self.db.device(mac)
        self.assertEqual((d["sw_port"], d["link"], d["wifi_ssid"]), ("", "wifi", "HomeNet"))

    def test_controllers_come_from_roles_not_the_type(self):
        from dataclasses import replace
        from unittest import mock
        from leasewatch.connectors.snmp_switch import SnmpSwitchConnector
        from leasewatch.connectors.unifi import UnifiConnector
        from leasewatch.switch import build_snapshot
        from leasewatch import collector as collector_mod
        col = Collector(cfg_with("switch", "unifi"), self.db, FakeClient([S("02:00:00:00:00:01", "10.0.0.5", src="arp")]))
        swap_client(col, "unifi", type("U", (), {"clients": lambda self: {}})())
        swap_client(col, "switch", type("W", (), {"snapshot": lambda self: build_snapshot([], [], [], [])})())
        for sw_roles, uf_roles, want in ((frozenset(), frozenset({"controller"}), {"unifi"}),
                                         (frozenset({"controller"}), frozenset(), {"switch"})):
            with self.subTest(want=want), \
                    mock.patch.object(SnmpSwitchConnector, "INFO", replace(SnmpSwitchConnector.INFO, roles=sw_roles)), \
                    mock.patch.object(UnifiConnector, "INFO", replace(UnifiConnector.INFO, roles=uf_roles)), \
                    mock.patch.object(collector_mod, "merge_batches", wraps=collector_mod.merge_batches) as m:
                col.run_once()
                self.assertEqual(m.call_args.args[4].controllers, frozenset(want))

    def test_batch_stats_are_optional(self):
        from leasewatch.switch import build_snapshot
        c = FakeClient([S("02:00:00:00:00:01", "10.0.0.5", src="arp")])
        c.sightings = lambda ignore=(): ([S("02:00:00:00:00:01", "10.0.0.5", src="arp")], {})
        col = Collector(cfg_with("switch", "unifi"), self.db, c)
        swap_client(col, "unifi", type("U", (), {"clients": lambda self: {}})())
        swap_client(col, "switch", type("W", (), {"snapshot": lambda self: build_snapshot([], [], [], [])})())
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual((self.db.get_meta("last_raw"), self.db.get_meta("conn.switch.count"), self.db.get_meta("conn.unifi.count")),
                         ("0 leases, 0 arp", "0", "0"))

    def test_enrich_error_names_a_bare_exception(self):
        col = Collector(cfg_with("switch"), self.db, FakeClient([S("02:00:00:00:00:01", "10.0.0.5")]))
        swap_client(col, "switch", type("W", (), {"snapshot": lambda self: (_ for _ in ()).throw(TimeoutError())})())
        col.run_once()
        self.assertEqual(self.db.get_meta("conn.switch.error"), "TimeoutError")

    def test_new_and_back_event_text(self):
        mac = "02:00:00:00:00:01"
        c = FakeClient([S("02:00:00:00:00:09", "10.0.0.9")]); col = Collector(self.cfg, self.db, c); col.run_once()
        c.sightings_data = [S(mac, "10.0.0.5", host="", vlan="IOT")]; col.run_once()
        self.assertEqual(self.db.events(mac)[0]["detail"], "10.0.0.5 Acme (IOT)")
        c.sightings_data = [S(mac, "10.0.0.6", host="", vlan="", vendor="")]; self.db.q("DELETE FROM devices WHERE mac=?", (mac,)); col.run_once()
        self.assertEqual(self.db.events(mac)[0]["detail"], "10.0.0.6")
        self.db.q("UPDATE devices SET online=0, last_online=? WHERE mac=?", (int(time.time()) - 86400 - 60, mac)); col.run_once()
        self.assertEqual(self.db.events(mac)[0]["detail"], "back after 1 day")

    def test_mail_failure_logs_kept_and_dropped(self):
        from leasewatch import notify
        os.environ.update({"MAILGUN_KEY": "k", "MAILGUN_DOMAIN": "mg.example", "MAIL_TO": "a@example.lan"})
        c = FakeClient([S("02:00:00:00:00:09", "10.0.0.9")]); col = Collector(Config(), self.db, c); col.run_once()
        col._unmailed = [{"mac": f"02:00:00:00:01:{i:02x}"} for i in range(60)]
        c.sightings_data.append(S("02:00:00:00:00:01", "10.0.0.5"))
        orig = notify.new_devices
        notify.new_devices = lambda cfg, devs: (_ for _ in ()).throw(RuntimeError("mailgun down"))
        try:
            with self.assertLogs("leasewatch.collector", "WARNING") as logs:
                col.run_once()
        finally:
            notify.new_devices = orig
        self.assertEqual(len(col._unmailed), 50)
        self.assertTrue(any("50 device(s) queued" in m for m in logs.output), logs.output)
        self.assertTrue(any("11 device(s) dropped" in m for m in logs.output), logs.output)


class DatabaseFixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "t.db"))
        self.mac = "02:00:00:00:00:01"
        self.db.q("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,?,?)", (self.mac, 1, 1))

    def tearDown(self): self.db._conn.close(); self.tmp.cleanup()

    def test_ctrl_keeps_zwj_and_strips_c1_and_bom(self):
        family = "\U0001F468\u200d\U0001F469\u200d\U0001F467"
        d = self.db.update_user_fields(self.mac, None, f"{family} TV\x85\ufeff\u2060\u061c", None)
        self.assertEqual(d["name"], f"{family} TV")

    def test_reack_keeps_acked_at_and_name_has_no_trailing_space(self):
        self.db.update_user_fields(self.mac, True, None, None)
        self.db.q("UPDATE devices SET acked_at=1 WHERE mac=?", (self.mac,))
        d = self.db.update_user_fields(self.mac, True, "x" * 79 + " y", None)
        self.assertEqual((d["acked_at"], d["name"]), (1, "x" * 79))
        self.assertIsNone(self.db.update_user_fields(self.mac, False, None, None)["acked_at"])

    def test_same_second_rows_newest_first(self):
        for k in ("a", "b", "c"):
            self.db.q("INSERT INTO events(ts,mac,kind,detail) VALUES(5,?,?,'')", (self.mac, k))
            self.db.q("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,5,?,'','','')", (self.mac, k))
        self.assertEqual([e["kind"] for e in self.db.events(self.mac)], ["c", "b", "a"])
        self.assertEqual([e["kind"] for e in self.db.events()], ["c", "b", "a"])
        self.assertEqual([h["ip"] for h in self.db.history(self.mac)], ["c", "b", "a"])

    def test_tx_rolls_back_and_keeps_the_original_exception(self):
        class Stop(BaseException): pass
        with self.assertRaises(KeyError):
            with self.db.tx() as c:
                c.execute("ROLLBACK")  # the later ROLLBACK in tx() now fails
                raise KeyError("original")
        self.assertFalse(self.db._conn.in_transaction)
        with self.assertRaises(Stop):
            with self.db.tx() as c:
                c.execute("UPDATE devices SET name='x'")
                raise Stop()
        self.assertFalse(self.db._conn.in_transaction)
        self.assertEqual(self.db.device(self.mac)["name"], "")


class LeaseTypeModeTests(unittest.TestCase):
    MAC = "02:00:00:00:10:01"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        os.environ.pop("LEASE_TYPE_MODE", None)

    def tearDown(self): self.db._conn.close(); self.tmp.cleanup(); restore(self._env)

    def _lease_then_arp_only(self, mode):
        """Poll 1: lease + ARP. Poll 2: ARP only (the lease is gone). Returns the collector for further polls."""
        if mode:
            os.environ["LEASE_TYPE_MODE"] = mode
        self.cfg = Config(); self.db = Database(self.cfg.db_path)
        self.client = FakeClient([S(self.MAC, "10.0.0.5", "pc", lt="static"), S(self.MAC, "10.0.0.5", src="arp")])
        col = Collector(self.cfg, self.db, self.client); col.run_once()
        self.client.sightings_data = [S(self.MAC, "10.0.0.5", src="arp")]
        col.run_once()
        return col

    def lease_events(self):
        return [r["detail"] for r in self.db.q("SELECT detail FROM events WHERE mac=? AND kind='lease_type'", (self.MAC,))]

    def test_keep_is_default_and_keeps_last_type(self):
        col = self._lease_then_arp_only(None)
        self.assertEqual(self.cfg.lease_type_mode, "keep")
        col.run_once()
        self.assertEqual(self.db.device(self.MAC)["lease_type"], "static")
        self.assertEqual(self.lease_events(), [])
        self.assertEqual(col._no_lease_since, {})

    def test_immediate_clears_on_first_poll_without_lease(self):
        self._lease_then_arp_only("immediate")
        self.assertEqual(self.db.device(self.MAC)["lease_type"], "")
        self.assertEqual(self.lease_events(), ["static -> no DHCP"])
        hist = self.db.q("SELECT lease_type FROM history WHERE mac=? ORDER BY id", (self.MAC,))
        self.assertEqual([r["lease_type"] for r in hist], ["static", ""])

    def test_grace_clears_only_after_grace_period(self):
        col = self._lease_then_arp_only("grace")
        self.assertEqual(self.db.device(self.MAC)["lease_type"], "static")  # inside the grace period
        self.assertIn(self.MAC, col._no_lease_since)
        col._no_lease_since[self.MAC] -= self.cfg.online_grace_minutes * 60  # backdate the first lease-less poll
        col.run_once()
        self.assertEqual(self.db.device(self.MAC)["lease_type"], "")
        self.assertEqual(self.lease_events(), ["static -> no DHCP"])
        self.assertNotIn(self.MAC, col._no_lease_since)

    def test_grace_clock_resets_when_lease_returns(self):
        col = self._lease_then_arp_only("grace")
        self.client.sightings_data = [S(self.MAC, "10.0.0.5", "pc", lt="static"), S(self.MAC, "10.0.0.5", src="arp")]
        col.run_once()
        self.assertNotIn(self.MAC, col._no_lease_since)
        self.assertEqual(self.db.device(self.MAC)["lease_type"], "static")



# the SCHEMA string of leasewatch/db.py at v1.0.0, copied so the test keeps working when db.py moves on
SCHEMA_1_0 = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    last_online INTEGER,
    ip          TEXT NOT NULL DEFAULT '',
    hostname    TEXT NOT NULL DEFAULT '',
    vendor      TEXT NOT NULL DEFAULT '',
    vlan        TEXT NOT NULL DEFAULT '',
    iface       TEXT NOT NULL DEFAULT '',
    lease_type  TEXT NOT NULL DEFAULT '',
    sources     TEXT NOT NULL DEFAULT '',
    online      INTEGER NOT NULL DEFAULT 0,
    baseline    INTEGER NOT NULL DEFAULT 0,
    acked       INTEGER NOT NULL DEFAULT 0,
    acked_at    INTEGER,
    name        TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL, ts INTEGER NOT NULL,
    ip TEXT NOT NULL, hostname TEXT NOT NULL, vlan TEXT NOT NULL, lease_type TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS history_mac ON history(mac, ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL, mac TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_mac ON events(mac, ts);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class SchemaVersionTests(unittest.TestCase):
    """C6: meta.schema_version, the seen table and the loc_source column, and the per-source upsert."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "t.db")

    def tearDown(self): self.tmp.cleanup()

    def test_fresh_db_is_current_version(self):
        db = Database(self.path)
        try:
            self.assertEqual(db.get_meta("schema_version"), "3")
            self.assertEqual(db.seen("02:00:00:00:00:01"), [])
            self.assertEqual(db.q("SELECT loc_source FROM devices"), [])
        finally:
            db._conn.close()

    def test_1_0_db_opens_and_migrates(self):
        import sqlite3
        conn = sqlite3.connect(self.path)
        conn.executescript(SCHEMA_1_0)
        conn.execute("INSERT INTO devices(mac,first_seen,last_seen,ip) VALUES('02:00:00:00:00:01',1,1,'10.0.0.5')")
        conn.execute("INSERT INTO meta(key,value) VALUES('first_run_done','1')")
        conn.commit(); conn.close()
        versions = []
        orig = Database.set_meta
        def spy(db, key, value, conn=None):
            if key == "schema_version": versions.append(value)
            return orig(db, key, value, conn)
        with unittest.mock.patch.object(Database, "set_meta", spy):
            db = Database(self.path)
        try:
            self.assertEqual(versions, ["1", "2", "3"])  # an unversioned DB is recorded as 1 first, then stepped up
            self.assertEqual(db.get_meta("schema_version"), "3")
            d = db.device("02:00:00:00:00:01")
            self.assertEqual((d["ip"], d["loc_source"], d["sw_port"], d["link"]), ("10.0.0.5", "", "", ""))
            self.assertEqual(db.seen("02:00:00:00:00:01"), [])
        finally:
            db._conn.close()
        db = Database(self.path)  # opening again changes nothing
        try:
            self.assertEqual(db.get_meta("schema_version"), "3")
        finally:
            db._conn.close()

    def test_non_integer_schema_version_is_treated_as_1(self):
        db = Database(self.path)
        db.set_meta("schema_version", "two"); db._conn.execute("DROP TABLE seen"); db._conn.close()
        with self.assertLogs("leasewatch.db", "WARNING") as logs:
            db = Database(self.path)
        try:
            self.assertIn("not a number; treated as 1", logs.output[0])
            self.assertEqual(db.get_meta("schema_version"), "3")
            self.assertEqual(db.seen("02:00:00:00:00:01"), [])  # step 2 ran again
        finally:
            db._conn.close()

    def test_zero_or_negative_schema_version_is_treated_as_1(self):
        for raw in ("0", "-1"):
            with self.subTest(raw=raw):
                db = Database(self.path)
                db.set_meta("schema_version", raw); db._conn.execute("DROP TABLE seen"); db._conn.close()
                with self.assertLogs("leasewatch.db", "WARNING") as logs:
                    db = Database(self.path)  # crashed with KeyError: VERSION_STEPS has no step 1 or 0
                try:
                    self.assertIn("below 1; treated as 1", logs.output[0])
                    self.assertEqual(db.get_meta("schema_version"), "3")
                    self.assertEqual(db.seen("02:00:00:00:00:01"), [])
                finally:
                    db._conn.close()

    def test_newer_schema_version_without_seen_table_creates_it(self):
        import sqlite3
        conn = sqlite3.connect(self.path)
        conn.executescript(SCHEMA_1_0)
        conn.execute("INSERT INTO meta(key,value) VALUES('schema_version','99')")
        conn.commit(); conn.close()
        with self.assertLogs("leasewatch.db", "WARNING") as logs:
            db = Database(self.path)
        try:
            self.assertIn("WARNING:leasewatch.db:database schema 99 lacks table seen; creating it", logs.output)
            self.assertEqual(db.get_meta("schema_version"), "99")  # left as is
            self.assertEqual(db.seen("02:00:00:00:00:01"), [])
        finally:
            db._conn.close()

    def test_newer_schema_version_warns_and_is_left_alone(self):
        db = Database(self.path)
        db.set_meta("schema_version", "9"); db._conn.close()
        with self.assertLogs("leasewatch.db", "WARNING") as logs:
            db = Database(self.path)
        try:
            self.assertEqual(logs.output, ["WARNING:leasewatch.db:database schema 9 is newer than this version (3); no migration"])
            self.assertEqual(db.get_meta("schema_version"), "9")
        finally:
            db._conn.close()

    def test_seen_rows_of_unconfigured_instances_are_pruned_at_startup(self):
        env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        try:
            cfg = Config(); db = Database(cfg.db_path)
            try:
                mac = "02:00:00:00:00:01"
                db._conn.executemany("INSERT INTO seen(mac,source,last_seen,last_present) VALUES(?,?,1,1)",
                                     [(mac, "fw1"), (mac, "sw-old"), (mac, "unifi-old")])
                db._conn.executemany("INSERT INTO devices(mac,first_seen,last_seen,loc_source) VALUES(?,1,1,?)",
                                     [(mac, "sw-old"), ("02:00:00:00:00:02", "fw1"), ("02:00:00:00:00:03", "")])
                with self.assertLogs("leasewatch.collector", "INFO") as logs:
                    Collector(cfg, db, FakeClient([]))
                self.assertEqual([r["source"] for r in db.seen(mac)], ["fw1"])
                self.assertEqual([r["loc_source"] for r in db.q("SELECT loc_source FROM devices ORDER BY mac")],
                                 ["", "fw1", ""])
                self.assertEqual([m for m in logs.output if "seen rows" in m],
                                 ["INFO:leasewatch.collector:removed 2 seen rows and 1 location sources of instances "
                                  "that are no longer configured"])
                with self.assertNoLogs("leasewatch.collector", "INFO"):
                    Collector(cfg, db, FakeClient([]))  # nothing left to prune: no log line
            finally:
                db._conn.close()
        finally:
            restore(env)

    def test_seen_upsert_keeps_last_present_on_a_listing_without_presence(self):
        env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        try:
            cfg = Config(); db = Database(cfg.db_path)
            try:
                mac = "02:00:00:00:00:01"
                c = FakeClient([S(mac, "10.0.0.5", "pc", online=False), S(mac, "10.0.0.5", src="arp")])
                col = Collector(cfg, db, c)
                col.run_once()
                (first,) = db.seen(mac)
                self.assertEqual(first["last_present"], first["last_seen"])
                db._conn.execute("UPDATE seen SET last_seen=last_seen-100, last_present=last_present-100")
                c.sightings_data = [S(mac, "10.0.0.5", "pc", online=False)]  # lease only: listed, not vouched for
                col.run_once()
                (second,) = db.seen(mac)
                self.assertEqual(second["source"], first["source"])
                self.assertGreaterEqual(second["last_seen"], first["last_seen"])
                self.assertEqual(second["last_present"], first["last_present"] - 100)
            finally:
                db._conn.close()
        finally:
            restore(env)


if __name__ == "__main__":
    unittest.main()
