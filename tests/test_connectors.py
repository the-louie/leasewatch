import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore
from leasewatch.config import Config
from leasewatch.connectors import (API_VERSION, Attachment, Batch, Connector, ConnectorError, HostContext, Sighting,
                                   make_redactor)
from leasewatch.connectors.legacy import legacy_instances
from leasewatch.connectors.opnsense import OpnsenseConnector
from leasewatch.connectors.snmp_switch import SnmpSwitchConnector
from leasewatch.connectors.unifi import UnifiConnector
from leasewatch.fw1 import Fw1Error
from leasewatch.fw1 import Sighting as Fw1Sighting
from leasewatch.switch import build_snapshot
from leasewatch.unifi import parse_clients

CTX = HostContext(now=lambda: 1700000000)
FW1 = {"url": "https://fw1.example.lan", "key": "k", "secret": "s"}
SW = {"host": "10.0.0.2", "name": "sw-rack", "auth_key": "a" * 8, "priv_key": "p" * 8}
UF = {"url": "https://unifi.example.lan", "user": "ro", "password": "pw"}


class Raises:
    """A client whose every call raises the given exception."""
    def __init__(self, exc): self.exc = exc
    def _raise(self, *a, **k): raise self.exc
    sightings = arp_raw = snapshot = clients = _raise


class FakeFw1:
    def __init__(self, rows): self.rows = rows; self.ignore = None
    def sightings(self, ignore=()):
        self.ignore = ignore
        return list(self.rows), {"leases": 2, "arp": 1, "reservations": 0}


class DescribeTests(unittest.TestCase):
    def test_describe_is_well_formed(self):
        for cls, secrets in ((OpnsenseConnector, {"key", "secret"}), (SnmpSwitchConnector, {"auth_key", "priv_key"}),
                             (UnifiConnector, {"password"})):
            info = cls.describe()
            self.assertEqual(info.api_version, API_VERSION)
            self.assertRegex(info.type, r"^[a-z0-9_]+$")
            self.assertTrue(info.produces <= {"sighting", "attachment"} and info.produces)
            keys = [s.key for s in info.settings]
            self.assertEqual(len(keys), len(set(keys)), cls)
            self.assertEqual({s.key for s in info.settings if s.secret}, secrets, cls)
            for s in info.settings:
                self.assertIsInstance(s.default, str)
                if s.choices and s.default:
                    self.assertIn(s.default, s.choices)

    def test_settings_cover_the_config_fields(self):
        self.assertEqual({s.key for s in OpnsenseConnector.describe().settings},
                         {"url", "key", "secret", "verify_tls", "dhcp_backend", "ignore_interfaces", "proxy"})
        self.assertEqual({s.key for s in SnmpSwitchConnector.describe().settings}, {"host", "name", "user", "auth", "auth_key", "priv_key"})
        self.assertEqual({s.key for s in UnifiConnector.describe().settings}, {"url", "site", "user", "password", "verify_tls", "proxy"})

    def test_wrappers_are_connectors(self):
        for c in (OpnsenseConnector("fw1", FW1, CTX), SnmpSwitchConnector("switch", SW, CTX), UnifiConnector("unifi", UF, CTX)):
            self.assertIsInstance(c, Connector)
            self.assertEqual(c.validate(), [])
            c.close()

    def test_repr_hides_secrets(self):
        r = repr(OpnsenseConnector("fw1", {**FW1, "secret": "topsecret"}, CTX)) + repr(UnifiConnector("unifi", {**UF, "password": "topsecret"}, CTX))
        self.assertNotIn("topsecret", r)

    def test_redactor(self):
        self.assertEqual(make_redactor(["abc", "", "abcdef"])("x abcdef abc"), "x *** ***")
        self.assertEqual(make_redactor([])("abc"), "abc")


class ValidateTests(unittest.TestCase):
    def test_opnsense(self):
        p = OpnsenseConnector("fw1", {"url": "fw1.example.lan", "dhcp_backend": "dnsmasq", "verify_tls": "maybe"}, CTX).validate()
        self.assertTrue(any("requires key" in x for x in p) and any("requires secret" in x for x in p), p)
        self.assertTrue(any(x.startswith("url must be a URL") for x in p), p)
        self.assertTrue(any("dhcp_backend must be one of isc, kea" in x for x in p), p)
        self.assertTrue(any(x.startswith("verify_tls must be a boolean") for x in p), p)
        self.assertEqual(OpnsenseConnector("fw1", {**FW1, "url": "https://user:pw@fw1.example.lan"}, CTX).validate(), ["url must not contain credentials"])
        self.assertEqual(OpnsenseConnector("fw1", {**FW1, "url": "https://[fw1"}, CTX).validate(), ["url is not a valid URL"])
        self.assertEqual(OpnsenseConnector("fw1", {**FW1, "dhcp_backend": "ISC"}, CTX).validate(), [])

    def test_switch(self):
        p = SnmpSwitchConnector("switch", {"host": "10.0.0.2", "auth": "md5"}, CTX).validate()
        self.assertTrue(any("requires auth_key" in x for x in p) and any("requires priv_key" in x for x in p), p)
        self.assertTrue(any("auth must be one of SHA, SHA256" in x for x in p), p)
        self.assertEqual(SnmpSwitchConnector("switch", {**SW, "auth": "sha-256"}, CTX).validate(), [])

    def test_unifi(self):
        p = UnifiConnector("unifi", {"url": "https://unifi.example.lan/"}, CTX).validate()
        self.assertTrue(any("requires user" in x for x in p) and any("requires password" in x for x in p), p)
        self.assertEqual(UnifiConnector("unifi", {**UF, "url": "ftp://unifi.example.lan"}, CTX).validate(),
                         ["url must be a URL (https://<controller>)"])


class OpnsenseTests(unittest.TestCase):
    def test_collect_reproduces_fw1_sightings(self):
        rows = [Fw1Sighting(mac="02:00:00:00:00:01", ip="10.0.0.5", hostname="phone", vendor="Acme", vlan="Clients", iface="opt3",
                            source="dhcp", lease_type="static", online=False),
                Fw1Sighting(mac="02:00:00:00:00:01", ip="10.0.0.5", hostname="", vendor="", vlan="Clients", iface="opt3",
                            source="arp", lease_type="", online=True)]
        fake = FakeFw1(rows)
        c = OpnsenseConnector("fw1", {**FW1, "ignore_interfaces": "wan,opt6"}, CTX, client=fake)
        b = c.collect()
        self.assertEqual(fake.ignore, ("wan", "opt6"))
        self.assertEqual(b.stats, {"leases": 2, "arp": 1, "reservations": 0})
        self.assertEqual(b.attachments, [])
        self.assertEqual(len(b.sightings), 2)
        for old, new in zip(rows, b.sightings):
            self.assertIsInstance(new, Sighting)
            self.assertEqual((new.mac, new.ip, new.hostname, new.vendor, new.network, new.iface, new.kind, new.lease_type, new.presence),
                             (old.mac, old.ip, old.hostname, old.vendor, old.vlan, old.iface, old.source, old.lease_type, old.online))
            self.assertEqual((new.source, new.observed_at, new.client_id), ("fw1", 1700000000, ""))

    def test_errors_become_connectorerror(self):
        c = OpnsenseConnector("fw1", FW1, CTX, client=Raises(Fw1Error("fw1 /api/x: HTTP 401")))
        with self.assertRaises(ConnectorError) as cm:
            c.collect()
        self.assertEqual(str(cm.exception), "fw1 /api/x: HTTP 401")
        with self.assertRaises(ConnectorError):
            c.check()

    def test_real_client_is_built_from_settings(self):
        c = OpnsenseConnector("fw1", {**FW1, "url": "https://fw1.example.lan/", "dhcp_backend": "ISC"}, CTX)
        self.assertEqual((c.client.url, c.client.dhcp_backend), ("https://fw1.example.lan", "isc"))
        self.assertEqual(OpnsenseConnector("fw1", FW1, CTX).client.dhcp_backend, "kea")


class SwitchConnectorTests(unittest.TestCase):
    def snap(self):
        fdb = [("110.2.0.94.107.39.107", 14), ("110.222.173.190.239.0.1", 3)] + [(f"110.1.2.3.4.5.{i}", 9) for i in range(7)]
        bp = [("3", 3), ("9", 9), ("14", 14)]
        names = [("3", "GigabitEthernet1/0/3"), ("9", "GigabitEthernet1/0/9"), ("14", "GigabitEthernet1/0/14")]
        return build_snapshot(fdb, bp, names, [("874999990.3.1", "ap-hall")])

    def test_collect_matches_describe(self):
        snap = self.snap()
        c = SnmpSwitchConnector("switch", SW, CTX, client=type("W", (), {"snapshot": lambda self: snap})())
        b = c.collect()
        self.assertIs(b.extra["snapshot"], snap)
        self.assertEqual(b.stats, {"macs": len(snap.by_mac)})
        self.assertEqual({a.mac for a in b.attachments}, set(snap.by_mac))
        for a in b.attachments:
            self.assertIsInstance(a, Attachment)
            self.assertEqual((a.port, a.via), snap.describe(a.mac))
            self.assertEqual((a.link, a.device, a.source, a.observed_at, a.vlan), ("wired", "sw-rack", "switch", 1700000000, 110))
        by = {a.mac: a for a in b.attachments}
        self.assertEqual((by["02:00:5e:6b:27:6b"].port, by["02:00:5e:6b:27:6b"].uplink), ("GE1/0/14", False))
        self.assertEqual((by["de:ad:be:ef:00:01"].via, by["de:ad:be:ef:00:01"].uplink), ("ap-hall", True))
        self.assertEqual((by["01:02:03:04:05:00"].via, by["01:02:03:04:05:00"].uplink), ("7 devices", True))

    def test_errors_become_connectorerror(self):
        with self.assertRaises(ConnectorError) as cm:
            SnmpSwitchConnector("switch", SW, CTX, client=Raises(RuntimeError("snmp: timeout after 60 s"))).collect()
        self.assertEqual(str(cm.exception), "snmp: timeout after 60 s")
        with self.assertRaises(ConnectorError) as cm:
            SnmpSwitchConnector("switch", SW, CTX, client=Raises(RuntimeError())).collect()
        self.assertEqual(str(cm.exception), "RuntimeError")


class UnifiConnectorTests(unittest.TestCase):
    def test_collect_matches_parse_clients(self):
        wifi = parse_clients([{"mac": "AA:BB:CC:DD:EE:01", "essid": "HomeNet", "ap_mac": "02:11:22:33:44:66", "signal": -61, "radio": "na", "name": "Alex's iPad"},
                              {"mac": "aa:bb:cc:dd:ee:02", "is_wired": True, "name": "NAS"}],
                             [{"mac": "02:11:22:33:44:66", "name": "ap-hall"}])
        c = UnifiConnector("unifi", UF, CTX, client=type("U", (), {"clients": lambda self: wifi})())
        b = c.collect()
        self.assertIs(b.extra["wifi"], wifi)
        self.assertEqual(b.stats, {"clients": 2})
        by = {a.mac: a for a in b.attachments}
        self.assertEqual(by["aa:bb:cc:dd:ee:01"], Attachment(mac="aa:bb:cc:dd:ee:01", source="unifi", observed_at=1700000000, link="wifi",
                                                             ssid="HomeNet", ap="ap-hall", signal=-61, radio="5 GHz", alias="Alex's iPad"))
        self.assertEqual(by["aa:bb:cc:dd:ee:02"], Attachment(mac="aa:bb:cc:dd:ee:02", source="unifi", observed_at=1700000000, link="wired", alias="NAS"))

    def test_errors_become_connectorerror(self):
        c = UnifiConnector("unifi", UF, CTX, client=Raises(RuntimeError("unifi: HTTP 403")))
        for call in (c.collect, c.check):
            with self.assertRaises(ConnectorError) as cm:
                call()
            self.assertEqual(str(cm.exception), "unifi: HTTP 403")


class LegacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def cfg(self, env):
        saved = clean_env({"DATA_DIR": self.tmp.name, **env})
        try:
            return Config()
        finally:
            restore(saved)

    def test_only_fw1_by_default(self):
        conns = legacy_instances(self.cfg({"FW1_URL": "https://fw1.example.lan", "FW1_KEY": "k", "FW1_SECRET": "s"}))
        self.assertEqual(list(conns), ["fw1"])
        self.assertEqual(conns["fw1"].validate(), [])
        self.assertEqual(conns["fw1"].ignore_interfaces, ("wan", "lo0"))

    def test_all_three_with_settings_from_config(self):
        cfg = self.cfg({"FW1_URL": "https://fw1.example.lan", "FW1_KEY": "k", "FW1_SECRET": "s", "DHCP_BACKEND": "isc",
                        "FW1_VERIFY_TLS": "0", "IGNORE_INTERFACES": "wan,opt6", "PROXY_FOR_LAN": "1",
                        "SNMP_HOST": "10.0.0.2", "SNMP_NAME": "sw-rack", "SNMP_AUTH": "sha256", "SNMP_AUTH_KEY": "a" * 8, "SNMP_PRIV_KEY": "p" * 8,
                        "UNIFI_URL": "https://unifi.example.lan/", "UNIFI_USER": "ro", "UNIFI_PASSWORD": "pw", "UNIFI_SITE": "home"})
        conns = legacy_instances(cfg)
        self.assertEqual(list(conns), ["fw1", "switch", "unifi"])
        for c in conns.values():
            self.assertEqual(c.validate(), [], c)
        fw = conns["fw1"]
        self.assertEqual((fw.client.dhcp_backend, fw.ignore_interfaces, fw.settings["verify_tls"], fw.settings["proxy"]),
                         ("isc", ("wan", "opt6"), "0", "1"))
        sw = conns["switch"].client.cfg
        self.assertEqual((sw.snmp_host, sw.snmp_auth, sw.snmp_auth_key), ("10.0.0.2", "SHA256", "a" * 8))
        self.assertEqual(conns["switch"].settings["name"], "sw-rack")
        uf = conns["unifi"].client.cfg
        self.assertEqual((uf.unifi_url, uf.unifi_site, uf.unifi_user, uf.unifi_password, uf.unifi_verify_tls, uf.lan_proxy),
                         ("https://unifi.example.lan", "home", "ro", "pw", True, True))
        self.assertNotIn("pw", repr(uf)); self.assertNotIn("a" * 8, repr(sw))
        self.assertEqual(fw.ctx.redact("bad pw here"), "bad *** here")

    def test_injected_client_is_used(self):
        fake = FakeFw1([])
        conns = legacy_instances(self.cfg({"FW1_KEY": "k", "FW1_SECRET": "s"}), fw1_client=fake)
        self.assertIs(conns["fw1"].client, fake)
        self.assertEqual(conns["fw1"].collect(), Batch(stats={"leases": 2, "arp": 1, "reservations": 0}))


if __name__ == "__main__":
    unittest.main()
