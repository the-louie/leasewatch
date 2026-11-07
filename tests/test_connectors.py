import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore
from leasewatch import snmp_profiles
from leasewatch.config import Config
from leasewatch.connectors import (API_VERSION, Attachment, Batch, Connector, ConnectorError, HostContext, Sighting,
                                   build_instance, instances_context, make_redactor)
from leasewatch.connectors.opnsense import OpnsenseConnector
from leasewatch.connectors.snmp_switch import SnmpSwitchConnector
from leasewatch.connectors.unifi import UnifiConnector
from leasewatch.fw1 import Fw1Error
from leasewatch.fw1 import Sighting as Fw1Sighting
from leasewatch.switch import build_snapshot
from leasewatch.unifi import parse_clients
from test_switch_profiles import FakePysnmp, FakeWalker, NoPysnmp

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

    def test_snmp_switch_version_counts_the_1_3_settings(self):
        # PORT, PRIV and the new AUTH names (1.3) are a connector change, as PLATFORM took unifi to 1.1
        self.assertEqual(SnmpSwitchConnector.describe().version, "1.1")

    def test_settings_cover_the_config_fields(self):
        self.assertEqual({s.key for s in OpnsenseConnector.describe().settings},
                         {"url", "key", "secret", "verify_tls", "dhcp_backend", "ignore_interfaces", "proxy"})
        self.assertEqual({s.key for s in SnmpSwitchConnector.describe().settings}, {"host", "port", "name", "user", "auth", "auth_key", "priv", "priv_key", "profile", "profile_file", "min_macs"})
        self.assertEqual({s.key for s in UnifiConnector.describe().settings}, {"url", "site", "user", "password", "verify_tls", "proxy", "platform"})

    def test_wrappers_are_connectors(self):
        for c in (OpnsenseConnector("fw1", FW1, CTX), SnmpSwitchConnector("switch", SW, CTX), UnifiConnector("unifi", UF, CTX)):
            self.assertIsInstance(c, Connector)
            self.assertEqual(c.validate(), [])
            c.close()

    def test_repr_hides_secrets(self):
        r = repr(OpnsenseConnector("fw1", {**FW1, "secret": "topsecret"}, CTX)) + repr(UnifiConnector("unifi", {**UF, "password": "topsecret"}, CTX))
        self.assertNotIn("topsecret", r)

    def test_repr_hides_secret_looking_keys(self):
        r = repr(SnmpSwitchConnector("switch", {**SW, "profile_file": "/run/secrets/sw.json", "api_token": "tok-1",
                                                "Some_Password": "pw-1", "KEYRING": "kr-1", "site": "visible-1"}, CTX))
        for hidden in ("/run/secrets/sw.json", "tok-1", "pw-1", "kr-1", "a" * 8, "p" * 8):
            self.assertNotIn(hidden, r)
        self.assertIn("visible-1", r)
        self.assertIn("'profile': ''", r)  # an empty value stays visible: nothing to hide

    def test_roles(self):
        self.assertEqual(UnifiConnector.describe().roles, frozenset({"controller"}))
        self.assertEqual(OpnsenseConnector.describe().roles, frozenset())
        self.assertEqual(SnmpSwitchConnector.describe().roles, frozenset())

    def test_redactor(self):
        self.assertEqual(make_redactor(["abcd-secret", "", "abcd-secret-long"])("x abcd-secret-long abcd-secret"), "x *** ***")
        self.assertEqual(make_redactor([])("abcd-secret"), "abcd-secret")


class ValidateTests(unittest.TestCase):
    def test_opnsense(self):
        p = OpnsenseConnector("fw1", {"url": "fw1.example.lan", "dhcp_backend": "dhcpd", "verify_tls": "maybe"}, CTX).validate()
        self.assertTrue("connector fw1 (opnsense): KEY is required" in p and "connector fw1 (opnsense): SECRET is required" in p, p)
        self.assertTrue(any(x.startswith("url must be a URL") for x in p), p)
        self.assertTrue("connector fw1 (opnsense): DHCP_BACKEND must be one of isc, kea, dnsmasq" in p, p)
        self.assertTrue(any(x.startswith("verify_tls must be a boolean") for x in p), p)
        self.assertEqual(OpnsenseConnector("fw1", {**FW1, "url": "https://user:pw@fw1.example.lan"}, CTX).validate(), ["url must not contain credentials"])
        self.assertEqual(OpnsenseConnector("fw1", {**FW1, "url": "https://[fw1"}, CTX).validate(), ["url is not a valid URL"])
        self.assertEqual(OpnsenseConnector("fw1", {**FW1, "dhcp_backend": "ISC"}, CTX).validate(), [])

    def test_switch(self):
        p = SnmpSwitchConnector("switch", {"host": "10.0.0.2", "auth": "md5"}, CTX).validate()
        self.assertTrue("connector switch (snmp_switch): AUTH_KEY is required" in p and "connector switch (snmp_switch): PRIV_KEY is required" in p, p)
        self.assertTrue("connector switch (snmp_switch): AUTH must be one of SHA, SHA256, SHA224, SHA384, SHA512" in p, p)
        self.assertEqual(SnmpSwitchConnector("switch", {**SW, "auth": "sha-256"}, CTX).validate(), [])

    def test_unifi(self):
        p = UnifiConnector("unifi", {"url": "https://unifi.example.lan/"}, CTX).validate()
        self.assertTrue("connector unifi (unifi): USER is required" in p and "connector unifi (unifi): PASSWORD is required" in p, p)
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


class SwitchProfileSettingTests(unittest.TestCase):
    def profile_file(self, data) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data if isinstance(data, str) else json.dumps(data))
        self.addCleanup(os.unlink, path)
        return path

    def test_profile_choices_are_the_builtin_profiles(self):
        s = {x.key: x for x in SnmpSwitchConnector.describe().settings}
        self.assertEqual(s["profile"].choices, snmp_profiles.BUILTIN)
        self.assertFalse(s["profile"].required or s["profile_file"].required or s["min_macs"].required)

    def test_resolution_order_file_then_name_then_detection(self):
        path = self.profile_file({"profile": "mine", "api_version": 1, "extends": "routeros"})
        c = SnmpSwitchConnector("switch", {**SW, "profile": "comware", "profile_file": path}, CTX)
        self.assertEqual((c.validate(), c.client.profile_name), ([], "mine"))
        self.assertEqual(SnmpSwitchConnector("switch", {**SW, "profile": "comware"}, CTX).client.profile_name, "comware")
        auto = SnmpSwitchConnector("switch", SW, CTX).client
        self.assertEqual((auto.profile, auto.min_macs), (None, None))
        self.assertEqual(SnmpSwitchConnector("switch", {**SW, "min_macs": "3"}, CTX).client.min_macs, 3)

    def test_validate_reports_bad_profile_settings_without_file_contents(self):
        p = SnmpSwitchConnector("switch", {**SW, "profile": "nope"}, CTX).validate()
        self.assertEqual(len(p), 1)
        self.assertIn("PROFILE must be one of standard, comware", p[0])
        self.assertEqual(SnmpSwitchConnector("switch", {**SW, "profile_file": "/nonexistent/x.json"}, CTX).validate(),
                         ["connector switch (snmp_switch): PROFILE_FILE cannot be read"])
        for data in ("{not json", {"profile": "TOPSECRET", "api_version": 1, "extends": "standard", "fdb": {"strategy": "TOPSECRET"}}):
            p = SnmpSwitchConnector("switch", {**SW, "profile_file": self.profile_file(data)}, CTX).validate()
            self.assertEqual(len(p), 1, p)
            self.assertIn("PROFILE_FILE is not a valid snmp profile", p[0])
            self.assertNotIn("TOPSECRET", p[0])
        for v in ("0", "x", "-1", "2.5"):
            self.assertEqual(SnmpSwitchConnector("switch", {**SW, "min_macs": v}, CTX).validate(),
                             ["connector switch (snmp_switch): MIN_MACS must be an integer >= 1"], v)

    def test_values_are_stripped_before_the_choices_check(self):
        c = SnmpSwitchConnector("switch", {**SW, "profile": " comware ", "auth": " sha256 ", "min_macs": " 3 "}, CTX)
        self.assertEqual(c.validate(), [])
        self.assertEqual((c.client.profile_name, c.settings["auth"], c.client.min_macs), ("comware", "SHA256", 3))

    def test_min_macs_unicode_digits(self):
        # "²" passes str.isdigit() but int() rejects it: a config problem, not a crash while building the connector
        self.assertEqual(SnmpSwitchConnector("switch", {**SW, "min_macs": "²"}, CTX).validate(),
                         ["connector switch (snmp_switch): MIN_MACS must be an integer >= 1"])
        self.assertEqual(SnmpSwitchConnector("switch", {**SW, "min_macs": "٣"}, CTX).client.min_macs, 3)

    def test_the_client_carries_the_instance_name_for_its_log_lines(self):
        self.assertEqual(SnmpSwitchConnector("core-sw", SW, CTX).client.name, "core-sw")

    def test_invalid_profile_settings_refuse_check_and_collect(self):
        snap = build_snapshot([], [], [], [])
        fake = type("W", (), {"snapshot": lambda self: snap, "probe": lambda self: ("", "")})
        for bad in ({"profile_file": "/nonexistent/x.json"}, {"profile": "nope"}, {"min_macs": "0"}):
            c = SnmpSwitchConnector("switch", {**SW, **bad}, CTX, client=fake())
            for call in (c.check, c.collect):
                with self.subTest(bad=bad, call=call.__name__), self.assertRaisesRegex(ConnectorError, "invalid profile settings"):
                    call()


class SwitchCheckTests(unittest.TestCase):
    """check() is one GET of sysObjectID/sysDescr through the real client against a fake agent."""

    def test_check_is_one_get_and_no_walk(self):
        c = SnmpSwitchConnector("switch", SW, CTX)
        with FakePysnmp(FakeWalker("comware")) as fake:
            self.assertIsNone(c.check())
        self.assertEqual([k for k, *_ in fake.calls], ["get"])
        self.assertEqual(c.client.profile_name, "")  # a probe does not fix the profile

    def test_check_errors_are_ui_safe_connectorerrors(self):
        c = SnmpSwitchConnector("switch", SW, CTX)
        with FakePysnmp(FakeWalker("comware")):
            async def get_cmd(eng, user, tgt, ctx, *oids):
                return "No SNMP response received before timeout", 0, 0, []
            sys.modules["pysnmp.hlapi.v3arch.asyncio"].get_cmd = get_cmd
            with self.assertRaises(ConnectorError) as cm:
                c.check()
        self.assertEqual(str(cm.exception), "snmp get sysObjectID: No SNMP response received before timeout")
        self.assertNotIn("a" * 8, str(cm.exception))
        with NoPysnmp(), self.assertRaisesRegex(ConnectorError, "^missing dependency pysnmp$"):
            c.check()


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
        self.assertEqual(b.stats, {"macs": len(snap.by_mac), "strategy": "qbridge"})  # strategy for conn.<name>.* meta
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

    def test_every_exception_becomes_connectorerror(self):
        own = ConnectorError("snmp: own text")
        probe = lambda exc: type("P", (), {"probe": lambda self: (_ for _ in ()).throw(exc), "snapshot": lambda self: (_ for _ in ()).throw(exc)})()
        for exc, text in ((ValueError("bad oid value"), "bad oid value"), (KeyError(), "KeyError"), (OSError(), "OSError"),
                          (ImportError("No module named 'pysnmp'"), "missing dependency pysnmp"), (own, "snmp: own text")):
            c = SnmpSwitchConnector("switch", SW, CTX, client=probe(exc))
            for call in (c.check, c.collect):
                with self.subTest(exc=type(exc).__name__, call=call.__name__), self.assertRaises(ConnectorError) as cm:
                    call()
                self.assertEqual(str(cm.exception), text)
                if exc is own:
                    self.assertIs(cm.exception, own)  # passed through, not wrapped

    def test_pysnmp_errors_lose_the_host(self):
        PySnmpError = type("PySnmpError", (Exception,), {})
        exc = PySnmpError("Bad IPv4/UDP transport address 10.0.0.2@161: [Errno -2] Name or service not known")
        c = SnmpSwitchConnector("switch", SW, CTX, client=type("P", (), {"probe": lambda self: (_ for _ in ()).throw(exc),
                                                                         "snapshot": lambda self: (_ for _ in ()).throw(exc)})())
        for call in (c.check, c.collect):
            with self.subTest(call=call.__name__), self.assertRaises(ConnectorError) as cm:
                call()
            self.assertEqual(str(cm.exception), "Bad IPv4/UDP transport address <host>@161: [Errno -2] Name or service not known")
            self.assertIs(cm.exception.__cause__, exc)

    def test_error_masks_every_spelling_of_host_and_user_but_only_whole_names(self):
        def err(settings, text):
            c = SnmpSwitchConnector("switch", {**SW, **settings}, CTX, client=Raises(RuntimeError(text)))
            with self.assertRaises(ConnectorError) as cm:
                c.collect()
            return str(cm.exception)
        # a host under 3 characters is not masked: "1" would garble every number
        self.assertEqual(err({"host": "1"}, "port 1 at 10.0.0.1"), "port 1 at 10.0.0.1")
        self.assertEqual(err({}, "Bad address 10.0.0.2@161, not 10.0.0.25 or 110.0.0.2"), "Bad address <host>@161, not 10.0.0.25 or 110.0.0.2")
        self.assertEqual(err({"host": "FE80::0002"}, "Bad address fe80::2@161 (fe80:0000:0000:0000:0000:0000:0000:0002), not fe80::2:5"),
                         "Bad address <host>@161 (<host>), not fe80::2:5")
        self.assertEqual(err({"host": "SW-HALL.example.lan."}, "no such host sw-hall.example.lan@161 nor SW-HALL.example.lan."),
                         "no such host <host>@161 nor <host>")  # the FQDN root dot is part of the name
        self.assertEqual(err({"user": "netmon"}, "unknown user name netmon (usmStatsUnknownUserNames), not netmonitor"),
                         "unknown user name <user> (usmStatsUnknownUserNames), not netmonitor")

    def test_key_that_is_part_of_the_host_does_not_expose_the_host(self):
        c = SnmpSwitchConnector("switch", {**SW, "auth_key": "0.0"}, CTX, client=Raises(RuntimeError()))
        self.assertEqual(c.redact("Bad address 10.0.0.2@161"), "Bad address <host>@161")

    def test_short_key_is_not_masked_but_a_4_char_key_is(self):
        c = SnmpSwitchConnector("switch", {**SW, "priv_key": "s"}, CTX, client=Raises(RuntimeError()))
        self.assertEqual(c.redact("snmp timeout k3y"), "snmp timeout k3y")
        c = SnmpSwitchConnector("switch", {**SW, "priv_key": "k3yz"}, CTX, client=Raises(RuntimeError()))
        self.assertEqual(c.redact("snmp timeout k3yz"), "snmp timeout ***")

    def test_json_escaped_key_is_masked(self):
        key = 'au"th\\K3y'
        c = SnmpSwitchConnector("switch", {**SW, "auth_key": key}, CTX, client=Raises(RuntimeError()))
        out = c.redact("body " + json.dumps({"k": key}))
        self.assertNotIn("K3y", out)

    def test_device_names_failure_becomes_connectorerror(self):
        ctx = HostContext(now=lambda: 1700000000, device_names=lambda: {}["x"])
        snap = self.snap()
        c = SnmpSwitchConnector("switch", SW, ctx, client=type("W", (), {"snapshot": lambda self: snap})())
        with self.assertRaises(ConnectorError) as cm:
            c.collect()
        self.assertEqual(str(cm.exception), "'x'")


class UnifiConnectorTests(unittest.TestCase):
    def test_collect_matches_parse_clients(self):
        wifi = parse_clients([{"mac": "AA:BB:CC:DD:EE:01", "essid": "HomeNet", "ap_mac": "02:11:22:33:44:66", "signal": -61, "radio": "na", "name": "Alex's iPad"},
                              {"mac": "aa:bb:cc:dd:ee:02", "is_wired": True, "name": "NAS"}],
                             [{"mac": "02:11:22:33:44:66", "name": "ap-hall"}])
        c = UnifiConnector("unifi", UF, CTX, client=type("U", (), {"clients": lambda self: wifi})())
        b = c.collect()
        self.assertEqual(b.stats, {"clients": 2})
        by = {a.mac: a for a in b.attachments}
        self.assertEqual(by["aa:bb:cc:dd:ee:01"], Attachment(mac="aa:bb:cc:dd:ee:01", source="unifi", observed_at=1700000000, link="wifi", present=True,
                                                             ssid="HomeNet", ap="ap-hall", signal=-61, radio="5 GHz", alias="Alex's iPad"))
        self.assertEqual(by["aa:bb:cc:dd:ee:02"], Attachment(mac="aa:bb:cc:dd:ee:02", source="unifi", observed_at=1700000000, link="wired", present=True, alias="NAS"))

    def test_errors_become_connectorerror(self):
        c = UnifiConnector("unifi", UF, CTX, client=Raises(RuntimeError("unifi: HTTP 403")))
        for call in (c.collect, c.check):
            with self.assertRaises(ConnectorError) as cm:
                call()
            self.assertEqual(str(cm.exception), "unifi: HTTP 403")

    def test_every_exception_becomes_connectorerror(self):
        own = ConnectorError("unifi: own text")
        for exc, text in ((ValueError("bad json"), "bad json"), (KeyError(), "KeyError"), (TypeError(), "TypeError"),
                          (own, "unifi: own text")):
            c = UnifiConnector("unifi", UF, CTX, client=Raises(exc))
            for call in (c.check, c.collect):
                with self.subTest(exc=type(exc).__name__, call=call.__name__), self.assertRaises(ConnectorError) as cm:
                    call()
                self.assertEqual(str(cm.exception), text)
                if exc is own:
                    self.assertIs(cm.exception, own)

    def test_bad_record_from_the_client_becomes_connectorerror(self):
        c = UnifiConnector("unifi", UF, CTX, client=type("U", (), {"clients": lambda self: {"02:00:00:00:00:01": None}})())
        with self.assertRaises(ConnectorError) as cm:
            c.collect()
        self.assertEqual(str(cm.exception), "'NoneType' object has no attribute 'wired'")


class InstanceSettingsTests(unittest.TestCase):
    """LW_CONNECTOR__<NAME>__<KEY> settings reach the clients the connectors wrap."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def instances(self, env, client=None):
        saved = clean_env({"DATA_DIR": self.tmp.name, **env})
        try:
            specs = Config().instances
        finally:
            restore(saved)
        ctx = instances_context(specs)
        return {sp.name: build_instance(sp, ctx, client=client if sp.name == "fw1" else None) for sp in specs}

    def test_fw1_defaults(self):
        conns = self.instances(FW1_ENV)
        self.assertEqual(list(conns), ["fw1"])
        self.assertEqual(conns["fw1"].validate(), [])
        self.assertEqual(conns["fw1"].ignore_interfaces, ("wan", "lo0"))
        self.assertEqual(conns["fw1"].client.dhcp_backend, "kea")

    def test_all_three_with_their_settings(self):
        conns = self.instances({
            **FW1_ENV, "LW_CONNECTORS": "fw1,switch,unifi", "LW_CONNECTOR__FW1__DHCP_BACKEND": "isc",
            "LW_CONNECTOR__FW1__VERIFY_TLS": "0", "LW_CONNECTOR__FW1__IGNORE_INTERFACES": "wan,opt6", "LW_CONNECTOR__FW1__PROXY": "1",
            "LW_CONNECTOR__SWITCH__TYPE": "snmp_switch", "LW_CONNECTOR__SWITCH__HOST": "10.0.0.2", "LW_CONNECTOR__SWITCH__NAME": "sw-rack",
            "LW_CONNECTOR__SWITCH__AUTH": "sha256", "LW_CONNECTOR__SWITCH__AUTH_KEY": "a" * 8, "LW_CONNECTOR__SWITCH__PRIV_KEY": "p" * 8,
            "LW_CONNECTOR__UNIFI__TYPE": "unifi", "LW_CONNECTOR__UNIFI__URL": "https://unifi.example.lan/",
            "LW_CONNECTOR__UNIFI__USER": "ro", "LW_CONNECTOR__UNIFI__PASSWORD": "pw-secret", "LW_CONNECTOR__UNIFI__SITE": "home",
            "LW_CONNECTOR__UNIFI__PROXY": "1"})
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
                         ("https://unifi.example.lan", "home", "ro", "pw-secret", True, True))
        self.assertNotIn("pw-secret", repr(uf)); self.assertNotIn("a" * 8, repr(sw))
        self.assertEqual(fw.ctx.redact("bad pw-secret here"), "bad *** here")

    def test_injected_client_is_used(self):
        fake = FakeFw1([])
        conns = self.instances(FW1_ENV, client=fake)
        self.assertIs(conns["fw1"].client, fake)
        self.assertEqual(conns["fw1"].collect(), Batch(stats={"leases": 2, "arp": 1, "reservations": 0}))

if __name__ == "__main__":
    unittest.main()
