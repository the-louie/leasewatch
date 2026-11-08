import unittest

from leasewatch.connectors import HostContext
from leasewatch.connectors.opnsense import OpnsenseConnector
from leasewatch.fw1 import Fw1Client, Fw1Error

CTX = HostContext(now=lambda: 1700000000)
FW1 = {"url": "https://fw1.example.lan", "key": "k", "secret": "s"}
LEASE = "/api/dhcpv4/leases/searchLease"
ARP = "/api/diagnostics/interface/get_arp"
NDP = "/api/diagnostics/interface/get_ndp"

LEASES = {"total": 1, "rows": [{"mac": "02:00:00:00:00:01", "address": "10.0.1.10", "hostname": "pc1", "man": "",
                                "if": "opt1", "if_descr": "LAN", "type": "dynamic", "status": "online"}]}
ARP_ROWS = [
    {"mac": "02:00:00:00:00:01", "ip": "10.0.1.10", "intf": "igb1", "intf_description": "LAN", "manufacturer": "",
     "hostname": "", "permanent": False, "expired": False},
    {"mac": "02:00:00:00:00:fe", "ip": "10.0.1.1", "intf": "igb1", "intf_description": "LAN", "manufacturer": "",
     "hostname": "", "permanent": True, "expired": False},  # the firewall itself
    {"mac": "02:00:00:00:00:02", "ip": "10.0.2.20", "intf": "igb2", "intf_description": "IOT", "manufacturer": "Acme",
     "hostname": "", "permanent": False, "expired": False},
]
NDP_ROWS = [
    {"ip": "2001:db8:1::10", "mac": "02:00:00:00:00:01", "intf": "igb1", "manufacturer": "Acme", "intf_description": "LAN"},
    {"ip": "fd00:2::20", "mac": "02:00:00:00:00:02", "intf": "igb2", "manufacturer": "", "intf_description": "IOT"},
    {"ip": "fe80::1%igb1", "mac": "02:00:00:00:00:03", "intf": "igb1", "manufacturer": "", "intf_description": "LAN"},
    {"ip": "fe80::4", "mac": "02:00:00:00:00:04", "intf": "igb1", "manufacturer": "", "intf_description": "LAN"},
    {"ip": "2001:db8:1::5", "mac": "(incomplete)", "intf": "igb1", "manufacturer": "", "intf_description": "LAN"},
    {"ip": "2001:db8:9::6", "mac": "02:00:00:00:00:06", "intf": "igb0", "manufacturer": "", "intf_description": "WAN"},
    {"ip": "2001:db8:1::1", "mac": "02:00:00:00:00:fe", "intf": "igb1", "manufacturer": "", "intf_description": "LAN"},
    {"ip": "not-an-address", "mac": "02:00:00:00:00:07", "intf": "igb1", "manufacturer": "", "intf_description": "LAN"},
    {"ip": "10.0.1.8", "mac": "02:00:00:00:00:08", "intf": "igb1", "manufacturer": "", "intf_description": "LAN"},
]
IGNORE = ("wan", "lo0")


class StubClient(Fw1Client):
    """Fw1Client whose _call records the paths and answers from fixtures; ndp_fail makes get_ndp raise."""
    def __init__(self, ndp=NDP_ROWS, ndp_fail=False):
        super().__init__("https://fw1.example.lan", "k", "s", dhcp_backend="isc")
        self.paths: list[str] = []
        self.ndp, self.ndp_fail = ndp, ndp_fail

    def _call(self, path, body=None):
        self.paths.append(path)
        if path == LEASE:
            return LEASES
        if path == ARP:
            return ARP_ROWS
        if path == NDP:
            if self.ndp_fail:
                raise Fw1Error("fw1 " + path + ": HTTP 403")
            return self.ndp
        raise AssertionError(path)


class NdpOffTests(unittest.TestCase):
    def test_off_makes_no_call_and_keeps_the_output(self):
        before, before_stats = StubClient().sightings(IGNORE)  # the call shape every existing caller uses
        c = StubClient()
        out, stats = c.sightings(IGNORE, ipv6=False)
        self.assertNotIn(NDP, c.paths)
        self.assertEqual(c.paths, [LEASE, ARP])
        self.assertEqual(out, before)
        self.assertEqual(stats, before_stats)
        self.assertEqual(stats, {"leases": 1, "arp": 3})
        self.assertEqual([(s.source, s.mac) for s in out],
                         [("dhcp", "02:00:00:00:00:01"), ("arp", "02:00:00:00:00:01"), ("arp", "02:00:00:00:00:02")])


class NdpOnTests(unittest.TestCase):
    def test_filters_keep_the_gua_and_ula_rows(self):
        c = StubClient()
        out, stats = c.sightings(IGNORE, ipv6=True)
        self.assertIn(NDP, c.paths)
        ndp = [s for s in out if s.source == "ndp"]
        self.assertEqual([(s.mac, s.ip6, s.vlan, s.iface, s.vendor) for s in ndp],
                         [("02:00:00:00:00:01", "2001:db8:1::10", "LAN", "igb1", "Acme"),
                          ("02:00:00:00:00:02", "fd00:2::20", "IOT", "igb2", "")])
        for s in ndp:
            self.assertEqual((s.ip, s.online, s.hostname, s.lease_type), ("", False, "", ""))
        self.assertEqual(stats, {"leases": 1, "arp": 3, "ndp": 2})
        off, _ = StubClient().sightings(IGNORE)
        self.assertEqual([s for s in out if s.source != "ndp"], off)

    def test_failure_keeps_ipv4_and_flags_it(self):
        c = StubClient(ndp_fail=True)
        off, off_stats = StubClient().sightings(IGNORE)
        with self.assertLogs("leasewatch.fw1", "WARNING") as logs:
            out, stats = c.sightings(IGNORE, ipv6=True)
        self.assertEqual(len(logs.records), 1)
        self.assertEqual(out, off)
        self.assertEqual(stats, {**off_stats, "ndp_unavailable": 1})
        self.assertNotIn("ndp", stats)

    def test_warning_once_per_spell(self):
        c = StubClient(ndp_fail=True)
        with self.assertLogs("leasewatch.fw1", "WARNING") as logs:
            c.sightings(IGNORE, ipv6=True)
            c.sightings(IGNORE, ipv6=True)  # still down: no second warning
            c.ndp_fail = False
            c.sightings(IGNORE, ipv6=True)  # back
            c.ndp_fail = True
            c.sightings(IGNORE, ipv6=True)  # a new spell
        self.assertEqual(len(logs.records), 2)

    def test_bad_shape_is_unavailable(self):
        with self.assertLogs("leasewatch.fw1", "WARNING"):
            _, stats = StubClient(ndp={"status": "error"}).sightings(IGNORE, ipv6=True)
        self.assertEqual(stats.get("ndp_unavailable"), 1)


class Recorder:
    def __init__(self, client): self.client, self.calls = client, []
    def sightings(self, *a, **k):
        self.calls.append((a, k))
        return self.client.sightings(*a, **k)
    def arp_raw(self): return self.client.arp_raw()


class ConnectorTests(unittest.TestCase):
    def test_ipv6_on_maps_ndp_sightings(self):
        rec = Recorder(StubClient())
        batch = OpnsenseConnector("fw1", {**FW1, "ipv6": "1"}, CTX, client=rec).collect()
        self.assertEqual(rec.calls, [((("wan", "lo0"),), {"ipv6": True})])
        ndp = [s for s in batch.sightings if s.kind == "ndp"]
        self.assertEqual([(s.mac, s.ip6, s.ip, s.presence, s.network, s.iface, s.source) for s in ndp],
                         [("02:00:00:00:00:01", "2001:db8:1::10", "", False, "LAN", "igb1", "fw1"),
                          ("02:00:00:00:00:02", "fd00:2::20", "", False, "IOT", "igb2", "fw1")])
        self.assertEqual(batch.stats["ndp"], 2)

    def test_default_is_off(self):
        rec = Recorder(StubClient())
        c = OpnsenseConnector("fw1", FW1, CTX, client=rec)
        self.assertEqual(c.settings["ipv6"], "0")
        batch = c.collect()
        # no keyword means the client's ipv6=False default
        self.assertEqual(rec.calls, [((("wan", "lo0"),), {})])
        self.assertNotIn(NDP, rec.client.paths)
        self.assertFalse([s for s in batch.sightings if s.kind == "ndp"])

    def test_validate_rejects_a_non_boolean(self):
        self.assertEqual(OpnsenseConnector("fw1", {**FW1, "ipv6": "yes"}, CTX).validate(), [])
        problems = OpnsenseConnector("fw1", {**FW1, "ipv6": "maybe"}, CTX).validate()
        self.assertTrue(any(p.startswith("ipv6 ") for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
