import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leasewatch.switch import build_snapshot, short_ifname
from leasewatch.unifi import parse_clients
from leasewatch.fw1 import Fw1Client


class SwitchTests(unittest.TestCase):
    def test_build_snapshot_maps_mac_to_port_and_marks_uplinks(self):
        fdb = [("110.0.12.41.107.39.107", 14), ("110.222.173.190.239.0.1", 3)] + [(f"110.1.2.3.4.5.{i}", 3) for i in range(6)] + [("120.1.2.3.4.5.99", 51)]
        bp = [("3", 3), ("14", 14), ("51", 51)]
        names = [("3", "GigabitEthernet1/0/3"), ("14", "GigabitEthernet1/0/14"), ("51", "Ten-GigabitEthernet1/0/51")]
        lldp = [("874999990.3.1", "ap-hall"), ("1418625124.51.1", "")]
        s = build_snapshot(fdb, bp, names, lldp)
        self.assertEqual(s.describe("00:0c:29:6b:27:6b"), ("GE1/0/14", ""))
        self.assertEqual(s.describe("de:ad:be:ef:00:01"), ("GE1/0/3", "ap-hall"))   # LLDP neighbour -> uplink, via = AP name
        self.assertEqual(s.describe("01:02:03:04:05:63"), ("XGE1/0/51", ""))         # LLDP row with empty name is not a neighbour
        self.assertEqual(s.describe("ff:ff:ff:ff:ff:ff"), ("", ""))
        self.assertEqual(s.by_mac["00:0c:29:6b:27:6b"], (14, 110))
        self.assertTrue(s.ports[3].uplink); self.assertFalse(s.ports[14].uplink)

    def test_many_macs_without_lldp_is_an_uplink(self):
        fdb = [(f"110.1.2.3.4.5.{i}", 9) for i in range(7)]
        s = build_snapshot(fdb, [("9", 9)], [("9", "GigabitEthernet1/0/9")], [])
        self.assertEqual(s.describe("01:02:03:04:05:00"), ("GE1/0/9", "7 devices"))

    def test_short_names(self):
        self.assertEqual(short_ifname("Ten-GigabitEthernet1/0/50"), "XGE1/0/50"); self.assertEqual(short_ifname("Bridge-Aggregation1"), "BAGG1")


    def test_lldp_local_port_number_is_mapped_through_locport_id(self):
        # a switch whose lldpLocPortNum (3) is not the ifIndex (14): lldpLocPortId names the interface
        s = build_snapshot([("1.1.2.3.4.5.1", 14)], [("14", 14)], [("14", "GigabitEthernet1/0/14"), ("3", "GigabitEthernet1/0/3")],
                           [("1.3.1", "ap-hall")], locports=[("3", "GigabitEthernet1/0/14")])
        self.assertEqual(s.ports[14].neighbor, "ap-hall"); self.assertEqual(s.ports[3].neighbor, "")
        self.assertEqual(s.describe("01:02:03:04:05:01"), ("GE1/0/14", "ap-hall"))
        # without locport rows the number is used as the ifIndex (Comware)
        s = build_snapshot([], [], [("3", "GigabitEthernet1/0/3")], [("1.3.1", "ap-hall")])
        self.assertEqual(s.ports[3].neighbor, "ap-hall")

    def test_fdb_port_zero_is_skipped(self):
        s = build_snapshot([("1.170.187.204.221.238.2", 0)], [], [], [])
        self.assertEqual(s.describe("aa:bb:cc:dd:ee:02"), ("", ""))
        self.assertNotIn(0, s.ports)

    def test_one_mac_in_many_vlans_is_one_device(self):
        fdb = [(f"{v}.2.0.0.0.0.1", 9) for v in range(1, 7)]
        s = build_snapshot(fdb, [("9", 9)], [("9", " GigabitEthernet1/0/9 ")], [])
        self.assertEqual((s.ports[9].macs, s.ports[9].uplink), (1, False))
        self.assertEqual(s.describe("02:00:00:00:00:01"), ("GE1/0/9", ""))  # ifName whitespace stripped

    def test_bad_baseport_and_ifname_rows_are_skipped(self):
        s = build_snapshot([("1.2.0.0.0.0.1", 5)], [("x", 7), ("5", 14)], [("14", "GigabitEthernet1/0/14"), ("y", "junk")], [])
        self.assertEqual(s.describe("02:00:00:00:00:01"), ("GE1/0/14", ""))
        with self.assertLogs("leasewatch.switch", "WARNING"):
            build_snapshot([("1.2.0.0.0.0.1", 5)], [], [], [])


class WalkTests(unittest.TestCase):
    BASE = "1.3.6.1.2.1.31.1.1.1.1"
    MODS = ("pysnmp", "pysnmp.hlapi", "pysnmp.hlapi.v3arch", "pysnmp.hlapi.v3arch.asyncio")

    def setUp(self):
        import types
        self._saved = {k: sys.modules.get(k) for k in self.MODS}
        for k in self.MODS:
            sys.modules[k] = types.ModuleType(k)
        fake = sys.modules["pysnmp.hlapi.v3arch.asyncio"]
        fake.ContextData = lambda: None
        fake.ObjectIdentity = lambda oid: oid
        fake.ObjectType = lambda ident: ident
        self.fake = fake

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v

    def walk(self, replies):
        """replies: (oid, value, err_stat) per call; more calls than replies means the walk never ended."""
        import asyncio
        from leasewatch.switch import SwitchClient
        calls = []

        async def next_cmd(eng, user, tgt, ctx, cur):
            calls.append(cur)
            if len(calls) > len(replies):
                raise AssertionError("walk did not terminate")
            oid, val, stat = replies[len(calls) - 1]
            return None, stat, 0, [(oid, val)]
        self.fake.next_cmd = next_cmd
        return asyncio.run(SwitchClient(None)._walk(None, None, None, self.BASE)), calls

    def test_stops_when_the_oid_does_not_advance(self):
        b = self.BASE
        out, calls = self.walk([(b + ".9", "a", 0), (b + ".10", "b", 0), (b + ".10", "b", 0)])
        self.assertEqual(out, [("9", "a"), ("10", "b")])  # numeric order: .10 is after .9
        self.assertEqual(calls, [b, b + ".9", b + ".10"])

    def test_stops_at_end_of_mib_view(self):
        EndOfMibView = type("EndOfMibView", (), {})
        out, _ = self.walk([(self.BASE + ".1", EndOfMibView(), 0)])
        self.assertEqual(out, [])

    def test_error_status_raises(self):
        with self.assertRaisesRegex(RuntimeError, "status 2"):
            self.walk([(self.BASE + ".1", "a", 2)])

    def test_snapshot_timeout_has_a_message(self):
        from leasewatch.switch import SwitchClient
        c = SwitchClient(None)

        async def slow():
            raise TimeoutError()
        c._snapshot_async = slow
        with self.assertRaisesRegex(RuntimeError, "timeout after 60 s"):
            c.snapshot()


class Fw1Tests(unittest.TestCase):
    ARP = [{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.5", "intf": "igc1", "intf_description": "LAN", "manufacturer": "Acme"}]

    def client(self, backend, leases):
        c = Fw1Client("https://fw.example", "k", "s", dhcp_backend=backend)
        c._call = lambda path, body=None: (self.calls.append(path), {"rows": leases} if "lease" in path else {"rows": self.ARP})[1]
        return c

    def setUp(self): self.calls = []

    def test_isc_leases(self):
        rows = [{"mac": "AA:BB:CC:DD:EE:01", "address": "10.0.0.5", "client-hostname": "pc", "if": "lan", "if_descr": "LAN", "type": "static", "state": "active", "status": "online", "man": "Acme"},
                {"mac": "aa:bb:cc:dd:ee:09", "address": "10.0.0.9", "state": "free", "if": "lan"}]
        s, stats = self.client("isc", rows).sightings(("wan",))
        self.assertEqual(self.calls[0], "/api/dhcpv4/leases/searchLease")
        d = [x for x in s if x.source == "dhcp"]
        self.assertEqual([(x.mac, x.hostname, x.lease_type, x.online, x.vlan) for x in d], [("aa:bb:cc:dd:ee:01", "pc", "static", True, "LAN")])
        self.assertEqual(stats, {"leases": 2, "arp": 1})

    def test_kea_leases(self):
        rows = [{"hwaddr": "aa:bb:cc:dd:ee:01", "address": "10.0.0.5", "hostname": "pc.home.example.", "state": "0", "if": "lan", "if_descr": "LAN", "is_reserved": "1"},
                {"hwaddr": "aa:bb:cc:dd:ee:02", "address": "10.0.0.6", "hostname": "", "state": 0, "if": "lan", "if_descr": "LAN"},
                {"hwaddr": "aa:bb:cc:dd:ee:03", "address": "10.0.0.7", "state": "2", "if": "lan"},       # expired-reclaimed
                {"hwaddr": "aa:bb:cc:dd:ee:04", "address": "10.0.0.8", "state": "0", "if": "wan"}]      # ignored interface
        self.ARP = self.ARP + [{"mac": "aa:bb:cc:dd:ee:05", "ip": None, "intf": None, "intf_description": None}]  # bug 12: null fields
        s, _ = self.client("kea", rows).sightings(("wan",))
        self.assertIn("aa:bb:cc:dd:ee:05", {x.mac for x in s if x.source == "arp"})
        self.assertEqual(self.calls[0], "/api/kea/leases4/search")
        d = {x.mac: x for x in s if x.source == "dhcp"}
        self.assertEqual(sorted(d), ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])
        self.assertEqual((d["aa:bb:cc:dd:ee:01"].hostname, d["aa:bb:cc:dd:ee:01"].lease_type, d["aa:bb:cc:dd:ee:01"].vlan), ("pc.home.example", "static", "LAN"))
        self.assertEqual((d["aa:bb:cc:dd:ee:02"].lease_type, d["aa:bb:cc:dd:ee:02"].online), ("dynamic", False))


class UnifiTests(unittest.TestCase):
    def test_parse_clients(self):
        sta = [{"mac": "AA:BB:CC:DD:EE:01", "essid": "HomeNet", "ap_mac": "11:22:33:44:55:66", "signal": -61, "radio": "na", "channel": "44", "name": "Alex iPad"},
               {"mac": "aa:bb:cc:dd:ee:02", "is_wired": True, "name": "NAS"},
               {"mac": "aa:bb:cc:dd:ee:03", "essid": "Guests", "ap_mac": "zz", "rssi": 55, "radio": "ng", "channel": "auto"}, {"mac": "bad"}]
        dev = [{"mac": "11:22:33:44:55:66", "name": "ap-hall"}]
        r = parse_clients(sta, dev)
        a = r["aa:bb:cc:dd:ee:01"]; self.assertEqual((a.ssid, a.ap, a.signal, a.radio, a.channel, a.wired, a.alias), ("HomeNet", "ap-hall", -61, "5 GHz", 44, False, "Alex iPad"))
        b = r["aa:bb:cc:dd:ee:02"]; self.assertTrue(b.wired); self.assertEqual(b.ssid, ""); self.assertEqual(b.alias, "NAS")
        c = r["aa:bb:cc:dd:ee:03"]; self.assertEqual((c.signal, c.radio, c.channel, c.ap), (None, "2.4 GHz", None, ""))  # rssi is not dBm
        self.assertNotIn("bad", r)


if __name__ == "__main__":
    unittest.main()
