import unittest

from leasewatch.fw1 import Fw1Client, Sighting, dnsmasq_leases

DNSMASQ = "/api/dnsmasq/leases/search"
HOSTS = "/api/dnsmasq/settings/search_host"
KEA = "/api/kea/leases4/search"
KEA_RES = "/api/kea/dhcpv4/searchReservation"
ARP = "/api/diagnostics/interface/get_arp"
NDP = "/api/diagnostics/interface/get_ndp"
FAR = 4102444800  # 2100-01-01

MAC = "02:00:00:00:00:01"
ROW4 = {"address": "10.0.1.10", "hwaddr": MAC, "hostname": "pc1", "client_id": "01:02:00:00:00:00:01", "expire": FAR,
        "if": "opt1", "if_descr": "LAN"}
ROW6 = {"address": "2001:db8:1::10%igb1", "hwaddr": MAC, "hostname": "pc1v6", "client_id": "00:02:00:00:00:01:aa",
        "expire": FAR, "if": "opt1", "if_descr": "LAN"}
ROWS = [
    ROW4,
    ROW6,
    {**ROW6, "address": "2001:db8:1::11", "hwaddr": "*"},
    {**ROW6, "address": "2001:db8:1::12", "hwaddr": "255-00:03:00:01:02:00:00:00:00:02"},
    {**ROW6, "address": "2001:db8:1::13", "hwaddr": ""},
    {**ROW6, "address": "2001:db8:1::14", "expire": 1},
]


class StubClient(Fw1Client):
    def __init__(self, backend, rows):
        super().__init__("https://fw1.example.lan", "k", "s", dhcp_backend=backend)
        self.rows = rows
        self.paths: list[str] = []

    def _call(self, path, body=None):
        self.paths.append(path)
        if path in (DNSMASQ, KEA):
            return {"total": len(self.rows), "rows": self.rows}
        if path in (HOSTS, KEA_RES):
            return {"total": 0, "rows": []}
        if path == ARP:
            return []
        if path == NDP:
            return []  # get_ndp stub
        raise AssertionError(path)


class Dhcp6Tests(unittest.TestCase):
    def test_on_gives_one_dhcp_and_one_dhcp6(self):
        out, stats = StubClient("dnsmasq", ROWS).sightings((), ipv6=True)
        self.assertEqual([s.source for s in out], ["dhcp", "dhcp6"])
        d4, d6 = out
        self.assertEqual((d4.mac, d4.ip, d4.ip6, d4.hostname), (MAC, "10.0.1.10", "", "pc1"))
        self.assertEqual(d6, Sighting(
            mac=MAC, ip="", hostname="pc1v6", vendor="", vlan="LAN", iface="opt1", source="dhcp6",
            lease_type="dynamic", online=False, client_id="00:02:00:00:00:01:aa", label="", ip6="2001:db8:1::10"))
        self.assertEqual(stats["leases6"], 1)
        self.assertEqual(stats["leases"], len(ROWS))
        self.assertEqual(stats["ndp"], 0)

    def test_off_is_the_ipv4_list(self):
        c = StubClient("dnsmasq", ROWS)
        out, stats = c.sightings(())
        self.assertEqual(c.paths, [DNSMASQ, HOSTS, ARP])
        self.assertEqual(out, [Sighting(
            mac=MAC, ip="10.0.1.10", hostname="pc1", vendor="", vlan="LAN", iface="opt1", source="dhcp",
            lease_type="dynamic", online=False, client_id="01:02:00:00:00:00:01", label="")])
        self.assertEqual(stats, {"leases": len(ROWS), "arp": 0, "reservations": 0})
        self.assertNotIn("leases6", stats)
        self.assertEqual(StubClient("dnsmasq", ROWS).sightings((), ipv6=False), (out, stats))

    def test_parser_off_drops_every_ipv6_row(self):
        self.assertEqual([r["address"] for r in dnsmasq_leases(ROWS, 1700000000)], ["10.0.1.10"])
        on = dnsmasq_leases(ROWS, 1700000000, ipv6=True)
        self.assertEqual([(r["address"], r.get("ip6")) for r in on],
                         [("10.0.1.10", None), ("", "2001:db8:1::10%igb1")])

    def test_v6_lease_does_not_hide_a_reservation(self):
        class C(StubClient):
            def _call(self, path, body=None):
                if path == HOSTS:
                    return {"rows": [{"hwaddr": MAC, "host": "pc1", "ip": "10.0.1.10"}]}
                return super()._call(path, body)
        out, _ = C("dnsmasq", [ROW6]).sightings((), ipv6=True)
        self.assertEqual([(s.source, s.ip, s.ip6) for s in out],
                         [("dhcp", "10.0.1.10", ""), ("dhcp6", "", "2001:db8:1::10")])

    def test_ignored_interface_skips_the_v6_lease(self):
        out, stats = StubClient("dnsmasq", ROWS).sightings(("LAN",), ipv6=True)
        self.assertEqual((out, stats["leases6"]), ([], 0))

    def test_kea_ignores_the_flag(self):
        kea_rows = [{"hwaddr": MAC, "address": "10.0.1.10", "hostname": "pc1", "if_name": "opt1", "if_descr": "LAN",
                     "state": 0}]
        off = StubClient("kea", kea_rows).sightings(())
        on = StubClient("kea", kea_rows).sightings((), ipv6=True)
        self.assertEqual(on[0], off[0])
        self.assertEqual(on[1], {**off[1], "ndp": 0})
        self.assertNotIn("leases6", on[1])


if __name__ == "__main__":
    unittest.main()
