"""The IPv6 address of a device: the pick among candidates, stickiness, and NDP/DHCPv6 as enrichment only."""
import unittest
from _env import FW1_ENV, clean_env, restore
from _fixtures import row
from leasewatch.config import Config
from leasewatch.connectors import Batch, Sighting
from leasewatch.connectors.merge import MergeState, merge

NOW = 1_700_000_000
A = "02:00:00:00:00:01"
B = "02:00:00:00:00:02"
EUI = "2001:db8::ff:fe00:1"   # EUI-64 of A
TEMP = "2001:db8::abcd"
TEMP2 = "2001:db8::bcde"
ULA = "fd00::1"


def sight(mac=A, ip="10.0.0.5", kind="arp", presence=True, **kw):
    return Sighting(mac=mac, source="fw1", kind=kind, presence=presence, observed_at=NOW, ip=ip,
                    network=kw.pop("network", "Clients"), iface=kw.pop("iface", "opt3"), **kw)


def ndp(addr, mac=A, **kw):
    return sight(mac=mac, ip="", kind="ndp", presence=False, ip6=addr, **kw)


def dhcp6(addr, mac=A, **kw):
    return sight(mac=mac, ip="", kind="dhcp6", presence=False, ip6=addr, **kw)


class Base(unittest.TestCase):
    def setUp(self):
        self._env = clean_env(FW1_ENV)
        self.cfg = Config()

    def tearDown(self):
        restore(self._env)

    def merge(self, prev, sightings, **st):
        return merge({r["mac"]: r for r in prev}, {"fw1": Batch(sightings=list(sightings))}, self.cfg, NOW,
                     MergeState(**st))

    def pick(self, *v6):
        """ip6 of a known device listed by ARP and the given v6 sightings, with nothing stored."""
        return self.merge([row(A)], [sight(), *v6]).rows[A]["ip6"]


class Pick(Base):
    def test_gua_before_ula(self):
        self.assertEqual(self.pick(ndp(ULA), ndp(TEMP)), TEMP)

    def test_ula_before_other(self):
        self.assertEqual(self.pick(ndp("100::1:2"), ndp(ULA)), ULA)  # 100::/64: neither GUA nor ULA

    def test_eui64_before_temporary(self):
        self.assertEqual(self.pick(ndp(TEMP), ndp(EUI)), EUI)

    def test_lowest_value_last(self):
        self.assertEqual(self.pick(ndp(TEMP2), ndp(TEMP)), TEMP)

    def test_dhcp6_before_ndp_only(self):
        self.assertEqual(self.pick(ndp(EUI), dhcp6(TEMP2)), TEMP2)

    def test_dhcp6_ula_loses_to_ndp_gua(self):
        self.assertEqual(self.pick(dhcp6(ULA), ndp(TEMP)), TEMP)

    def test_new_row_takes_the_best(self):
        res = self.merge([], [sight(), ndp(TEMP), ndp(EUI)])
        self.assertEqual(res.rows[A]["ip6"], EUI)


class Sticky(Base):
    def test_eui64_replaces_stored_temporary(self):
        res = self.merge([row(A, ip6=TEMP)], [sight(), ndp(TEMP), ndp(EUI)])
        self.assertEqual(res.rows[A]["ip6"], EUI)

    def test_stored_temporary_kept_beside_another_temporary(self):
        res = self.merge([row(A, ip6=TEMP2)], [sight(), ndp(TEMP), ndp(TEMP2)])
        self.assertEqual(res.rows[A]["ip6"], TEMP2)

    def test_temporary_rotation_keeps_eui64(self):
        res = self.merge([row(A, ip6=EUI)], [sight(), ndp(EUI), ndp(TEMP2)])
        self.assertEqual(res.rows[A]["ip6"], EUI)

    def test_gua_replaces_stored_ula(self):
        res = self.merge([row(A, ip6=ULA)], [sight(), ndp(ULA), ndp(TEMP)])
        self.assertEqual(res.rows[A]["ip6"], TEMP)

    def test_dhcp6_replaces_stored_ndp_only(self):
        res = self.merge([row(A, ip6=EUI)], [sight(), ndp(EUI), dhcp6(TEMP2)])
        self.assertEqual(res.rows[A]["ip6"], TEMP2)

    def test_stored_gone_takes_best(self):
        res = self.merge([row(A, ip6=TEMP)], [sight(), ndp(TEMP2)])
        self.assertEqual(res.rows[A]["ip6"], TEMP2)

    def test_no_candidate_keeps_stored(self):
        res = self.merge([row(A, ip6=EUI)], [sight()])
        self.assertEqual(res.rows[A]["ip6"], EUI)

    def test_change_writes_no_event_or_history(self):
        res = self.merge([row(A, ip6=ULA)], [sight(), ndp(TEMP)])
        self.assertEqual(res.rows[A]["ip6"], TEMP)
        self.assertEqual([e for e in res.events if e[0] == A], [])
        self.assertEqual(res.history, [])


class Enrichment(Base):
    def test_v6_only_mac_creates_no_row(self):
        res = self.merge([row(A)], [sight(), ndp(TEMP, mac=B), dhcp6("2001:db8::2", mac=B, hostname="nas")])
        self.assertNotIn(B, res.rows)
        self.assertNotIn(B, res.new)
        self.assertEqual([e for e in res.events if e[0] == B], [])
        self.assertNotIn(B, [s[0] for s in res.seen])
        self.assertEqual(res.stats["new"], 0)

    def test_v6_only_mac_on_first_run_creates_no_row(self):
        res = self.merge([], [sight(), ndp(TEMP, mac=B)], first_run=True)
        self.assertEqual(set(res.rows), {A})

    def test_known_device_listed_only_by_ndp_is_updated_not_online(self):
        old = NOW - 7200
        prev = row(A, online=0, last_online=old, last_seen=old, sources="arp")
        res = self.merge([prev], [ndp(TEMP, network="Other", iface="opt9")])
        r = res.rows[A]
        self.assertEqual(r["ip6"], TEMP)
        self.assertEqual(r["online"], 0)
        self.assertEqual(r["last_online"], old)
        self.assertEqual(r["last_seen"], NOW)
        self.assertEqual((r["ip"], r["vlan"], r["iface"]), ("10.0.0.5", "Clients", "opt3"))
        self.assertEqual(r["sources"], "ndp")
        self.assertEqual(res.events, [])
        self.assertEqual(res.history, [])
        self.assertIn((A, "fw1", NOW, None), res.seen)

    def test_known_device_listed_only_by_dhcp6_changes_nothing_else(self):
        # its ARP entry and v4 lease dropped out while the DHCPv6 lease is still listed
        prev = row(A, hostname="laptop", lease_type="dynamic", sources="arp,dhcp", watch=1, watch_online=1)
        res = self.merge([prev], [dhcp6(EUI, hostname="laptop.example.lan", network="Other", iface="opt9")])
        r = res.rows[A]
        self.assertEqual((r["ip"], r["hostname"], r["lease_type"], r["vlan"], r["iface"]),
                         ("10.0.0.5", "laptop", "dynamic", "Clients", "opt3"))
        self.assertEqual(r["ip6"], EUI)
        self.assertEqual(r["last_seen"], NOW)
        self.assertEqual(r["last_online"], NOW - 60)
        self.assertEqual(r["online"], 1)  # still within the grace after its last sighting
        self.assertEqual([e for e in res.events if e[0] == A], [])
        self.assertEqual([h for h in res.history if h[0] == A], [])

    def test_known_device_listed_only_by_dhcp6_goes_offline_by_the_grace_rule(self):
        old = NOW - 7200
        prev = row(A, hostname="laptop", lease_type="dynamic", last_online=old, watch=1, watch_online=1)
        res = self.merge([prev], [dhcp6(EUI, hostname="laptop.example.lan")])
        self.assertEqual(res.rows[A]["online"], 0)
        self.assertEqual([k for m, k, _ in res.events if m == A], ["offline"])
        self.assertEqual(res.history, [])

    def test_split_row_listed_only_by_ndp_keeps_its_marker(self):
        res = self.merge([row(A, sources="", split_from=B)], [ndp(EUI)])
        self.assertEqual((res.rows[A]["sources"], res.rows[A]["ip6"]), ("", EUI))

    def test_sources_name_the_v6_kinds(self):
        res = self.merge([row(A)], [sight(), ndp(EUI), dhcp6(TEMP)])
        self.assertEqual(res.rows[A]["sources"], "arp,dhcp6,ndp")

    def test_dhcp6_hostname_is_last_fallback(self):
        res = self.merge([], [sight(hostname="from-arp"), dhcp6(TEMP, hostname="from-v6")])
        self.assertEqual(res.rows[A]["hostname"], "from-arp")
        res = self.merge([], [sight(), dhcp6(TEMP, hostname="from-v6")])
        self.assertEqual(res.rows[A]["hostname"], "from-v6")

    def test_ndp_vendor_is_last_fallback(self):
        res = self.merge([], [sight(vendor="ArpCo"), ndp(TEMP, vendor="NdpCo")])
        self.assertEqual(res.rows[A]["vendor"], "ArpCo")
        res = self.merge([], [sight(vendor=""), ndp(TEMP, vendor="NdpCo")])
        self.assertEqual(res.rows[A]["vendor"], "NdpCo")

    def test_ndp_does_not_place_a_device(self):
        res = self.merge([], [sight(kind="client", ip="", network="", iface=""), ndp(TEMP, network="Other", iface="opt9")])
        self.assertEqual((res.rows[A]["vlan"], res.rows[A]["iface"]), ("", ""))


if __name__ == "__main__":
    unittest.main()
