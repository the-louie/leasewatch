"""The stable IPv6 address of a device (ip6_stable): the pick, the class rule, renumbering, events and history."""
import unittest
from test_merge_ip6 import A, EUI, TEMP, TEMP2, ULA, NOW, Base, dhcp6, ndp, sight
from _fixtures import row
from leasewatch import collector
from leasewatch.connectors.merge import Fw1Sighting, _pick_ip6_stable

B = "02:00:00:00:00:02"
EUI1 = "2001:db8:1::ff:fe00:1"  # EUI-64 of A in 2001:db8:1::/64
EUI2 = "2001:db8:2::ff:fe00:1"  # EUI-64 of A in 2001:db8:2::/64
ULA_EUI = "fd00::ff:fe00:1"      # EUI-64 of A in fd00::/64
DHCP = "2001:db8::1:20"          # an IA_NA address
TEMP1 = "2001:db8:1::abcd"       # a temporary address in 2001:db8:1::/64


def ev(res, mac=A):
    return [(k, d) for m, k, d in res.events if m == mac]


def hist(res, mac=A):
    return [h for m, h in res.history if m == mac]


class Pick(Base):
    def stable(self, *v6):
        return self.merge([row(A)], [sight(), *v6]).rows[A]["ip6_stable"]

    def test_eui64_not_temporary(self):
        self.assertEqual(self.stable(ndp(TEMP), ndp(EUI)), EUI)

    def test_temporary_alone_is_no_stable_address(self):
        self.assertEqual(self.stable(ndp(TEMP), ndp(TEMP2)), "")

    def test_dhcp6_before_eui64(self):
        self.assertEqual(self.stable(ndp(EUI), dhcp6(DHCP)), DHCP)

    def test_gua_before_ula(self):
        self.assertEqual(self.stable(ndp(ULA_EUI), ndp(EUI)), EUI)
        self.assertEqual(self.stable(dhcp6(ULA), ndp(EUI)), EUI)

    def test_lowest_value_within_the_class(self):
        self.assertEqual(self.stable(ndp(EUI2), ndp(EUI1)), EUI1)

    def test_eui64_of_any_listed_mac(self):
        ss = [Fw1Sighting(mac=A, ip="", hostname="", vendor="", vlan="", iface="", source="ndp", lease_type="",
                          online=False, ip6=a) for a in (EUI, TEMP)]
        self.assertEqual(list(_pick_ip6_stable((B, A), ss)), [EUI])
        self.assertEqual(list(_pick_ip6_stable((B,), ss)), [])


class ClassRule(Base):
    def test_worse_class_never_replaces(self):
        res = self.merge([row(A, ip6_stable=EUI)], [sight(), ndp(ULA_EUI)])
        self.assertEqual(res.rows[A]["ip6_stable"], EUI)
        self.assertEqual((ev(res), hist(res)), ([], []))

    def test_eui64_does_not_replace_stored_dhcp6(self):
        res = self.merge([row(A, ip6_stable=DHCP)], [sight(), ndp(EUI)])
        self.assertEqual(res.rows[A]["ip6_stable"], DHCP)
        self.assertEqual((ev(res), hist(res)), ([], []))

    def test_better_class_replaces_with_event(self):
        res = self.merge([row(A, ip6_stable=ULA_EUI)], [sight(), ndp(ULA_EUI), ndp(EUI)])
        self.assertEqual(res.rows[A]["ip6_stable"], EUI)
        self.assertEqual(ev(res), [("ip6", f"{ULA_EUI} -> {EUI}")])

    def test_no_candidate_keeps_stored(self):
        res = self.merge([row(A, ip6_stable=EUI)], [sight(), ndp(TEMP)])
        self.assertEqual(res.rows[A]["ip6_stable"], EUI)
        self.assertEqual((ev(res), hist(res)), ([], []))


class Events(Base):
    def test_first_stable_address_writes_history_not_event(self):
        res = self.merge([row(A)], [sight(), ndp(EUI)])
        self.assertEqual(ev(res), [])
        self.assertEqual(hist(res), [{"ip": "10.0.0.5", "hostname": "", "vlan": "Clients", "lease_type": "", "ip6": EUI}])
        self.assertEqual(res.stats["changed"], 1)

    def test_temporary_rotation_writes_nothing(self):
        res = self.merge([row(A, ip6=TEMP, ip6_stable=EUI)], [sight(), ndp(EUI), ndp(TEMP2)])
        self.assertEqual(res.rows[A]["ip6_stable"], EUI)
        self.assertEqual((ev(res), hist(res), res.stats["changed"]), ([], [], 0))

    def test_eui64_temporary_flip_writes_nothing(self):
        prev = row(A, ip6=TEMP, ip6_stable=EUI)
        for listed in ([ndp(EUI), ndp(TEMP)], [ndp(TEMP)], [ndp(EUI), ndp(TEMP)]):
            res = self.merge([prev], [sight(), *listed])
            self.assertEqual(res.rows[A]["ip6_stable"], EUI)
            self.assertEqual((ev(res), hist(res)), ([], []))
            prev = res.rows[A]

    def test_ip6_is_no_mail_kind(self):
        self.assertNotIn("ip6", collector.WATCH_KINDS)
        self.assertNotIn("ip6", collector.ALERT_KINDS)


class Renumbering(Base):
    def renumber(self, old, new):
        res = self.merge([row(A, ip6_stable=old)], [sight(), ndp(old), ndp(new)])  # the old one deprecated, still listed
        self.assertEqual(res.rows[A]["ip6_stable"], old)
        self.assertEqual((ev(res), hist(res)), ([], []))
        res = self.merge([res.rows[A]], [sight(), ndp(new)])
        self.assertEqual(res.rows[A]["ip6_stable"], new)
        self.assertEqual(ev(res), [("ip6", f"{old} -> {new}")])
        self.assertEqual([h["ip6"] for h in hist(res)], [new])
        res = self.merge([res.rows[A]], [sight(), ndp(new)])
        self.assertEqual((ev(res), hist(res)), ([], []))

    def test_new_prefix_higher(self):
        self.renumber(EUI1, EUI2)

    def test_new_prefix_lower(self):
        self.renumber(EUI2, EUI1)

    def test_two_live_prefixes_do_not_flap(self):
        # NDP ages the device's entry for one of two live prefixes out now and then; the stored prefix is still
        # listed this poll, by the device's own temporary address or by another device
        for other in ([ndp(TEMP1)], [ndp(TEMP1), ndp(TEMP)], [ndp(EUI_B1, mac=B)]):
            with self.subTest(other=other):
                r = row(A, ip6_stable=EUI1)
                for addr in (EUI2, EUI1, EUI2, EUI1):
                    res = self.merge([r], [sight(), ndp(addr), *other])
                    r = res.rows[A]
                    self.assertEqual((r["ip6_stable"], ev(res)), (EUI1, []))

    def test_old_prefix_on_another_device_keeps_the_stored_one(self):
        res = self.merge([row(A, ip6_stable=EUI1)], [sight(), ndp(EUI2), ndp(EUI_B1, mac=B)])
        self.assertEqual((res.rows[A]["ip6_stable"], ev(res), hist(res)), (EUI1, [], []))
        res = self.merge([res.rows[A]], [sight(), ndp(EUI2), ndp(EUI_B2, mac=B)])
        self.assertEqual(res.rows[A]["ip6_stable"], EUI2)
        self.assertEqual(ev(res), [("ip6", f"{EUI1} -> {EUI2}")])
        self.assertEqual([h["ip6"] for h in hist(res)], [EUI2])


class Dhcp6Lease(Base):
    NEW = "2001:db8::1:99"

    def test_unlisted_lease_gives_way_to_a_new_lease_in_the_same_prefix(self):
        res = self.merge([row(A, ip6_stable=DHCP)], [sight(), dhcp6(self.NEW)])
        self.assertEqual(res.rows[A]["ip6_stable"], self.NEW)
        self.assertEqual(ev(res), [("ip6", f"{DHCP} -> {self.NEW}")])
        self.assertEqual([h["ip6"] for h in hist(res)], [self.NEW])
        res = self.merge([res.rows[A]], [sight(), dhcp6(self.NEW)])
        self.assertEqual((ev(res), hist(res)), ([], []))

    def test_listed_lease_stays_beside_a_second_lease(self):
        res = self.merge([row(A, ip6_stable=DHCP)], [sight(), dhcp6(DHCP), dhcp6("2001:db8::1:10")])
        self.assertEqual(res.rows[A]["ip6_stable"], DHCP)
        self.assertEqual((ev(res), hist(res)), ([], []))

    def test_unlisted_lease_stays_against_a_worse_class(self):
        res = self.merge([row(A, ip6_stable=DHCP)], [sight(), ndp(EUI)])
        self.assertEqual(res.rows[A]["ip6_stable"], DHCP)
        self.assertEqual((ev(res), hist(res)), ([], []))


class History(Base):
    def test_new_row_takes_the_stable_candidate(self):
        res = self.merge([], [sight(), ndp(TEMP), ndp(EUI)])
        self.assertEqual(res.rows[A]["ip6_stable"], EUI)
        self.assertEqual([h["ip6"] for h in hist(res)], [EUI])
        self.assertEqual([k for k, _ in ev(res)], ["new"])

    def test_every_row_carries_ip6(self):
        res = self.merge([row(A, ip6_stable=EUI)], [sight(ip="10.0.0.6")])
        self.assertEqual([h["ip6"] for h in hist(res)], [EUI])
        res = self.merge([row(A, ip6_stable=EUI)], [sight()], first_run=True)
        self.assertEqual([h["ip6"] for h in hist(res)], [EUI])

    def test_change_beside_another_is_one_row(self):
        res = self.merge([row(A, ip6_stable=EUI1)], [sight(ip="10.0.0.6"), ndp(EUI2)])
        self.assertEqual([k for k, _ in ev(res)], ["ip", "ip6"])
        self.assertEqual(hist(res), [{"ip": "10.0.0.6", "hostname": "", "vlan": "Clients", "lease_type": "", "ip6": EUI2}])
        self.assertEqual(res.stats["changed"], 1)


class V6Only(Base):
    def test_renumbering_writes_event_and_history(self):
        old = NOW - 7200
        prev = row(A, hostname="laptop", lease_type="dynamic", online=0, last_online=old, ip6_stable=EUI1)
        res = self.merge([prev], [ndp(EUI2, network="Other", iface="opt9")])
        r = res.rows[A]
        self.assertEqual(r["ip6_stable"], EUI2)
        self.assertEqual(ev(res), [("ip6", f"{EUI1} -> {EUI2}")])
        self.assertEqual(hist(res), [{"ip": "10.0.0.5", "hostname": "laptop", "vlan": "Clients", "lease_type": "dynamic",
                                      "ip6": EUI2}])
        self.assertEqual(res.stats["changed"], 1)
        # everything else as on the enrichment path
        self.assertEqual((r["online"], r["last_online"], r["lease_type"], r["sources"], r["vlan"]),
                         (0, old, "dynamic", "ndp", "Clients"))

    def test_lease_clock_untouched(self):
        st = {"no_lease_since": {}}
        res = self.merge([row(A, lease_type="dynamic", ip6_stable=EUI1)], [dhcp6(EUI2)], **st)
        self.assertEqual(res.rows[A]["lease_type"], "dynamic")
        self.assertEqual(st["no_lease_since"], {})

    def test_first_stable_address_writes_a_history_row_and_no_event(self):
        prev = row(A, hostname="laptop", lease_type="dynamic")
        res = self.merge([prev], [ndp(EUI, network="Other", iface="opt9")])
        self.assertEqual(res.rows[A]["ip6_stable"], EUI)
        self.assertEqual(ev(res), [])
        self.assertEqual(hist(res), [{"ip": "10.0.0.5", "hostname": "laptop", "vlan": "Clients", "lease_type": "dynamic",
                                      "ip6": EUI}])
        self.assertEqual(res.stats["changed"], 1)

    def test_first_stable_address_then_a_full_poll_is_one_history_row(self):
        res = self.merge([row(A)], [ndp(EUI)])
        self.assertEqual([h["ip6"] for h in hist(res)], [EUI])
        res = self.merge([res.rows[A]], [sight(), ndp(EUI)])
        self.assertEqual((res.rows[A]["ip6_stable"], ev(res), hist(res), res.stats["changed"]), (EUI, [], [], 0))

    def test_no_candidate_keeps_stored(self):
        res = self.merge([row(A, ip6_stable=EUI)], [ndp(TEMP)])
        self.assertEqual(res.rows[A]["ip6_stable"], EUI)
        self.assertEqual((ev(res), hist(res)), ([], []))


EUI_B1 = "2001:db8:1::ff:fe00:2"  # EUI-64 of B in 2001:db8:1::/64
EUI_B2 = "2001:db8:2::ff:fe00:2"  # EUI-64 of B in 2001:db8:2::/64


class AliasMacs(Base):
    """A device that owns the alias MAC B: B's EUI-64 address is a stable address of the device."""

    def test_pick_with_and_without_the_alias(self):
        ss = [Fw1Sighting(mac=A, ip="", hostname="", vendor="", vlan="", iface="", source="ndp", lease_type="",
                          online=False, ip6=a) for a in (EUI_B1, TEMP)]
        self.assertEqual(list(_pick_ip6_stable((A, B), ss)), [EUI_B1])
        self.assertEqual(list(_pick_ip6_stable((A,), ss)), [])

    def test_alias_eui64_is_stable_with_a_history_row_and_no_event(self):
        res = self.merge([row(A)], [sight(), ndp(EUI_B1, mac=B), ndp(TEMP)], aliases={B: A})
        self.assertEqual(res.rows[A]["ip6_stable"], EUI_B1)
        self.assertEqual(ev(res), [])
        self.assertEqual([h["ip6"] for h in hist(res)], [EUI_B1])

    def test_alias_eui64_renumbered_is_one_event(self):
        res = self.merge([row(A, ip6_stable=EUI_B1)], [sight(), ndp(EUI_B1, mac=B), ndp(EUI_B2, mac=B)], aliases={B: A})
        self.assertEqual((res.rows[A]["ip6_stable"], ev(res), hist(res)), (EUI_B1, [], []))
        res = self.merge([res.rows[A]], [sight(), ndp(EUI_B2, mac=B)], aliases={B: A})
        self.assertEqual(res.rows[A]["ip6_stable"], EUI_B2)
        self.assertEqual(ev(res), [("ip6", f"{EUI_B1} -> {EUI_B2}")])
        self.assertEqual([h["ip6"] for h in hist(res)], [EUI_B2])

    def test_alias_eui64_not_listed_keeps_the_stored_one(self):
        res = self.merge([row(A, ip6_stable=EUI_B1)], [sight(), ndp(TEMP)], aliases={B: A})
        self.assertEqual((res.rows[A]["ip6_stable"], ev(res)), (EUI_B1, []))

    def test_alias_eui64_of_a_non_alias_is_no_stable_address(self):
        res = self.merge([row(A)], [sight(), ndp(EUI_B1, mac=A)])
        self.assertEqual(res.rows[A]["ip6_stable"], "")


class Displayed(Base):
    def polls(self, *polls, prev=None):
        """Merge the polls in turn, each on the rows of the one before; the A row after each."""
        rows, out = prev or [row(A)], []
        for v6 in polls:
            res = self.merge(rows, [sight(), *v6])
            rows = [res.rows[A]]
            out.append(res.rows[A])
        return out

    def test_aged_out_eui64_does_not_flip_the_address(self):
        got = self.polls([ndp(EUI), ndp(TEMP)], [ndp(TEMP)], [ndp(EUI), ndp(TEMP2)])
        self.assertEqual([r["ip6"] for r in got], [EUI] * 3)
        self.assertEqual([r["ip6_stable"] for r in got], [EUI] * 3)

    def test_stored_temporary_moves_to_the_stable_address(self):
        res = self.merge([row(A, ip6=TEMP)], [sight(), ndp(TEMP), ndp(EUI)])
        self.assertEqual((res.rows[A]["ip6"], res.rows[A]["ip6_stable"]), (EUI, EUI))

    def test_stored_temporary_stays_while_the_stable_one_is_not_listed(self):
        res = self.merge([row(A, ip6=TEMP, ip6_stable=EUI)], [sight(), ndp(TEMP)])
        self.assertEqual((res.rows[A]["ip6"], res.rows[A]["ip6_stable"]), (TEMP, EUI))

    def test_without_a_stable_address_the_sticky_rule_holds(self):
        got = self.polls([ndp(TEMP), ndp(TEMP2)], [ndp(TEMP2)], [ndp(TEMP), ndp(TEMP2)])
        self.assertEqual([r["ip6"] for r in got], [TEMP, TEMP2, TEMP2])
        self.assertEqual([r["ip6_stable"] for r in got], [""] * 3)

    def test_dhcp6_stable_address_shown_beside_a_ula_eui64(self):
        # a global DHCPv6 address is held while only a unique-local address is listed (a worse prefix class)
        got = self.polls([dhcp6(DHCP), ndp(ULA_EUI)], [ndp(ULA_EUI)], [dhcp6(DHCP), ndp(ULA_EUI)])
        self.assertEqual([r["ip6"] for r in got], [DHCP] * 3)
        self.assertEqual([r["ip6_stable"] for r in got], [DHCP] * 3)

    def test_gone_dhcp6_address_gives_way_to_the_listed_eui64(self):
        got = self.polls([ndp(EUI)], [ndp(EUI)], [ndp(EUI), ndp(TEMP)], prev=[row(A, ip6=DHCP, ip6_stable=DHCP)])
        self.assertEqual([r["ip6"] for r in got], [EUI] * 3)
        self.assertEqual([r["ip6_stable"] for r in got], [DHCP] * 3)


if __name__ == "__main__":
    unittest.main()
