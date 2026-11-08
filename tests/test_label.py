"""Sighting.label: the Kea reservation description through fw1, the coercion and the merge precedence."""
import unittest
from _env import FW1_ENV, clean_env, restore
from leasewatch import fw1
from leasewatch.config import Config
from leasewatch.connectors import Batch, Sighting
from leasewatch.connectors.merge import (ROW_DEFAULTS, ConnectorFailure, MergeState, merge, merge_sightings,
                                         normalise_batch, to_fw1)
from leasewatch.connectors.opnsense import to_sighting

A = "02:00:00:00:00:01"
RES = {"hw_address": A, "ip_address": "10.0.0.5", "hostname": "pr1", "subnet": "10.0.0.0/24"}


def sight(kind="dhcp", label="", ip="10.0.0.5", host="h", **kw):
    return Sighting(mac=A, source="x", kind=kind, presence=False, observed_at=1, ip=ip, hostname=host,
                    label=label, **kw)


class Fw1Label(unittest.TestCase):
    def rows(self, row):
        return fw1.kea_reservations([row], {})

    def test_description_becomes_label(self):
        self.assertEqual(self.rows({**RES, "description": " Kitchen printer "})[0]["label"], "Kitchen printer")

    def test_missing_key_is_empty(self):
        self.assertEqual(self.rows(RES)[0]["label"], "")
        self.assertEqual(self.rows({**RES, "description": None})[0]["label"], "")

    def test_cap_128(self):
        self.assertEqual(len(self.rows({**RES, "description": "x" * 200})[0]["label"]), 128)

    def test_reaches_sighting(self):
        c = fw1.Fw1Client.__new__(fw1.Fw1Client)
        c.dhcp_backend = "kea"
        out, _ = c._sightings([], [], lambda *a: False, [{**RES, "description": "Den"}])
        self.assertEqual(out[0].label, "Den")
        self.assertEqual(to_sighting(out[0], "fw", 5).label, "Den")


class LeasedReservationLabel(unittest.TestCase):
    LEASE = {"hwaddr": A, "address": "10.0.0.5", "hostname": "pr1.example.lan.", "state": 0,
             "if_name": "opt3", "if": "vlan0110"}

    def run_sightings(self, leases, reservations):
        c = fw1.Fw1Client.__new__(fw1.Fw1Client)
        c.dhcp_backend = "kea"
        out, _ = c._sightings(leases, [], lambda *a: False, reservations)
        return out

    def test_leased_and_reserved_gets_label(self):
        out = self.run_sightings([self.LEASE], [{**RES, "description": "Den printer"}])
        self.assertEqual([(s.mac, s.source, s.label) for s in out], [(A, "dhcp", "Den printer")])

    def test_leased_without_reservation_has_no_label(self):
        out = self.run_sightings([self.LEASE], [{**RES, "hw_address": "02:00:00:00:00:02", "description": "Other"}])
        self.assertEqual([s.label for s in out if s.mac == A], [""])
        self.assertEqual([s.label for s in out if s.mac != A], ["Other"])  # its own lease-less row, untouched

    def test_leaseless_reservation_keeps_label(self):
        out = self.run_sightings([], [{**RES, "description": "Den printer"}])
        self.assertEqual([(s.mac, s.label) for s in out], [(A, "Den printer")])

    def test_missing_or_null_description_is_empty(self):
        for res in (RES, {**RES, "description": None}):
            out = self.run_sightings([self.LEASE], [res])
            self.assertEqual([s.label for s in out], [""])

    def test_two_subnets_take_the_reservation_of_the_lease_subnet_in_either_api_order(self):
        here = {**RES, "description": "Den printer"}
        other = {**RES, "ip_address": "10.0.9.5", "subnet": "10.0.9.0/24", "description": "Guest printer"}
        for rows in ([here, other], [other, here]):
            out = self.run_sightings([self.LEASE], rows)
            self.assertEqual([s.label for s in out], ["Den printer"], rows)

    def test_two_subnets_none_matching_take_the_first_labelled_row(self):
        a = {**RES, "subnet": "10.0.8.0/24", "description": "First"}
        b = {**RES, "subnet": "10.0.9.0/24", "description": "Second"}
        self.assertEqual([s.label for s in self.run_sightings([self.LEASE], [a, b])], ["First"])
        self.assertEqual([s.label for s in self.run_sightings([self.LEASE], [{**a, "description": ""}, b])], ["Second"])


class ReservationsUnavailable(unittest.TestCase):
    def client(self, reservations):
        c = fw1.Fw1Client.__new__(fw1.Fw1Client)
        c.dhcp_backend = "kea"
        c.leases_raw = lambda: [LeasedReservationLabel.LEASE]
        c.arp_raw = lambda: []
        c.reservations_raw = reservations
        return c

    def test_failed_search_flags_the_labels_unavailable(self):
        def fail():
            raise fw1.Fw1Error("fw1 /api/kea/dhcpv4/searchReservation: HTTP 500")
        with self.assertLogs("leasewatch", "WARNING"):
            out, stats = self.client(fail).sightings()
        self.assertEqual(stats.get("labels_unavailable"), 1)
        self.assertNotIn("reservations", stats)
        self.assertEqual([s.label for s in out], [""])

    def test_answered_search_sets_no_flag(self):
        out, stats = self.client(lambda: [{**RES, "description": "Den"}]).sightings()
        self.assertNotIn("labels_unavailable", stats)
        self.assertEqual([s.label for s in out], ["Den"])


class StoredLabel(unittest.TestCase):
    """merge(): the stored label stays while the labels could not be read this poll."""
    NOW = 1_700_000_000

    def setUp(self):
        self._env = clean_env(FW1_ENV)
        self.addCleanup(restore, self._env)
        self.cfg = Config()
        self.prev = {A: {**ROW_DEFAULTS, "mac": A, "first_seen": 1, "baseline": 0, "last_seen": 1, "last_online": 1,
                         "ip": "10.0.0.5", "hostname": "h", "vendor": "", "vlan": "", "iface": "", "lease_type": "static",
                         "sources": "dhcp", "online": 0, "label": "Den printer"}}

    def label(self, batches, producers=frozenset({"fw1", "other"})):
        res = merge(self.prev, batches, self.cfg, self.NOW, MergeState(producers=producers))
        return res.rows[A]["label"]

    def test_poll_ok_takes_the_label(self):
        self.assertEqual(self.label({"fw1": Batch(sightings=[sight(label="Hall printer")])}), "Hall printer")

    def test_reservations_unavailable_keeps_the_label(self):
        b = Batch(sightings=[sight()], stats={"leases": 1, "arp": 0, "labels_unavailable": 1})
        self.assertEqual(self.label({"fw1": b}), "Den printer")
        # a label read this poll still wins
        b = Batch(sightings=[sight(label="Hall printer")], stats={"labels_unavailable": 1})
        self.assertEqual(self.label({"fw1": b}), "Hall printer")

    def test_poll_ok_with_the_description_removed_clears_the_label(self):
        b = Batch(sightings=[sight()], stats={"leases": 1, "arp": 0, "reservations": 1})
        self.assertEqual(self.label({"fw1": b}), "")

    def test_fw1_failed_and_another_producer_lists_the_device_keeps_the_label(self):
        batches = {"fw1": ConnectorFailure("fw1", "TimeoutError", self.NOW), "other": Batch(sightings=[sight("arp")])}
        self.assertEqual(self.label(batches), "Den printer")
        self.assertEqual(self.label(batches, producers=None), "Den printer")

    def test_a_failed_switch_with_producers_known_does_not_hold_the_label(self):
        batches = {"fw1": Batch(sightings=[sight()]), "sw": ConnectorFailure("sw", "SNMP timeout", self.NOW)}
        self.assertEqual(self.label(batches, producers=frozenset({"fw1"})), "")


class Coercion(unittest.TestCase):
    def norm(self, **kw):
        return normalise_batch("n", Batch(sightings=[sight(**kw)])).sightings

    def test_old_field_set_is_valid(self):
        s = normalise_batch("n", Batch(sightings=[Sighting(mac=A, source="", kind="dhcp", presence=True,
                                                           observed_at=1, ip="10.0.0.5")])).sightings
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0].label, "")

    def test_bytes_and_non_str(self):
        self.assertEqual(self.norm(label=b"abc")[0].label, "b'abc'")
        self.assertEqual(self.norm(label=7)[0].label, "7")
        self.assertEqual(self.norm(label=None)[0].label, "")

    def test_control_chars_stripped(self):
        self.assertEqual(self.norm(label="a\x00b‮c")[0].label, "abc")


class Precedence(unittest.TestCase):
    def merged(self, *ss):
        return merge_sightings([to_fw1(s) for s in ss])[A].label

    def test_dhcp_label_first(self):
        self.assertEqual(self.merged(sight("client", "from-client"), sight("dhcp", "from-dhcp")), "from-dhcp")

    def test_any_non_empty_when_dhcp_has_none(self):
        self.assertEqual(self.merged(sight("dhcp", ""), sight("client", "from-client")), "from-client")

    def test_none(self):
        self.assertEqual(self.merged(sight("dhcp"), sight("arp")), "")


if __name__ == "__main__":
    unittest.main()
