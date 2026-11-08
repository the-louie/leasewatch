"""Sighting.ip6: the host's normalisation and the two IPv6 kinds. Synthetic data only."""
import unittest
from dataclasses import fields
from leasewatch.connectors import Batch, Sighting
from leasewatch.connectors.merge import normalise_batch
from leasewatch.connectors.testing import SIGHTING_KINDS

A = "02:00:00:00:00:01"


def norm(ip6, kind="ndp"):
    s = Sighting(mac=A, source="", kind=kind, presence=True, observed_at=1_700_000_000, ip6=ip6)
    out = normalise_batch("lan", Batch(sightings=[s], attachments=[])).sightings
    assert len(out) == 1
    return out[0].ip6


class Ip6Field(unittest.TestCase):
    def test_v6_kinds_never_assert_presence(self):
        # a third-party connector's ndp/dhcp6 sighting with presence=True is read as False by the host; dhcp keeps it
        for kind, want in (("ndp", False), ("dhcp6", False), ("dhcp", True)):
            s = Sighting(mac=A, source="", kind=kind, presence=True, observed_at=1_700_000_000, ip6="2001:db8::1")
            out = normalise_batch("lan", Batch(sightings=[s], attachments=[])).sightings
            self.assertEqual(out[0].presence, want, kind)

    def test_normalised(self):
        for given, want in (("2001:DB8::0001", "2001:db8::1"), ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
                            ("fd00::1", "fd00::1"), ("  2001:db8::5%igb0 ", "2001:db8::5"), ("", "")):
            with self.subTest(given=given):
                self.assertEqual(norm(given), want)

    def test_emptied(self):
        for given in ("fe80::1%igb0", "fe80::1", "10.0.0.1", "::ffff:10.0.0.1", "junk", "2001:db8::g", None):
            with self.subTest(given=given):
                self.assertEqual(norm(given), "")

    def test_default_and_last_field(self):
        s = Sighting(mac=A, source="", kind="arp", presence=False, observed_at=0)
        self.assertEqual(s.ip6, "")
        self.assertEqual(fields(Sighting)[-1].name, "ip6")

    def test_kinds_allowed(self):
        self.assertLessEqual({"ndp", "dhcp6"}, SIGHTING_KINDS)
        self.assertEqual(norm("2001:db8::2", kind="DHCP6"), "2001:db8::2")


if __name__ == "__main__":
    unittest.main()
