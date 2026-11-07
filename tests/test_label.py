"""Sighting.label: the Kea reservation description through fw1, the coercion and the merge precedence."""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leasewatch import fw1
from leasewatch.connectors import Batch, Sighting
from leasewatch.connectors.merge import merge_sightings, normalise_batch, to_fw1
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
