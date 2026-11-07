"""S4 T-02: the DHCP client-id per source (ISC uid, Kea and dnsmasq client_id), its normal form, the merge and the
devices.client_id column. Synthetic ids only."""
import os
import sys
import tempfile
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_instances import FW1, MAC, Base  # noqa: E402
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from test_merge import NOW, A, S, arp, row  # noqa: E402
from leasewatch import fw1  # noqa: E402
from leasewatch.connectors import Batch, Sighting  # noqa: E402
from leasewatch.connectors.merge import (MergeState, merge, merge_sightings, norm_client_id, normalise_batch,  # noqa: E402
                                         to_fw1)
from leasewatch.connectors.opnsense import to_sighting  # noqa: E402
from leasewatch.fw1 import Sighting as Fw1Sighting  # noqa: E402
from leasewatch.config import Config  # noqa: E402

CID = "0102000000000101"  # type 1 + a locally administered MAC


def C(kind, ip, cid):
    return Sighting(mac=A, source="fw1", kind=kind, presence=kind == "arp", observed_at=NOW, ip=ip, client_id=cid)


class NormTests(unittest.TestCase):
    def test_separated_groups_are_padded(self):
        self.assertEqual(norm_client_id("1:2:0:0:0:1:1"), "01020000000101")  # MikroTik drops leading zeros
        self.assertEqual(norm_client_id("01:02:00:00:00:01:01"), "01020000000101")
        self.assertEqual(norm_client_id("01-02-AB"), "0102ab")

    def test_plain_hex_must_be_even(self):
        self.assertEqual(norm_client_id("014890"), "014890")
        self.assertEqual(norm_client_id(" 01AB "), "01ab")
        self.assertEqual(norm_client_id("01489"), "")

    def test_star_empty_short_and_junk_are_empty(self):
        for v in ("", "*", "01", "1", "0g", "01::02", "zz:01", "001:02", ":", "01 02", None):
            self.assertEqual(norm_client_id(v), "", v)

    def test_idempotent(self):
        self.assertEqual(norm_client_id(norm_client_id("1:2:ab")), "0102ab")


class IscTests(unittest.TestCase):
    def uid(self, text):
        return fw1.isc_leases([{"mac": "02:00:00:00:01:01", "uid": text, "state": "active"}])[0]["client_id"]

    def test_escaped_uid_is_decoded_to_hex(self):
        self.assertEqual(self.uid(r"\001\002\000\000\000\001\001"), "01020000000101")
        self.assertEqual(self.uid(r"\001AB\\\""), "014142" + "5c" + "22")  # printable bytes, \\ and \"

    def test_missing_short_or_bad_uid_is_empty(self):
        self.assertEqual(fw1.isc_leases([{"mac": "02:00:00:00:01:01", "state": "active"}])[0]["client_id"], "")
        for text in ("", r"\001", "a", "\\", r"\9", "āĂ"):
            self.assertEqual(self.uid(text), "", text)


class KeaDnsmasqTests(unittest.TestCase):
    def test_kea_client_id_is_kept(self):
        rows = fw1.kea_leases([{"hwaddr": "02:00:00:00:01:01", "state": 0, "client_id": "01:02:00:00:00:01:01"}])
        self.assertEqual(rows[0]["client_id"], "01:02:00:00:00:01:01")
        self.assertEqual(fw1.kea_leases([{"hwaddr": "02:00:00:00:01:01", "state": 0}])[0]["client_id"], "")

    def test_dnsmasq_client_id_star_is_empty(self):
        base = {"expire": 0, "hwaddr": "02:00:00:00:02:01", "address": "10.0.110.15"}
        self.assertEqual(fw1.dnsmasq_leases([{**base, "client_id": "01:02:00:00:00:02:01"}], NOW)[0]["client_id"],
                         "01:02:00:00:00:02:01")
        self.assertEqual(fw1.dnsmasq_leases([{**base, "client_id": "*"}], NOW)[0]["client_id"], "")

    def test_sightings_carry_it_to_the_connector_record(self):
        c = fw1.Fw1Client("https://fw1.example.lan", "k", "s", dhcp_backend="kea")
        out, _ = c._sightings([{"hwaddr": "02:00:00:00:01:01", "address": "10.0.0.5", "state": 0,
                                "client_id": "1:2:0:0:0:1:1"}], [], lambda *a: False)
        self.assertEqual(out[0].client_id, "1:2:0:0:0:1:1")
        s = to_sighting(out[0], "fw1", NOW)
        self.assertEqual(s.client_id, "1:2:0:0:0:1:1")
        self.assertEqual(to_fw1(s).client_id, "1:2:0:0:0:1:1")


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})

    def tearDown(self):
        self.tmp.cleanup()
        restore(self._env)

    def run_merge(self, prev, sightings):
        return merge(prev, {"fw1": Batch(sightings=sightings)}, Config(), NOW, MergeState())

    def test_normalise_batch_applies_the_normal_form(self):
        b = normalise_batch("x", Batch(sightings=[C("dhcp", "", "1:2:AB"), C("dhcp", "", "*")]))
        self.assertEqual([s.client_id for s in b.sightings], ["0102ab", ""])

    def test_merged_takes_the_chosen_lease_only(self):
        lease, other = C("dhcp", "10.0.0.5", CID), C("dhcp", "10.0.0.9", "0102ffffffffffff")
        wire = C("arp", "10.0.0.5", "0102eeeeeeeeeeee")
        self.assertEqual(merge_sightings([to_fw1(x) for x in (other, wire, lease)])[A].client_id, CID)
        self.assertEqual(merge_sightings([to_fw1(wire)])[A].client_id, "")  # ARP is no lease

    def test_merge_writes_new_and_keeps_stored_when_lease_has_none(self):
        lease = S(A, "10.0.0.5")
        res = self.run_merge({}, [replace(lease, client_id="1:2:0:0:0:1:1")])
        self.assertEqual(res.rows[A]["client_id"], "01020000000101")
        res = self.run_merge({A: row(A, client_id=CID)}, [lease, arp(A)])
        self.assertEqual(res.rows[A]["client_id"], CID)
        res = self.run_merge({A: row(A, client_id=CID)}, [replace(lease, client_id="0102aaaaaaaaaaaa")])
        self.assertEqual(res.rows[A]["client_id"], "0102aaaaaaaaaaaa")


class StoreTests(Base):
    def lease(self, cid):
        return Fw1Sighting(mac=MAC, ip="10.0.0.5", hostname="", vendor="", vlan="LAN", iface="lan", source="dhcp",
                           lease_type="dynamic", online=True, client_id=cid)

    def test_devices_client_id_is_stored_and_kept(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1}, rows=[self.lease("1:2:0:0:0:1:1")])
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.device(MAC)["client_id"], "01020000000101")
        self.client.rows = [self.lease("")]
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.device(MAC)["client_id"], "01020000000101")
        self.client.rows = [self.lease("0102aaaaaaaaaaaa")]
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.device(MAC)["client_id"], "0102aaaaaaaaaaaa")


if __name__ == "__main__":
    unittest.main()
