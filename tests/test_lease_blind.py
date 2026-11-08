"""Which failed instances hold a new private MAC's merge back: only those that listed a lease when they last answered
(a firewall does, a Wi-Fi controller never does, though both produce sightings). Synthetic data only."""
import json
import unittest
from dataclasses import replace

from test_instances import FW1, Base
from test_merge import NOW, S, arp, row
from test_merge_private_mac import CID, DEV, NEWP
from leasewatch.collector import Collector
from leasewatch.config import Config
from leasewatch.connectors import Batch
from leasewatch.connectors.merge import ConnectorFailure, MergeState, merge
from leasewatch.fw1 import Sighting as Fw1Sighting


def client(mac, ip="10.0.0.7"):
    return S(mac, ip, kind="client")


def lease(mac, ip="10.0.0.7"):
    return replace(S(mac, ip), client_id=CID)


class LeaseBlindTests(unittest.TestCase):
    PREV = {DEV: row(DEV, client_id=CID, hostname="phone-x", online=0)}

    def run_merge(self, batches, **state):
        st = MergeState(producers=frozenset({"fw1", "unifi"}), **state)
        return merge(dict(self.PREV), batches, Config(), NOW, st)

    def test_failed_sighting_producer_without_leases_holds_nothing(self):
        res = self.run_merge({"fw1": Batch(sightings=[lease(NEWP)]), "unifi": ConnectorFailure("unifi", "down", NOW)},
                             lease_holders=frozenset({"fw1"}))
        self.assertEqual([a[:2] for a in res.aliases], [(NEWP, DEV)])
        self.assertNotIn(NEWP, res.new)

    def test_failed_firewall_that_listed_leases_holds_the_merge(self):
        res = self.run_merge({"fw1": ConnectorFailure("fw1", "down", NOW),
                              "unifi": Batch(sightings=[client(NEWP)])}, lease_holders=frozenset({"fw1"}))
        self.assertEqual((res.aliases, res.new), ([], []))
        self.assertNotIn(NEWP, res.rows)

    def test_holders_unknown_falls_back_to_the_producers(self):
        res = self.run_merge({"fw1": Batch(sightings=[arp(NEWP)]), "unifi": ConnectorFailure("unifi", "down", NOW)})
        self.assertEqual((res.aliases, res.new), ([], []))  # held back, as before holders were tracked
        self.assertIn("unifi", res.lease_holders)         # a suspect until it has answered

    def test_holder_set_follows_the_last_answer(self):
        st = {"lease_holders": frozenset({"fw1"})}
        res = self.run_merge({"fw1": Batch(sightings=[lease(NEWP)]), "unifi": Batch(sightings=[client(NEWP)])}, **st)
        self.assertEqual(res.lease_holders, frozenset({"fw1"}))
        # a failed instance keeps its state; an instance that answers without a lease drops out
        res = self.run_merge({"fw1": ConnectorFailure("fw1", "down", NOW), "unifi": Batch(sightings=[client(NEWP)])}, **st)
        self.assertEqual(res.lease_holders, frozenset({"fw1"}))
        res = self.run_merge({"fw1": Batch(sightings=[arp(NEWP)]), "unifi": Batch(sightings=[client(NEWP)])}, **st)
        self.assertEqual(res.lease_holders, frozenset())
        # an empty answer is no evidence: the instance stays (or becomes) a suspect
        res = self.run_merge({"fw1": Batch(sightings=[]), "unifi": Batch(sightings=[])}, **st)
        self.assertEqual(res.lease_holders, frozenset({"fw1", "unifi"}))
        # a new holder is added
        res = self.run_merge({"unifi": Batch(sightings=[lease(NEWP)])}, **st)
        self.assertEqual(res.lease_holders, frozenset({"fw1", "unifi"}))


class PersistTests(Base):
    def test_holders_stored_and_read_at_start(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1}, rows=[Fw1Sighting(
            mac=DEV, ip="10.0.0.5", hostname="", vendor="", vlan="LAN", iface="lan", source="dhcp",
            lease_type="dynamic", online=True)])
        self.assertIsNone(col._lease_holders)
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(json.loads(db.get_meta("lease_holders")), ["fw1"])
        self.assertEqual(col._lease_holders, frozenset({"fw1"}))
        again = Collector(self.cfg({"LW_CONNECTORS": "fw1", **FW1}), db, self.client)
        self.assertEqual(again._lease_holders, frozenset({"fw1"}))

    def test_bad_meta_is_unknown(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1})
        for bad in ("not json", '{"a": 1}', "[1]"):
            db.set_meta("lease_holders", bad)
            self.assertIsNone(col._load_lease_holders())


if __name__ == "__main__":
    unittest.main()
