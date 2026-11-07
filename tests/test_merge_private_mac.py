"""A new private (locally administered) MAC merged into the device it matches (client-id, then hostname),
the alias rewrite of its records, the `merged` event, and no new-device mail for private MACs. Synthetic data only:
the universally administered MACs are from the documentation range 00:00:5e:00:53:xx (RFC 7042)."""
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_instances import FW1, Base  # noqa: E402
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from test_merge import NOW, S, arp, row, port  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.connectors import Batch  # noqa: E402
from leasewatch.connectors.merge import (MERGE_HOLD_SECONDS, MERGE_RECENT_DAYS, ConnectorFailure, MergeState,  # noqa: E402
                                         _merge_host, is_private_mac, merge)
from leasewatch.fw1 import Sighting as Fw1Sighting  # noqa: E402

DEV = "02:00:00:00:10:01"     # the known device (its key)
NEWP = "06:00:00:00:10:02"    # a new private MAC
NEWP2 = "0a:00:00:00:10:03"   # another new private MAC
UA_DEV = "00:00:5e:00:53:01"  # universally administered (documentation range)
UA_NEW = "00:00:5e:00:53:02"
CID = "ff00000000000001"      # a DUID-style client-id that does not depend on the MAC
MAIL = {"MAILGUN_KEY": "mg-key", "MAILGUN_DOMAIN": "example.com", "MAIL_TO": "ops@example.com"}


def lease(mac, ip="10.0.0.7", host="", cid="", presence=True):
    return replace(S(mac, ip, host, presence=presence), client_id=cid)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})

    def tearDown(self):
        self.tmp.cleanup()
        restore(self._env)

    def run_merge(self, prev, sightings, attachments=(), aliases=None, **state):
        prev = {r["mac"]: r for r in prev}
        st = MergeState(aliases=dict(aliases or {}), **state)
        return merge(prev, {"fw1": Batch(sightings=list(sightings), attachments=list(attachments))}, Config(), NOW, st)

    def assertMerged(self, res, alias, device, reason, detail):
        self.assertEqual(res.aliases, [(alias, device, reason, detail)])
        self.assertNotIn(alias, res.rows)
        self.assertNotIn(alias, res.new)
        self.assertIn((device, "merged", f"{alias} ({'client-id' if reason == 'client-id' else 'hostname ' + detail})"),
                      res.events)
        self.assertFalse([e for e in res.events if e[1] == "new"])

    def assertNotMerged(self, res, mac):
        self.assertEqual(res.aliases, [])
        self.assertIn(mac, res.new)
        self.assertFalse([e for e in res.events if e[1] == "merged"])

    def test_is_private_mac(self):
        self.assertTrue(is_private_mac("02:00:00:00:00:01"))
        self.assertTrue(is_private_mac("ae:00:00:00:00:01"))
        self.assertFalse(is_private_mac(UA_DEV))
        self.assertFalse(is_private_mac("03:00:00:00:00:01"))  # multicast

    def test_client_id_merge(self):
        res = self.run_merge([row(DEV, client_id=CID, last_online=NOW - 90 * 86400, online=0)],
                             [lease(NEWP, cid=CID), arp(NEWP, "10.0.0.7")])
        self.assertMerged(res, NEWP, DEV, "client-id", CID)  # client-id: the candidate need not be recent
        self.assertEqual(res.rows[DEV]["ip"], "10.0.0.7")
        self.assertEqual(res.alias_seen, [NEWP])

    def test_client_id_merges_while_target_online(self):
        # the old MAC lingers in ARP after the phone rotated; one client-id cannot belong to two devices
        res = self.run_merge([row(DEV, client_id=CID)], [lease(NEWP, cid=CID), arp(DEV, "10.0.0.5")])
        self.assertMerged(res, NEWP, DEV, "client-id", CID)

    def test_client_id_into_a_universally_administered_device(self):
        res = self.run_merge([row(UA_DEV, client_id=CID, online=0)], [lease(NEWP, cid=CID)])
        self.assertMerged(res, NEWP, UA_DEV, "client-id", CID)

    def test_hostname_merge(self):
        res = self.run_merge([row(DEV, hostname="Alex-Laptop", online=0, last_online=NOW - 3 * 86400)],
                             [lease(NEWP, host="alex-laptop.example.lan.")])
        self.assertMerged(res, NEWP, DEV, "hostname", "alex-laptop")

    def test_hostname_denied(self):
        old = NOW - (MERGE_RECENT_DAYS + 1) * 86400
        cases = {
            "generic": ([row(DEV, hostname="iPhone", online=0)], [lease(NEWP, host="iphone")]),
            "generic pattern": ([row(DEV, hostname="android-1a2b3c", online=0)], [lease(NEWP, host="android-1a2b3c")]),
            # a default model name (brand stem + model) is shared by every device of that model
            "model name": ([row(DEV, hostname="Galaxy-S21", online=0)], [lease(NEWP, host="Galaxy-S21.lan")]),
            "mac-derived": ([row(DEV, hostname="0a-1b-2c", online=0)], [lease(NEWP, host="0a-1b-2c")]),
            "too short": ([row(DEV, hostname="tv", online=0)], [lease(NEWP, host="tv")]),
            "not unique": ([row(DEV, hostname="alex-laptop", online=0),
                            row("02:00:00:00:10:09", hostname="alex-laptop", online=0)], [lease(NEWP, host="alex-laptop")]),
            "too old": ([row(DEV, hostname="alex-laptop", online=0, last_online=old, last_seen=old)],
                        [lease(NEWP, host="alex-laptop")]),
            "target online": ([row(DEV, hostname="alex-laptop")], [lease(NEWP, host="alex-laptop"), arp(DEV, "10.0.0.5")]),
            "arp-only hostname": ([row(DEV, hostname="alex-laptop", online=0)], [arp(NEWP, "10.0.0.7", host="alex-laptop")]),
            "two new macs, one value": ([row(DEV, hostname="alex-laptop", online=0)],
                                        [lease(NEWP, host="alex-laptop"), lease(NEWP2, "10.0.0.8", host="alex-laptop")]),
            "same value on a new hardware mac": ([row(DEV, hostname="alex-laptop", online=0)],
                                                 [lease(NEWP, host="alex-laptop"), lease(UA_NEW, "10.0.0.8", host="alex-laptop")]),
        }
        for name, (prev, sightings) in cases.items():
            with self.subTest(name):
                self.assertNotMerged(self.run_merge(prev, sightings), NEWP)

    def test_generic_brand_prefix(self):
        # a hostname that starts with a generic brand/model stem is generic, whatever follows
        for h in ("Galaxy-S21", "galaxy-a52", "Pixel-7", "Chromecast-Ultra", "iPhone-15", "iPad-Pro", "android-tv",
                  "pixel7"):
            with self.subTest(h):
                self.assertEqual(_merge_host(h), "")
        for h in ("alex-laptop", "alexs-iphone", "kitchen-tv"):  # the stem must be the start
            with self.subTest(h):
                self.assertEqual(_merge_host(h), h)

    def test_no_decision_while_a_lease_producer_failed(self):
        # the failed DHCP instance may hold the new MAC's lease (its client-id); deciding now would give the
        # MAC its own row for good. It waits (no row, not new) and merges once the lease is back
        prev = {DEV: row(DEV, client_id=CID, hostname="phone-x", online=0)}
        st = MergeState(producers=frozenset({"fw1", "dhcp"}))
        res = merge(prev, {"fw1": Batch(sightings=[arp(NEWP, "10.0.0.7")]),
                           "dhcp": ConnectorFailure("dhcp", "down", NOW)}, Config(), NOW, st)
        self.assertEqual((res.aliases, res.new), ([], []))
        self.assertNotIn(NEWP, res.rows)
        self.assertNotIn(NEWP, {m for m, *_ in res.seen})
        res = merge(prev, {"fw1": Batch(sightings=[arp(NEWP, "10.0.0.7")]),
                           "dhcp": Batch(sightings=[lease(NEWP, cid=CID)])}, Config(), NOW + 60, st)
        self.assertMerged(res, NEWP, DEV, "client-id", CID)
        # a hardware MAC never merges, so it is not held back: it is new at once
        res = merge(prev, {"fw1": Batch(sightings=[arp(UA_NEW, "10.0.0.8")]),
                           "dhcp": ConnectorFailure("dhcp", "down", NOW)}, Config(), NOW, st)
        self.assertEqual(res.new, [UA_NEW])

    def test_held_back_at_most_merge_hold_seconds(self):
        # a producer that stays down must not hide a new private MAC for ever: after MERGE_HOLD_SECONDS it gets its
        # own row (no decision is made in a lease-blind poll)
        prev = {DEV: row(DEV, client_id=CID, online=0)}
        st = MergeState(producers=frozenset({"fw1", "dhcp"}))
        batches = {"fw1": Batch(sightings=[arp(NEWP, "10.0.0.7")]), "dhcp": ConnectorFailure("dhcp", "down", NOW)}
        self.assertNotIn(NEWP, merge(prev, batches, Config(), NOW, st).rows)
        self.assertNotIn(NEWP, merge(prev, batches, Config(), NOW + MERGE_HOLD_SECONDS - 1, st).rows)
        res = merge(prev, batches, Config(), NOW + MERGE_HOLD_SECONDS, st)
        self.assertEqual((res.aliases, res.new), ([], [NEWP]))
        self.assertEqual(st.undecided_since, {})

    def test_client_id_denied(self):
        cases = {
            "two candidates": ([row(DEV, client_id=CID, online=0), row("02:00:00:00:10:09", client_id=CID, online=0)],
                               [lease(NEWP, cid=CID)]),
            "short client-id": ([row(DEV, client_id="", online=0)], [lease(NEWP, cid="01")]),
        }
        for name, (prev, sightings) in cases.items():
            with self.subTest(name):
                self.assertNotMerged(self.run_merge(prev, sightings), NEWP)

    def test_two_hardware_macs_never_merge(self):
        res = self.run_merge([row(UA_DEV, client_id=CID, hostname="alex-laptop", online=0)],
                             [lease(UA_NEW, cid=CID, host="alex-laptop")])
        self.assertNotMerged(res, UA_NEW)

    def test_first_poll_and_baseline_wait_never_merge(self):
        for state in ({"first_run": True}, {"first_run": True, "held_back": True}):
            with self.subTest(state):
                res = self.run_merge([row(DEV, client_id=CID, online=0)], [lease(NEWP, cid=CID)], **state)
                self.assertEqual(res.aliases, [])
                self.assertIn(NEWP, res.rows)

    def test_known_alias_lands_on_the_device(self):
        res = self.run_merge([row(DEV, online=0)], [arp(NEWP, "10.0.0.9")], [port(NEWP, "GE1/0/3")],
                             aliases={NEWP: DEV})
        self.assertEqual(res.aliases, [])
        self.assertNotIn(NEWP, res.rows)
        self.assertIn((DEV, "ip", "10.0.0.5 -> 10.0.0.9"), res.events)
        self.assertEqual(res.rows[DEV]["sw_port"], "GE1/0/3")
        self.assertEqual({m for m, *_ in res.seen}, {DEV})
        self.assertEqual(res.alias_seen, [NEWP])

    def test_merge_into_an_archived_device_is_allowed(self):
        res = self.run_merge([row(DEV, client_id=CID, online=0, archived_ts=NOW - 86400)], [lease(NEWP, cid=CID)])
        self.assertMerged(res, NEWP, DEV, "client-id", CID)


class CollectorTests(Base):
    def lease(self, mac, ip="10.0.0.5", host="", cid=""):
        return Fw1Sighting(mac=mac, ip=ip, hostname=host, vendor="", vlan="LAN", iface="lan", source="dhcp",
                           lease_type="dynamic", online=True, client_id=cid)

    def poll(self, col, rows):
        self.client.rows = rows
        with mock.patch("leasewatch.collector.notify.new_devices") as mail:
            self.assertTrue(col.run_once()["ok"])
        return mail

    def test_alias_sightings_land_on_the_device_and_no_mail(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1, **MAIL}, rows=[self.lease(DEV, cid=CID)])
        self.poll(col, [self.lease(DEV, cid=CID)])  # baseline
        mail = self.poll(col, [self.lease(NEWP, "10.0.0.6", cid=CID)])
        mail.assert_not_called()
        self.assertIsNone(db.device(NEWP))
        a = db.q("SELECT * FROM aliases")
        self.assertEqual([(r["mac"], r["device"], r["reason"], r["detail"]) for r in a], [(NEWP, DEV, "client-id", CID)])
        self.assertEqual(db.device(DEV)["ip"], "10.0.0.6")
        kinds = [(e["kind"], e["detail"]) for e in db.events(DEV)]
        self.assertIn(("merged", f"{NEWP} (client-id)"), kinds)
        self.assertIn(("ip", "10.0.0.5 -> 10.0.0.6"), kinds)
        self.assertEqual([s["source"] for s in db.seen(DEV)], ["fw1"])
        self.assertEqual(db.q("SELECT COUNT(*) n FROM seen WHERE mac=?", (NEWP,))[0]["n"], 0)
        # seen again later, without the client-id: still the device (the alias table, not the rule)
        mail = self.poll(col, [self.lease(NEWP, "10.0.0.8")])
        mail.assert_not_called()
        self.assertIsNone(db.device(NEWP))
        self.assertIn(("ip", "10.0.0.6 -> 10.0.0.8"), [(e["kind"], e["detail"]) for e in db.events(DEV)])
        self.assertEqual(len(db.q("SELECT 1 FROM aliases")), 1)
        # an uplink of a switch is named after the device
        db.update_user_fields(DEV, None, "Alex laptop", None)
        self.assertEqual(col._device_names()[NEWP], "Alex laptop")

    def test_private_new_device_without_merge_gets_no_mail(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1, **MAIL}, rows=[self.lease(DEV)])
        self.poll(col, [self.lease(DEV)])
        mail = self.poll(col, [self.lease(DEV), self.lease(NEWP, "10.0.0.6")])
        mail.assert_not_called()
        self.assertIsNotNone(db.device(NEWP))
        self.assertIn("new", [e["kind"] for e in db.events(NEWP)])
        mail = self.poll(col, [self.lease(DEV), self.lease(UA_NEW, "10.0.0.7")])  # a hardware MAC is still mailed
        self.assertEqual([d["mac"] for d in mail.call_args[0][1]], [UA_NEW])


if __name__ == "__main__":
    unittest.main()
