"""The deferred hostname merge ("fold") in the pure merge: an existing private row nobody touched becomes an alias of
the older device with its DHCP hostname, once that device is off the wire. Synthetic data only: the universally
administered MAC is from the documentation range 00:00:5e:00:53:xx (RFC 7042)."""
import unittest
from dataclasses import replace

from _case import EnvTmpCase
from test_merge import NOW, arp, row
from test_merge_private_mac import CID, DEV, NEWP, NEWP2, UA_NEW, lease
from leasewatch.config import Config
from leasewatch.connectors import Batch
from leasewatch.connectors.merge import (FOLD_OVERLAP_SECONDS, MERGE_FOLD_DAYS, ConnectorFailure, MergeState,
                                         merge)

HOST = "alex-laptop"
T = NOW - 3600                 # the candidate's first_seen
DEV2 = "02:00:00:00:10:04"     # a second device with the hostname
OTHER = "02:00:00:00:10:05"    # an unrelated device


def target(**kw):
    """The device the candidate folds into: older than the candidate, off the wire 10 min after it appeared."""
    return row(DEV, **{"hostname": HOST, "first_seen": NOW - 30 * 86400, "last_online": T + 600, "last_seen": T + 600,
                       "online": 0, **kw})


def cand(mac=NEWP, **kw):
    """The candidate: an untouched private row first seen at T."""
    return row(mac, **{"hostname": HOST, "first_seen": T, "split_from": "", **kw})


class FoldTests(EnvTmpCase):
    def run_merge(self, prev, sightings, aliases=None, extra=None, **state):
        prev = {r["mac"]: r for r in prev}
        st = MergeState(aliases=dict(aliases or {}), **state)
        batches = {"fw1": Batch(sightings=list(sightings)), **(extra or {})}
        self.state = st
        return merge(prev, batches, Config(), NOW, st)

    def assertFolded(self, res, c=NEWP, dev=DEV):
        self.assertEqual(res.folds, [(c, dev, "hostname", HOST)])
        self.assertIn((c, dev, "hostname", HOST), res.aliases)
        self.assertNotIn(c, res.rows)
        self.assertNotIn(c, res.new)
        self.assertIn(c, res.alias_seen)

    def assertNotFolded(self, res):
        self.assertEqual(res.folds, [])
        self.assertFalse([a for a in res.aliases if a[0] == NEWP])

    def test_fold(self):
        res = self.run_merge([target(), cand(ip="10.0.0.7")], [lease(NEWP, "10.0.0.9", host=HOST)])
        self.assertFolded(res)
        # this poll's records land on the device
        self.assertEqual(res.rows[DEV]["ip"], "10.0.0.9")
        self.assertEqual(res.rows[DEV]["online"], 1)
        self.assertIn((DEV, "merged", f"{NEWP} (hostname {HOST}, own row for 60 min)"), res.events)
        self.assertFalse([e for e in res.events if e[0] == NEWP or e[1] == "new"])
        self.assertFalse([s for s in res.seen if s[0] == NEWP])
        self.assertIn((DEV, "fw1", NOW, NOW), res.seen)

    def test_fold_clears_the_candidates_clocks(self):
        prev = [target(), cand(lease_type="dynamic")]
        st = {"no_lease_since": {NEWP: NOW - 100}, "undecided_since": {NEWP: NOW - 100}}
        res = self.run_merge(prev, [lease(NEWP, host=HOST)], **st)
        self.assertFolded(res)
        self.assertNotIn(NEWP, self.state.no_lease_since)
        self.assertNotIn(NEWP, self.state.undecided_since)

    def test_docked_laptop(self):
        # the Wi-Fi row appears while the cable row is on the wire; the cable row goes offline later
        for off, folds in ((FOLD_OVERLAP_SECONDS - 60, True), (FOLD_OVERLAP_SECONDS, False),
                           (FOLD_OVERLAP_SECONDS + 600, False)):
            with self.subTest(off=off):
                res = self.run_merge([target(last_online=T + off, last_seen=T + off), cand()],
                                     [lease(NEWP, host=HOST)])
                if folds:
                    self.assertFolded(res)
                else:
                    self.assertNotFolded(res)
                    self.assertIn(NEWP, res.rows)

    def test_no_fold(self):
        old = NOW - MERGE_FOLD_DAYS * 86400 - 1
        cases = {
            "named": ([target(), cand(name="Alex")], [lease(NEWP, host=HOST)]),
            "noted": ([target(), cand(note="spare")], [lease(NEWP, host=HOST)]),
            "acked": ([target(), cand(acked=1, acked_at=NOW - 100)], [lease(NEWP, host=HOST)]),
            "archived": ([target(), cand(archived_ts=NOW - 100)], [lease(NEWP, host=HOST)]),
            "baseline": ([target(), cand(baseline=1)], [lease(NEWP, host=HOST)]),
            "older than MERGE_FOLD_DAYS": ([target(last_online=old + 600), cand(first_seen=old)],
                                           [lease(NEWP, host=HOST)]),
            "split from the target": ([target(), cand(split_from=DEV)], [lease(NEWP, host=HOST)]),
            "generic hostname": ([target(hostname="iPhone"), cand(hostname="iPhone")], [lease(NEWP, host="iphone")]),
            "hostname only from ARP": ([target(), cand()], [arp(NEWP, "10.0.0.7", host=HOST)]),
            "not listed": ([target(), cand()], [arp(OTHER, "10.0.0.8")]),
            "two targets": ([target(), row(DEV2, hostname=HOST, first_seen=NOW - 9 * 86400, online=0,
                                           last_online=T + 300), cand()], [lease(NEWP, host=HOST)]),
            "target on the wire": ([target(), cand()], [lease(NEWP, host=HOST), arp(DEV, "10.0.0.5")]),
            "target newer": ([target(first_seen=T + 1), cand()], [lease(NEWP, host=HOST)]),
            "fresh mac with the hostname": ([target(), cand()],
                                            [lease(NEWP, host=HOST), lease(NEWP2, "10.0.0.8", host=HOST)]),
            "fresh hardware mac with the hostname": ([target(), cand()],
                                                     [lease(NEWP, host=HOST), lease(UA_NEW, "10.0.0.8", host=HOST)]),
            "hardware candidate": ([target(), cand(UA_NEW)], [lease(UA_NEW, host=HOST)]),
        }
        for name, (prev, sightings) in cases.items():
            with self.subTest(name):
                res = self.run_merge(prev, sightings)
                self.assertEqual(res.folds, [])
                self.assertEqual(res.aliases, [])

    def test_folded_mac_eui64_is_a_stable_address_of_the_device(self):
        eui = "2001:db8::400:ff:fe00:1002"  # EUI-64 of NEWP (06:00:00:00:10:02)
        ndp = replace(lease(NEWP, "", presence=False), kind="ndp", ip6=eui)
        res = self.run_merge([target(), cand()], [lease(NEWP, host=HOST), ndp])
        self.assertFolded(res)
        self.assertEqual(res.rows[DEV]["ip6_stable"], eui)

    def test_candidate_with_aliases(self):
        # a fold never re-points a chain
        res = self.run_merge([target(), cand()], [lease(NEWP, host=HOST)], aliases={NEWP2: NEWP})
        self.assertNotFolded(res)

    def test_first_run_and_baseline_wait(self):
        for st in ({"first_run": True}, {"first_run": True, "held_back": True}):
            with self.subTest(**st):
                self.assertNotFolded(self.run_merge([target(), cand()], [lease(NEWP, host=HOST)], **st))

    def test_producer_failed(self):
        res = self.run_merge([target(), cand()], [lease(NEWP, host=HOST)],
                             extra={"dhcp": ConnectorFailure("dhcp", "TimeoutError", NOW)},
                             producers=frozenset({"fw1", "dhcp"}))
        self.assertNotFolded(res)
        self.assertIn(NEWP, res.rows)
        # the same poll with every producer answering folds
        self.assertFolded(self.run_merge([target(), cand()], [lease(NEWP, host=HOST)],
                                         producers=frozenset({"fw1", "dhcp"})))

    def test_direction(self):
        # two private rows with one hostname, both listed with a lease: only the newer folds into the older
        older = cand(NEWP2, first_seen=T - 600, last_online=T + 300, last_seen=T + 300, online=0)
        res = self.run_merge([older, cand()], [lease(NEWP, host=HOST), lease(NEWP2, "10.0.0.8", host=HOST,
                                                                             presence=False)])
        self.assertFolded(res, NEWP, NEWP2)

    def test_two_candidates_one_target(self):
        res = self.run_merge([target(), cand(), cand(NEWP2, first_seen=T + 60)],
                             [lease(NEWP, host=HOST), lease(NEWP2, "10.0.0.8", host=HOST)])
        self.assertEqual(res.folds, [])

    def test_fold_and_fresh_merge_into_one_device(self):
        # a client-id merge of a new MAC and a fold into the same device in one poll: neither happens (the new MAC is
        # listed without presence, so the device is not on the wire through it)
        cid = "ff00000000000001"
        res = self.run_merge([target(client_id=cid), cand()],
                             [lease(NEWP, host=HOST), lease(NEWP2, "10.0.0.8", cid=cid, presence=False)])
        self.assertEqual(res.folds, [])
        self.assertEqual(res.aliases, [])
        self.assertIn(NEWP, res.rows)
        self.assertIn(NEWP2, res.new)
        self.assertNotIn(NEWP2, res.alias_seen)
        self.assertFalse([e for e in res.events if e[1] == "merged"])

    def test_split_then_fold_elsewhere(self):
        # split from DEV: never back into DEV, but into DEV2 when DEV2 alone carries the hostname
        res = self.run_merge([target(hostname="old-name"), row(DEV2, hostname=HOST, first_seen=NOW - 9 * 86400,
                                                               online=0, last_online=T + 300),
                              cand(split_from=DEV)], [lease(NEWP, host=HOST)])
        self.assertFolded(res, NEWP, DEV2)
        res = self.run_merge([target(), cand(split_from=DEV)], [lease(NEWP, host=HOST)])
        self.assertNotFolded(res)

    def test_target_folded_itself_is_no_target(self):
        # NEWP2 would fold into DEV3 and NEWP into NEWP2 in one poll: the chain is not built
        dev3 = "02:00:00:00:10:06"
        prev = [row(dev3, hostname="Bob-PC", first_seen=NOW - 30 * 86400, online=0, last_online=T + 100),
                cand(NEWP2, hostname="newp2-host", first_seen=T - 600, online=0, last_online=T + 300),
                cand(hostname="newp2-host")]
        # NEWP2's lease now names bob-pc; NEWP's names the value only NEWP2 carries
        res = self.run_merge(prev, [lease(NEWP2, "10.0.0.8", host="bob-pc", presence=False),
                                    lease(NEWP, host="newp2-host")])
        self.assertEqual(res.folds, [(NEWP2, dev3, "hostname", "bob-pc")])

    def test_candidate_a_new_mac_merges_into_is_not_folded(self):
        # NEWP2 carries NEWP's client-id this poll and merges into it: NEWP must not be folded away
        res = self.run_merge([target(), cand(client_id=CID)],
                             [lease(NEWP, "10.0.0.9", host=HOST, cid=CID), lease(NEWP2, "10.0.0.10", cid=CID)])
        self.assertEqual(res.folds, [])
        self.assertEqual([a[:3] for a in res.aliases], [(NEWP2, NEWP, "client-id")])
        self.assertIn(NEWP, res.rows)
        self.assertNotIn(NEWP, res.new)


if __name__ == "__main__":
    unittest.main()
