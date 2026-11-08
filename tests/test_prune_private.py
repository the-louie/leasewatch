"""PRUNE_PRIVATE_DAYS: a shorter archive threshold for private MACs that never merged. Synthetic data only."""
import os
import unittest

from _case import EnvTmpCase
from _fixtures import NOW, row
from leasewatch.config import Config
from leasewatch.connectors import Batch
from leasewatch.connectors.merge import MergeState, merge

DAY = 86400
PRIV = "02:00:00:00:40:01"
HW = "00:00:5e:00:53:41"


class PrunePrivateTests(EnvTmpCase):
    def run_merge(self, prev, private=0, prune=0, **state):
        os.environ["PRUNE_PRIVATE_DAYS"] = str(private)
        os.environ["PRUNE_DAYS"] = str(prune)
        return merge({r["mac"]: r for r in prev}, {"fw1": Batch(sightings=[])}, Config(), NOW, MergeState(**state))

    def off(self, days, mac=PRIV, **kw):
        return row(mac, online=0, last_online=NOW - int(days * DAY), **kw)

    def archived(self, res):
        return sorted((m, d) for m, k, d in res.events if k == "archived")

    def test_default_follows_prune_days(self):
        prev = [self.off(10)]
        self.assertEqual(self.run_merge(prev, 0, 30).rows, {})
        self.assertEqual(self.archived(self.run_merge([self.off(31)], 0, 30)), [(PRIV, "auto: not online for 31 days")])

    def test_private_only_with_prune_days_off(self):
        n = "02:00:00:00:40:"
        prev = [self.off(8), self.off(8, HW), self.off(8, n + "02", name="Phone"), self.off(8, n + "03", note="x"),
                self.off(8, n + "04", acked=1), self.off(8, n + "05", split_from=PRIV), self.off(8, n + "06")]
        res = self.run_merge(prev, 7, 0, aliases={n + "99": n + "06"})
        self.assertEqual(self.archived(res), [(PRIV, "auto (private): not online for 8 days")])
        self.assertEqual({m for m, r in res.rows.items() if r["archived_ts"]}, {PRIV})

    def test_watched_device_is_never_archived(self):
        # watch spares a device like a name or an ack: by PRUNE_PRIVATE_DAYS and by PRUNE_DAYS
        for res in (self.run_merge([self.off(8, watch=1)], 7, 0),
                    self.run_merge([self.off(31, watch=1), self.off(31, HW, watch=1)], 7, 30)):
            self.assertEqual(self.archived(res), [])
            self.assertEqual([m for m, r in res.rows.items() if r["archived_ts"]], [])

    def test_not_old_enough(self):
        self.assertEqual(self.run_merge([self.off(6)], 7, 0).rows, {})

    def test_hardware_mac_follows_prune_days(self):
        prev = [self.off(10), self.off(10, HW)]
        res = self.run_merge(prev, 7, 30)
        self.assertEqual(self.archived(res), [(PRIV, "auto (private): not online for 10 days")])
        res = self.run_merge([self.off(31), self.off(31, HW)], 7, 30)
        self.assertEqual(self.archived(res), [(HW, "auto: not online for 31 days"),
                                              (PRIV, "auto (private): not online for 31 days")])

    def test_restored_hold_applies(self):
        res = self.run_merge([self.off(10)], 7, 0, restored={PRIV: NOW - 60})
        self.assertEqual(res.rows, {})

    def test_first_run_never_archives(self):
        self.assertEqual(self.run_merge([self.off(100)], 7, 0, first_run=True).rows, {})

    def test_two_day_boundary(self):
        # the minimum of 2 days: a private row offline 1.5 days stays, one offline 2.5 days is archived
        self.assertEqual(self.run_merge([self.off(1.5)], 2, 0, prune_now=NOW).rows, {})
        res = self.run_merge([self.off(2.5)], 2, 0, prune_now=NOW)
        self.assertEqual(self.archived(res), [(PRIV, "auto (private): not online for 2 days")])

    def test_never_longer_than_prune_days(self):
        self.assertEqual(self.run_merge([self.off(6)], 30, 7).rows, {})
        res = self.run_merge([self.off(10)], 30, 7)
        self.assertEqual(self.archived(res), [(PRIV, "auto (private): not online for 10 days")])

    def validate(self, value):
        os.environ["PRUNE_PRIVATE_DAYS"] = value
        return [p for p in Config().validate() if "PRUNE_PRIVATE_DAYS" in p]

    def test_validation(self):
        self.assertEqual(Config().prune_private_days, 0)
        self.assertEqual(self.validate("1"), ["PRUNE_PRIVATE_DAYS must be at least 2 (0 = use PRUNE_DAYS)"])
        self.assertEqual(self.validate("-3"), ["PRUNE_PRIVATE_DAYS must be at least 2 (0 = use PRUNE_DAYS)"])
        self.assertEqual(self.validate("3651"), ["PRUNE_PRIVATE_DAYS must be at most 3650"])
        self.assertEqual(self.validate("1.5"), ["PRUNE_PRIVATE_DAYS must be a whole number"])
        for v in ("0", "2", "3650"):
            self.assertEqual(self.validate(v), [])


if __name__ == "__main__":
    unittest.main()
