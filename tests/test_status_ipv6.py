"""The status line text (meta last_raw) carries the IPv6 stats of the opnsense connector when they are present."""
import unittest

from test_instances import FW1, Base
from leasewatch.connectors import Batch, Sighting


class LastRawIpv6Tests(Base):
    def last_raw(self, stats):
        col, db = self.collector({"LW_CONNECTORS": "fw1,fx", **FW1, "LW_CONNECTOR__FX__TYPE": "fakefw"}, rows=[])
        col._connectors["fx"].on_collect = lambda: Batch(
            sightings=[Sighting(mac="02:00:00:00:00:02", source="", kind="arp", observed_at=0, presence=True)],
            stats=stats)
        self.assertTrue(col.run_once()["ok"])
        return db.get_meta("last_raw")

    def test_without_the_keys_the_text_is_unchanged(self):
        self.assertEqual(self.last_raw({"leases": 2, "arp": 1}), "2 leases, 1 arp")

    def test_ndp_count_and_unavailable_flag(self):
        self.assertEqual(self.last_raw({"leases": 2, "arp": 1, "ndp": 4, "ndp_unavailable": 1}),
                         "2 leases, 1 arp, 4 ndp, ndp unavailable")

    def test_zero_counts_show_and_kea6_flag(self):
        self.assertEqual(self.last_raw({"leases": 2, "arp": 1, "ndp": 0, "leases6": 0, "kea6_unavailable": 1}),
                         "2 leases, 1 arp, 0 ndp, 0 leases6, kea6 unavailable")


if __name__ == "__main__":
    unittest.main()
