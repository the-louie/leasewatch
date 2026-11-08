"""The contrib dnsmasq_leases connector against the host's record contract (merge.normalise_batch).

Lives in the core suite: contrib code may import only the public connector names, and normalise_batch is not one.
"""
from __future__ import annotations

import os
import unittest

from _contrib import CONTRIB, use_contrib

from leasewatch.connectors import HostContext
from leasewatch.connectors.merge import normalise_batch

DIST = "leasewatch-dnsmasq"


class DnsmasqNormaliseTest(unittest.TestCase):
    def setUp(self) -> None:
        use_contrib(self, DIST)
        from leasewatch_dnsmasq.connector import DnsmasqLeasesConnector
        path = os.path.join(CONTRIB, DIST, "tests", "fixtures", "mixed.leases")
        self.conn = DnsmasqLeasesConnector("dhcp1", {"path": path, "network": "LAN"},
                                           HostContext(now=lambda: 1_800_000_000))

    def test_batch_passes_normalise_batch(self) -> None:
        b = self.conn.collect()
        n = normalise_batch("dhcp1", b)
        self.assertEqual([(s.mac, s.ip, s.source, s.kind, s.presence, s.network, s.lease_type) for s in n.sightings],
                         [("02:00:00:00:00:01", "10.0.0.10", "dhcp1", "dhcp", False, "LAN", "dynamic"),
                          ("02:00:00:00:00:03", "10.0.0.12", "dhcp1", "dhcp", False, "LAN", "dynamic")])
        # the host adds its own drops (none here) to the connector's
        self.assertEqual(n.stats, {"leases": 2, "dropped": 5})
        self.assertEqual(normalise_batch("dhcp1", n).stats["dropped"], 5)

    def test_host_drops_add_to_connector_drops(self) -> None:
        from leasewatch_dnsmasq.connector import parse_leases
        from leasewatch.connectors import Batch
        # an Ethernet hwaddr that is not 6 bytes passes the parser and is dropped by the host
        sightings, dropped = parse_leases("0 02:00:00:00:00:01:02 10.0.0.10 a *\n0 20- 10.0.0.11 b *\n", 1)
        n = normalise_batch("dhcp1", Batch(sightings=sightings, stats={"leases": len(sightings), "dropped": dropped}))
        self.assertEqual((n.sightings, n.stats), ([], {"leases": 1, "dropped": 2}))


if __name__ == "__main__":
    unittest.main()
