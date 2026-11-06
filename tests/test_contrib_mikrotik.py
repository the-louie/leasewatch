"""The contrib mikrotik connector against the host's record contract (merge.normalise_batch).

Lives in the core suite: contrib code may import only the public connector names, and normalise_batch is not one.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _contrib import use_contrib  # noqa: E402

from leasewatch.connectors import Batch, HostContext  # noqa: E402
from leasewatch.connectors.merge import normalise_batch  # noqa: E402

DIST = "leasewatch-mikrotik"
SERVERS = [{"name": "dhcp-lan", "interface": "bridge-lan"}]
LEASES = [
    {"address": "10.0.0.10", "mac-address": "02:00:00:00:00:01", "server": "dhcp-lan", "status": "bound",
     "dynamic": "false", "disabled": "false", "host-name": "alex-ipad"},
    {"address": "10.0.0.11", "mac-address": "02:00:00:00:00:0A", "server": "dhcp-lan", "status": "bound"},
    {"address": "10.0.0.12", "mac-address": "not-a-mac", "server": "dhcp-lan", "status": "bound"},
    {"address": "10.0.0.13", "mac-address": "02:00:00:00:00:03", "status": "bound", "dynamic": "maybe"},
]
ARP = [{"address": "10.0.0.20", "mac-address": "02:00:00:00:00:02", "interface": "bridge-lan", "complete": "true",
        "invalid": "false", "disabled": "false", "status": "reachable"}]


class MikrotikNormaliseTest(unittest.TestCase):
    def setUp(self) -> None:
        use_contrib(self, DIST)
        from leasewatch_mikrotik.connector import parse
        sightings, dropped = parse(SERVERS, LEASES, ARP, 1_800_000_000)
        self.batch = Batch(sightings=sightings, stats={"leases": len(LEASES), "arp": len(ARP), "dropped": dropped})

    def test_batch_passes_normalise_batch(self) -> None:
        n = normalise_batch("mt1", self.batch)
        self.assertEqual([(s.mac, s.ip, s.source, s.kind, s.presence, s.network, s.lease_type) for s in n.sightings],
                         [("02:00:00:00:00:01", "10.0.0.10", "mt1", "dhcp", False, "bridge-lan", "static"),
                          ("02:00:00:00:00:0a", "10.0.0.11", "mt1", "dhcp", False, "bridge-lan", "dynamic"),
                          ("02:00:00:00:00:02", "10.0.0.20", "mt1", "arp", True, "bridge-lan", "")])
        # the connector dropped the bad flag, the host the bad MAC
        self.assertEqual(n.stats, {"leases": 4, "arp": 1, "dropped": 2})
        self.assertEqual(normalise_batch("mt1", n).stats["dropped"], 2)

    def test_connector_builds_without_io(self) -> None:
        from leasewatch_mikrotik.connector import MikrotikConnector

        def no_io(**kw: bool) -> object:
            raise AssertionError("I/O before check")
        conn = MikrotikConnector("mt1", {"url": "https://router.example.lan", "user": "lw-reader",
                                         "password": "s3cr3t-Pa55word"}, HostContext(opener_factory=no_io))
        self.assertEqual(conn.validate(), [])


if __name__ == "__main__":
    unittest.main()
