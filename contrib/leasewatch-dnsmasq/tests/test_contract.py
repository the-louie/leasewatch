"""The connector contract (leasewatch.connectors.testing) applied to dnsmasq_leases, against the fixture files."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

from leasewatch.connectors import HostContext  # noqa: E402
from leasewatch.connectors.testing import ConnectorContractTests  # noqa: E402
from leasewatch_dnsmasq.connector import DnsmasqLeasesConnector  # noqa: E402

NOW = 1_800_000_000


class DnsmasqContract(ConnectorContractTests, unittest.TestCase):
    connector_class = DnsmasqLeasesConnector

    def valid_settings(self) -> dict[str, str]:
        return {"path": os.path.join(HERE, "fixtures", "v4.leases"), "network": "LAN"}

    def failing_settings(self) -> dict[str, str]:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        return {"path": os.path.join(tmp, "missing.leases")}

    def make_context(self) -> HostContext:
        return HostContext(now=lambda: NOW)


if __name__ == "__main__":
    unittest.main()
