"""The connector contract (leasewatch.connectors.testing) applied to mdns, with the fake socket of test_mdns: no
socket is opened and no multicast is needed."""
from __future__ import annotations

import errno
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # test_mdns, when not started from here
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

from leasewatch.connectors import Connector, HostContext  # noqa: E402
from leasewatch.connectors.testing import ConnectorContractTests  # noqa: E402
from leasewatch_mdns.connector import MdnsConnector  # noqa: E402
from test_mdns import IP_A, MAC_A, NOW, FakeSocketFactory  # noqa: E402


class MdnsContract(ConnectorContractTests, unittest.TestCase):
    connector_class = MdnsConnector

    def setUp(self) -> None:
        self.factory = FakeSocketFactory()

    def tearDown(self) -> None:
        for s in self.factory.sockets:
            self.assertEqual(s.sent, [], "the connector transmitted on its socket")

    def valid_settings(self) -> dict[str, str]:
        return {"interface": "", "max_age_days": "7", "max_entries": "4096"}

    def failing_settings(self) -> dict[str, str]:
        # port 5353 taken by a responder that does not share it
        self.factory.error = OSError(errno.EADDRINUSE, os.strerror(errno.EADDRINUSE))
        return self.valid_settings()

    def make_context(self) -> HostContext:
        return HostContext(now=lambda: NOW, device_ips=lambda: {IP_A: MAC_A})

    def make_connector(self, settings: dict[str, str]) -> Connector:
        conn = super().make_connector(settings)
        conn._socket_factory = self.factory
        # one name as the parser path would hand it over, so collect() has a record to check
        conn._hear("printer-7", IP_A, "Synthetic Printer", NOW)
        return conn


if __name__ == "__main__":
    unittest.main()
