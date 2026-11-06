"""The connector contract (leasewatch.connectors.testing) applied to mikrotik, against the fake RouterOS of
test_mikrotik on an ephemeral port."""
from __future__ import annotations

import os
import sys
import unittest
import urllib.request
from typing import Any
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # test_mikrotik, when not started from here
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

from leasewatch.connectors import HostContext, build_opener  # noqa: E402
from leasewatch.connectors.testing import ConnectorContractTests  # noqa: E402
from leasewatch_mikrotik.connector import MikrotikConnector  # noqa: E402
from test_mikrotik import NOW, PASSWORD, SERVERS, USER, FakeRouter, arp, lease  # noqa: E402

URL = "https://router.example.lan"


class ToFake:
    """An opener that sends each request to a fake router over plain HTTP: the connector requires an https:// URL,
    and the fake has no certificate."""
    def __init__(self, fake_url: str, **kw: bool) -> None:
        self.fake_url, self.opener = fake_url, build_opener(**kw)

    def open(self, req: urllib.request.Request, timeout: float = 0) -> Any:
        parts = urlsplit(req.full_url)
        req.full_url = self.fake_url + parts.path + ("?" + parts.query if parts.query else "")
        return self.opener.open(req, timeout=timeout)


class MikrotikContract(ConnectorContractTests, unittest.TestCase):
    connector_class = MikrotikConnector

    def setUp(self) -> None:
        self.router = FakeRouter()
        self.addCleanup(self.router.close)
        self.router.json("/rest/system/resource", {"version": "7.16 (stable)"})
        self.router.json("/rest/ip/dhcp-server", SERVERS)
        self.router.json("/rest/ip/dhcp-server/lease", [lease()])
        self.router.json("/rest/ip/arp", [arp()])
        self.fake = self.router

    def valid_settings(self) -> dict[str, str]:
        return {"url": URL, "user": USER, "password": PASSWORD}

    def failing_settings(self) -> dict[str, str]:
        # a router that refuses the credential on every path
        self.fake = FakeRouter()
        self.addCleanup(self.fake.close)
        for path in ("/rest/system/resource", "/rest/ip/dhcp-server", "/rest/ip/dhcp-server/lease", "/rest/ip/arp"):
            self.fake.json(path, {"error": 401, "message": f"Unauthorized at {URL}"}, status=401)
        return {"url": URL, "user": USER, "password": "wrong-" + PASSWORD}

    def make_context(self) -> HostContext:
        return HostContext(now=lambda: NOW, opener_factory=lambda **kw: ToFake(self.fake.url, **kw))


if __name__ == "__main__":
    unittest.main()
