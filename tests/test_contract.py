"""The public host mask helper, and the connector contract (leasewatch.connectors.testing) applied to every built-in
connector type, each with a fake client as in test_connectors. Synthetic data only; no network."""
from __future__ import annotations

import unittest

from leasewatch.connectors import Connector, HostContext, make_host_mask, mask_url_host
from leasewatch.connectors.opnsense import OpnsenseConnector
from leasewatch.connectors.snmp_switch import SnmpSwitchConnector
from leasewatch.connectors.testing import ConnectorContractTests
from leasewatch.connectors.unifi import UnifiConnector
from leasewatch.fw1 import Fw1Error
from leasewatch.fw1 import Sighting as Fw1Sighting
from leasewatch.switch import build_snapshot
from leasewatch.unifi import parse_clients

NOW = 1_800_000_000
WRONG = "wrong-credential-value"


class Raises:
    """A client whose every call raises the given exception."""
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def _raise(self, *a: object, **k: object) -> None:
        raise self.exc
    sightings = arp_raw = probe = snapshot = clients = _raise


class MakeHostMaskTests(unittest.TestCase):
    def test_url_whole_occurrences_only(self) -> None:
        mask = make_host_mask("https://10.0.0.1")
        self.assertEqual(mask("10.0.0.1 and 10.0.0.15 and 10.0.0.1:443"), "<host> and 10.0.0.15 and <host>:443")

    def test_ipv6_compressed_and_exploded(self) -> None:
        mask = make_host_mask("https://[fd00::1]")
        self.assertEqual(mask("fd00::1 fd00::1:5 fd00:0000:0000:0000:0000:0000:0000:0001"), "<host> fd00::1:5 <host>")

    def test_case_and_trailing_dot(self) -> None:
        self.assertEqual(make_host_mask("https://ROUTER.example.lan.")("router.EXAMPLE.lan"), "<host>")

    def test_bare_host(self) -> None:
        self.assertEqual(make_host_mask("10.0.0.2")("no answer from 10.0.0.2@161, not 10.0.0.25"),
                         "no answer from <host>@161, not 10.0.0.25")
        self.assertEqual(make_host_mask("fe80::2")("no response from fe80::2: timeout"), "no response from <host>: timeout")

    def test_idna_form(self) -> None:
        mask = make_host_mask("https://ränder.example.lan:8443")
        self.assertEqual(mask("not valid for 'xn--rnder-gra.example.lan'"), "not valid for '<host>'")

    def test_nothing_to_mask(self) -> None:
        for value in ("", "https://", "https://[bad"):
            self.assertEqual(make_host_mask(value)("text 10.0.0.1"), "text 10.0.0.1")

    def test_mask_url_host_keeps_the_label(self) -> None:
        self.assertEqual(mask_url_host("fw1 /api/x: fw1 refused", "https://fw1:8443"), "fw1 /api/x: <host> refused")


class OpnsenseContract(ConnectorContractTests, unittest.TestCase):
    connector_class = OpnsenseConnector

    def valid_settings(self) -> dict[str, str]:
        return {"url": "https://fw1.example.lan", "key": "api-key-value", "secret": "api-secret-value"}

    def failing_settings(self) -> dict[str, str]:
        return {**self.valid_settings(), "secret": WRONG}

    def make_context(self) -> HostContext:
        return HostContext(now=lambda: NOW)

    def make_connector(self, settings: dict[str, str]) -> Connector:
        rows = [Fw1Sighting(mac="02:00:00:00:00:01", ip="10.0.0.5", hostname="alex-ipad", vendor="", vlan="LAN",
                            iface="lan", source="dhcp", lease_type="dynamic", online=False),
                Fw1Sighting(mac="02:00:00:00:00:01", ip="10.0.0.5", hostname="", vendor="", vlan="LAN",
                            iface="lan", source="arp", lease_type="", online=True)]
        fake = type("F", (), {"arp_raw": lambda self: [], "sightings": lambda self, ignore=(): (list(rows), {"leases": 1, "arp": 1})})()
        if settings.get("secret") == WRONG:
            fake = Raises(Fw1Error("fw1 /api/diagnostics/interface/get_arp: HTTP 401 from fw1.example.lan"))
        return OpnsenseConnector(self.instance_name, settings, self.make_context(), client=fake)


class SnmpSwitchContract(ConnectorContractTests, unittest.TestCase):
    connector_class = SnmpSwitchConnector

    def valid_settings(self) -> dict[str, str]:
        return {"host": "10.0.0.2", "name": "sw-rack", "auth_key": "auth-key-value", "priv_key": "priv-key-value"}

    def failing_settings(self) -> dict[str, str]:
        return {**self.valid_settings(), "auth_key": WRONG}

    def make_context(self) -> HostContext:
        return HostContext(now=lambda: NOW)

    def make_connector(self, settings: dict[str, str]) -> Connector:
        snap = build_snapshot([("110.2.0.0.0.0.3", 3)], [("3", 3)], [("3", "GigabitEthernet1/0/3")], [])
        fake = type("W", (), {"probe": lambda self: ("", ""), "snapshot": lambda self: snap})()
        if settings.get("auth_key") == WRONG:
            fake = Raises(RuntimeError(f"wrong digest for {WRONG} from 10.0.0.2@161"))
        return SnmpSwitchConnector(self.instance_name, settings, self.make_context(), client=fake)


class UnifiContract(ConnectorContractTests, unittest.TestCase):
    connector_class = UnifiConnector

    def valid_settings(self) -> dict[str, str]:
        return {"url": "https://unifi.example.lan:8443", "user": "ro", "password": "controller-password"}

    def failing_settings(self) -> dict[str, str]:
        return {**self.valid_settings(), "password": WRONG}

    def make_context(self) -> HostContext:
        return HostContext(now=lambda: NOW)

    def make_connector(self, settings: dict[str, str]) -> Connector:
        wifi = parse_clients([{"mac": "02:00:00:00:00:04", "essid": "HomeNet", "ap_mac": "02:00:00:00:00:aa",
                               "signal": -61, "radio": "na"}], [{"mac": "02:00:00:00:00:aa", "name": "ap-hall"}])
        fake = type("U", (), {"clients": lambda self: dict(wifi)})()
        if settings.get("password") == WRONG:
            fake = Raises(RuntimeError("unifi: login refused by unifi.example.lan"))
        return UnifiConnector(self.instance_name, settings, self.make_context(), client=fake)


if __name__ == "__main__":
    unittest.main()
