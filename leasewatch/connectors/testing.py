"""The connector contract as reusable tests, for built-in and third-party connector types.

Mix ConnectorContractTests into a unittest.TestCase and fill in the hooks:

    class MyContract(ConnectorContractTests, unittest.TestCase):
        connector_class = MyConnector

        def valid_settings(self) -> dict[str, str]:
            return {"url": f"http://127.0.0.1:{self.fake.port}", "password": "s3cret-value"}

It is a mixin, not a TestCase: `unittest discover` would otherwise collect the imported base class in every module
that imports it and run its hooks unfilled. Every test it adds is named test_contract_*.

Hooks:
- connector_class: the class under test (class attribute).
- valid_settings(): settings that work against a fake (a local server, a temporary file), never the network.
- make_context(): the HostContext lent to the instance; default HostContext().
- failing_settings(): optional, settings for which check() or collect() raises ConnectorError against the fake
  (a wrong credential); None (the default) skips that test.
- make_connector(settings): optional, how an instance is built; default connector_class(name, settings,
  make_context()). A built-in wrapper overrides it to hand in a fake client.

What is checked: describe() is well formed; __init__ and validate() make no network connection; validate() accepts
the valid settings and names every required key that is missing (through the host's own instance_problems()); the
repr shows no secret value; check() then collect() return a Batch of well-formed records of the declared kinds; a
failure raises ConnectorError whose text holds no secret value and no host of a URL setting; close() never raises.
"""
from __future__ import annotations

import re
import socket
from typing import TYPE_CHECKING, ClassVar
from unittest import mock
from urllib.parse import urlparse

import leasewatch.connectors as _connectors
from leasewatch.connectors import (API_VERSION, HOST_KEYS, MIN_SECRET_LEN, Attachment, Batch, Connector,
                                   ConnectorError, HostContext, InstanceSpec, Sighting, instance_problems)

__all__ = ["ConnectorContractTests"]

if TYPE_CHECKING:  # the assert methods come from the TestCase it is mixed into
    import unittest
    _Base = unittest.TestCase
else:
    _Base = object

TYPE_RE = re.compile(r"^[a-z0-9_]+$")
SIGHTING_KINDS = frozenset({"dhcp", "arp", "client", "scan"})
LINKS = frozenset({"wired", "wifi"})


def _no_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("network I/O in __init__ or validate()")


class ConnectorContractTests(_Base):
    connector_class: ClassVar[type]
    instance_name: ClassVar[str] = "contract"

    # --- hooks ---------------------------------------------------------------------------------------------------

    def valid_settings(self) -> dict[str, str]:
        raise NotImplementedError("a ConnectorContractTests subclass must define valid_settings()")

    def failing_settings(self) -> dict[str, str] | None:
        return None

    def make_context(self) -> HostContext:
        return HostContext()

    def make_connector(self, settings: dict[str, str]) -> Connector:
        return self.connector_class(self.instance_name, settings, self.make_context())

    # --- helpers -------------------------------------------------------------------------------------------------

    def _build(self, settings: dict[str, str]) -> Connector:
        conn = self.make_connector(dict(settings))
        self.addCleanup(conn.close)
        return conn

    def _secret_values(self, settings: dict[str, str]) -> list[str]:
        keys = {s.key for s in self.connector_class.describe().settings if s.secret}
        # a value under MIN_SECRET_LEN is not masked by make_redactor (see there), so it is not looked for either
        return [v for k, v in settings.items() if k in keys and len(v) >= MIN_SECRET_LEN]

    # --- the contract --------------------------------------------------------------------------------------------

    def test_contract_describe(self) -> None:
        info = self.connector_class.describe()
        self.assertRegex(info.type, TYPE_RE)
        self.assertEqual(info.api_version, API_VERSION)
        self.assertTrue(info.produces, "produces is empty")
        self.assertLessEqual(set(info.produces), {"sighting", "attachment"})
        self.assertLessEqual(set(info.roles), {"controller"})
        keys = [s.key for s in info.settings]
        self.assertEqual(len(keys), len(set(keys)), "setting keys are not unique")
        for k in keys:
            self.assertEqual(k, k.lower(), f"setting key {k!r} is not lower case")
            self.assertNotIn(k, HOST_KEYS, f"setting key {k!r} is a host key")

    def test_contract_no_network_in_init_or_validate(self) -> None:
        with mock.patch.object(socket.socket, "connect", _no_network), \
                mock.patch.object(socket.socket, "connect_ex", _no_network), \
                mock.patch.object(socket, "create_connection", _no_network), \
                mock.patch.object(socket, "getaddrinfo", _no_network):
            conn = self._build(self.valid_settings())
            conn.validate()

    def test_contract_validate(self) -> None:
        settings = self.valid_settings()
        conn = self._build(settings)
        problems = conn.validate()
        self.assertIsInstance(problems, list)
        self.assertEqual(problems, [])
        info = self.connector_class.describe()
        # instance_problems() looks the type up in the registry; a third-party type under test is not in it
        with mock.patch.object(_connectors, "registry", lambda: {info.type: self.connector_class}):
            self.assertEqual(instance_problems(InstanceSpec(self.instance_name, info.type, settings), conn), [])
            for s in info.settings:
                if not s.required:
                    continue
                with self.subTest(missing=s.key):
                    rest = {k: v for k, v in settings.items() if k != s.key}
                    problems = instance_problems(InstanceSpec(self.instance_name, info.type, rest), self._build(rest))
                    self.assertTrue(any(s.key.upper() in p for p in problems), problems)

    def test_contract_repr_hides_secrets(self) -> None:
        settings = self.valid_settings()
        text = repr(self._build(settings))
        for v in self._secret_values(settings):
            self.assertNotIn(v, text)

    def test_contract_check_and_collect(self) -> None:
        conn = self._build(self.valid_settings())
        self.assertIsNone(conn.check())
        batch = conn.collect()
        self.assertIsInstance(batch, Batch)
        info = self.connector_class.describe()
        self.assertTrue(batch.sightings or batch.attachments, "the valid fixture gives no records")
        if "sighting" not in info.produces:
            self.assertEqual(batch.sightings, [])
        if "attachment" not in info.produces:
            self.assertEqual(batch.attachments, [])
        norm_mac = HostContext().norm_mac
        for r in batch.sightings:
            self.assertIsInstance(r, Sighting)
            self.assertIn(r.kind, SIGHTING_KINDS)
        for r in batch.attachments:
            self.assertIsInstance(r, Attachment)
            self.assertIn(r.link, LINKS)
        for r in [*batch.sightings, *batch.attachments]:
            self.assertTrue(norm_mac(r.mac), f"MAC {r.mac!r} fails norm_mac")
            self.assertIsInstance(r.observed_at, int)
            self.assertGreater(r.observed_at, 0)

    def test_contract_failure_raises_connector_error(self) -> None:
        settings = self.failing_settings()
        if settings is None:
            self.skipTest("no failing_settings()")
        conn = self._build(settings)
        with self.assertRaises(ConnectorError) as cm:
            conn.check()
            conn.collect()
        text = str(cm.exception)
        for v in self._secret_values(settings):
            self.assertNotIn(v, text)
        for v in settings.values():
            if v.lower().startswith(("http://", "https://")):
                try:
                    host = urlparse(v).hostname or ""
                except ValueError:
                    host = ""
                if host:
                    self.assertNotIn(host.lower(), text.lower())

    def test_contract_close(self) -> None:
        conn = self.make_connector(self.valid_settings())
        conn.close()
        conn.close()
        conn = self.make_connector(self.valid_settings())
        try:
            conn.check()
            conn.collect()
        finally:
            conn.close()
        conn.close()
