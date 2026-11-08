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
- make_connector(settings): optional, how an instance is built; default as build_instance(): connector_class(name,
  settings without the host keys, make_context() with timeout from TIMEOUT). A built-in wrapper overrides it to hand
  in a fake client.

What is checked: describe() is well formed; __init__ and validate() make no network connection; validate() accepts
the valid settings and names every required key that is missing (through the host's own instance_problems()); the
repr shows no secret value; check() then collect() return a Batch of well-formed records of the declared kinds; a
failure raises ConnectorError whose text holds no secret value and no host of a URL setting; close() never raises.
"""
from __future__ import annotations

import contextlib
import json
import re
import socket
from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar
from unittest import mock

import leasewatch.connectors as _connectors
from leasewatch.connectors import (API_VERSION, HOST_KEYS, MIN_SECRET_LEN, Attachment, Batch, Connector,
                                   ConnectorError, HostContext, InstanceSpec, Sighting, instance_problems,
                                   make_host_mask)

__all__ = ["ConnectorContractTests"]

if TYPE_CHECKING:  # the assert methods come from the TestCase it is mixed into
    import unittest
    _Base = unittest.TestCase
else:
    _Base = object

# \A...\Z, not ^...$: "$" also matches before a final newline, and no env variable name holds one
TYPE_RE = re.compile(r"\A[a-z0-9_]+\Z")
# a setting key becomes the <KEY> of LW_CONNECTOR__<NAME>__<KEY>, so it must be a non-empty shell-exportable word
KEY_RE = TYPE_RE
SETTING_KINDS = frozenset({"str", "int"})  # setting_problems() range-checks only "int"; a typo would skip it silently
SIGHTING_KINDS = frozenset({"dhcp", "arp", "client", "scan", "ndp", "dhcp6"})
LINKS = frozenset({"wired", "wifi"})


# what the no-network test stops: connecting, a connectionless datagram and every name lookup (gethostbyname and
# friends and getnameinfo call the C resolver directly, not getaddrinfo)
_SOCKET_METHODS = ("connect", "connect_ex", "sendto", "sendmsg")
_SOCKET_FUNCS = ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
                 "getnameinfo")


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
        # as build_instance() does: the host keys never reach the connector, and TIMEOUT arrives as ctx.timeout, so
        # a connector that reads settings["timeout"] fails here as it would in production
        ctx = replace(self.make_context(), timeout=InstanceSpec(self.instance_name, "", settings).timeout)
        return self.connector_class(self.instance_name, {k: v for k, v in settings.items() if k not in HOST_KEYS}, ctx)

    # --- helpers -------------------------------------------------------------------------------------------------

    def _build(self, settings: dict[str, str]) -> Connector:
        conn = self.make_connector(dict(settings))
        self.addCleanup(conn.close)
        return conn

    def _secret_values(self, settings: dict[str, str]) -> list[str]:
        keys = {s.key for s in self.connector_class.describe().settings if s.secret}
        # a value under MIN_SECRET_LEN is not masked by make_redactor (see there), so it is not looked for either.
        # The repr and JSON escaped forms too, as make_redactor masks them: a {x!r} or a JSON body echoes a secret
        # with a quote or backslash escaped, and the literal would then not match
        return [f for k, v in settings.items() if k in keys and len(v) >= MIN_SECRET_LEN
                for f in {v, repr(v)[1:-1], json.dumps(v)[1:-1]}]

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
            self.assertRegex(k, KEY_RE, f"setting key {k!r} is not of the form [a-z0-9_]+")
            self.assertNotIn(k, HOST_KEYS, f"setting key {k!r} is a host key")
        for s in info.settings:
            self.assertIn(s.kind, SETTING_KINDS, f"setting {s.key!r} has an unknown kind")
            if s.secret:  # parse_instances() takes <KEY>_FILE as the secret's file, so such a key never arrives
                self.assertNotIn(f"{s.key}_file", keys, f"setting key {s.key + '_file'!r} is {s.key}'s _FILE form")

    def test_contract_no_network_in_init_or_validate(self) -> None:
        settings = self.valid_settings()  # outside the guard: the fixture may start a local fake on port 0
        calls: list[str] = []

        def stop(what: str) -> object:
            def no_network(*args: object, **kwargs: object) -> None:
                # recorded as well as raised: a connector's own `except Exception` would swallow the raise
                calls.append(what)
                raise AssertionError(f"network I/O in __init__ or validate(): {what}")
            return no_network
        with contextlib.ExitStack() as stack:
            for name in _SOCKET_METHODS:
                if not hasattr(socket.socket, name):  # sendmsg is Unix only; a missing one cannot be called either
                    continue
                stack.enter_context(mock.patch.object(socket.socket, name, stop(f"socket.{name}")))
            for name in _SOCKET_FUNCS:
                stack.enter_context(mock.patch.object(socket, name, stop(name)))
            conn = self._build(settings)
            conn.validate()
        self.assertEqual(calls, [], "network I/O in __init__ or validate()")

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
        # normalise_batch() drops a field that is not a list or tuple whole (a generator would also be used up by
        # the first loop below, so its records would go unchecked)
        self.assertIsInstance(batch.sightings, (list, tuple))
        self.assertIsInstance(batch.attachments, (list, tuple))
        info = self.connector_class.describe()
        self.assertTrue(batch.sightings or batch.attachments, "the valid fixture gives no records")
        # assertFalse, not == []: an empty tuple is as clean to normalise_batch() as an empty list
        if "sighting" not in info.produces:
            self.assertFalse(batch.sightings, "sightings from a type that does not produce them")
        if "attachment" not in info.produces:
            self.assertFalse(batch.attachments, "attachments from a type that does not produce them")
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
            self.assertNotIsInstance(r.observed_at, bool, "observed_at is a bool")  # the host reads a bool as 0
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
                # whole occurrences in every spelling make_host_mask() covers (case, trailing dot, IDNA, IPv6
                # exploded), so "10.0.0.15" is not the host 10.0.0.1 but "fd00:0000:...:0001" is fd00::1
                self.assertEqual(make_host_mask(v)(text), text, "the error text holds the host of a URL setting")

    def test_contract_close(self) -> None:
        conn = self.make_connector(self.valid_settings())
        conn.close()
        conn.close()
        conn = self.make_connector(self.valid_settings())
        try:
            conn.check()
            conn.collect()
        except Exception:  # noqa: BLE001 - test_contract_check_and_collect reports it; here only close() is tested
            pass
        finally:
            conn.close()
        conn.close()
