"""Regression tests for the connector contract kit (leasewatch.connectors.testing): each case runs one contract test
against a small stub connector and checks that the kit fails what breaks the contract and passes what keeps it.
Synthetic data only; no network (every socket call in these stubs is stopped by the kit's guard or never made)."""
from __future__ import annotations

import json
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leasewatch.connectors import (API_VERSION, Batch, ConnectorError, ConnectorInfo, HostContext,  # noqa: E402
                                   Setting, Sighting, make_host_mask)
from leasewatch.connectors.testing import ConnectorContractTests  # noqa: E402

NOW = 1_800_000_000


class Stub:
    """A well-behaved connector; each case overrides the one method or setting under test."""
    settings_decl: tuple[Setting, ...] = (Setting("path", required=True), Setting("password", secret=True))

    @classmethod
    def describe(cls) -> ConnectorInfo:
        return ConnectorInfo("stubtype", "0.1", API_VERSION, frozenset({"sighting"}), cls.settings_decl)

    def __init__(self, name: str, settings: dict, ctx: HostContext) -> None:
        self.name, self.settings, self.ctx = name, dict(settings), ctx

    def __repr__(self) -> str:
        return f"Stub({self.name!r})"

    def validate(self) -> list[str]:
        return []

    def check(self) -> None:
        return None

    def collect(self) -> Batch:
        return Batch(sightings=[Sighting("02:00:00:00:00:01", "", "arp", True, NOW)])

    def close(self) -> None:
        pass


def run(cls: type, test: str, settings: dict | None = None, failing: dict | None = None) -> unittest.TestResult:
    """Run one contract test of the kit against connector class `cls`; the result's failures/errors say if it failed."""
    class Contract(ConnectorContractTests, unittest.TestCase):
        connector_class = cls

        def valid_settings(self) -> dict[str, str]:
            return dict(settings or {"path": "/data/x", "password": "s3cret-value"})

        def failing_settings(self) -> dict[str, str] | None:
            return failing
    result = unittest.TestResult()
    Contract(test).run(result)
    return result


def failed(result: unittest.TestResult) -> bool:
    return bool(result.failures or result.errors)


class NoNetworkTests(unittest.TestCase):
    T = "test_contract_no_network_in_init_or_validate"

    def test_swallowed_lookup_still_fails(self) -> None:
        class C(Stub):
            def validate(self) -> list[str]:
                try:
                    socket.getaddrinfo("router.example.lan", 443)
                except Exception:  # noqa: BLE001 - the broad except under test
                    return []
                return []
        self.assertTrue(failed(run(C, self.T)))

    def test_udp_sendto_fails(self) -> None:
        class C(Stub):
            def validate(self) -> list[str]:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    try:
                        s.sendto(b"x", ("10.0.0.2", 161))
                    except Exception:  # noqa: BLE001
                        pass
                return []
        self.assertTrue(failed(run(C, self.T)))

    def test_gethostbyname_fails(self) -> None:
        for fn in ("gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
            class C(Stub):
                def validate(self, fn: str = fn) -> list[str]:
                    try:
                        getattr(socket, fn)("router.example.lan")
                    except Exception:  # noqa: BLE001
                        pass
                    return []
            with self.subTest(fn=fn):
                self.assertTrue(failed(run(C, self.T)))

    def test_fixture_setup_is_outside_the_guard(self) -> None:
        # valid_settings() may start a local fake (port 0); only the connector is under the no-network rule
        class Contract(ConnectorContractTests, unittest.TestCase):
            connector_class = Stub

            def valid_settings(self) -> dict[str, str]:
                socket.getaddrinfo("127.0.0.1", 0)
                return {"path": "/data/x"}
        result = unittest.TestResult()
        Contract(self.T).run(result)
        self.assertFalse(failed(result), result.failures + result.errors)

    def test_clean_connector_passes(self) -> None:
        self.assertFalse(failed(run(Stub, self.T)))


class MakeConnectorTests(unittest.TestCase):
    def test_host_keys_removed_and_timeout_lent_as_build_instance_does(self) -> None:
        seen = []

        class C(Stub):
            def __init__(self, name: str, settings: dict, ctx: HostContext) -> None:
                super().__init__(name, settings, ctx)
                seen.append((settings.get("timeout"), ctx.timeout))
        run(C, "test_contract_validate", settings={"path": "/data/x", "timeout": "30"})
        self.assertTrue(seen)
        self.assertEqual(set(seen), {(None, 30)})


class SecretFormsTests(unittest.TestCase):
    SECRETS = ("back\\slash-secret", "it's \"quoted\"", 'pa"ss-word')

    def test_repr_escaped_secret_fails(self) -> None:
        class C(Stub):
            def __repr__(self) -> str:
                return f"Leaky({self.settings!r})"
        for secret in self.SECRETS:
            with self.subTest(secret=secret):
                self.assertTrue(failed(run(C, "test_contract_repr_hides_secrets",
                                           settings={"path": "/data/x", "password": secret})))

    def test_error_with_escaped_secret_fails(self) -> None:
        class R(Stub):
            def check(self) -> None:
                raise ConnectorError(f"bad login {self.settings['password']!r}")

        class J(Stub):
            def check(self) -> None:
                raise ConnectorError("bad body " + json.dumps({"p": self.settings["password"]}))
        for cls in (R, J):
            for secret in self.SECRETS:
                with self.subTest(cls=cls.__name__, secret=secret):
                    self.assertTrue(failed(run(cls, "test_contract_failure_raises_connector_error",
                                               failing={"path": "/data/x", "password": secret})))


class DescribeTests(unittest.TestCase):
    T = "test_contract_describe"

    def _with(self, *settings: Setting) -> type:
        return type("C", (Stub,), {"settings_decl": settings})

    def test_key_not_exportable_fails(self) -> None:
        for key in ("", "base-url", "a b"):
            with self.subTest(key=key):
                self.assertTrue(failed(run(self._with(Setting(key, required=True)), self.T)))

    def test_unknown_kind_fails(self) -> None:
        self.assertTrue(failed(run(self._with(Setting("port", kind="integer", max=10)), self.T)))

    def test_secret_file_key_collision_fails(self) -> None:
        self.assertTrue(failed(run(self._with(Setting("cert", secret=True), Setting("cert_file")), self.T)))

    def test_valid_settings_pass(self) -> None:
        self.assertFalse(failed(run(self._with(Setting("base_url"), Setting("port", kind="int", max=10),
                                               Setting("cert", secret=True)), self.T)))


class CheckAndCollectTests(unittest.TestCase):
    T = "test_contract_check_and_collect"

    def test_generator_field_fails(self) -> None:
        class C(Stub):
            def collect(self) -> Batch:
                recs = [Sighting("02:00:00:00:00:01", "", "arp", True, NOW), Sighting("not-a-mac", "", "arp", True, -5)]
                return Batch(sightings=(r for r in recs))  # type: ignore[arg-type]
        self.assertTrue(failed(run(C, self.T)))

    def test_bool_observed_at_fails(self) -> None:
        class C(Stub):
            def collect(self) -> Batch:
                return Batch(sightings=[Sighting("02:00:00:00:00:01", "", "arp", True, True)])  # type: ignore[arg-type]
        self.assertTrue(failed(run(C, self.T)))


class HostCheckTests(unittest.TestCase):
    T = "test_contract_failure_raises_connector_error"

    def _raising(self, text: str) -> type:
        class C(Stub):
            def check(self) -> None:
                raise ConnectorError(text)
        return C

    def test_longer_address_is_not_the_host(self) -> None:
        msg = make_host_mask("https://10.0.0.1")("no route to 10.0.0.15 via 10.0.0.1")
        self.assertFalse(failed(run(self._raising(msg), self.T, failing={"url": "https://10.0.0.1"})))

    def test_other_spellings_of_the_host_fail(self) -> None:
        for url, leak in (("https://[fd00::1]/", "fd00:0000:0000:0000:0000:0000:0000:0001"),
                          ("https://router.example.lan./", "router.example.lan"),
                          ("https://ränder.example.lan/", "xn--rnder-gra.example.lan"),
                          ("https://10.0.0.1", "10.0.0.1")):
            with self.subTest(url=url):
                self.assertTrue(failed(run(self._raising("TLS mismatch for " + leak), self.T, failing={"url": url})))


class CloseTests(unittest.TestCase):
    def test_check_failure_is_not_blamed_on_close(self) -> None:
        class C(Stub):
            def check(self) -> None:
                raise ConnectorError("fake down")
        self.assertFalse(failed(run(C, "test_contract_close")))

    def test_close_that_raises_still_fails(self) -> None:
        class C(Stub):
            def close(self) -> None:
                raise RuntimeError("close raises")
        self.assertTrue(failed(run(C, "test_contract_close")))


if __name__ == "__main__":
    unittest.main()
