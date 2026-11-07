"""Edge cases of the connector helpers (redaction, URL checks, settings, SNMP and OPNsense wrappers)."""
from __future__ import annotations

import io
import os
import ssl
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore, sources
from leasewatch import snmp_profiles
from leasewatch.config import Config, parse_instances
from leasewatch.fw1 import Fw1Error
from leasewatch.connectors import (HOST_SETTINGS, ConnectorError, HostContext, InstanceSpec, Setting, build_instance,
                                   instance_problems, make_redactor, mask_url_host, setting_problems, url_problems)
from leasewatch.connectors.opnsense import OpnsenseConnector
from leasewatch.connectors.snmp_switch import SnmpSwitchConnector, _bounded, _forms, to_attachments
from leasewatch.connectors.unifi import UnifiConnector
from leasewatch.switch import build_snapshot

CTX = HostContext(now=lambda: 1700000000)
SW = {"host": "10.0.0.2", "name": "sw-rack", "auth_key": "a" * 8, "priv_key": "p" * 8}
FW = {"url": "https://fw1.example.lan", "key": "abcdkey1", "secret": "abcdsec1"}
UF = {"url": "https://unifi.example.lan", "user": "ro", "password": "pw123456"}


class Raises:
    """A client whose every call raises the given exception."""
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    def _raise(self, *a: object, **k: object) -> None:
        raise self.exc
    sightings = arp_raw = snapshot = clients = probe = _raise


class _Body(io.BytesIO):
    def __enter__(self) -> "_Body":
        return self

    def __exit__(self, *a: object) -> None:
        self.close()


class EnvTest(unittest.TestCase):
    """Config() and parse_instances read a cleaned environment, restored after each test."""
    def setUp(self) -> None:
        self._saved = clean_env()

    def tearDown(self) -> None:
        restore(self._saved)


class RedactorTests(unittest.TestCase):
    def test_overlapping_secrets_are_both_masked(self) -> None:
        self.assertNotIn("pass", make_redactor(["pass1234", "1234word"])("x pass1234word y"))
        out = make_redactor(["abcdef", "defghi"])("tok abcdefghi")
        self.assertEqual(out, "tok ***")
        self.assertEqual(make_redactor(["abcdef", "defghi"])("k=abcdef p=defghi"), "k=*** p=***")


class UrlTests(unittest.TestCase):
    def test_bad_port_and_control_chars_are_reported(self) -> None:
        for u in ("https://fw:abc", "https://fw:99999", "https://fw:-1", "https://10.0.0.1\x00x", "https://fw\n.example.lan"):
            self.assertEqual(url_problems("url", u, "hint"), ["url is not a valid URL"], repr(u))
            self.assertTrue(OpnsenseConnector("fw1", {**FW, "url": u}).validate(), repr(u))
        self.assertEqual(url_problems("url", "https://fw:8443", "hint"), [])

    def test_unparseable_url_with_credentials_reports_both(self) -> None:
        self.assertEqual(url_problems("url", "https://u:p@[::1", "hint"),
                         ["url is not a valid URL", "url must not contain credentials"])

    def test_url_of_only_slashes_is_not_reported_as_missing(self) -> None:
        for u in ("/", "///"):
            problems = UnifiConnector("n", {**UF, "url": u}).validate()
            self.assertFalse(any("is required" in p for p in problems), problems)
            self.assertTrue(any("must be a URL" in p for p in problems), problems)


class SettingsTests(EnvTest):
    def test_empty_choice_setting_with_default_is_reported(self) -> None:
        os.environ.update({"LW_CONNECTORS": "fw1", "LW_CONNECTOR__FW1__TYPE": "opnsense",
                           "LW_CONNECTOR__FW1__URL": "https://fw.example.lan", "LW_CONNECTOR__FW1__KEY": "abcdkey1",
                           "LW_CONNECTOR__FW1__SECRET": "abcdsec1", "LW_CONNECTOR__FW1__DHCP_BACKEND": ""})
        specs, _ = parse_instances(os.environ)
        problems = instance_problems(specs[0])
        self.assertTrue(any("DHCP_BACKEND must be one of" in p for p in problems), problems)

    def test_empty_snmp_auth_and_user_are_reported(self) -> None:
        problems = SnmpSwitchConnector("sw1", {**SW, "auth": ""}, CTX, client=object()).validate()
        self.assertTrue(any("AUTH must be one of" in p for p in problems), problems)
        problems = SnmpSwitchConnector("sw1", {**SW, "user": ""}, CTX, client=object()).validate()
        self.assertTrue(any("USER is required" in p for p in problems), problems)
        # detection (empty PROFILE) stays fine: its default is empty
        self.assertEqual(SnmpSwitchConnector("sw1", {**SW, "profile": ""}, CTX, client=object()).validate(), [])

    def test_defaults_still_valid(self) -> None:  # must not flag a setting left at its default
        os.environ.update(sources("switch", "unifi"))
        for spec in Config().instances:
            self.assertEqual(instance_problems(spec), [], spec)

    def test_repr_hides_pass_and_community(self) -> None:
        r = repr(OpnsenseConnector("fw1", {**FW, "auth_pass": "hunter22", "community": "private1", "passphrase": "xyzw1234"}))
        for v in ("hunter22", "private1", "xyzw1234"):
            self.assertNotIn(v, r)

    def test_huge_integer_says_too_large(self) -> None:
        self.assertEqual(setting_problems("fw1", "opnsense", HOST_SETTINGS[1:], {"timeout": "9" * 5000}),
                         ["connector fw1 (opnsense): TIMEOUT must be at most 3600"])
        self.assertEqual(setting_problems("fw1", "opnsense", HOST_SETTINGS[1:], {"timeout": "-" + "9" * 5000}),
                         ["connector fw1 (opnsense): TIMEOUT must be at least 1"])
        self.assertEqual(setting_problems("fw1", "opnsense", HOST_SETTINGS[1:], {"timeout": "x9"}),
                         ["connector fw1 (opnsense): TIMEOUT must be an integer"])


class OpnsenseTests(unittest.TestCase):
    def _conn(self, body: str | None = None, exc: BaseException | None = None, **extra: str) -> OpnsenseConnector:
        c = OpnsenseConnector("fw1", {**FW, **extra}, CTX)

        def open_(req: object, timeout: float | None = None) -> _Body:
            if exc is not None:
                raise exc
            return _Body(body.encode())
        c.client._opener.open = open_  # type: ignore[method-assign]
        return c

    def test_tls_mismatch_does_not_show_the_host(self) -> None:
        err = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname "
                                              "mismatch, certificate is not valid for 'fw1.example.lan'. (_ssl.c:1000)")
        c = self._conn(exc=urllib.error.URLError(err))
        for call in (c.check, c.collect):
            with self.assertRaises(ConnectorError) as cm:
                call()
            self.assertNotIn("fw1.example.lan", str(cm.exception))
            self.assertIn("<host>", str(cm.exception))
            self.assertTrue(str(cm.exception).startswith("fw1 /api/"), str(cm.exception))

    def test_infinite_total_is_a_connector_error_or_ignored(self) -> None:
        for backend, body in (("kea", '{"rows":[],"total":1e999}'), ("isc", '{"rows":[],"total":-Infinity}')):
            c = self._conn(body=body, dhcp_backend=backend)
            self.assertEqual(c.client.leases_raw(), [])
        c = self._conn(body='{"rows":[],"total":1e999}', dhcp_backend="kea")
        self.assertEqual(c.client.reservations_raw(), [])


class UnifiTests(unittest.TestCase):
    def test_tls_mismatch_does_not_show_the_host(self) -> None:
        for host in ("unifi.example.lan", "10.0.0.9"):
            msg = (f"unifi: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname "
                   f"mismatch, certificate is not valid for '{host}'. (_ssl.c:1000)>")
            c = UnifiConnector("unifi", {**UF, "url": f"https://{host}:8443"}, CTX, client=Raises(RuntimeError(msg)))
            for call in (c.check, c.collect):
                with self.assertRaises(ConnectorError) as cm:
                    call()
                self.assertNotIn(host, str(cm.exception))
                self.assertTrue(str(cm.exception).startswith("unifi: "))


class SnmpTests(unittest.TestCase):
    def test_scoped_ipv6_host_is_masked_not_crashing(self) -> None:
        self.assertIn("fe80::2%eth0", _forms("fe80::2%eth0"))
        c = SnmpSwitchConnector("sw", {**SW, "host": "fe80::2%eth0"}, CTX, client=Raises(RuntimeError("no answer from fe80::2%eth0@161")))
        with self.assertRaises(ConnectorError) as cm:
            c.collect()
        self.assertNotIn("fe80::2", str(cm.exception))

    def test_ipv6_followed_by_punctuation_colon_is_masked(self) -> None:
        def r(h: str, t: str) -> str:
            for rx in _bounded(_forms(h)):
                t = rx.sub("<host>", t)
            return t
        self.assertEqual(r("fe80::2", "no response from fe80::2: timeout"), "no response from <host>: timeout")
        self.assertEqual(r("fe80::2", "fe80::2:5"), "fe80::2:5")
        self.assertEqual(r("fe80::2", "[fe80::2]:161"), "[<host>]:161")

    def test_deep_profile_file_is_a_profile_problem(self) -> None:
        # a value nested ~600 deep passes json.loads but makes copy.deepcopy raise RecursionError
        def deep(path: str) -> dict:
            raise RecursionError("maximum recursion depth exceeded")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with open(path, "w") as f:
                f.write("{}")
            with mock.patch.object(snmp_profiles, "load_file", deep):
                c = SnmpSwitchConnector("sw1", {**SW, "profile_file": path}, CTX, client=object())
        self.assertTrue(any("PROFILE_FILE is not a valid snmp profile" in p for p in c.validate()), c.validate())

    def test_secret_containing_user_or_host_is_masked_whole(self) -> None:
        cases = (({"user": "admin", "auth_key": "admin@2024x"}, "bad key admin@2024x", "2024x"),
                 ({"user": "admin", "priv_key": "admin pass 99"}, "got 'admin pass 99'", "pass 99"),
                 ({"auth_key": "10.0.0.2/secret"}, "echo 10.0.0.2/secret", "secret"))
        for extra, text, leak in cases:
            c = SnmpSwitchConnector("sw", {**SW, **extra}, CTX, client=Raises(RuntimeError(text)))
            self.assertNotIn(leak, c.redact(text), extra)
            with self.assertRaises(ConnectorError) as cm:
                c.collect()
            self.assertNotIn(leak, str(cm.exception))

    def test_user_mask_does_not_hit_host_mask(self) -> None:
        for user in ("host", "HOST"):
            c = SnmpSwitchConnector("switch", {**SW, "user": user}, CTX, client=object())
            self.assertEqual(c.redact("Bad address 10.0.0.2@161 user host"), "Bad address <host>@161 user <user>")

    def test_import_error_names_the_missing_module(self) -> None:
        c = SnmpSwitchConnector("sw", SW, CTX, client=Raises(ModuleNotFoundError("No module named 'imp'", name="imp")))
        with self.assertRaises(ConnectorError) as cm:
            c.check()
        self.assertIn("imp", str(cm.exception))
        self.assertIn("pysnmp", str(cm.exception))
        c = SnmpSwitchConnector("sw", SW, CTX, client=Raises(ModuleNotFoundError("No module named 'pysnmp'", name="pysnmp")))
        with self.assertRaises(ConnectorError) as cm:
            c.check()
        self.assertEqual(str(cm.exception), "missing dependency pysnmp")

    def test_bridge_vlan_zero_is_unknown(self) -> None:
        snap = build_snapshot([("0.2.0.0.0.0.1", 1)], [("1", 1)], [("1", "ge1")], [])
        self.assertIsNone(to_attachments(snap, "sw", "switch", 0)[0].vlan)

    def test_builtin_profile_that_fails_to_load_is_reported(self) -> None:
        def boom(name: str) -> dict:
            raise snmp_profiles.ProfileError("x")
        with mock.patch.object(snmp_profiles, "load", boom):
            c = SnmpSwitchConnector("sw", {**SW, "profile": "standard"}, CTX, client=object())
        self.assertTrue(c.validate(), "validate() must name why check()/collect() refuse")
        with self.assertRaises(ConnectorError):
            c.check()


class _Falsy:
    """A test double that is falsy (len 0) but still a client."""
    def __len__(self) -> int:
        return 0


class ClientInjectionTests(unittest.TestCase):
    def test_falsy_client_double_is_kept(self) -> None:
        for conn in (UnifiConnector("unifi", UF, CTX, client=_Falsy()),
                     SnmpSwitchConnector("sw", SW, CTX, client=_Falsy()),
                     OpnsenseConnector("fw1", FW, CTX, client=_Falsy())):
            self.assertIsInstance(conn.client, _Falsy, type(conn).__name__)

    def test_switch_timeout_reaches_the_snmp_client(self) -> None:
        c = build_instance(InstanceSpec("sw", "snmp_switch", {**SW, "timeout": "180"}), CTX)
        self.assertEqual(c.client.timeout, 180)  # was a fixed 60 s, whatever TIMEOUT said
        self.assertEqual(CTX.timeout, 60)  # the shared context is not changed


def _mask(host: str, text: str) -> str:
    for rx in _bounded(_forms(host)):
        text = rx.sub("<host>", text)
    return text


class RedactionAndUrlEdgeTests(unittest.TestCase):
    def test_host_right_after_angle_bracket_is_masked(self) -> None:
        self.assertEqual(_mask("10.0.0.2", "no route to <10.0.0.2>"), "no route to <<host>>")
        self.assertEqual(_mask("fe80::2", "no route to <fe80::2>"), "no route to <<host>>")
        self.assertEqual(mask_url_host("unifi: no route to <fw1.example.lan>", "https://fw1.example.lan:8443/"),
                         "unifi: no route to <<host>>")

    def test_secret_inside_host_does_not_split_the_host(self) -> None:
        c = SnmpSwitchConnector("sw", {**SW, "host": "admin-sw01.example.com", "user": "admin", "auth_key": "admin-sw01"},
                                CTX, client=object())
        self.assertEqual(c.redact("Bad address admin-sw01.example.com@161"), "Bad address <host>@161")
        self.assertEqual(c.redact("key admin-sw01 refused"), "key *** refused")

    def test_absent_choice_key_is_not_refused(self) -> None:
        st = [Setting("mode", default="a", choices=("a", "b"))]
        self.assertEqual(setting_problems("p", "plain", st, {}), [])
        self.assertEqual(setting_problems("p", "plain", st, {"mode": ""}), ["connector p (plain): MODE must be one of a, b"])

    def _import_error(self, e: ImportError) -> str:
        c = SnmpSwitchConnector("sw", SW, CTX, client=Raises(e))
        with self.assertRaises(ConnectorError) as cm:
            c.check()
        return str(cm.exception)

    def test_import_error_text_matches_the_failure(self) -> None:
        crypto = self._import_error(ModuleNotFoundError("No module named 'Cryptodome'", name="Cryptodome"))
        self.assertIn("no module Cryptodome", crypto)
        self.assertNotIn("(pysnmp 7 is needed)", crypto)  # pysnmp 7 may be installed; its backend is not
        name = self._import_error(ImportError("cannot import name 'octets' from 'pyasn1.compat'", name="pyasn1.compat"))
        self.assertNotIn("no module", name)  # the module exists, a name in it is missing
        self.assertIn("pyasn1.compat", name)
        older = type(sys)("pysnmp")  # an installed pysnmp before 7: the package imports, its v3arch does not
        for e in (ModuleNotFoundError("No module named 'pysnmp.hlapi.v3arch'", name="pysnmp.hlapi.v3arch"),
                  ImportError("cannot import name 'bulk_cmd'", name="pysnmp.hlapi.v3arch.asyncio")):
            with mock.patch.dict(sys.modules, {"pysnmp": older}):
                text = self._import_error(e)
            self.assertNotEqual(text, "missing dependency pysnmp")  # it is installed, in the wrong version
            self.assertIn("pysnmp 7", text)

    def test_idn_host_punycode_is_masked(self) -> None:
        for host, alabel in (("r\u00e4nder.example.lan", "xn--rnder-gra.example.lan"), ("b\u00fccher.example.lan", "xn--bcher-kva.example.lan")):
            msg = f"<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate is not valid for '{alabel}'. (_ssl.c:1000)>"
            self.assertNotIn(alabel, mask_url_host("unifi: " + msg, f"https://{host}:8443"))
            u = UnifiConnector("unifi", {**UF, "url": f"https://{host}:8443"}, CTX, client=Raises(RuntimeError("unifi: " + msg)))
            o = OpnsenseConnector("fw1", {**FW, "url": f"https://{host}"}, CTX, client=Raises(Fw1Error("fw1 /api/x: " + msg)))
            for call in (u.check, u.collect, o.check, o.collect):
                with self.assertRaises(ConnectorError) as cm:
                    call()
                self.assertNotIn(alabel, str(cm.exception))
                self.assertIn("<host>", str(cm.exception))

    def test_credentials_before_slash_query_or_fragment_are_reported(self) -> None:
        for u in ("https://admin:1234/s3cret@fw1.example.lan", "https://u:1234?pw@fw", "https://u:1234#pw@fw"):
            self.assertIn("url must not contain credentials", url_problems("url", u, "hint"), u)
        self.assertEqual(url_problems("url", "https://fw1.example.lan:8443", "hint"), [])

    def test_uppercase_scheme_is_a_url(self) -> None:
        self.assertEqual(url_problems("url", "HTTPS://fw1.example.lan", "hint"), [])
        self.assertEqual(url_problems("url", "Http://fw1.example.lan", "hint"), [])
        self.assertEqual(url_problems("url", "ftp://fw1.example.lan", "hint"), ["url must be a URL (hint)"])

    def test_leading_zeros_do_not_make_an_integer_too_large(self) -> None:
        t = HOST_SETTINGS[1:]
        self.assertEqual(setting_problems("a", "t", t, {"timeout": "0" * 5000 + "5"}), [])
        self.assertEqual(setting_problems("a", "t", t, {"timeout": "-" + "0" * 5000 + "5"}),
                         ["connector a (t): TIMEOUT must be at least 1"])
        self.assertEqual(setting_problems("a", "t", t, {"timeout": "0" * 5000 + "9" * 5000}),
                         ["connector a (t): TIMEOUT must be at most 3600"])

    def test_ipv6_host_followed_by_colon_and_word_is_masked(self) -> None:
        self.assertEqual(_mask("fe80::2", "fe80::2:failed to connect"), "<host>:failed to connect")
        self.assertEqual(_mask("fe80::2", "host fe80::2:connection refused"), "host <host>:connection refused")
        self.assertEqual(_mask("2001:db8::1", "2001:db8::1:abort"), "<host>:abort")
        self.assertEqual(_mask("fe80::2", "fe80::2:5"), "fe80::2:5")  # another address
        self.assertEqual(_mask("fe80::2", "fe80::2:beef"), "fe80::2:beef")
        self.assertEqual(_mask("fe80::2", "fe80::2::"), "fe80::2::")


    def test_at_in_path_or_query_is_not_credentials(self) -> None:  # the same rule as Config.validate()
        for u in ("https://fw1.example.lan/api@x", "https://fw1.example.lan/?x=a@b"):
            self.assertEqual(url_problems("url", u, "hint"), [], u)  # test_config_edge_cases asserts the Config side
        # a ":" before the "@" is still taken for a password, as in Config.validate()
        self.assertEqual(url_problems("url", "https://fw1.example.lan:8443/a@b", "hint"),
                         ["url must not contain credentials"])
        self.assertEqual(url_problems("url", "https://[fd00::1]/a@b", "hint"), [])
        self.assertEqual(url_problems("url", "https://u:p@[fd00::1]/", "hint"), ["url must not contain credentials"])

    def test_timeout_with_leading_zeros_is_used_as_validated(self) -> None:
        s = InstanceSpec("fw1", "opnsense", {**FW, "timeout": "0" * 5000 + "5"})
        self.assertEqual(instance_problems(s), [])
        self.assertEqual(s.timeout, 5)

    def test_zero_run_before_garbage_is_refused_quickly(self) -> None:
        import time
        t0 = time.monotonic()
        self.assertEqual(setting_problems("a", "t", HOST_SETTINGS[1:], {"timeout": "0" * 50000 + " x"}),
                         ["connector a (t): TIMEOUT must be an integer"])
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(setting_problems("a", "t", HOST_SETTINGS[1:], {"timeout": "0" * 5000}),
                         ["connector a (t): TIMEOUT must be at least 1"])

    def test_empty_userinfo_is_refused(self) -> None:  # urllib keeps "@fw1..." as the host
        for u in ("https://@fw1.example.lan", "https://@fw1.example.lan/", "https://@fw1.example.lan:443"):
            self.assertEqual(url_problems("url", u, "hint"), ["url must not contain credentials"], u)
        self.assertEqual(OpnsenseConnector("fw1", {**FW, "url": "https://@fw1.example.lan"}, CTX).validate(),
                         ["url must not contain credentials"])

    def test_colon_after_path_start_is_not_a_password(self) -> None:
        for u in ("https://lw.example.lan/?t=10:00&m=a@b", "https://fw1.example.lan/api/v1:x@y",
                  "https://fw1.example.lan#a:b@c"):
            self.assertEqual(url_problems("url", u, "hint"), [], u)
        # a "user:" that a "/", "?" or "#" in the password cuts short is still refused
        self.assertIn("url must not contain credentials", url_problems("url", "https://u:1234/x@fw", "hint"))

if __name__ == "__main__":
    unittest.main()
