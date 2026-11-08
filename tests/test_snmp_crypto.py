"""AUTH and PRIV choices of snmp_switch: each one reaches UsmUserData as the pysnmp constant, under either spelling."""
import asyncio, os, sys, types, unittest
from unittest import mock
from types import SimpleNamespace

from leasewatch import switch
from leasewatch.connectors import HostContext
from leasewatch.connectors.snmp_switch import SnmpSwitchConnector

CTX = HostContext(now=lambda: 1700000000)
SW = {"host": "10.0.0.2", "auth_key": "x" * 16, "priv_key": "y" * 16}
MODS = ("pysnmp", "pysnmp.hlapi", "pysnmp.hlapi.v3arch", "pysnmp.hlapi.v3arch.asyncio")


class FakeHlapi:
    """A fake pysnmp.hlapi.v3arch.asyncio with one sentinel per constant, in the given spelling (0 = camelCase,
    1 = UPPER_CASE); `missing` names settings values whose constant is left out."""

    def __init__(self, spelling: int, missing: tuple[str, ...] = ()):
        self.spelling, self.missing = spelling, missing
        self.users: list[tuple[tuple, dict]] = []
        self.sentinels = {n: object() for table in (switch.AUTH_NAMES, switch.PRIV_NAMES) for n in table}

    def __enter__(self):
        self._saved = {k: sys.modules.get(k) for k in MODS}
        for k in MODS:
            sys.modules[k] = types.ModuleType(k)
        m = sys.modules[MODS[-1]]
        users = self.users
        m.UsmUserData = lambda *a, **k: users.append((a, k))
        m.SnmpEngine = type("SnmpEngine", (), {"close_dispatcher": lambda self: None})

        class UdpTransportTarget:
            @staticmethod
            async def create(addr, timeout, retries):
                return None
        m.UdpTransportTarget = UdpTransportTarget
        for table in (switch.AUTH_NAMES, switch.PRIV_NAMES):
            for value, names in table.items():
                if value not in self.missing:
                    setattr(m, names[self.spelling], self.sentinels[value])
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def session(conn: SnmpSwitchConnector) -> None:
    asyncio.run(conn.client._session({"timeout": 1, "retries": 0}))


class CryptoChoices(unittest.TestCase):
    def test_choice_to_constant_table(self):
        self.assertEqual(
            {k: v[1] for k, v in switch.AUTH_NAMES.items()},
            {"SHA": "USM_AUTH_HMAC96_SHA", "SHA256": "USM_AUTH_HMAC192_SHA256", "SHA224": "USM_AUTH_HMAC128_SHA224",
             "SHA384": "USM_AUTH_HMAC256_SHA384", "SHA512": "USM_AUTH_HMAC384_SHA512"})
        self.assertEqual(
            {k: v[1] for k, v in switch.PRIV_NAMES.items()},
            {"AES": "USM_PRIV_CFB128_AES", "AES192": "USM_PRIV_CFB192_AES", "AES256": "USM_PRIV_CFB256_AES",
             "AES192B": "USM_PRIV_CFB192_AES_BLUMENTHAL", "AES256B": "USM_PRIV_CFB256_AES_BLUMENTHAL"})

    def test_every_choice_resolves_under_both_spellings(self):
        for spelling in (0, 1):
            for auth in switch.AUTH_NAMES:
                for priv in switch.PRIV_NAMES:
                    with self.subTest(spelling=spelling, auth=auth, priv=priv), FakeHlapi(spelling) as f:
                        c = SnmpSwitchConnector("sw", {**SW, "auth": auth, "priv": priv}, CTX)
                        self.assertEqual(c.validate(), [])
                        session(c)
                        (args, kw), = f.users
                        self.assertEqual(args, ("leasewatch", "x" * 16, "y" * 16))
                        self.assertIs(kw["authProtocol"], f.sentinels[auth])
                        self.assertIs(kw["privProtocol"], f.sentinels[priv])

    def test_dashes_and_case_are_normalised(self):
        c = SnmpSwitchConnector("sw", {**SW, "auth": "sha-512", "priv": "aes-256-b"}, CTX)
        self.assertEqual((c.settings["auth"], c.settings["priv"]), ("SHA512", "AES256B"))
        self.assertEqual((c.client.cfg.snmp_auth, c.client.cfg.snmp_priv), ("SHA512", "AES256B"))

    def test_upper_case_name_wins_when_both_exist(self):
        m = types.SimpleNamespace(usmAesCfb128Protocol="old", USM_PRIV_CFB128_AES="new")
        self.assertEqual(switch._usm(m, "usmAesCfb128Protocol", "USM_PRIV_CFB128_AES"), "new")
        self.assertIsNone(switch._usm(types.SimpleNamespace(), "a", "B"))

    def test_missing_constant_is_a_setting_problem_and_disables_the_instance(self):
        for spelling in (0, 1):
            with FakeHlapi(spelling, missing=("SHA384", "AES256B")):
                c = SnmpSwitchConnector("sw", {**SW, "auth": "SHA384", "priv": "AES256B"}, CTX)
                p = c.validate()
                self.assertEqual(p, ["connector sw (snmp_switch): AUTH SHA384 is not supported by the installed pysnmp",
                                     "connector sw (snmp_switch): PRIV AES256B is not supported by the installed pysnmp"])
                with self.assertRaises(Exception) as cm:
                    c.check()
                self.assertEqual(type(cm.exception).__name__, "ConnectorError")
                self.assertEqual(str(cm.exception), "AUTH SHA384 is not supported by the installed pysnmp")
                # a supported choice on the same module is fine
                self.assertEqual(SnmpSwitchConnector("sw", {**SW, "auth": "SHA512"}, CTX).validate(), [])

    def test_session_names_the_missing_constant(self):
        with FakeHlapi(1, missing=("AES192",)):
            c = SnmpSwitchConnector("sw", {**SW, "priv": "AES192"}, CTX)
            with self.assertRaisesRegex(RuntimeError, "PRIV AES192 is not supported by the installed pysnmp"):
                session(c)

    def test_unknown_values_are_the_generic_choices_error(self):
        with FakeHlapi(1):
            p = SnmpSwitchConnector("sw", {**SW, "auth": "MD5", "priv": "DES"}, CTX).validate()
        self.assertTrue(any("AUTH must be one of SHA" in x for x in p), p)
        self.assertTrue(any("PRIV must be one of AES" in x for x in p), p)
        self.assertFalse(any("not supported by the installed pysnmp" in x for x in p), p)

    def test_describe_lists_priv(self):
        st = {s.key: s for s in SnmpSwitchConnector.describe().settings}
        self.assertEqual((st["priv"].default, st["priv"].choices), ("AES", ("AES", "AES192", "AES256", "AES192B", "AES256B")))
        self.assertEqual(st["auth"].default, "SHA")
        self.assertEqual(st["auth"].choices, ("SHA", "SHA256", "SHA224", "SHA384", "SHA512"))
        self.assertFalse(st["priv"].secret)

    def test_existing_config_keeps_sha_and_aes128(self):
        with FakeHlapi(0) as f:
            c = SnmpSwitchConnector("sw", SW, CTX)
            self.assertEqual(c.validate(), [])
            self.assertEqual((c.client.cfg.snmp_auth, c.client.cfg.snmp_priv), ("SHA", "AES"))
            session(c)
            (_, kw), = f.users
            self.assertIs(kw["authProtocol"], f.sentinels["SHA"])
            self.assertIs(kw["privProtocol"], f.sentinels["AES"])

    def test_cfg_without_priv_means_aes128(self):
        # a 1.0-style cfg object (no snmp_priv) still works
        cfg = SimpleNamespace(snmp_host="10.0.0.2", snmp_user="u", snmp_auth="SHA", snmp_auth_key="x" * 16, snmp_priv_key="y" * 16)
        with FakeHlapi(1) as f:
            asyncio.run(switch.SwitchClient(cfg)._session({"timeout": 1, "retries": 0}))
            self.assertIs(f.users[0][1]["privProtocol"], f.sentinels["AES"])

    def test_snmp_detect_connector_carries_both(self):
        from leasewatch.__main__ import _detect_connector
        os.environ["TEST_AK"], os.environ["TEST_PK"] = "x" * 16, "y" * 16
        try:
            args = SimpleNamespace(host="10.0.0.2", port=1161, instance=None, user="leasewatch", auth="SHA256", priv="AES256",
                                   profile=None, profile_file=None, auth_key_env="TEST_AK", priv_key_env="TEST_PK")
            conn, problems, err = _detect_connector(args)
        finally:
            os.environ.pop("TEST_AK"), os.environ.pop("TEST_PK")
        self.assertEqual(err, "")
        self.assertEqual((conn.client.cfg.snmp_auth, conn.client.cfg.snmp_priv, conn.client.cfg.snmp_port), ("SHA256", "AES256", 1161))

    def test_snmp_detect_flags_accept_every_protocol_name(self):
        # the --host form offers the same names as an instance's AUTH and PRIV settings
        from leasewatch.__main__ import snmp_detect_cmd
        with mock.patch("leasewatch.__main__._pysnmp_problem", return_value="pysnmp not installed"), \
                mock.patch("leasewatch.__main__._out"), mock.patch("sys.argv", ["x"]):
            for auth, priv in (("SHA512", "AES192B"), ("SHA224", "AES256")):
                self.assertEqual(snmp_detect_cmd(["--host", "10.0.0.2", "--port", "1161", "--auth", auth, "--priv", priv]), 1)
            with self.assertRaises(SystemExit):
                snmp_detect_cmd(["--host", "10.0.0.2", "--priv", "DES"])


if __name__ == "__main__":
    unittest.main()
