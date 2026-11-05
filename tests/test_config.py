import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore
from leasewatch.__main__ import startup_line
from leasewatch.config import Config

BASE = {"FW1_URL": "https://fw1.example.lan", "FW1_KEY": "k", "FW1_SECRET": "s"}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._saved = clean_env(BASE)

    def tearDown(self):
        restore(self._saved)

    def problems(self, **env):
        os.environ.update(env)
        return Config().validate()

    def test_startup_line_names_instances_not_urls(self):
        os.environ.update({"SNMP_HOST": "10.0.0.2", "SNMP_AUTH_KEY": "a" * 8, "SNMP_PRIV_KEY": "p" * 8,
                           "UNIFI_URL": "https://unifi.example.lan", "UNIFI_USER": "ro", "UNIFI_PASSWORD": "pw"})
        line = startup_line(Config(), "1.1.0.dev0")
        self.assertEqual(line, "leasewatch 1.1.0.dev0, connectors fw1 (opnsense), switch (snmp_switch), unifi (unifi); poll 120 s; mail off")
        self.assertNotIn("fw1.example.lan", line)

    def test_snmp_detect_finds_an_lw_connectors_instance(self):
        # Config.instances is a property; snmp-detect once tested callable() on it and only ever saw the legacy SNMP_*
        import contextlib, io, logging
        from leasewatch.__main__ import main
        from test_switch_profiles import FakePysnmp, FakeWalker
        root = logging.getLogger()  # main() calls basicConfig; keep the test run's handlers as they were
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)
        os.environ.update({"LW_CONNECTORS": "fw1,core-sw", "LW_CONNECTOR__FW1__TYPE": "opnsense",
                           "LW_CONNECTOR__FW1__URL": "https://fw1.example.lan", "LW_CONNECTOR__FW1__KEY": "k",
                           "LW_CONNECTOR__FW1__SECRET": "s", "LW_CONNECTOR__CORE-SW__TYPE": "snmp_switch",
                           "LW_CONNECTOR__CORE-SW__HOST": "10.0.0.4", "LW_CONNECTOR__CORE-SW__AUTH_KEY": "a" * 8,
                           "LW_CONNECTOR__CORE-SW__PRIV_KEY": "p" * 8, "LW_CONNECTOR__CORE-SW__PROFILE": "comware"})
        buf = io.StringIO()
        with FakePysnmp(FakeWalker("comware")) as fake, contextlib.redirect_stdout(buf):
            rc = main(["snmp-detect", "core-sw"])
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(fake.targets[0][0], ("10.0.0.4", 161))
        self.assertIn("profile:     comware (set by profile/profile_file)", buf.getvalue())

    def test_base_is_valid(self):
        self.assertEqual(self.problems(), [])

    def test_public_url_without_host(self):
        self.assertIn("PUBLIC_URL is not a valid URL", self.problems(PUBLIC_URL="https://:8080"))

    def test_public_url_bad_ipv6(self):
        self.assertIn("PUBLIC_URL is not a valid URL", self.problems(PUBLIC_URL="https://[fe80::1"))

    def test_unifi_url_scheme(self):
        p = self.problems(UNIFI_URL="unifi.example.lan:8443", UNIFI_USER="ro", UNIFI_PASSWORD="pw")
        self.assertIn("UNIFI_URL must be a URL (https://<controller>)", p)

    def test_credentials_in_urls_rejected(self):
        p = self.problems(FW1_URL="https://u:p@fw1.example.lan", UNIFI_URL="https://u:p@unifi.example.lan",
                          UNIFI_USER="ro", UNIFI_PASSWORD="pw", PUBLIC_URL="https://u@leases.example.lan")
        for name in ("FW1_URL", "UNIFI_URL", "PUBLIC_URL"):
            self.assertIn(f"{name} must not contain credentials", p)

    def test_listen_port_range(self):
        self.assertIn("LISTEN_PORT must be 1-65535", self.problems(LISTEN_PORT="0"))
        self.assertIn("LISTEN_PORT must be 1-65535", self.problems(LISTEN_PORT="70000"))
        self.assertEqual(self.problems(LISTEN_PORT="8089"), [])

    def test_public_url_with_trailing_dot_allows_host(self):
        os.environ["PUBLIC_URL"] = "https://leases.example.lan."
        c = Config()
        self.assertTrue(c.host_allowed("leases.example.lan"))
        self.assertTrue(c.host_allowed("leases.example.lan.:8080"))
        self.assertFalse(c.host_allowed("evil.example.com"))

    def test_secrets_not_in_repr(self):
        secrets = {"FW1_KEY": "sekret-fw1key", "FW1_SECRET": "sekret-fw1secret", "MAILGUN_KEY": "sekret-mg",
                   "SNMP_AUTH_KEY": "sekret-auth", "SNMP_PRIV_KEY": "sekret-priv", "UNIFI_PASSWORD": "sekret-unifi"}
        os.environ.update(secrets)
        r = repr(Config())
        for v in secrets.values():
            self.assertNotIn(v, r)

    def test_mailgun_api_base(self):
        self.assertEqual(Config().mailgun_api_base, "https://api.mailgun.net")
        os.environ["MAILGUN_API_BASE"] = "https://api.eu.mailgun.net/"
        self.assertEqual(Config().mailgun_api_base, "https://api.eu.mailgun.net")

    def test_mailgun_api_base_scheme(self):
        self.assertIn("MAILGUN_API_BASE must be a URL (https://api.mailgun.net or https://api.eu.mailgun.net)",
                      self.problems(MAILGUN_API_BASE="api.eu.mailgun.net"))
        self.assertEqual(self.problems(MAILGUN_API_BASE="https://api.eu.mailgun.net"), [])

    def test_fw1_url_bad_ipv6(self):
        self.assertIn("FW1_URL is not a valid URL", self.problems(FW1_URL="https://[fe80::1"))

    def test_fw1_url_without_host(self):
        self.assertIn("FW1_URL is not a valid URL", self.problems(FW1_URL="https://:443"))

    def test_unifi_url_bad_ipv6(self):
        p = self.problems(UNIFI_URL="https://[fe80::1", UNIFI_USER="ro", UNIFI_PASSWORD="pw")
        self.assertIn("UNIFI_URL is not a valid URL", p)

    def test_mailgun_api_base_credentials(self):
        p = self.problems(MAILGUN_API_BASE="https://user:pw@api.mailgun.net")
        self.assertIn("MAILGUN_API_BASE must not contain credentials", p)

    def test_upper_bounds(self):
        self.assertIn("POLL_SECONDS must be at most 86400", self.problems(POLL_SECONDS="86401"))
        self.assertIn("ONLINE_GRACE_MINUTES must be at most 10080", self.problems(ONLINE_GRACE_MINUTES="10081"))
        self.assertIn("NEW_DAYS must be at most 3650", self.problems(NEW_DAYS="3651"))

    def test_upper_bounds_inclusive(self):
        self.assertEqual(self.problems(POLL_SECONDS="86400", ONLINE_GRACE_MINUTES="10080", NEW_DAYS="3650"), [])

    def test_allowed_hosts_with_port(self):
        os.environ["ALLOWED_HOSTS"] = "leases.example.lan:8443, Other.example.lan., [fd00::1]:8443"
        c = Config()
        self.assertTrue(c.host_allowed("leases.example.lan:8443"))
        self.assertTrue(c.host_allowed("leases.example.lan"))
        self.assertTrue(c.host_allowed("other.example.lan"))
        self.assertIn("fd00::1", c.allowed_hosts)
        self.assertFalse(c.host_allowed("evil.example.com:8443"))


class SettingDefaultsTests(unittest.TestCase):
    def setUp(self):
        self._saved = clean_env(BASE)
        for k in ("LEASE_TYPE_MODE", "PROXY_FOR_LAN"):
            os.environ.pop(k, None)

    def tearDown(self):
        restore(self._saved)

    def test_default_backend_is_kea(self):
        self.assertEqual(Config().dhcp_backend, "kea")

    def test_lease_type_mode_default_and_validation(self):
        self.assertEqual(Config().lease_type_mode, "keep")
        for mode in ("keep", "grace", "immediate", "GRACE"):
            os.environ["LEASE_TYPE_MODE"] = mode
            self.assertEqual(Config().validate(), [], mode)
        os.environ["LEASE_TYPE_MODE"] = "forever"
        self.assertIn("LEASE_TYPE_MODE must be keep, grace or immediate", Config().validate())

    def test_lan_proxy_default_off(self):
        self.assertFalse(Config().lan_proxy)
        os.environ["PROXY_FOR_LAN"] = "1"
        self.assertTrue(Config().lan_proxy)


if __name__ == "__main__":
    unittest.main()
