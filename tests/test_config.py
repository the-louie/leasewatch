import os, sys, unittest
from _env import FW1_ENV, clean_env, restore, sources
from leasewatch.__main__ import startup_line
from leasewatch.config import Config

BASE = FW1_ENV


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._saved = clean_env(BASE)

    def tearDown(self):
        restore(self._saved)

    def problems(self, **env):
        os.environ.update(env)
        return Config().validate()

    def test_startup_line_names_instances_not_urls(self):
        os.environ.update(sources("switch", "unifi"))
        line = startup_line(Config(), "1.1.0.dev0")
        self.assertEqual(line, "leasewatch 1.1.0.dev0, connectors fw1 (opnsense), switch (snmp_switch), unifi (unifi); poll 120 s; mail off; writes all")
        self.assertNotIn("fw1.example.lan", line)

    def test_snmp_detect_finds_an_lw_connectors_instance(self):
        # Config.instances is a property; snmp-detect once tested callable() on it and never saw the instances
        import contextlib, io, logging
        from leasewatch.__main__ import main
        from test_switch_profiles import FakePysnmp, FakeWalker
        root = logging.getLogger()  # main() calls basicConfig; keep the test run's handlers as they were
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)
        os.environ.update({"LW_CONNECTORS": "fw1,coresw", "LW_CONNECTOR__FW1__TYPE": "opnsense",
                           "LW_CONNECTOR__FW1__URL": "https://fw1.example.lan", "LW_CONNECTOR__FW1__KEY": "k",
                           "LW_CONNECTOR__FW1__SECRET": "s", "LW_CONNECTOR__CORESW__TYPE": "snmp_switch",
                           "LW_CONNECTOR__CORESW__HOST": "10.0.0.4", "LW_CONNECTOR__CORESW__AUTH_KEY": "a" * 8,
                           "LW_CONNECTOR__CORESW__PRIV_KEY": "p" * 8, "LW_CONNECTOR__CORESW__PROFILE": "comware"})
        buf = io.StringIO()
        with FakePysnmp(FakeWalker("comware")) as fake, contextlib.redirect_stdout(buf):
            rc = main(["snmp-detect", "coresw"])
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
        p = self.problems(**{**sources("unifi"), "LW_CONNECTOR__UNIFI__URL": "unifi.example.lan:8443"})
        self.assertIn("connector unifi (unifi): url must be a URL (https://<controller>)", p)

    def test_credentials_in_urls_rejected(self):
        p = self.problems(**{**sources("unifi"), "LW_CONNECTOR__FW1__URL": "https://u:p@fw1.example.lan",
                             "LW_CONNECTOR__UNIFI__URL": "https://u:p@unifi.example.lan", "PUBLIC_URL": "https://u@leases.example.lan"})
        for line in ("connector fw1 (opnsense): url", "connector unifi (unifi): url", "PUBLIC_URL"):
            self.assertIn(f"{line} must not contain credentials", p)

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
        secrets = {"LW_CONNECTOR__FW1__KEY": "sekret-fw1key", "LW_CONNECTOR__FW1__SECRET": "sekret-fw1secret",
                   "MAILGUN_KEY": "sekret-mg", "LW_CONNECTOR__SWITCH__AUTH_KEY": "sekret-auth",
                   "LW_CONNECTOR__SWITCH__PRIV_KEY": "sekret-priv", "LW_CONNECTOR__UNIFI__PASSWORD": "sekret-unifi"}
        os.environ.update(sources("switch", "unifi"))
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
        self.assertIn("connector fw1 (opnsense): url is not a valid URL", self.problems(LW_CONNECTOR__FW1__URL="https://[fe80::1"))

    def test_fw1_url_without_host(self):
        self.assertIn("connector fw1 (opnsense): url is not a valid URL", self.problems(LW_CONNECTOR__FW1__URL="https://:443"))

    def test_unifi_url_bad_ipv6(self):
        p = self.problems(**{**sources("unifi"), "LW_CONNECTOR__UNIFI__URL": "https://[fe80::1"})
        self.assertIn("connector unifi (unifi): url is not a valid URL", p)

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

    def tearDown(self):
        restore(self._saved)

    def test_default_backend_is_kea(self):
        from leasewatch.connectors import build_instance, instances_context
        spec = Config().instances[0]
        self.assertEqual(build_instance(spec, instances_context([spec])).settings["dhcp_backend"], "kea")

    def test_lease_type_mode_default_and_validation(self):
        self.assertEqual(Config().lease_type_mode, "keep")
        for mode in ("keep", "grace", "immediate", "GRACE"):
            os.environ["LEASE_TYPE_MODE"] = mode
            self.assertEqual(Config().validate(), [], mode)
        os.environ["LEASE_TYPE_MODE"] = "forever"
        self.assertIn("LEASE_TYPE_MODE must be keep, grace or immediate", Config().validate())

    def test_ui_lang_default_values_and_fallback(self):
        self.assertEqual(Config().ui_lang, "auto")
        for value, want in (("en", "en"), ("sv", "sv"), ("SV", "sv"), ("auto", "auto"), ("", "auto")):
            os.environ["UI_LANG"] = value
            with self.assertNoLogs("leasewatch.config", "WARNING"):
                c = Config()
            self.assertEqual((c.ui_lang, c.validate()), (want, []), value)
        # a typo does not stop the start: a warning, and the browser picks the language
        os.environ["UI_LANG"] = "xx"
        with self.assertLogs("leasewatch.config", "WARNING") as logs:
            c = Config()
        self.assertEqual(c.ui_lang, "auto")
        self.assertEqual(c.validate(), [])
        self.assertIn("UI_LANG='xx' is not auto, en or sv: using auto", logs.output[0])

    def test_lan_proxy_default_off(self):
        from leasewatch.connectors import build_instance, instances_context
        spec = Config().instances[0]
        self.assertEqual(build_instance(spec, instances_context([spec])).settings["proxy"], "0")
        os.environ["LW_CONNECTOR__FW1__PROXY"] = "1"
        spec = Config().instances[0]
        self.assertEqual(build_instance(spec, instances_context([spec])).settings["proxy"], "1")


class RemovedVariablesTests(unittest.TestCase):
    """1.1 reads sources only from LW_CONNECTORS: a 1.0 source variable stops the start, named, never with its value."""
    def setUp(self):
        self._saved = clean_env(BASE)

    def tearDown(self):
        restore(self._saved)

    def refused(self, env):
        os.environ.update(env)
        p = Config().validate()
        for v in env.values():
            if "sekret" in v:
                self.assertNotIn(v, "\n".join(p))
        return p

    def test_one_problem_per_family_without_values(self):
        cases = [
            ({"FW1_URL": "https://sekret-host.example.lan", "FW1_KEY": "sekret-key", "FW1_SECRET": "sekret-secret",
              "FW1_VERIFY_TLS": "sekret-tls"},
             "FW1_URL, FW1_KEY, FW1_SECRET, FW1_VERIFY_TLS are no longer supported: configure the firewall as LW_CONNECTORS=fw1 "
             "with LW_CONNECTOR__FW1__TYPE=opnsense, LW_CONNECTOR__FW1__URL=…, LW_CONNECTOR__FW1__KEY=…, "
             "LW_CONNECTOR__FW1__SECRET=…, LW_CONNECTOR__FW1__VERIFY_TLS=… (see .env.example)"),
            ({"DHCP_BACKEND": "sekret-dhcp"},
             "DHCP_BACKEND is no longer supported: configure the firewall as LW_CONNECTORS=fw1 with "
             "LW_CONNECTOR__FW1__TYPE=opnsense, LW_CONNECTOR__FW1__DHCP_BACKEND=… (default kea) (see .env.example)"),
            ({"IGNORE_INTERFACES": "wan,sekret9"},
             "IGNORE_INTERFACES is no longer supported: configure the firewall as LW_CONNECTORS=fw1 with "
             "LW_CONNECTOR__FW1__TYPE=opnsense, LW_CONNECTOR__FW1__IGNORE_INTERFACES=… (default wan,lo0) (see .env.example)"),
            ({"PROXY_FOR_LAN": "sekret-proxy"},
             "PROXY_FOR_LAN is no longer supported: configure the firewall as LW_CONNECTORS=fw1 with "
             "LW_CONNECTOR__FW1__TYPE=opnsense, LW_CONNECTOR__FW1__PROXY=… (default 0; a unifi instance takes PROXY too) "
             "(see .env.example)"),
            ({"SNMP_HOST": "sekret-sw.example.lan", "SNMP_AUTH_KEY": "sekret-auth", "SNMP_PRIV_KEY": "sekret-priv", "SNMP_NAME": "sw-hall"},
             "SNMP_HOST, SNMP_NAME, SNMP_AUTH_KEY, SNMP_PRIV_KEY are no longer supported: configure the switch as "
             "LW_CONNECTORS=fw1,switch with LW_CONNECTOR__SWITCH__TYPE=snmp_switch, LW_CONNECTOR__SWITCH__HOST=…, "
             "LW_CONNECTOR__SWITCH__NAME=…, LW_CONNECTOR__SWITCH__AUTH_KEY=…, LW_CONNECTOR__SWITCH__PRIV_KEY=… (see .env.example)"),
            ({"UNIFI_URL": "https://sekret-ctl.example.lan", "UNIFI_USER": "sekret-user", "UNIFI_PASSWORD": "sekret-pw"},
             "UNIFI_URL, UNIFI_USER, UNIFI_PASSWORD are no longer supported: configure the UniFi controller as "
             "LW_CONNECTORS=fw1,unifi with LW_CONNECTOR__UNIFI__TYPE=unifi, LW_CONNECTOR__UNIFI__URL=…, "
             "LW_CONNECTOR__UNIFI__USER=…, LW_CONNECTOR__UNIFI__PASSWORD=… (see .env.example)"),
        ]
        for env, msg in cases:
            with self.subTest(env=sorted(env)):
                saved = dict(os.environ)
                try:
                    self.assertEqual(self.refused(env), [msg])
                finally:
                    restore(saved)

    def test_all_families_at_once_and_empty_values_count(self):
        # an empty line left in the env file ("SNMP_HOST=") is still a 1.0 setting to remove
        p = self.refused({"FW1_KEY": "sekret-key", "DHCP_BACKEND": "", "IGNORE_INTERFACES": "", "PROXY_FOR_LAN": "",
                          "SNMP_HOST": "", "UNIFI_URL": ""})
        self.assertEqual([x.split(" ", 1)[0] for x in p],
                         ["FW1_KEY", "DHCP_BACKEND", "IGNORE_INTERFACES", "PROXY_FOR_LAN", "SNMP_HOST", "UNIFI_URL"])
        self.assertNotIn("sekret-key", "\n".join(p))

    def test_removed_variables_are_refused_without_lw_connectors_too(self):
        del os.environ["LW_CONNECTORS"]
        p = self.refused({"FW1_URL": "https://fw1.example.lan"})
        self.assertTrue(p[0].startswith("FW1_URL is no longer supported"), p)
        self.assertIn("LW_CONNECTORS is not set: list the connector instances, e.g. LW_CONNECTORS=fw1 with "
                      "LW_CONNECTOR__FW1__TYPE=opnsense (see .env.example)", p)

    def test_lw_connectors_is_required(self):
        for k in [k for k in os.environ if k.startswith("LW_CONNECTOR")]:
            del os.environ[k]
        c = Config()
        self.assertEqual(c.instances, [])
        self.assertEqual(c.validate(), ["LW_CONNECTORS is not set: list the connector instances, e.g. LW_CONNECTORS=fw1 "
                                        "with LW_CONNECTOR__FW1__TYPE=opnsense (see .env.example)"])
        os.environ["LW_CONNECTORS"] = " "  # blank is unset
        self.assertTrue(Config().validate()[0].startswith("LW_CONNECTORS is not set"))

    def test_the_server_refuses_to_start(self):
        import subprocess
        env = dict(os.environ, SNMP_PRIV_KEY="sekret-priv", PYTHONPATH=os.path.join(os.path.dirname(__file__), ".."))
        out = subprocess.run([sys.executable, "-m", "leasewatch"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 2)
        self.assertIn("config: SNMP_PRIV_KEY is no longer supported", out.stderr)
        self.assertNotIn("sekret-priv", out.stderr)


class InstanceNameTests(unittest.TestCase):
    """Instance names are a-z and 0-9 only, so every LW_CONNECTOR__<NAME>__<KEY> can be exported from a POSIX shell."""
    def setUp(self):
        self._saved = clean_env(BASE)

    def tearDown(self):
        restore(self._saved)

    def test_letters_and_digits_only(self):
        for bad in ("sw-rack", "sw_rack", "Sw1", "sw.1", "wlan ap"):
            with self.subTest(name=bad):
                os.environ["LW_CONNECTORS"] = f"fw1,{bad}"
                p = Config().validate()
                self.assertIn(f"LW_CONNECTORS: {bad!r} is not a valid instance name (only a-z and 0-9)", p)
        os.environ.update({"LW_CONNECTORS": "fw1,sw2", "LW_CONNECTOR__SW2__TYPE": "snmp_switch",
                           "LW_CONNECTOR__SW2__HOST": "10.0.0.2", "LW_CONNECTOR__SW2__AUTH_KEY": "a" * 8,
                           "LW_CONNECTOR__SW2__PRIV_KEY": "p" * 8})
        c = Config()
        self.assertEqual(c.validate(), [])
        self.assertEqual([s.name for s in c.instances], ["fw1", "sw2"])

    def test_a_hyphenated_name_cannot_be_exported_from_a_posix_shell(self):
        # why the rule exists: sh refuses the variable name a hyphenated instance would need
        import shutil, subprocess
        sh = shutil.which("sh")
        if not sh:
            self.skipTest("no sh")
        bad = subprocess.run([sh, "-c", "export LW_CONNECTOR__SW-RACK__HOST=x"], capture_output=True, text=True)
        good = subprocess.run([sh, "-c", "export LW_CONNECTOR__SWRACK__HOST=x"], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(good.returncode, 0)


if __name__ == "__main__":
    unittest.main()
