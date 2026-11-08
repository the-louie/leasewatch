"""The snmp_switch PORT setting: reaches the SNMP transport, is validated, shows in describe(), and snmp-detect uses it.

Synthetic data only; the switch is a FakeWalker behind the fake pysnmp module of test_switch_profiles.
"""
import contextlib, io, logging, os, unittest
from _env import clean_env, restore, sources
from test_switch_profiles import FakePysnmp, FakeWalker
from leasewatch.__main__ import main
from leasewatch.config import Config
from leasewatch.connectors.snmp_switch import SnmpSwitchConnector

BASE = {"host": "10.0.0.4", "auth_key": "a" * 8, "priv_key": "p" * 8, "profile": "comware"}


def conn(**extra) -> SnmpSwitchConnector:
    return SnmpSwitchConnector("sw", {**BASE, **extra})


class PortTest(unittest.TestCase):
    def setUp(self):
        self._saved = clean_env()
        root = logging.getLogger()  # main() calls basicConfig; keep the test run's handlers as they were
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)

    def tearDown(self):
        restore(self._saved)

    def targets(self, c) -> list:
        with FakePysnmp(FakeWalker("comware")) as fake:
            c.client.snapshot()
        return fake.targets

    def test_default_port_reaches_the_transport(self):
        self.assertEqual(self.targets(conn())[0][0], ("10.0.0.4", 161))

    def test_port_setting_reaches_the_transport(self):
        self.assertEqual(self.targets(conn(port="1161"))[0][0], ("10.0.0.4", 1161))

    def test_port_from_the_environment_reaches_the_transport(self):
        os.environ.update(sources("switch"))
        os.environ["LW_CONNECTOR__SWITCH__PORT"] = "1161"
        os.environ["LW_CONNECTOR__SWITCH__PROFILE"] = "comware"
        from leasewatch.connectors import build_instance, instances_context
        spec = next(s for s in Config().instances if s.name == "switch")
        c = build_instance(spec, instances_context([spec]))
        self.assertEqual(self.targets(c)[0][0], ("10.0.0.2", 1161))

    def test_bad_ports_are_reported_with_the_settings_own_text(self):
        for value, text in (("0", "must be at least 1"), ("70000", "must be at most 65535"), ("abc", "must be an integer")):
            with self.subTest(value=value):
                self.assertEqual(conn(port=value).validate(), [f"connector sw (snmp_switch): PORT {text}"])

    def test_bad_port_is_reported_by_config_validate(self):
        os.environ.update(sources("switch"))
        os.environ["LW_CONNECTOR__SWITCH__PORT"] = "70000"
        self.assertIn("connector switch (snmp_switch): PORT must be at most 65535", Config().validate())

    def test_good_port_has_no_problem(self):
        self.assertEqual(conn(port="1161").validate(), [])
        self.assertEqual(conn().validate(), [])

    def test_describe_lists_the_setting(self):
        s = next(s for s in SnmpSwitchConnector.describe().settings if s.key == "port")
        self.assertEqual((s.default, s.kind, s.min, s.max, s.required), ("161", "int", 1, 65535, False))

    def test_snmp_detect_uses_the_port(self):
        os.environ.update(sources("switch"))
        os.environ["LW_CONNECTOR__SWITCH__PORT"] = "1161"
        os.environ["LW_CONNECTOR__SWITCH__PROFILE"] = "comware"
        buf = io.StringIO()
        with FakePysnmp(FakeWalker("comware")) as fake, contextlib.redirect_stdout(buf):
            rc = main(["snmp-detect", "switch"])
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(fake.targets[0][0], ("10.0.0.2", 1161))


if __name__ == "__main__":
    unittest.main()
