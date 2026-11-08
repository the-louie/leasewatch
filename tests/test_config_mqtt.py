import os, tempfile, unittest
from _env import FW1_ENV, clean_env, restore
from leasewatch.config import Config

BASE = FW1_ENV
URL = {"MQTT_URL": "mqtt://mqtt.example.lan"}


class MqttConfigTests(unittest.TestCase):
    def setUp(self):
        self._saved = clean_env(BASE)

    def tearDown(self):
        restore(self._saved)

    def cfg(self, **env):
        os.environ.update(env)
        return Config()

    def problems(self, **env):
        return self.cfg(**{**URL, **env}).validate()

    def test_default_is_off(self):
        c = self.cfg()
        self.assertFalse(c.mqtt_on)
        self.assertEqual(c.mail_channels, [])
        self.assertEqual(c.validate(), [])

    def test_orphan_settings_without_url_are_not_an_error(self):
        self.assertEqual(self.cfg(MQTT_TOPIC="#", MQTT_USER="u").validate(), [])

    def test_full_valid_set(self):
        with tempfile.NamedTemporaryFile() as ca:
            c = self.cfg(MQTT_URL="mqtts://mqtt.example.lan:8884", MQTT_USER="lw", MQTT_PASSWORD="pw", MQTT_VERIFY_TLS="0",
                         MQTT_CA_FILE=ca.name, MQTT_TOPIC="home/lw", MQTT_CLIENT_ID="lw-1", MQTT_DISCOVERY="0",
                         MQTT_DISCOVERY_PREFIX="ha", MQTT_DEVICES="ALL", MQTT_EVENTS="1")
            self.assertEqual(c.validate(), [])
        self.assertEqual(c.mqtt_endpoint, ("mqtt.example.lan", 8884, True))
        self.assertEqual((c.mqtt_on, c.mqtt_verify_tls_on, c.mqtt_discovery_on, c.mqtt_events_on), (True, False, False, True))
        self.assertEqual(c.mqtt_devices, "all")
        self.assertEqual(c.mqtt_client_id_effective, "lw-1")

    def test_default_ports(self):
        self.assertEqual(self.cfg(**URL).mqtt_endpoint, ("mqtt.example.lan", 1883, False))
        self.assertEqual(self.cfg(MQTT_URL="mqtts://10.0.0.5").mqtt_endpoint, ("10.0.0.5", 8883, True))

    def test_defaults(self):
        c = self.cfg(**URL)
        self.assertEqual((c.mqtt_topic, c.mqtt_discovery_prefix, c.mqtt_devices), ("leasewatch", "homeassistant", "watched"))
        self.assertTrue(c.mqtt_verify_tls_on and c.mqtt_discovery_on and not c.mqtt_events_on)
        self.assertEqual(c.validate(), [])

    def test_each_bad_value_is_one_named_problem(self):
        cases = (
            ({"MQTT_URL": "mqtt://u:p@mqtt.example.lan"}, "MQTT_URL must not contain credentials"),
            ({"MQTT_URL": "mqtt://mqtt.example.lan/x"}, "MQTT_URL must have no path or query"),
            ({"MQTT_URL": "mqtt://mqtt.example.lan?a=1"}, "MQTT_URL must have no path or query"),
            ({"MQTT_URL": "http://mqtt.example.lan"}, "MQTT_URL must be a URL"),
            ({"MQTT_URL": "mqtt://mqtt.example.lan:99999"}, "MQTT_URL is not a valid URL"),
            ({"MQTT_TOPIC": "a/#"}, "MQTT_TOPIC must be"),
            ({"MQTT_TOPIC": "$SYS/x"}, "MQTT_TOPIC must be"),
            ({"MQTT_TOPIC": "/a"}, "MQTT_TOPIC must be"),
            ({"MQTT_TOPIC": "a/"}, "MQTT_TOPIC must be"),
            ({"MQTT_TOPIC": "a/+/b"}, "MQTT_TOPIC must be"),
            ({"MQTT_DISCOVERY_PREFIX": "#"}, "MQTT_DISCOVERY_PREFIX must be"),
            ({"MQTT_CLIENT_ID": "a" * 24}, "MQTT_CLIENT_ID must be"),
            ({"MQTT_CLIENT_ID": "a_b"}, "MQTT_CLIENT_ID must be"),
            ({"MQTT_DEVICES": "everyone"}, "MQTT_DEVICES must be"),
            ({"MQTT_EVENTS": "maybe"}, "MQTT_EVENTS must be 1 or 0"),
            ({"MQTT_DISCOVERY": "maybe"}, "MQTT_DISCOVERY must be 1 or 0"),
            ({"MQTT_VERIFY_TLS": "maybe"}, "MQTT_VERIFY_TLS must be 1 or 0"),
            ({"MQTT_USER": "lw"}, "MQTT_USER and MQTT_PASSWORD must be set together"),
            ({"MQTT_PASSWORD": "pw"}, "MQTT_USER and MQTT_PASSWORD must be set together"),
            ({"MQTT_CA_FILE": "/nonexistent/ca.pem"}, "MQTT_CA_FILE cannot be read"),
        )
        for env, text in cases:
            with self.subTest(env=env):
                for k in [k for k in os.environ if k.startswith("MQTT_")]:
                    del os.environ[k]
                got = self.problems(**env)
                self.assertEqual(len(got), 1, got)
                self.assertIn(text, got[0])

    def test_password_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as f:
            f.write("s3cret\n")
            f.flush()
            c = self.cfg(MQTT_USER="lw", MQTT_PASSWORD_FILE=f.name, **URL)
            self.assertEqual(c.mqtt_password, "s3cret")
            self.assertEqual(c.validate(), [])
            os.environ["MQTT_PASSWORD"] = "other"
            got = Config().validate()
            self.assertEqual(got, ["set MQTT_PASSWORD or MQTT_PASSWORD_FILE, not both"])

    def test_unreadable_password_file(self):
        got = self.problems(MQTT_USER="lw", MQTT_PASSWORD_FILE="/nonexistent/pw")
        self.assertEqual(len(got), 1, got)
        self.assertIn("cannot read MQTT_PASSWORD_FILE", got[0])
        self.assertNotIn("/nonexistent", got[0])

    def test_password_not_in_repr_or_str(self):
        c = self.cfg(MQTT_USER="lw", MQTT_PASSWORD="hunter2-xyz", **URL)
        self.assertNotIn("hunter2-xyz", repr(c))
        self.assertNotIn("hunter2-xyz", str(c))

    def test_derived_client_id(self):
        c = self.cfg(SITE_NAME="Louie's Home")
        self.assertEqual(c.mqtt_client_id_effective, "leasewatch-louie-s-home")
        self.assertEqual(self.cfg(SITE_NAME="A very long site name here").mqtt_client_id_effective, "leasewatch-a-very-long")
        self.assertEqual(self.cfg(SITE_NAME="!!!").mqtt_client_id_effective, "leasewatch")
        for name in ("Louie's Home", "x" * 80, "Åäö Hemma"):
            eff = self.cfg(SITE_NAME=name).mqtt_client_id_effective
            self.assertLessEqual(len(eff), 23)
            self.assertRegex(eff, r"[0-9a-zA-Z-]+")

    def test_events_adds_the_channel(self):
        self.assertEqual(self.cfg(MQTT_EVENTS="1").mail_channels, [])  # no URL: off
        self.assertEqual(self.cfg(MQTT_EVENTS="0", **URL).mail_channels, [])
        c = self.cfg(MQTT_EVENTS="1", WEBHOOK_URL="https://hook.example.lan/x", **URL)
        self.assertEqual(c.mail_channels, ["webhook", "mqtt"])


if __name__ == "__main__":
    unittest.main()
