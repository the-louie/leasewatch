"""leasewatch.mqtt_pub.Publisher against the fake broker in _mqttfake (loopback, port 0) and a real Database in the
test's DATA_DIR. Synthetic data only."""
from __future__ import annotations

import json
import os

import _env  # noqa: F401  # the repo root on the path and the network guard, also when this module runs on its own
from _case import EnvTmpCase
from _env import FW1_ENV
from _mqttfake import FakeBroker
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.mqtt import MqttError
from leasewatch.mqtt_pub import Publisher, node_id

MAC_A, MAC_B, MAC_C, MAC_D = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0c", "02:00:00:00:00:0d"
ID_A, ID_B = "02000000000a", "02000000000b"
STATS = {"total": 4, "online": 2, "unacked": 1, "new": 1, "vlans": []}
STATS_JSON = b'{"devices":4,"new":1,"online":2,"unacked":1}'


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class PubCase(EnvTmpCase):
    ENV = {**FW1_ENV, "SITE_NAME": "Example Home", "PUBLIC_URL": "https://lw.example.lan/", "POLL_SECONDS": "60",
           "MQTT_TOPIC": "lw", "MQTT_DEVICES": "watched"}
    broker_kw: dict = {}

    def setUp(self) -> None:
        super().setUp()
        self.broker = FakeBroker(**self.broker_kw)
        self.addCleanup(self.broker.close)
        os.environ["MQTT_URL"] = f"mqtt://{self.broker.host}:{self.broker.port}"
        self.db = Database(os.path.join(self.tmp.name, "lw.sqlite3"))
        self.addCleanup(self.db._conn.close)
        # (mac, online, watch, name, acked, archived_ts)
        for mac, online, watch, name, acked, arch in (
                (MAC_A, 1, 1, "tv", 1, None), (MAC_B, 0, 1, "", 0, None),
                (MAC_C, 1, 0, "", 1, None), (MAC_D, 1, 1, "old", 1, 50)):
            self.db.q("INSERT INTO devices (mac, first_seen, last_seen, last_online, online, acked, watch, name, "
                      "archived_ts, ip, ip6, hostname, vlan, sw_port, wifi_ssid, tags) "
                      "VALUES (?,1,1,?,?,?,?,?,?,'10.0.0.5','fd00::5','host.example.lan','LAN','Gi1/0/3','','a,b')",
                      (mac, 1700000000 if online else None, online, acked, watch, name, arch))
        self.clock = Clock()
        self.pub = self.make()

    def make(self) -> Publisher:
        p = Publisher(Config(), self.db, "1.5.0", clock=self.clock)
        p.timeout = 1.0
        self.addCleanup(lambda: p.client and p.client.close())
        return p

    def rows(self) -> list[dict]:
        return self.db.devices()

    def poll(self, p: Publisher | None = None) -> list[tuple[str, bytes, int, bool]]:
        """publish_poll; the packets it sent as (topic, payload, qos, retain)."""
        p = p or self.pub
        start = len(self.broker.published)
        p.publish_poll(self.rows(), STATS)
        return [t[:4] for t in self.broker.published[start:]]


class SelectionTests(PubCase):
    def macs(self, mode: str) -> list[str]:
        os.environ["MQTT_DEVICES"] = mode
        return sorted(r["mac"] for r in Publisher(Config(), self.db, "x").selected(self.rows()))

    def test_modes(self) -> None:
        self.assertEqual(self.macs("watched"), [MAC_A, MAC_B])
        self.assertEqual(self.macs("named"), [MAC_A])
        self.assertEqual(self.macs("known"), [MAC_A, MAC_C])
        self.assertEqual(self.macs("all"), [MAC_A, MAC_B, MAC_C])  # MAC_D is archived

    def test_node_id(self) -> None:
        self.assertEqual(node_id(Config()), "leasewatch_example_home")


class ConnectTests(PubCase):
    def test_connect_status_will_and_birth_subscription(self) -> None:
        self.pub.connect()
        self.assertTrue(self.pub.connected)
        self.assertTrue(self.pub.full)
        self.assertTrue(self.broker.wait_published(1))
        self.assertEqual(self.broker.published[0][:4], ("lw/status", b"online", 1, True))
        self.assertEqual(self.broker.will, ("lw/status", b"offline", 1, True))
        self.assertEqual(self.broker.keepalive, 120)
        self.assertEqual(self.broker.client_id, "leasewatch-example-home")
        self.assertEqual([s[:2] for s in self.broker.subscriptions], [("homeassistant/status", 1)])

    def test_no_subscription_without_discovery(self) -> None:
        os.environ["MQTT_DISCOVERY"] = "0"
        p = self.make()
        p.connect()
        self.assertEqual(self.broker.subscriptions, [])


class PollTests(PubCase):
    def setUp(self) -> None:
        super().setUp()
        self.pub.connect()

    def test_first_poll_publishes_everything(self) -> None:
        got = self.poll()
        self.assertFalse(self.pub.full)
        attrs_a = (b'{"hostname":"host.example.lan","ip":"10.0.0.5","ip6":"fd00::5","last_online":"2023-11-14T22:13:20Z",'
                   b'"mac":"02:00:00:00:00:0a","name":"tv","switch_port":"Gi1/0/3","tags":["a","b"],'
                   b'"url":"https://lw.example.lan/?device=02:00:00:00:00:0a","vlan":"LAN","wifi_ssid":""}')
        by_topic = {t: (p, q, r) for t, p, q, r in got}
        self.assertEqual(by_topic[f"lw/device/{ID_A}/state"], (b"home", 1, True))
        self.assertEqual(by_topic[f"lw/device/{ID_A}/attributes"], (attrs_a, 1, True))
        self.assertEqual(by_topic[f"lw/device/{ID_B}/state"], (b"not_home", 1, True))
        self.assertIsNone(json.loads(by_topic[f"lw/device/{ID_B}/attributes"][0])["last_online"])
        self.assertEqual(by_topic["lw/stats"], (STATS_JSON, 1, True))
        self.assertEqual(len(got), 11)  # 2 x (config, state, attributes), 4 sensor configs, stats
        self.assertEqual(json.loads(self.db.get_meta("mqtt.published")), [ID_A, ID_B])

    def test_device_tracker_config_payload(self) -> None:
        got = {t: (p, q, r) for t, p, q, r in self.poll()}
        expected = (
            b'{"availability_topic":"lw/status","device":{"connections":[["mac","02:00:00:00:00:0a"]],'
            b'"identifiers":["leasewatch_example_home_02000000000a"],"name":"tv","via_device":"leasewatch_example_home"},'
            b'"json_attributes_topic":"lw/device/02000000000a/attributes","name":"tv",'
            b'"origin":{"name":"leasewatch","support_url":"https://github.com/the-louie/leasewatch","sw_version":"1.5.0"},'
            b'"payload_available":"online","payload_home":"home","payload_not_available":"offline",'
            b'"payload_not_home":"not_home","source_type":"router","state_topic":"lw/device/02000000000a/state",'
            b'"unique_id":"leasewatch_example_home_02000000000a"}')
        topic = f"homeassistant/device_tracker/leasewatch_example_home/{ID_A}/config"
        self.assertEqual(got[topic], (expected, 1, True))
        conf_b = json.loads(got[topic.replace(ID_A, ID_B)][0])
        self.assertEqual(conf_b["name"], "host.example.lan")  # no name: the hostname
        self.assertNotIn("manufacturer", conf_b["device"])
        self.db.q("UPDATE devices SET vendor='Example Corp' WHERE mac=?", (MAC_A,))
        self.pub.full = True
        got = {t: p for t, p, _, _ in self.poll()}
        self.assertEqual(json.loads(got[topic])["device"]["manufacturer"], "Example Corp")

    def test_sensor_configs_on_first_poll(self) -> None:
        got = {t: p for t, p, _, _ in self.poll()}
        base = "homeassistant/sensor/leasewatch_example_home"
        self.assertEqual([k for k in got if k.startswith(base)],
                         [f"{base}/{k}/config" for k in ("devices", "online", "unacked", "new")])
        conf = json.loads(got[f"{base}/unacked/config"])
        self.assertEqual(conf, {
            "name": "Not yet known", "unique_id": "leasewatch_example_home_unacked", "state_topic": "lw/stats",
            "value_template": "{{ value_json.unacked }}", "state_class": "measurement",
            "availability_topic": "lw/status",
            "device": {"identifiers": ["leasewatch_example_home"], "name": "leasewatch Example Home",
                       "manufacturer": "leasewatch", "sw_version": "1.5.0",
                       "configuration_url": "https://lw.example.lan"},
            "origin": {"name": "leasewatch", "sw_version": "1.5.0",
                       "support_url": "https://github.com/the-louie/leasewatch"}})
        self.assertEqual(self.poll(), [("lw/stats", STATS_JSON, 1, True)])  # sensors only when full

    def test_name_change_republishes_only_that_config(self) -> None:
        self.poll()
        self.db.q("UPDATE devices SET name='lamp' WHERE mac=?", (MAC_B,))
        got = self.poll()
        self.assertEqual([g[0] for g in got], [
            f"homeassistant/device_tracker/leasewatch_example_home/{ID_B}/config", f"lw/device/{ID_B}/attributes",
            "lw/stats"])
        self.assertEqual(json.loads(got[0][1])["name"], "lamp")

    def test_second_identical_poll_only_stats(self) -> None:
        self.poll()
        self.assertEqual(self.poll(), [("lw/stats", STATS_JSON, 1, True)])

    def test_online_change_publishes_only_state(self) -> None:
        self.poll()
        self.db.q("UPDATE devices SET online=0 WHERE mac=?", (MAC_A,))
        self.assertEqual(self.poll(), [(f"lw/device/{ID_A}/state", b"not_home", 1, True),
                                       ("lw/stats", STATS_JSON, 1, True)])

    def test_ip_change_publishes_only_attributes(self) -> None:
        self.poll()
        self.db.q("UPDATE devices SET ip='10.0.0.9' WHERE mac=?", (MAC_B,))
        got = self.poll()
        self.assertEqual([g[0] for g in got], [f"lw/device/{ID_B}/attributes", "lw/stats"])
        self.assertEqual(json.loads(got[0][1])["ip"], "10.0.0.9")

    def test_unwatch_clears_three_retained_topics(self) -> None:
        self.poll()
        self.db.q("UPDATE devices SET watch=0 WHERE mac=?", (MAC_B,))
        self.assertEqual(self.poll(), [
            (f"lw/device/{ID_B}/state", b"", 1, True), (f"lw/device/{ID_B}/attributes", b"", 1, True),
            (f"homeassistant/device_tracker/leasewatch_example_home/{ID_B}/config", b"", 1, True),
            ("lw/stats", STATS_JSON, 1, True)])
        self.assertEqual(json.loads(self.db.get_meta("mqtt.published")), [ID_A])

    def poll_until_more_than_stats(self) -> list[tuple[str, bytes, int, bool]]:
        for _ in range(100):  # the handler sends it within one tick; each poll reads what has arrived
            got = self.poll()
            if len(got) > 1:
                return got
            self.broker.wait_for(lambda: False, 0.02)
        return got

    def test_birth_online_republishes_everything_once(self) -> None:
        self.poll()
        self.broker.inject("homeassistant/status", b"online", qos=1)
        got = self.poll_until_more_than_stats()
        self.assertEqual(len(got), 11)
        self.assertFalse(self.pub.birth_seen)
        self.assertEqual(self.poll(), [("lw/stats", STATS_JSON, 1, True)])  # the next poll is diff-only

    def test_birth_offline_changes_nothing(self) -> None:
        self.poll()
        self.broker.inject("homeassistant/status", b"offline", qos=1)
        for _ in range(5):
            self.assertEqual(self.poll(), [("lw/stats", STATS_JSON, 1, True)])
            self.broker.wait_for(lambda: False, 0.02)


class DiscoveryOffTests(PubCase):
    def setUp(self) -> None:
        super().setUp()
        os.environ["MQTT_DISCOVERY"] = "0"
        self.pub = self.make()
        self.db.set_meta("mqtt.published", json.dumps([ID_A, ID_B]))
        self.pub.connect()

    def test_no_configs_and_stale_ones_cleared_once(self) -> None:
        got = self.poll()
        configs = [g for g in got if g[0].startswith("homeassistant/")]
        base = "homeassistant/%s/leasewatch_example_home"
        self.assertEqual(sorted(c[0] for c in configs), sorted(
            [f"{base % 'device_tracker'}/{ID_A}/config", f"{base % 'device_tracker'}/{ID_B}/config"]
            + [f"{base % 'sensor'}/{k}/config" for k in ("devices", "online", "unacked", "new")]))
        self.assertTrue(all(c[1] == b"" and c[2:] == (1, True) for c in configs))
        self.assertEqual(self.db.get_meta("mqtt.discovery_cleared"), "1")
        self.assertEqual(len(got), 11)
        self.pub.full = True  # a reconnect: nothing is cleared again
        self.assertEqual([g for g in self.poll() if g[0].startswith("homeassistant/")], [])
        p = self.make()  # a restart
        p.connect()
        self.assertEqual([g for g in self.poll(p) if g[0].startswith("homeassistant/")], [])

    def test_discovery_on_again_resets_the_flag(self) -> None:
        self.poll()
        os.environ["MQTT_DISCOVERY"] = "1"
        p = self.make()
        p.connect()
        got = self.poll(p)
        self.assertEqual(len([g for g in got if g[0].startswith("homeassistant/") and g[1]]), 6)
        self.assertEqual(self.db.get_meta("mqtt.discovery_cleared"), "0")


class RestartTests(PubCase):
    def test_stale_id_removed_on_first_poll(self) -> None:
        self.db.set_meta("mqtt.published", json.dumps([ID_A, "020000000099"]))
        self.pub.connect()
        got = self.poll()
        stale = [g for g in got if "020000000099" in g[0]]
        self.assertEqual(stale, [
            ("lw/device/020000000099/state", b"", 1, True), ("lw/device/020000000099/attributes", b"", 1, True),
            ("homeassistant/device_tracker/leasewatch_example_home/020000000099/config", b"", 1, True)])
        self.assertEqual(json.loads(self.db.get_meta("mqtt.published")), [ID_A, ID_B])


class StatusTests(PubCase):
    def setUp(self) -> None:
        super().setUp()
        self.pub.connect()

    def test_publish_status_offline(self) -> None:
        self.pub.publish_status(False)
        self.assertEqual(self.broker.published[-1][:4], ("lw/status", b"offline", 1, True))

    def test_close_offline_then_disconnect(self) -> None:
        self.pub.close()
        self.assertEqual(self.broker.published[-1][:4], ("lw/status", b"offline", 1, True))
        self.assertTrue(self.broker.wait_for(lambda: self.broker.disconnected))
        self.assertFalse(self.pub.connected)
        self.pub.close()  # a second close does nothing and does not raise

    def test_ping_if_idle(self) -> None:
        sent = self.pub.client.last_sent
        self.clock.now = sent + 59  # keepalive 120: idle for less than 60 s
        self.pub.ping_if_idle()
        self.assertEqual(self.broker.pings, 0)
        self.clock.now = sent + 60
        self.pub.ping_if_idle()
        self.assertTrue(self.broker.wait_for(lambda: self.broker.pings == 1))
        self.pub.ping_if_idle()  # the PINGREQ itself counts as sent
        self.assertEqual(self.broker.pings, 1)


class FailureTests(PubCase):
    def test_withheld_puback_propagates(self) -> None:
        self.pub.connect()
        self.pub.publish_poll(self.rows(), STATS)
        self.db.q("UPDATE devices SET online=0 WHERE mac IN (?,?)", (MAC_A, MAC_B))
        self.broker.withhold_puback = True
        last = dict(self.pub.last)
        with self.assertRaises(MqttError):
            self.pub.publish_poll(self.rows(), STATS)
        self.assertFalse(self.pub.connected)
        self.assertTrue(self.pub.full)
        self.assertEqual(self.pub.last, last)  # the device whose publish failed keeps its old entry
        self.pub.close()  # never raises on a closed connection
