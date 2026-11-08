"""leasewatch.notify.MqttChannel against the fake broker in _mqttfake (loopback, port 0), through a Publisher's
connection. Synthetic data only."""
from __future__ import annotations

import json
import os

import _env  # noqa: F401  # the repo root on the path and the network guard, also when this module runs on its own
from _case import EnvTmpCase
from _env import FW1_ENV
from _mqttfake import FakeBroker
from leasewatch import notify
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.mqtt import MqttError
from leasewatch.mqtt_pub import Publisher
from leasewatch.notify import Backoff, MqttChannel, MqttChannelError, NotifyError, build_message, webhook_json_body

ROW = {"mac": "02:00:00:00:00:0a", "ip": "10.0.0.5", "hostname": "host.example.lan", "vendor": "Example Inc",
       "vlan": "LAN", "lease_type": "dhcp"}
PASSWORD = "s3cret-pw-value"


class ChannelCase(EnvTmpCase):
    ENV = {**FW1_ENV, "SITE_NAME": "Example Home", "PUBLIC_URL": "https://lw.example.lan/", "MQTT_TOPIC": "lw",
           "MQTT_EVENTS": "1"}
    broker_kw: dict = {}

    def setUp(self) -> None:
        super().setUp()
        self.broker = FakeBroker(**self.broker_kw)
        self.addCleanup(self.broker.close)
        os.environ["MQTT_URL"] = f"mqtt://{self.broker.host}:{self.broker.port}"
        self.cfg = Config()
        self.db = Database(os.path.join(self.tmp.name, "lw.sqlite3"))
        self.addCleanup(self.db._conn.close)
        self.pub = Publisher(self.cfg, self.db, "1.5.0")
        self.pub.timeout = 1.0
        self.addCleanup(lambda: self.pub.client and self.pub.client.close())
        self.addCleanup(notify.set_shared_client, lambda: None)
        notify.set_shared_client(lambda: self.pub.client if self.pub.connected else None)

    def events(self) -> list[tuple]:
        return [p for p in self.broker.published if p[0] == "lw/event"]


class MqttChannelTests(ChannelCase):
    def test_listed_only_with_mqtt_events(self):
        self.assertIn("mqtt", [c.name for c in notify.channels(self.cfg)])
        self.assertTrue(any(isinstance(c, MqttChannel) for c in notify.channels(self.cfg)))
        os.environ["MQTT_EVENTS"] = "0"
        self.assertFalse(any(isinstance(c, MqttChannel) for c in notify.channels(Config())))

    def test_new_devices_published_as_the_webhook_body(self):
        self.pub.connect()
        msg = build_message(self.cfg, [ROW])
        self.assertEqual(notify.send(self.cfg, msg, Backoff()), ["mqtt"])
        (topic, payload, qos, retain, _), = self.events()
        self.assertEqual((topic, qos, retain), ("lw/event", 1, False))
        self.assertEqual(payload, webhook_json_body(self.cfg, msg))
        body = json.loads(payload)
        self.assertEqual(body["event"], "new_devices")
        self.assertEqual(body["devices"][0]["mac"], ROW["mac"])
        for key in ("subject", "message"):  # the webhook's own names: title and message
            self.assertIn({"subject": "title"}.get(key, key), body)

    def test_watch_alert_published(self):
        self.pub.connect()
        msg = notify.Message(subject="Watched device offline", text="tv went offline", devices=[ROW], event="watch")
        self.assertEqual(notify.send(self.cfg, msg, Backoff(), "watch alert"), ["mqtt"])
        (_, payload, qos, retain, _), = self.events()
        self.assertEqual((qos, retain), (1, False))
        self.assertEqual(json.loads(payload)["event"], "watch")
        self.assertEqual(payload, webhook_json_body(self.cfg, msg))

    def test_not_connected_is_deferred_without_a_backoff_failure(self):
        backoff = Backoff(base=120)
        msg = build_message(self.cfg, [ROW])
        with self.assertRaises(MqttChannelError) as cm:
            MqttChannel(self.cfg).send(msg)
        self.assertEqual(str(cm.exception), "mqtt: not connected")
        self.assertIsInstance(cm.exception, notify.NotifyDeferred)
        with self.assertRaises(notify.NotifyDeferred):  # not tried: the queue stays
            notify.send(self.cfg, msg, backoff)
        # the "mqtt" backoff is the publisher's reconnect wait: an event it could not try must not push it back
        self.assertNotIn("mqtt", backoff.states())
        self.assertTrue(backoff.due("mqtt"))
        self.assertEqual(self.broker.connections, 0)  # no connection of its own

    def test_publish_failure_counts_on_the_backoff(self):
        backoff = Backoff(base=120)
        self.pub.connect()
        self.broker.withhold_puback = True
        self.pub.client.timeout = 0.3
        with self.assertRaises(MqttChannelError), self.assertLogs("leasewatch.notify", "WARNING"):
            notify.send(self.cfg, build_message(self.cfg, [ROW]), backoff)
        self.assertIs(backoff.states()["mqtt"], False)
        self.assertEqual(backoff.retry_in("mqtt"), 120)

    def test_not_connected_with_another_channel_delivering(self):
        os.environ.update(WEBHOOK_URL="https://hook.example.lan/x")
        cfg = Config()
        calls = []
        orig = notify.WebhookChannel.send
        notify.WebhookChannel.send = lambda _self, msg: calls.append(msg)
        self.addCleanup(setattr, notify.WebhookChannel, "send", orig)
        backoff = Backoff(base=120)
        self.assertEqual(notify.send(cfg, build_message(cfg, [ROW]), backoff), ["webhook"])
        self.assertEqual(len(calls), 1)
        self.assertNotIn("mqtt", backoff.states())

    def test_publish_error_is_wrapped(self):
        self.pub.connect()
        self.pub.client.close()
        with self.assertRaises(NotifyError) as cm:
            MqttChannel(self.cfg, lambda: self.pub.client).send(build_message(self.cfg, [ROW]))
        self.assertIsInstance(cm.exception, MqttChannelError)
        self.assertTrue(str(cm.exception).startswith("mqtt:"))

    def test_retry_in(self):
        now = [100.0]
        b = Backoff(base=60, clock=lambda: now[0])
        self.assertEqual(b.retry_in("x"), 0)
        b.failed("x", "e")
        self.assertEqual(b.retry_in("x"), 60)
        now[0] = 130.0
        self.assertEqual(b.retry_in("x"), 30)
        now[0] = 500.0
        self.assertEqual(b.retry_in("x"), 0)


class PasswordNotLoggedTests(ChannelCase):
    broker_kw = {"connack_code": 5}
    ENV = {**ChannelCase.ENV, "MQTT_USER": "lw", "MQTT_PASSWORD": PASSWORD}

    def test_password_in_no_log_line(self):
        msg = build_message(self.cfg, [ROW])
        with self.assertLogs("leasewatch", level="DEBUG") as logs:
            with self.assertRaises(MqttError):
                self.pub.connect()
            with self.assertRaises(notify.NotifyDeferred):  # not connected: not tried
                notify.send(self.cfg, msg, Backoff())
        self.assertTrue(logs.output)
        self.assertNotIn(PASSWORD, "\n".join(logs.output))
