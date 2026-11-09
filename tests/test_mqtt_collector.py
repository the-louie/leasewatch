"""The collector drives the MQTT publisher: after a good poll, on failed polls (status offline at SOURCE_DOWN_POLLS), with
the broker down (the "mqtt" backoff, notify.mqtt.ok) and at close(). The fake broker in _mqttfake (loopback, port 0)
and FakeClient as fw1. Synthetic data only."""
from __future__ import annotations

import contextlib
import http.client
import io
import json
import logging
import os
import socket
import threading
import time
import unittest.mock

import _env  # noqa: F401  # the repo root on the path and the network guard, also when this module runs on its own
from _case import EnvTmpCase
from _env import FW1_ENV
from _fixtures import FakeClient, S
from _mqttfake import FakeBroker
from leasewatch import notify
from leasewatch.__main__ import check_cmd, startup_line
from leasewatch.collector import ALERT_MARK, SOURCE_DOWN_POLLS, Collector
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.web import serve

MACS = ("02:00:00:00:00:1a", "02:00:00:00:00:1b", "02:00:00:00:00:1c")


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def free_port() -> int:
    """A loopback port with nothing listening on it (bound once, then released)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MqttCollectorCase(EnvTmpCase):
    ENV = {**FW1_ENV, "MQTT_TOPIC": "lw", "MQTT_DEVICES": "all", "POLL_SECONDS": "60", "LISTEN_HOST": "127.0.0.1",
           "LISTEN_PORT": "0"}

    def setUp(self) -> None:
        super().setUp()
        self.broker = FakeBroker()
        self.addCleanup(self.broker.close)
        self.use_port(self.broker.port)
        self.db = Database(os.path.join(self.tmp.name, "lw.sqlite3"))
        self.addCleanup(self.db._conn.close)
        # offline sightings: no last_online that moves between two polls, so an unchanged poll sends only the stats
        self.fw = FakeClient([S(m, f"10.0.0.{i + 10}", f"host{i}", online=False) for i, m in enumerate(MACS)])
        self.col = self.make()

    def use_port(self, port: int) -> None:
        os.environ["MQTT_URL"] = f"mqtt://127.0.0.1:{port}"

    def make(self) -> Collector:
        col = Collector(Config(), self.db, self.fw)
        self.addCleanup(col.close)
        col._mqtt.timeout = 1.0
        self.clock = Clock()
        col._mail_backoff = notify.Backoff(60, clock=self.clock)
        return col

    def sent(self, start: int) -> list[tuple[str, bytes]]:
        return [(t, p) for t, p, *_ in self.broker.published[start:]]

    def poll(self, fail: bool = False) -> tuple[dict, list[tuple[str, bytes]]]:
        self.fw.fail = fail
        start = len(self.broker.published)
        res = self.col.run_once()
        return res, self.sent(start)


class PollTests(MqttCollectorCase):
    def test_good_poll_connects_and_publishes_everything(self) -> None:
        res, sent = self.poll()
        self.assertTrue(res["ok"])
        topics = [t for t, _ in sent]
        self.assertEqual(sent[0], ("lw/status", b"online"))
        states = [t for t in topics if t.startswith("lw/device/") and t.endswith("/state")]
        self.assertEqual(len(states), len(MACS))
        self.assertEqual(topics[-1], "lw/stats")
        self.assertEqual(json.loads(sent[-1][1])["devices"], len(MACS))
        self.assertEqual(self.db.get_meta("notify.mqtt.ok"), "1")  # never failed: ok after the first publish

    def test_second_poll_sends_only_stats_without_reconnect(self) -> None:
        self.poll()
        res, sent = self.poll()
        self.assertTrue(res["ok"])
        self.assertEqual([t for t, _ in sent], ["lw/stats"])
        self.assertEqual(self.broker.connections, 1)

    def test_failed_polls_then_offline_then_online_and_full_republish(self) -> None:
        self.poll()
        for i in range(1, SOURCE_DOWN_POLLS):
            res, sent = self.poll(fail=True)
            self.assertFalse(res["ok"])
            self.assertEqual(sent, [], i)
        res, sent = self.poll(fail=True)
        self.assertEqual(sent, [("lw/status", b"offline")])
        res, sent = self.poll(fail=True)  # once per spell
        self.assertEqual(sent, [])
        res, sent = self.poll()
        self.assertTrue(res["ok"])
        topics = [t for t, _ in sent]
        self.assertEqual(sent[-1], ("lw/status", b"online"))
        self.assertEqual(len([t for t in topics if t.endswith("/state")]), len(MACS))
        self.assertIn("lw/stats", topics)
        self.assertEqual(self.broker.connections, 1)

    def test_crashed_polls_count_toward_offline(self) -> None:
        self.poll()
        start = len(self.broker.published)

        class Stop(threading.Event):  # set after `left` waits, so loop() runs that many polls without sleeping
            left = SOURCE_DOWN_POLLS

            def wait(self, timeout: float | None = None) -> bool:
                self.left -= 1
                if self.left <= 0:
                    self.set()
                return self.is_set()

        with unittest.mock.patch.object(self.col, "_commit", side_effect=RuntimeError("synthetic")), \
                self.assertLogs("leasewatch.collector", "ERROR"):
            self.col.loop(Stop())
        self.assertEqual(self.sent(start), [("lw/status", b"offline")])

    def test_broker_down_warns_once_and_records_not_ok(self) -> None:
        self.use_port(free_port())
        self.col = self.make()
        with self.assertLogs("leasewatch.collector", logging.DEBUG) as cm:
            res = self.col.run_once()
            self.assertTrue(res["ok"])
            self.clock.now += 3600
            self.assertTrue(self.col.run_once()["ok"])
        lines = [r for r in cm.records if r.getMessage().startswith("mqtt: ")]
        self.assertEqual([r.levelname for r in lines], ["WARNING", "DEBUG"])
        self.assertRegex(lines[0].getMessage(), r"^mqtt: .+ \(retry in \d+ s\)$")
        self.assertEqual(self.db.get_meta("notify.mqtt.ok"), "0")
        srv = serve(self.col.cfg, self.db, "test")
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
            try:
                conn.request("GET", "/api/status")
                body = json.loads(conn.getresponse().read())
            finally:
                conn.close()
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(5)
        self.assertEqual(body["meta"]["notify"], {"mqtt": False})  # without MQTT_EVENTS too

    def test_withheld_puback_closes_and_the_next_due_poll_reconnects(self) -> None:
        self.poll()
        self.broker.withhold_puback = True
        self.col._mqtt.client.timeout = 0.3
        with self.assertLogs("leasewatch.collector", logging.WARNING):
            res, _ = self.poll()
        self.assertTrue(res["ok"])
        self.assertFalse(self.col._mqtt.connected)
        self.assertEqual(self.db.get_meta("notify.mqtt.ok"), "0")
        self.assertTrue(self.broker.wait_gone())
        self.broker.withhold_puback = False
        res, sent = self.poll()  # backoff not due: no attempt
        self.assertEqual((sent, self.broker.connections), ([], 1))
        self.clock.now += 3600
        with self.assertLogs("leasewatch.collector", logging.INFO) as cm:
            res, sent = self.poll()
        self.assertIn("mqtt: publishing again", [r.getMessage() for r in cm.records])
        self.assertEqual(self.broker.connections, 2)
        self.assertEqual(sent[0], ("lw/status", b"online"))
        self.assertEqual(len([t for t, _ in sent if t.endswith("/state")]), len(MACS))  # a full republish
        self.assertEqual(self.db.get_meta("notify.mqtt.ok"), "1")

    def test_close_sends_offline_then_disconnect(self) -> None:
        self.poll()
        start = len(self.broker.published)
        self.col.close()
        self.assertTrue(self.broker.wait_for(lambda: self.broker.disconnected))
        self.assertEqual(self.sent(start), [("lw/status", b"offline")])

    def test_without_mqtt_url_nothing_is_built(self) -> None:
        os.environ.pop("MQTT_URL")
        col = Collector(Config(), self.db, self.fw)
        self.addCleanup(col.close)
        self.assertIsNone(col._mqtt)
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(self.db.get_meta("notify.mqtt.ok"), "")
        self.assertEqual(self.broker.connections, 0)


class EventsTests(MqttCollectorCase):
    """MQTT_EVENTS=1 with MQTT as the only channel: events go to <topic>/event through the publisher's connection."""
    ENV = {**MqttCollectorCase.ENV, "MQTT_EVENTS": "1", "MAIL_ON_SOURCE": "1", "MAIL_ON_WATCH": "1"}

    @staticmethod
    def events(sent: list[tuple[str, bytes]]) -> list[dict]:
        return [json.loads(p) for t, p in sent if t == "lw/event"]

    def source_down(self) -> int:
        """A source_down event written while the process runs (or was down); its id."""
        self.db.q("INSERT INTO events(ts, mac, kind, detail) VALUES (?,?,?,?)",
                  (int(time.time()), "", "source_down", "fw1: timeout"))
        return int(self.db.q("SELECT MAX(id) FROM events")[0][0])

    def assert_reconnected_with_alert(self, sent: list[tuple[str, bytes]], event_id: int) -> None:
        self.assertEqual(self.broker.connections, 2)
        self.assertTrue(self.col._mqtt.connected)
        topics = [t for t, _ in sent]
        self.assertEqual(sent[0], ("lw/status", b"online"))
        self.assertEqual(len([t for t in topics if t.endswith("/state")]), len(MACS))  # the full republish
        self.assertEqual([e["event"] for e in self.events(sent)], ["source_down"])
        self.assertGreater(topics.index("lw/event"), topics.index("lw/stats"))  # after the presence publish
        self.assertGreaterEqual(int(self.db.get_meta(ALERT_MARK)), event_id)
        self.assertEqual(self.db.get_meta("notify.mqtt.ok"), "1")

    def test_dropped_connection_reconnects_before_the_pending_alert(self) -> None:
        self.poll()  # connects; the alert mark is set
        self.col._mqtt.client.close()
        self.assertTrue(self.broker.wait_gone())
        event_id = self.source_down()
        res, sent = self.poll()  # the "mqtt" backoff never failed: due at once
        self.assertTrue(res["ok"])
        self.assert_reconnected_with_alert(sent, event_id)

    def test_restart_with_a_pending_alert(self) -> None:
        self.poll()
        self.col.close()
        self.assertTrue(self.broker.wait_gone())
        event_id = self.source_down()
        self.col = self.make()  # the same database
        res, sent = self.poll()
        self.assertTrue(res["ok"])
        self.assert_reconnected_with_alert(sent, event_id)

    def test_new_device_mail_is_cleared_by_the_mqtt_delivery(self) -> None:
        self.poll()  # the baseline
        mac = "00:00:5e:00:53:2a"  # a global MAC: a private one is never mailed
        self.fw.sightings_data.append(S(mac, "10.0.0.42", "newhost", online=False))
        res, sent = self.poll()
        (ev,) = self.events(sent)
        self.assertEqual((ev["event"], [d["mac"] for d in ev["devices"]]), ("new_devices", [mac]))
        self.assertIsNone(self.db.q("SELECT mail_queued FROM devices WHERE mac=?", (mac,))[0][0])

    def test_watch_alert_moves_the_mark(self) -> None:
        self.poll()
        self.db.q("UPDATE devices SET watch=1 WHERE mac=?", (MACS[0],))
        self.fw.sightings_data[0] = S(MACS[0], "10.0.0.99", "host0", online=False)
        res, sent = self.poll()
        (ev,) = self.events(sent)
        self.assertEqual(ev["event"], "watch")
        top = self.db.q("SELECT MAX(id) FROM events WHERE mac=? AND kind='ip'", (MACS[0],))[0][0]
        self.assertIsNotNone(top)
        self.assertGreaterEqual(int(self.db.get_meta(ALERT_MARK)), top)


class EventsOffTests(MqttCollectorCase):
    ENV = {**MqttCollectorCase.ENV, "MQTT_EVENTS": "0", "MAIL_ON_SOURCE": "1"}

    def test_no_event_but_presence(self) -> None:
        self.poll()
        mac = "00:00:5e:00:53:2b"
        self.fw.sightings_data.append(S(mac, "10.0.0.43", "newhost", online=False))
        self.db.q("INSERT INTO events(ts, mac, kind, detail) VALUES (?,?,?,?)",
                  (int(time.time()), "", "source_down", "fw1: timeout"))
        res, sent = self.poll()
        topics = [t for t, _ in sent]
        self.assertNotIn("lw/event", [p[0] for p in self.broker.published])
        self.assertIn("lw/device/00005e00532b/state", topics)


class LineTests(EnvTmpCase):
    ENV = {**FW1_ENV, "MQTT_URL": "mqtt://127.0.0.1:1883", "MQTT_USER": "lwuser-synthetic",
           "MQTT_PASSWORD": "pw-synthetic"}

    def test_startup_line(self) -> None:
        line = startup_line(Config(), "1.5.0")
        self.assertIn("; mqtt on (mqtt://127.0.0.1:1883, discovery, watched)", line)
        self.assertNotIn("lwuser-synthetic", line)
        self.assertNotIn("pw-synthetic", line)
        os.environ.update(MQTT_URL="mqtts://broker.example.lan", MQTT_DISCOVERY="0", MQTT_DEVICES="all")
        self.assertIn("; mqtt on (mqtts://broker.example.lan:8883, no discovery, all)", startup_line(Config(), "1.5.0"))
        os.environ.pop("MQTT_URL")
        self.assertNotIn("mqtt", startup_line(Config(), "1.5.0"))

    def check_out(self) -> str:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            check_cmd(["nosuch"])  # an unknown instance: nothing is contacted
        return buf.getvalue()

    def test_check_line(self) -> None:
        out = self.check_out()
        self.assertIn("\nmqtt: mqtt://127.0.0.1:1883 (watched, discovery on)\n", out)
        self.assertNotIn("lwuser-synthetic", out)
        os.environ.pop("MQTT_URL")
        self.assertIn("\nmqtt: off\n", self.check_out())
