"""MAIL_ON_SOURCE: the source_down/source_up events sent through the notification channels, one message per poll,
from the mark in meta notify.alert_event_id. notify.send is stubbed; fake connector types only."""
from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from test_ops_events import ENV, Clock, down  # noqa: E402
from test_instances import Base  # noqa: E402
from leasewatch import notify  # noqa: E402
from leasewatch.collector import ALERT_MARK, Collector  # noqa: E402
from leasewatch.connectors import Batch  # noqa: E402

ON = {**ENV, "WEBHOOK_URL": "https://hook.example.com/t", "MAIL_ON_SOURCE": "1"}


class SourceAlertTests(Base):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        for p in (mock.patch("time.time", self.clock), mock.patch("leasewatch.notify.send", side_effect=self.sent)):
            p.start()
            self.addCleanup(p.stop)
        self.msgs = []
        self.fail_with = None

    def sent(self, cfg, msg, backoff=None, what="new devices"):
        if self.fail_with is not None:
            raise self.fail_with
        if msg.event != "new_devices":
            self.msgs.append(msg)
        return ["webhook"]

    def poll(self, col, n=1):
        for _ in range(n):
            col.run_once()
            self.clock.tick()

    def start(self, env=ON):
        col, db = self.collector(env)
        self.addCleanup(col.close)
        self.poll(col)  # baseline taken; the mark is set
        return col, db

    def test_off_by_default(self):
        col, db = self.start({**ON, "MAIL_ON_SOURCE": ""})
        self.assertFalse(col.cfg.mail_on_source)
        col._connectors["x"].on_collect = down
        self.poll(col, 4)
        col._connectors["x"].on_collect = Batch
        self.poll(col)
        self.assertEqual(self.msgs, [])
        self.assertEqual(db.get_meta(ALERT_MARK, "unset"), "unset")

    def test_down_then_up(self):
        col, db = self.start()
        x = col._connectors["x"]
        x.on_collect = down
        self.poll(col, 2)
        self.assertEqual(self.msgs, [])
        self.poll(col)
        self.assertEqual(len(self.msgs), 1)
        m = self.msgs[0]
        self.assertEqual((m.event, m.subject, m.devices), ("source_down", "x is down", []))
        self.assertRegex(m.text, r"^\d{4}-\d\d-\d\d \d\d:\d\d source_down: x: down$")
        self.poll(col, 2)
        self.assertEqual(len(self.msgs), 1)
        x.on_collect = Batch
        self.poll(col)
        self.assertEqual([(m.event, m.subject) for m in self.msgs[1:]], [("source_up", "x is back")])
        self.assertIn("source_up: x: up after 10m", self.msgs[1].text)
        top = db.q("SELECT MAX(id) FROM events")[0][0]
        self.assertEqual(db.get_meta(ALERT_MARK), str(top))

    def test_all_producers_down_alerts_from_the_fail_path(self):
        col, db = self.start()
        self.client.fail = True
        self.poll(col, 3)
        self.assertEqual([(m.event, m.subject) for m in self.msgs], [("source_down", "fw1 is down")])

    def test_several_events_in_one_message(self):
        col, db = self.start()
        col._connectors["x"].on_collect = down
        self.poll(col, 2)
        self.client.fail = True
        self.poll(col, 3)  # fw1 down (x not collected)
        self.client.fail = False
        self.poll(col)  # fw1 up and x's third failure: two events in one poll
        m = self.msgs[-1]
        self.assertEqual((m.subject, m.event), ("2 source events", "source_down"))
        self.assertEqual([ln.split(" ", 2)[2] for ln in m.text.splitlines()],
                         ["source_up: fw1: up after 6m", "source_down: x: down"])

    def test_restart_during_the_outage_sends_nothing_new(self):
        col, db = self.start()
        col._connectors["x"].on_collect = down
        self.poll(col, 3)
        self.assertEqual(len(self.msgs), 1)
        col.close()
        col2 = Collector(col.cfg, db, self.client)
        self.addCleanup(col2.close)
        col2._connectors["x"].on_collect = down
        self.poll(col2, 4)
        self.assertEqual(len(self.msgs), 1)
        col2._connectors["x"].on_collect = Batch
        self.poll(col2)
        self.assertEqual([m.event for m in self.msgs], ["source_down", "source_up"])

    def test_no_channel_sends_nothing(self):
        env = {k: v for k, v in ON.items() if k != "WEBHOOK_URL"}
        col, db = self.start(env)
        self.assertFalse(col.cfg.mail_enabled)
        col._connectors["x"].on_collect = down
        with self.assertLogs("leasewatch.collector", "DEBUG") as logs:
            self.poll(col, 3)
        self.assertFalse([o for o in logs.output if "alert" in o])
        self.assertEqual(self.msgs, [])
        self.assertEqual(notify.send.call_count, 0)

    def test_deferred_keeps_the_mark_and_sends_once_later(self):
        col, db = self.start()
        mark = db.get_meta(ALERT_MARK)
        col._connectors["x"].on_collect = down
        self.fail_with = notify.NotifyDeferred("waiting")
        self.poll(col, 3)
        self.assertEqual(db.get_meta(ALERT_MARK), mark)
        self.fail_with = None
        self.poll(col)
        self.poll(col)
        self.assertEqual([m.event for m in self.msgs], ["source_down"])
        self.assertNotEqual(db.get_meta(ALERT_MARK), mark)

    def test_failed_send_keeps_the_mark_and_logs_no_url(self):
        col, db = self.start()
        mark = db.get_meta(ALERT_MARK)
        col._connectors["x"].on_collect = down
        self.fail_with = notify.WebhookError("webhook: HTTP 500")
        with self.assertLogs("leasewatch.collector", "WARNING") as logs:
            self.poll(col, 3)
        self.assertEqual(db.get_meta(ALERT_MARK), mark)
        self.assertTrue(any("source alert failed (1 event(s)): webhook: HTTP 500" in o for o in logs.output))
        self.assertFalse(any("hook.example.com" in o for o in logs.output))
        self.fail_with = None
        self.poll(col)
        self.assertEqual([m.event for m in self.msgs], ["source_down"])

    def test_first_start_with_old_events_sends_nothing_and_sets_the_mark(self):
        col, db = self.collector({**ON, "MAIL_ON_SOURCE": "0"})
        self.addCleanup(col.close)
        self.poll(col)
        col._connectors["x"].on_collect = down
        self.poll(col, 3)
        col._connectors["x"].on_collect = Batch
        self.poll(col)
        self.assertEqual(len(db.q("SELECT 1 FROM events WHERE kind LIKE 'source%'")), 2)
        col.close()
        col2, db2 = self.collector(ON)
        self.addCleanup(col2.close)
        self.poll(col2)
        self.assertEqual(self.msgs, [])
        self.assertEqual(db2.get_meta(ALERT_MARK), str(db2.q("SELECT MAX(id) FROM events")[0][0]))

    def test_turned_off_and_on_again_sends_no_old_events(self):
        col, db = self.start()
        col.close()
        col2, db2 = self.collector({**ON, "MAIL_ON_SOURCE": "0"})
        self.addCleanup(col2.close)
        self.poll(col2)
        self.assertEqual(db2.get_meta(ALERT_MARK, "unset"), "unset")
        col2._connectors["x"].on_collect = down
        self.poll(col2, 3)
        col2.close()
        col3, _ = self.collector(ON)
        self.addCleanup(col3.close)
        self.poll(col3, 2)
        self.assertEqual(self.msgs, [])

    def test_failure_in_the_alert_pass_does_not_stop_the_poll(self):
        col, db = self.start()
        col._connectors["x"].on_collect = down
        self.poll(col, 2)
        with mock.patch("leasewatch.notify.build_alert", side_effect=ValueError("bug")), \
                self.assertLogs("leasewatch.collector", "WARNING") as logs:
            res = col.run_once()
        self.clock.tick()
        self.assertTrue(res["ok"])
        self.assertIn("WARNING:leasewatch.collector:source alert skipped: ValueError", logs.output)
        with mock.patch.object(col, "_alert_subject", side_effect=sqlite3.OperationalError("locked")), \
                self.assertLogs("leasewatch.collector", "WARNING") as logs:
            self.assertTrue(col.run_once()["ok"])
        self.clock.tick()
        self.assertIn("WARNING:leasewatch.collector:source alert skipped: database error (OperationalError)", logs.output)
        self.assertEqual(self.msgs, [])
        self.poll(col)  # the event waits for the next poll
        self.assertEqual([m.event for m in self.msgs], ["source_down"])

    def test_bad_value_is_a_problem(self):
        cfg = self.cfg({**ON, "MAIL_ON_SOURCE": "maybe"})
        self.assertIn("MAIL_ON_SOURCE must be 1 or 0", cfg.validate())
        self.assertNotIn("MAIL_ON_SOURCE must be 1 or 0", self.cfg(ON).validate())


if __name__ == "__main__":
    unittest.main()
