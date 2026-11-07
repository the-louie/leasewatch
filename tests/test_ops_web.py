"""/healthz: a stuck collector is told from a source outage, and the page banner follows."""
from __future__ import annotations

import json
import os
import sys
import time
import unittest
from unittest import mock

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_web_edge_cases as QW  # noqa: E402  (module import: its TestCase classes are not collected twice)
from leasewatch.collector import Collector  # noqa: E402
from leasewatch import web  # noqa: E402
from leasewatch.fw1 import Sighting  # noqa: E402


class HealthzTests(QW.Base):
    def health(self) -> tuple[int, dict]:
        h = self.handler(path="/healthz")
        h.do_GET()
        raw = h.wfile.getvalue()
        return self.status(raw), json.loads(raw.partition(b"\r\n\r\n")[2])

    def meta(self, poll_age: int, ok: bool, attempt_age: int | None) -> None:
        now = int(time.time())
        self.db.set_meta("last_poll_ts", str(now - poll_age))
        self.db.set_meta("last_poll_ok", "1" if ok else "0")
        if attempt_age is not None:
            self.db.set_meta("last_attempt_ts", str(now - attempt_age))

    def test_fresh_poll_is_ok(self) -> None:
        self.meta(5, True, 5)
        code, body = self.health()
        self.assertEqual((code, body["ok"], body["reason"], body["collector_stale"]), (200, True, "ok", False))

    def test_old_poll_with_recent_attempts_is_source(self) -> None:
        self.meta(3600, False, 30)
        code, body = self.health()
        self.assertEqual((code, body["ok"], body["reason"], body["collector_stale"]), (503, False, "source", False))

    def old_process(self, age: int = 7200) -> None:
        with mock.patch("leasewatch.web.time.time", return_value=time.time() - age):
            self.H = web.make_handler(self.cfg, self.db, "9.9.9")

    def test_no_attempt_within_limit_is_collector(self) -> None:
        self.old_process()
        self.meta(3600, True, 3600)
        code, body = self.health()
        self.assertEqual((code, body["ok"], body["reason"], body["collector_stale"]), (503, False, "collector", True))
        self.assertEqual(body["attempt_limit"], 2 * 120 + 2 * 60 + 120)  # the default instance timeout is 60 s

    def test_no_attempt_ever_depends_on_process_age(self) -> None:
        code, body = self.health()  # young process: not the collector yet
        self.assertEqual((code, body["reason"], body["collector_stale"], body["last_attempt_ts"]), (503, "source", False, None))
        with mock.patch("leasewatch.web.time.time", return_value=time.time() - 3600):
            self.H = web.make_handler(self.cfg, self.db, "9.9.9")  # a process that started an hour ago
        code, body = self.health()
        self.assertEqual((code, body["reason"], body["collector_stale"]), (503, "collector", True))

    def test_attempt_from_before_the_start_counts_as_none(self) -> None:
        # a restart after downtime longer than the limit: the old attempt says nothing about this process
        self.meta(900, True, 900)
        code, body = self.health()
        self.assertEqual((code, body["reason"], body["collector_stale"]), (503, "source", False))
        self.meta(5, True, 900)
        self.assertEqual(self.health()[1]["reason"], "ok")
        self.old_process(3600)  # the process is older than the limit and the attempt is from before its start
        self.meta(7200, True, 7200)
        code, body = self.health()
        self.assertEqual((code, body["reason"], body["collector_stale"]), (503, "collector", True))

    def test_attempt_in_the_future_counts_by_abs(self) -> None:
        self.meta(5, True, -3600)
        self.assertTrue(self.health()[1]["collector_stale"])

    def test_attempt_in_the_future_is_collector(self) -> None:
        self.meta(3600, False, -3600)
        code, body = self.health()
        self.assertEqual((code, body["reason"], body["collector_stale"]), (503, "collector", True))
        self.assertLess(body["now"], body["last_attempt_ts"])  # the page words this as a clock step, not a dead collector

    def test_meta_notify_hides_unconfigured_channels(self) -> None:
        # no channel configured here: the rows of removed channels stay in the database but are not shown
        self.db.set_meta("notify.smtp.ok", "1")
        self.db.set_meta("notify.webhook.ok", "0")
        self.assertEqual(self.handler(path="/api/stats")._meta()["notify"], {})
        self.assertEqual(self.health()[1]["notify"], {})
        self.assertEqual(self.db.get_meta("notify.smtp.ok"), "1")

    def test_meta_in_api_exposes_collector_stale(self) -> None:
        self.meta(5, True, 5)
        h = self.handler(path="/api/stats")
        m = h._meta()
        self.assertIs(m["collector_stale"], False)
        self.assertIn("last_attempt_age", m)

    def test_readme_row_names_the_body(self) -> None:
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            row = next(ln for ln in f if ln.startswith("| GET | `/healthz`"))
        self.assertTrue(all(w in row for w in ("reason", "ok", "source", "collector", "attempt_limit")))
        self.assertIn("reason", self.health()[1])


class NotifyChannelTests(QW.Base):
    env = {"SMTP_HOST": "smtp.example.lan", "SMTP_FROM": "lw@example.lan", "MAIL_TO": "ops@example.lan",
           "WEBHOOK_URL": "https://hook.example.lan/x"}

    def test_meta_notify_lists_configured_channel_state(self) -> None:
        self.db.set_meta("notify.smtp.ok", "1")
        self.db.set_meta("notify.webhook.ok", "0")
        self.db.set_meta("notify.mailgun.ok", "1")  # mailgun was removed from the config
        self.assertEqual(self.handler(path="/api/stats")._meta()["notify"], {"smtp": True, "webhook": False})

    def test_configured_channel_without_a_send_yet_is_absent(self) -> None:
        self.db.set_meta("notify.smtp.ok", "0")
        self.assertEqual(self.handler(path="/api/stats")._meta()["notify"], {"smtp": False})


class FakeClient:
    def __init__(self, sightings: list) -> None:
        self.data = sightings

    def arp_raw(self) -> list:
        return []

    def sightings(self, ignore: tuple = ()) -> tuple:
        return list(self.data), {"leases": len(self.data), "arp": 0}


class AttemptWrittenTests(QW.Base):
    def test_success_and_failure_write_the_attempt(self) -> None:
        client = FakeClient([Sighting(mac=QW.MAC, ip="10.0.1.5", hostname="desktop", vendor="Acme", vlan="HomeNet",
                                      iface="lan", source="dhcp", lease_type="dynamic", online=True)])
        col = Collector(self.cfg, self.db, client)
        before = int(time.time())
        self.assertTrue(col.run_once()["ok"])
        self.assertGreaterEqual(int(self.db.get_meta("last_attempt_ts")), before)
        self.db.set_meta("last_attempt_ts", "1")
        client.data = []  # no sightings after the baseline: still a good poll; force a failure instead
        col._fail("boom")
        self.assertGreaterEqual(int(self.db.get_meta("last_attempt_ts")), before)
        self.assertEqual(self.db.get_meta("last_poll_ok"), "0")


if __name__ == "__main__":
    unittest.main()
