"""The generic send path: a message without devices (a later source-down or watch alert) through every channel
format, the backoff shared with new_devices(), and new_devices() as a wrapper of send(). Local stub servers on
port 0 (the webhook test's HTTP recorder, tests/_smtpfake.py); synthetic data only."""
from __future__ import annotations

import email
import email.policy
import json
import os
import sys
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore  # noqa: E402
from _smtpfake import FakeSmtp  # noqa: E402
from test_webhook_channel import Hook  # noqa: E402
from leasewatch import notify  # noqa: E402
from leasewatch.config import Config  # noqa: E402

DEV = {"mac": "02:00:00:00:00:09", "ip": "10.0.0.9", "hostname": "pad", "vendor": "", "vlan": "", "lease_type": ""}
SUBJECT, TEXT = "fw1 is down", "fw1: connection refused (3 failed polls)"
TOKEN = "tok3n-in-the-url-abc"


def alert() -> notify.Message:
    return notify.Message(subject=SUBJECT, text=TEXT, event="source_down")


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.saved = clean_env({"no_proxy": "*", "NO_PROXY": "*"})
        self.addCleanup(restore, self.saved)

    def hook(self, status: int = 200) -> Hook:
        h = Hook(status=status)
        self.addCleanup(h.close)
        return h

    def cfg(self, **env: str) -> Config:
        os.environ.update(env)
        return Config()


class MessageTests(unittest.TestCase):
    def test_defaults_keep_old_constructors(self) -> None:
        m = notify.Message("s", "t")
        self.assertEqual((m.event, m.devices, m.blocks, m.links, m.url), ("new_devices", [], [], [], ""))

    def test_build_alert(self) -> None:
        m = notify.build_alert(Config(), "fw1\r\nis down", ["fw1: refused", "evil\nline"], "source_down")
        self.assertEqual(m.subject, "fw1  is down")  # no header injection, as build_message
        self.assertEqual(m.text, "fw1: refused\nevil line")
        self.assertEqual((m.event, m.devices, m.blocks, m.url), ("source_down", [], [], ""))


class DevicelessSendTests(Base):
    def body(self, h: Hook) -> dict:
        self.assertEqual(len(h.requests), 1)
        return json.loads(h.requests[0][2])

    def test_webhook_json(self) -> None:
        h = self.hook()
        with self.assertLogs("leasewatch.notify", "INFO") as logs:
            self.assertEqual(notify.send(self.cfg(WEBHOOK_URL=h.url + "/x/" + TOKEN, SITE_NAME="HomeNet"), alert(),
                                         what="source down alert"), ["webhook"])
        body = self.body(h)
        self.assertEqual((body["event"], body["count"], body["devices"], body["url"]), ("source_down", 0, [], None))
        self.assertEqual((body["site"], body["title"], body["message"]), ("HomeNet", SUBJECT, TEXT))
        self.assertEqual(logs.output, ["INFO:leasewatch.notify:mail sent: source down alert (webhook)"])

    def test_webhook_ntfy(self) -> None:
        h = self.hook()
        notify.send(self.cfg(WEBHOOK_URL=h.url + "/lw-alerts", WEBHOOK_FORMAT="ntfy", PUBLIC_URL="https://lw.example.lan"),
                    alert())
        body = self.body(h)
        self.assertEqual(body, {"topic": "lw-alerts", "title": SUBJECT, "message": TEXT})  # no click without a link

    def test_webhook_ntfy_long_alert_is_cut_by_lines(self) -> None:
        h = self.hook()
        lines = [f"instance-{i}: " + "x" * 90 for i in range(60)]
        notify.send(self.cfg(WEBHOOK_URL=h.url + "/lw", WEBHOOK_FORMAT="ntfy"), notify.build_alert(Config(), "s", lines, "watch"))
        message = self.body(h)["message"]
        self.assertLess(len(message.encode()), notify.NTFY_MAX)
        self.assertTrue(message.startswith(lines[0] + "\n"))
        self.assertRegex(message, r"… and \d+ more$")

    def test_webhook_discord(self) -> None:
        h = self.hook()
        notify.send(self.cfg(WEBHOOK_URL=h.url + "/d", WEBHOOK_FORMAT="discord"), alert())
        body = self.body(h)
        self.assertEqual(body["content"], f"{SUBJECT}\n```\n{TEXT}\n```")
        self.assertEqual(body["allowed_mentions"], {"parse": []})

    def test_mailgun(self) -> None:
        h = self.hook()
        cfg = self.cfg(MAILGUN_KEY="mg-key-123", MAILGUN_DOMAIN="mg.example.com", MAIL_TO="ops@example.com",
                       MAILGUN_API_BASE=h.url)
        self.assertEqual(notify.send(cfg, alert()), ["mailgun"])
        form = urllib.parse.parse_qs(h.requests[0][2].decode())
        self.assertEqual((form["subject"], form["text"]), ([SUBJECT], [TEXT]))

    def test_smtp(self) -> None:
        srv = FakeSmtp()
        self.addCleanup(srv.close)
        cfg = self.cfg(SMTP_HOST="127.0.0.1", SMTP_PORT=str(srv.port), SMTP_TLS="none", MAIL_TO="ops@example.com",
                       SMTP_FROM="leasewatch@example.com")
        self.assertEqual(notify.send(cfg, alert()), ["smtp"])
        m = email.message_from_bytes(srv.messages[0], policy=email.policy.default)
        self.assertEqual(m["Subject"], SUBJECT)
        self.assertEqual(m.get_content().strip(), TEXT)

    def test_failure_logs_what_and_no_secret(self) -> None:
        h = self.hook(status=503)
        cfg = self.cfg(WEBHOOK_URL=h.url + "/hook/" + TOKEN, MAILGUN_KEY="mg-key-123", MAILGUN_DOMAIN="mg.example.com",
                       MAIL_TO="ops@example.com", MAILGUN_API_BASE=h.url)
        with self.assertRaises(notify.NotifyError), self.assertLogs("leasewatch.notify", "DEBUG") as logs:
            notify.send(cfg, alert(), notify.Backoff(120), "source down alert")
        self.assertTrue(any("webhook failed (source down alert): webhook: HTTP 503; retrying" in m for m in logs.output),
                        logs.output)
        for m in logs.output:
            self.assertNotIn(TOKEN, m)
            self.assertNotIn("mg-key-123", m)


class Chan:
    def __init__(self, name: str) -> None:
        self.name, self.calls, self.fail = name, 0, False

    def send(self, msg: notify.Message) -> None:
        self.calls += 1
        if self.fail:
            raise notify.NotifyError(f"{self.name}: timeout")


class SharedBackoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.t = [1000.0]
        self.b = notify.Backoff(120, clock=lambda: self.t[0])
        self.smtp, self.hook = Chan("smtp"), Chan("webhook")
        p = mock.patch.object(notify, "channels", lambda cfg: [self.smtp, self.hook])
        p.start()
        self.addCleanup(p.stop)

    def test_failed_on_send_waits_for_new_devices(self) -> None:
        self.smtp.fail = True
        with self.assertLogs("leasewatch.notify", "WARNING"):
            self.assertEqual(notify.send(Config(), alert(), self.b, "source down alert"), ["webhook"])
        self.assertEqual(notify.new_devices(Config(), [DEV], backoff=self.b), ["webhook"])
        self.assertEqual((self.smtp.calls, self.hook.calls), (1, 2))

    def test_failed_on_new_devices_waits_for_send(self) -> None:
        self.hook.fail = True
        with self.assertLogs("leasewatch.notify", "WARNING"):
            self.assertEqual(notify.new_devices(Config(), [DEV], backoff=self.b), ["smtp"])
        self.assertEqual(notify.send(Config(), alert(), self.b), ["smtp"])
        self.assertEqual((self.smtp.calls, self.hook.calls), (2, 1))
        self.t[0] += 120
        self.hook.fail = False
        self.assertEqual(notify.send(Config(), alert(), self.b), ["smtp", "webhook"])


class NewDevicesWrapperTests(unittest.TestCase):
    def test_same_message_and_logs(self) -> None:
        got: list[notify.Message] = []
        ch = Chan("smtp")
        ch.send = got.append  # type: ignore[method-assign]
        with mock.patch.object(notify, "channels", lambda cfg: [ch]), \
                self.assertLogs("leasewatch.notify", "INFO") as logs:
            self.assertEqual(notify.new_devices(Config(), [DEV]), ["smtp"])
            notify.new_devices(Config(), [DEV, DEV])
        self.assertEqual(got[0], notify.build_message(Config(), [DEV]))
        self.assertEqual(got[0].event, "new_devices")
        self.assertEqual(logs.output, ["INFO:leasewatch.notify:mail sent: 1 new device (smtp)",
                                       "INFO:leasewatch.notify:mail sent: 2 new devices (smtp)"])


if __name__ == "__main__":
    unittest.main()
