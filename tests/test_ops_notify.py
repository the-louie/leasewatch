"""Notification backoff per channel: a failing channel is not called again until its backoff elapsed, the other
channels still get the batch, the queue follows its own rules, one warning per failed spell. Synthetic data only;
fake channels and a fake clock (no sleeps)."""
import time
import unittest
from unittest import mock

from test_instances import FW1, Base
from leasewatch import notify
from leasewatch.config import Config

DEV = {"mac": "02:00:00:00:00:09", "ip": "10.0.0.9", "hostname": "pad", "vendor": "", "vlan": "", "lease_type": ""}
MAIL = {"LW_CONNECTORS": "fw1", **FW1, "MAILGUN_KEY": "k", "MAILGUN_DOMAIN": "mg.example.com",
        "MAIL_TO": "a@example.com", "SMTP_HOST": "smtp.example.com", "SMTP_FROM": "lw@example.com"}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Chan:
    def __init__(self, name):
        self.name = name
        self.calls = 0
        self.fail = False

    def send(self, msg):
        self.calls += 1
        if self.fail:
            raise notify.NotifyError(f"{self.name}: timeout")


class BackoffTests(unittest.TestCase):
    def test_doubles_to_the_cap_and_resets(self):
        clk = Clock()
        b = notify.Backoff(120, clock=clk)
        waits = []
        for _ in range(7):
            t0 = clk.t
            b.failed("smtp", "x")
            waits.append(int(b._state["smtp"].retry_at - t0))
            clk.t = b._state["smtp"].retry_at
        self.assertEqual(waits, [120, 240, 480, 960, 1800, 1800, 1800])
        self.assertEqual(b.delivered("smtp"), 7)
        self.assertTrue(b.due("smtp"))
        self.assertEqual(b.delivered("smtp"), 0)
        b.failed("smtp", "x")
        self.assertEqual(int(b._state["smtp"].retry_at - clk.t), 120)

    def test_not_due_until_elapsed(self):
        clk = Clock()
        b = notify.Backoff(120, clock=clk)
        self.assertTrue(b.failed("smtp", "x"))
        self.assertFalse(b.failed("smtp", "x"))
        clk.t += 239
        self.assertFalse(b.due("smtp"))
        clk.t += 1
        self.assertTrue(b.due("smtp"))


class NewDevicesBackoffTests(unittest.TestCase):
    def setUp(self):
        self.clk = Clock()
        self.b = notify.Backoff(120, clock=self.clk)
        self.smtp, self.hook = Chan("smtp"), Chan("webhook")
        p = mock.patch.object(notify, "channels", lambda cfg: [self.smtp, self.hook])
        p.start()
        self.addCleanup(p.stop)

    def send(self):
        return notify.new_devices(Config(), [DEV], backoff=self.b)

    def test_failed_channel_skipped_while_other_delivers(self):
        self.smtp.fail = True
        with self.assertLogs("leasewatch.notify", "INFO") as logs:
            self.assertEqual(self.send(), ["webhook"])
        self.assertEqual(self.send(), ["webhook"])  # smtp waits: not called
        self.assertEqual((self.smtp.calls, self.hook.calls), (1, 2))
        self.clk.t += 120
        self.assertEqual(self.send(), ["webhook"])
        self.assertEqual(self.smtp.calls, 2)
        self.assertEqual(len([m for m in logs.output if "smtp failed" in m]), 1)

    def test_one_warning_per_spell_and_one_info_on_recovery(self):
        self.smtp.fail = True
        with self.assertLogs("leasewatch.notify", "DEBUG") as logs:
            for _ in range(3):
                self.send()
                self.clk.t += 1800
            self.smtp.fail = False
            self.send()
            self.send()
        warn = [r for r in logs.records if r.levelname == "WARNING"]
        info = [r.getMessage() for r in logs.records if "delivers again" in r.getMessage()]
        self.assertEqual(len(warn), 1)
        self.assertIn("smtp failed (1 device(s)): smtp: timeout; retrying with backoff up to 30 min", warn[0].getMessage())
        self.assertEqual(info, ["smtp delivers again after 3 failed attempt(s)"])
        self.assertEqual(sum(r.levelname == "WARNING" for r in logs.records), 1)

    def test_all_failed_raises_notifyerror_and_all_waiting_raises_deferred(self):
        self.smtp.fail = self.hook.fail = True
        with self.assertRaises(notify.NotifyError) as cm, self.assertLogs("leasewatch.notify", "WARNING"):
            self.send()
        self.assertNotIsInstance(cm.exception, notify.NotifyDeferred)
        with self.assertRaises(notify.NotifyDeferred):
            self.send()
        self.assertEqual((self.smtp.calls, self.hook.calls), (1, 1))

    def test_without_backoff_every_channel_is_called(self):
        self.smtp.fail = True
        with self.assertLogs("leasewatch.notify", "WARNING"):
            notify.new_devices(Config(), [DEV])
        with self.assertLogs("leasewatch.notify", "WARNING"):
            notify.new_devices(Config(), [DEV])
        self.assertEqual(self.smtp.calls, 2)


class CollectorNotifyTests(Base):
    def setUp(self):
        super().setUp()
        self.clk = Clock()
        self.smtp, self.mg = Chan("smtp"), Chan("mailgun")
        p = mock.patch.object(notify, "channels", lambda cfg: [self.mg, self.smtp])
        p.start()
        self.addCleanup(p.stop)
        self.col, self.db = self.collector(MAIL)
        self.col._mail_backoff = notify.Backoff(120, clock=self.clk)

    def queue(self, mac="02:00:00:00:00:09"):
        now = int(time.time())
        self.db.q("INSERT INTO devices(mac,first_seen,last_seen,mail_queued) VALUES(?,?,?,?)", (mac, now, now, now))

    def queued(self):
        return self.db.q("SELECT COUNT(*) n FROM devices WHERE mail_queued IS NOT NULL")[0]["n"]

    def meta(self, ch):
        return self.db.get_meta(f"notify.{ch}.ok", None)

    def test_dead_channel_in_backoff_is_not_called_and_queue_cleared(self):
        self.smtp.fail = True
        self.queue()
        with self.assertLogs("leasewatch", "WARNING"):
            self.col._notify()
        self.assertEqual(self.queued(), 0)  # mailgun delivered
        self.assertEqual((self.meta("mailgun"), self.meta("smtp")), ("1", "0"))
        self.queue("02:00:00:00:00:0a")
        self.col._notify()
        self.assertEqual(self.smtp.calls, 1)  # in backoff: no 20 s stall
        self.assertEqual(self.mg.calls, 2)

    def test_queue_kept_when_every_channel_failed_or_waits_cleared_on_delivery(self):
        self.smtp.fail = self.mg.fail = True
        self.queue()
        with self.assertLogs("leasewatch", "WARNING"):
            self.col._notify()
        self.assertEqual(self.queued(), 1)
        self.assertEqual((self.meta("mailgun"), self.meta("smtp")), ("0", "0"))
        self.col._notify()  # both wait: nothing called
        self.assertEqual((self.smtp.calls, self.mg.calls), (1, 1))
        self.assertEqual(self.queued(), 1)
        self.clk.t += 120
        self.mg.fail = False
        with self.assertLogs("leasewatch", "INFO"):
            self.col._notify()
        self.assertEqual(self.queued(), 0)
        self.assertEqual((self.meta("mailgun"), self.meta("smtp")), ("1", "0"))
        self.assertEqual(self.smtp.calls, 2)  # failed again, the batch it missed stays missed

    def test_meta_written_only_on_change(self):
        self.queue()
        with mock.patch.object(self.db, "set_meta", wraps=self.db.set_meta) as sm:
            self.col._notify()
            self.queue("02:00:00:00:00:0a")
            self.col._notify()
        keys = [c.args[0] for c in sm.call_args_list if c.args[0].startswith("notify.")]
        self.assertEqual(sorted(keys), ["notify.mailgun.ok", "notify.smtp.ok"])

    def test_repeated_collector_warning_only_when_text_changes(self):
        self.smtp.fail = self.mg.fail = True
        self.queue()
        with self.assertLogs("leasewatch.collector", "DEBUG") as logs:
            self.col._notify()
            self.clk.t += 1800
            self.col._notify()
        self.assertEqual([r.levelname for r in logs.records if "mail failed" in r.getMessage()], ["WARNING", "DEBUG"])

    def test_two_channels_failing_out_of_phase_warn_once_per_spell(self):
        self.smtp.fail = True  # smtp fails from poll 0, mailgun from poll 3: the error text keeps changing
        with self.assertLogs("leasewatch", "DEBUG") as logs:
            for poll in range(200):
                if poll == 3:
                    self.mg.fail = True
                self.queue(f"02:00:00:00:{poll // 256:02x}:{poll % 256:02x}")
                self.col._notify()
                self.clk.t += 120
            self.mg.fail = False
            self.clk.t += 1800
            self.col._notify()
        collector_log = [r for r in logs.records if r.name == "leasewatch.collector"]
        warn = [r for r in collector_log if r.levelname == "WARNING"]
        self.assertEqual(len(warn), 1, [r.getMessage() for r in warn])
        self.assertIn("mail failed", warn[0].getMessage())
        self.assertEqual(len([r for r in logs.records if r.levelname == "WARNING" and r.name == "leasewatch.notify"]), 2)
        self.assertEqual(len([r for r in collector_log if r.levelname == "INFO" and "mail delivers again" in r.getMessage()]), 1)


if __name__ == "__main__":
    unittest.main()
