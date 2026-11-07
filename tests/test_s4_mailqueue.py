"""S4 T-09: the durable mail queue (devices.mail_queued). A new device is queued in the poll's write transaction, the
queue survives a restart, a failed mail keeps it however old it is, acked or archived devices leave
it, one mail holds at most 50 devices, and a private MAC is never queued. Synthetic data only: hardware MACs are from
the documentation range 00:00:5e:00:53:xx (RFC 7042). Fake connectors; Mailgun is stubbed."""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_instances import FW1, MAC, Base, arp  # noqa: E402
from leasewatch import notify  # noqa: E402
from leasewatch.collector import Collector  # noqa: E402

MAIL = {"LW_CONNECTORS": "fw1", **FW1, "MAILGUN_KEY": "k", "MAILGUN_DOMAIN": "mg.example.com",
        "MAIL_TO": "a@example.com"}
UA1 = "00:00:5e:00:53:01"
UA2 = "00:00:5e:00:53:02"
PRIV = "06:00:00:00:20:01"


def down(cfg, devs):
    raise RuntimeError("mailgun down")


class MailQueueTests(Base):
    def setUp(self):
        super().setUp()
        self.sent = []

    def ok(self, cfg, devs):
        self.sent.append([d["mac"] for d in devs])

    def baseline(self, env=MAIL):
        """A collector whose first poll (the baseline, no mail) is done."""
        col, db = self.collector(env, rows=[arp(MAC, "10.0.0.5")])
        col.run_once()
        return col, db

    def queued(self, db, mac):
        r = db.q("SELECT mail_queued FROM devices WHERE mac=?", (mac,))
        return r[0]["mail_queued"] if r else None

    def test_queued_in_the_insert_transaction(self):
        col, db = self.baseline()
        self.client.rows.append(arp(UA1, "10.0.0.6"))
        t = int(time.time())
        with mock.patch.object(Collector, "_notify", lambda self, *a: None):  # nothing after the write may queue it
            col.run_once()
        self.assertGreaterEqual(self.queued(db, UA1), t)
        self.assertIsNone(self.queued(db, MAC))  # the baseline is never queued

    def test_mail_off_queues_nothing(self):
        col, db = self.baseline({"LW_CONNECTORS": "fw1", **FW1})
        self.client.rows.append(arp(UA1, "10.0.0.6"))
        col.run_once()
        self.assertIsNone(self.queued(db, UA1))
        self.assertEqual(db.q("SELECT COUNT(*) n FROM devices WHERE mac=?", (UA1,))[0]["n"], 1)

    def test_restart_sends_the_queued_mail(self):
        col, db = self.baseline()
        self.client.rows.append(arp(UA1, "10.0.0.6"))
        with mock.patch.object(notify, "new_devices", down), self.assertLogs("leasewatch.collector", "WARNING"):
            col.run_once()
        col2 = Collector(col.cfg, db, self.client)  # a restart: a new collector on the same database
        with mock.patch.object(notify, "new_devices", self.ok):
            col2.run_once()
        self.assertEqual(self.sent, [[UA1]])
        self.assertIsNone(self.queued(db, UA1))

    def test_failure_keeps_the_queue(self):
        col, db = self.baseline()
        self.client.rows.append(arp(UA1, "10.0.0.6"))
        with mock.patch.object(notify, "new_devices", down), \
                self.assertLogs("leasewatch.collector", "WARNING") as logs:
            col.run_once()
        self.assertIsNotNone(self.queued(db, UA1))
        self.assertTrue(any("1 device(s) queued" in m for m in logs.output), logs.output)
        with mock.patch.object(notify, "new_devices", self.ok):
            col.run_once()
        self.assertEqual(self.sent, [[UA1]])

    def test_old_entries_stay_until_mailed(self):
        # S4R01 (owner decision): no age limit. A device queued while the clock ran days behind (or one jumped ahead)
        # must not be dropped unmailed once the clock is right; the queue keeps it until mailed, acked or archived
        col, db = self.baseline()
        now = int(time.time())
        db.q("INSERT INTO devices(mac,first_seen,last_seen,mail_queued) VALUES(?,?,?,?)", (UA1, now, now, now - 2 * 86400))
        db.q("INSERT INTO devices(mac,first_seen,last_seen,mail_queued) VALUES(?,?,?,?)", (UA2, now, now, now - 3600))
        with mock.patch.object(notify, "new_devices", self.ok):
            col._notify()
        self.assertEqual(self.sent, [[UA1, UA2]])
        self.assertIsNone(self.queued(db, UA1))

    def test_acked_or_archived_devices_leave_the_queue(self):
        col, db = self.baseline()
        now = int(time.time())
        for mac in (UA1, UA2):
            db.q("INSERT INTO devices(mac,first_seen,last_seen,mail_queued) VALUES(?,?,?,?)", (mac, now, now, now))
        db.update_user_fields(UA1, True, None, None)
        db.q("UPDATE devices SET archived_ts=? WHERE mac=?", (now, UA2))
        with mock.patch.object(notify, "new_devices", self.ok):
            col._notify()
        self.assertEqual(self.sent, [])
        self.assertEqual((self.queued(db, UA1), self.queued(db, UA2)), (None, None))

    def test_one_mail_holds_at_most_50(self):
        col, db = self.baseline()
        now = int(time.time())
        macs = [f"00:00:5e:00:53:{i:02x}" for i in range(60)]
        for i, mac in enumerate(macs):
            db.q("INSERT INTO devices(mac,first_seen,last_seen,mail_queued) VALUES(?,?,?,?)", (mac, now, now, now - 60 + i))
        with mock.patch.object(notify, "new_devices", self.ok):
            col._notify()
            col._notify()
        self.assertEqual(self.sent, [macs[:50], macs[50:]])

    def test_queue_mails_current_values(self):
        col, db = self.baseline()
        self.client.rows.append(arp(UA1, "10.0.0.6"))
        with mock.patch.object(notify, "new_devices", down), self.assertLogs("leasewatch.collector", "WARNING"):
            col.run_once()
        self.client.rows[-1] = arp(UA1, "10.0.0.7")
        got = []
        with mock.patch.object(notify, "new_devices", lambda cfg, devs: got.extend(devs)):
            col.run_once()
        self.assertEqual([(d["mac"], d["ip"]) for d in got], [(UA1, "10.0.0.7")])

    def test_private_macs_are_never_queued(self):
        col, db = self.baseline()
        self.client.rows += [arp(PRIV, "10.0.0.8"), arp(UA1, "10.0.0.6")]
        with mock.patch.object(Collector, "_notify", lambda self, *a: None):
            col.run_once()
        self.assertIsNone(self.queued(db, PRIV))
        self.assertIsNotNone(self.queued(db, UA1))  # the hardware MAC of the same poll is queued


if __name__ == "__main__":
    unittest.main()
