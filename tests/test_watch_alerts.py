"""MAIL_ON_WATCH: the offline/online events of watched devices, and their ip/vlan/port/wifi changes, sent through the
notification channels as one digest per poll, on the same mark as MAIL_ON_SOURCE. notify.send is stubbed; fake
connector types only."""
from __future__ import annotations

import os
import sys
import unittest
from dataclasses import replace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from test_ops_events import ENV, Clock, down  # noqa: E402
from test_instances import MAC, Base, Fake, arp  # noqa: E402
from leasewatch.connectors import Attachment, Batch, Sighting, registry  # noqa: E402
ON = {**ENV, "WEBHOOK_URL": "https://hook.example.com/t", "MAIL_ON_WATCH": "1", "PUBLIC_URL": "https://lw.example.lan/"}
MAC2, MAC3, MAC4, MAC5 = (f"02:00:00:00:00:0{i}" for i in range(2, 6))
GRACE = 10 * 60


class FakeCtl(Fake):
    """A Wi-Fi controller: its attachments are the complete client list."""
    INFO = replace(Fake.INFO, type="fakectl", roles=frozenset({"controller"}))


def sighting(mac, ip, vlan="LAN"):
    return replace(arp(mac, ip), vlan=vlan)


class WatchAlertTests(Base):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        for p in (mock.patch("time.time", self.clock), mock.patch("leasewatch.notify.send", side_effect=self.sent),
                  mock.patch.dict(registry(), {"fakectl": FakeCtl})):
            p.start()
            self.addCleanup(p.stop)
        self.msgs = []

    def sent(self, cfg, msg, backoff=None, what="new devices"):
        if msg.event != "new_devices":
            self.msgs.append(msg)
        return ["webhook"]

    def poll(self, col, n=1):
        for _ in range(n):
            col.run_once()
            self.clock.tick()

    def start(self, env=ON, rows=None):
        col, db = self.collector(env, rows)
        self.addCleanup(col.close)
        self.poll(col)  # baseline taken; the mark is set
        return col, db

    @staticmethod
    def watch(db, *macs, name=None):
        for mac in macs:
            db.update_user_fields(mac, None, name, None, watch=True, actor="op")

    @staticmethod
    def events(db, kinds=("offline", "online", "back")):
        return [(r["mac"], r["kind"]) for r in db.q(
            f"SELECT mac, kind FROM events WHERE kind IN ({','.join('?' * len(kinds))}) ORDER BY id", kinds)]

    def leave(self, col, mac=MAC):
        """The device drops off the wire; polls until the grace has passed."""
        self.client.rows = [r for r in self.client.rows if r.mac != mac]
        self.poll(col, GRACE // self.clock.step + 1)

    def test_offline_after_the_grace_then_online(self):
        col, db = self.start()
        self.watch(db, MAC, name="printer")
        self.client.rows = []
        self.poll(col, GRACE // self.clock.step - 1)
        self.assertEqual(self.events(db), [])  # still within the grace
        self.poll(col, 2)
        self.assertEqual(self.events(db), [(MAC, "offline")])
        detail = db.q("SELECT detail FROM events WHERE kind='offline'")[0][0]
        self.assertRegex(detail, r"^last seen \d+ min ago$")
        self.assertEqual(len(self.msgs), 1)
        m = self.msgs[0]
        self.assertEqual((m.event, m.subject, m.devices), ("watch", "printer: offline", []))
        line, empty, link = m.text.splitlines()
        self.assertRegex(line, r"^\d{4}-\d\d-\d\d \d\d:\d\d printer offline: last seen \d+ min ago$")
        self.assertEqual((empty, link), ("", f"https://lw.example.lan/?device={MAC}"))
        self.assertEqual((m.links, m.url), ([link], link))
        self.client.rows = [arp(MAC, "10.0.0.5")]
        self.poll(col)
        self.assertEqual(self.events(db), [(MAC, "offline"), (MAC, "online")])
        self.assertEqual([(m.subject, m.event) for m in self.msgs[1:]], [("printer: online", "watch")])
        self.assertRegex(self.msgs[1].text.splitlines()[0], r" printer online$")
        self.poll(col, 2)
        self.assertEqual(len(self.msgs), 2)

    def test_back_after_a_day_is_back_not_online(self):
        col, db = self.start()
        self.watch(db, MAC)
        self.leave(col)
        self.clock.t += 2 * 86400
        self.client.rows = [arp(MAC, "10.0.0.5")]
        self.poll(col)
        self.assertEqual(self.events(db), [(MAC, "offline"), (MAC, "back")])
        self.assertEqual([m.subject for m in self.msgs], [f"{MAC}: offline"])  # back is no watch kind

    def test_five_changes_in_one_poll_are_one_message(self):
        rows = [arp(MAC, "10.0.0.5"), arp(MAC2, "10.0.0.6"), arp(MAC3, "10.0.0.7"), arp(MAC4, "10.0.0.8"),
                arp(MAC5, "10.0.0.9")]
        env = {**ON, "LW_CONNECTORS": "fw1,x,ctl", "LW_CONNECTOR__CTL__TYPE": "fakectl"}
        col, db = self.collector(env, rows)
        self.addCleanup(col.close)
        x, ctl = col._connectors["x"], col._connectors["ctl"]
        port = {"p": "GE1/0/1"}
        ssid = {"s": "HomeNet"}
        x.on_collect = lambda: Batch(attachments=[Attachment(mac=MAC, source="x", observed_at=0, link="wired",
                                                             port=port["p"])])
        ctl.on_collect = lambda: Batch(attachments=[Attachment(mac=MAC2, source="ctl", observed_at=0, link="wifi",
                                                               ssid=ssid["s"], ap="ap1")])
        self.poll(col)
        self.poll(col)
        self.watch(db, MAC, MAC2, MAC3, MAC4, MAC5)
        self.assertEqual(self.msgs, [])
        self.client.rows = [arp(MAC, "10.0.0.5"), arp(MAC2, "10.0.0.6"), arp(MAC3, "10.0.0.17"),
                            sighting(MAC4, "10.0.0.8", "IOT")]
        port["p"], ssid["s"] = "GE1/0/2", "Guest"
        self.clock.t += GRACE  # MAC5 is past the grace in this same poll
        self.poll(col)
        self.assertEqual(len(self.msgs), 1)
        m = self.msgs[0]
        self.assertEqual((m.subject, m.event), ("5 changes on watched devices", "watch"))
        kinds = sorted(ln.split(" ")[3].rstrip(":") for ln in m.text.splitlines() if ln[:1].isdigit())
        self.assertEqual(kinds, ["ip", "offline", "port", "vlan", "wifi"])
        self.assertEqual(sum(1 for ln in m.text.splitlines() if "?device=" in ln), 5)
        self.assertEqual((len(m.links), m.url), (5, ""))

    def test_unwatched_device_gets_no_event_and_no_message(self):
        col, db = self.start()
        self.leave(col)
        self.client.rows = [arp(MAC, "10.0.0.6")]
        self.poll(col)
        self.assertEqual(self.events(db), [])
        self.assertEqual(len(db.q("SELECT 1 FROM events WHERE kind='ip'")), 1)
        self.assertEqual(self.msgs, [])

    def test_failed_poll_writes_no_offline_now_or_after(self):
        col, db = self.start()
        self.watch(db, MAC)
        self.client.fail = True
        self.poll(col, GRACE // self.clock.step + 2)  # _fail turns it offline after the grace, silently
        self.assertEqual(db.q("SELECT online FROM devices WHERE mac=?", (MAC,))[0][0], 0)
        self.client.fail = False
        self.client.rows = []
        self.poll(col, 3)  # still away: the first good poll has prev_ok off, the later ones see no change
        self.assertEqual(self.events(db), [])
        self.client.rows = [arp(MAC, "10.0.0.5")]
        self.poll(col)
        self.assertEqual(self.events(db), [(MAC, "online")])  # a real change after a good poll

    def test_back_in_the_poll_after_a_failure_is_no_online(self):
        col, db = self.start()
        self.watch(db, MAC)
        self.client.fail = True
        self.poll(col, GRACE // self.clock.step + 2)
        self.client.fail = False
        self.poll(col)
        self.assertEqual(self.events(db), [])
        self.assertEqual([m.event for m in self.msgs if m.event == "watch"], [])

    def test_mixed_with_a_source_event_is_one_message(self):
        col, db = self.start({**ON, "MAIL_ON_SOURCE": "1"})
        self.watch(db, MAC, name="printer")
        col._connectors["x"].on_collect = down
        self.poll(col, 2)
        self.client.rows = []
        self.clock.t += GRACE
        self.poll(col)  # x's third failure and the offline in one poll
        self.assertEqual(len(self.msgs), 1)
        m = self.msgs[0]
        self.assertEqual((m.subject, m.event), ("2 alerts", "source_down"))
        lines = m.text.splitlines()
        self.assertTrue(any(ln.endswith("source_down: x: down") for ln in lines))
        self.assertTrue(any(" printer offline: " in ln for ln in lines))

    def test_flag_off_sends_nothing(self):
        col, db = self.start({**ON, "MAIL_ON_WATCH": ""})
        self.assertFalse(col.cfg.mail_on_watch)
        self.watch(db, MAC)
        self.leave(col)
        self.assertEqual(self.events(db), [(MAC, "offline")])  # the event is written all the same
        self.assertEqual(self.msgs, [])
        self.assertEqual(db.get_meta("notify.alert_event_id", "unset"), "unset")

    def test_unwatched_after_the_event_is_not_sent(self):
        col, db = self.start()
        self.watch(db, MAC)
        self.client.rows = [arp(MAC, "10.0.0.6")]
        with mock.patch.object(col, "_alert"):
            self.poll(col)  # the ip event is written, the alert pass does not run
        db.update_user_fields(MAC, None, None, None, watch=False, actor="op")
        self.poll(col)
        self.assertEqual(self.msgs, [])

    def test_acked_and_archived_still_sent(self):
        col, db = self.start()
        self.watch(db, MAC)
        self.client.rows = [arp(MAC, "10.0.0.6")]
        db.update_user_fields(MAC, True, None, None, archived=True, actor="op")
        self.poll(col)
        self.assertEqual([m.subject for m in self.msgs], [f"{MAC}: ip"])

    def test_events_of_a_device_watched_later_are_not_sent(self):
        col, db = self.start()
        for i in range(5):
            self.client.rows = [arp(MAC, f"10.0.0.{10 + i}")]
            self.poll(col)
        self.assertEqual(len(db.q("SELECT 1 FROM events WHERE kind='ip'")), 5)
        self.watch(db, MAC)
        self.poll(col, 2)
        self.assertEqual(self.msgs, [])
        self.client.rows = [arp(MAC, "10.0.0.30")]
        self.poll(col)
        self.assertEqual([m.subject for m in self.msgs], [f"{MAC}: ip"])  # only what is written after the watch

    def test_watch_turned_on_after_source_alone_sends_nothing_old(self):
        col, db = self.start({**ON, "MAIL_ON_WATCH": "0", "MAIL_ON_SOURCE": "1"})
        self.watch(db, MAC)
        for i in range(4):
            self.client.rows = [arp(MAC, f"10.0.0.{10 + i}")]
            self.poll(col)
        self.assertEqual(len(db.q("SELECT 1 FROM events WHERE kind='ip'")), 4)
        col.close()
        col2, db2 = self.collector({**ON, "MAIL_ON_SOURCE": "1"}, [arp(MAC, "10.0.0.13")])
        self.addCleanup(col2.close)
        self.poll(col2, 2)
        self.assertEqual(self.msgs, [])

    def test_partial_outage_writes_no_offline_or_online(self):
        env = {**ON, "LW_CONNECTORS": "fw1,x,fy", "LW_CONNECTOR__FY__TYPE": "fakefw"}
        col, db = self.collector(env)
        self.addCleanup(col.close)
        fy = col._connectors["fy"]
        ok = lambda: Batch(sightings=[Sighting(mac=MAC2, source="", kind="arp", observed_at=0, presence=True,  # noqa: E731
                                               ip="10.0.0.6")])
        fy.on_collect = ok
        self.poll(col, 2)
        self.watch(db, MAC, MAC2)
        self.poll(col)
        fy.on_collect = down  # fy alone sees MAC2; fw1 still answers
        self.poll(col, GRACE // self.clock.step + 3)
        self.assertEqual(db.q("SELECT online FROM devices WHERE mac=?", (MAC2,))[0][0], 0)  # the grace rule
        fy.on_collect = ok
        self.poll(col, 3)
        self.assertEqual(self.events(db), [])
        self.assertEqual(self.msgs, [])

    def test_offline_swallowed_by_a_failed_poll_is_written_at_the_next_trusted_poll(self):
        col, db = self.start()
        self.watch(db, MAC)
        self.poll(col)
        self.client.rows = []
        self.poll(col, GRACE // self.clock.step - 1)
        self.client.fail = True
        self.poll(col, 2)  # the grace passes in _fail: online turns off silently
        self.client.fail = False
        self.poll(col)  # the previous poll failed: not trusted
        self.assertEqual(self.events(db), [])
        self.poll(col)
        self.assertEqual(self.events(db), [(MAC, "offline")])
        self.poll(col, 2)
        self.assertEqual([m.subject for m in self.msgs], [f"{MAC}: offline"])

    def test_left_during_a_long_outage_is_reported_once_the_sources_are_back(self):
        col, db = self.start()
        self.watch(db, MAC)
        self.poll(col)
        self.client.fail = True
        self.client.rows = []
        self.poll(col, GRACE // self.clock.step + 3)
        self.assertEqual(self.events(db), [])
        self.client.fail = False
        self.poll(col, 4)
        self.assertEqual(self.events(db), [(MAC, "offline")])
        self.assertEqual([m.subject for m in self.msgs], [f"{MAC}: offline"])

    def test_watched_again_after_unwatch_gets_no_stale_event(self):
        col, db = self.start()
        self.watch(db, MAC)
        self.poll(col)
        self.assertEqual(db.q("SELECT watch_online FROM devices WHERE mac=?", (MAC,))[0][0], 1)
        db.update_user_fields(MAC, None, None, None, watch=False, actor="op")
        self.poll(col)
        self.assertIsNone(db.q("SELECT watch_online FROM devices WHERE mac=?", (MAC,))[0][0])
        self.leave(col)  # offline while not watched: no event
        self.watch(db, MAC)
        self.poll(col, 2)
        self.assertEqual(self.events(db), [])
        self.assertEqual(db.q("SELECT watch_online FROM devices WHERE mac=?", (MAC,))[0][0], 0)
        self.client.rows = [arp(MAC, "10.0.0.5")]
        self.poll(col)
        self.assertEqual(self.events(db), [(MAC, "online")])
        self.assertEqual([m.subject for m in self.msgs], [f"{MAC}: online"])

    def test_bad_value_is_a_problem(self):
        self.assertIn("MAIL_ON_WATCH must be 1 or 0", self.cfg({**ON, "MAIL_ON_WATCH": "2"}).validate())
        self.assertNotIn("MAIL_ON_WATCH must be 1 or 0", self.cfg(ON).validate())


if __name__ == "__main__":
    unittest.main()
