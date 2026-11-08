"""Archive and restore. The device POST sets devices.archived_ts, the list API keeps archived devices (the
page hides them), stats skip them, the CSV has an `archived` column, a device that comes online again leaves the
archive with one `back` event, and PRUNE_DAYS archives long-offline devices without a name or ack. Synthetic data
only: private MACs and the RFC 7042 documentation range 00:00:5e:00:53:xx."""
import csv
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from test_instances import FW1, Base, arp  # noqa: E402
from test_merge import NOW, S, row  # noqa: E402
from test_web import MAC1, MAC2, MAC3, WebTestCase  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.connectors import Batch  # noqa: E402
from leasewatch.connectors.merge import MergeState, merge  # noqa: E402
from leasewatch.fw1 import Sighting as Fw1Sighting  # noqa: E402

DAY = 86400
UA = "00:00:5e:00:53:01"
DEV = "02:00:00:00:30:01"
MAIL = {"MAILGUN_KEY": "k", "MAILGUN_DOMAIN": "mg.example.com", "MAIL_TO": "a@example.com"}


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})

    def tearDown(self):
        self.tmp.cleanup()
        restore(self._env)

    def run_merge(self, prev, sightings, prune_days=0, **state):
        os.environ["PRUNE_DAYS"] = str(prune_days)
        st = MergeState(**state)
        return merge({r["mac"]: r for r in prev}, {"fw1": Batch(sightings=list(sightings))}, Config(), NOW, st)

    def archived(self, **kw):
        return row(UA, online=0, last_online=NOW - 10 * DAY, archived_ts=NOW - 3 * DAY, **kw)

    def test_online_again_restores_with_one_back_event(self):
        res = self.run_merge([self.archived(name="Alex's iPad", acked=1)], [S(UA, "10.0.0.5")])
        self.assertIsNone(res.rows[UA]["archived_ts"])
        self.assertEqual([e for e in res.events if e[1] == "back"], [(UA, "back", "back from the archive (archived 3 days ago)")])
        self.assertEqual(res.new, [])
        self.assertFalse([e for e in res.events if e[1] == "new"])
        self.assertEqual((res.rows[UA]["first_seen"], res.rows[UA]["name"], res.rows[UA]["acked"]), (NOW - 5000, "Alex's iPad", 1))

    def test_restored_after_one_day_says_day(self):
        res = self.run_merge([row(UA, online=0, last_online=NOW - 2 * DAY, archived_ts=NOW - DAY - 5)], [S(UA, "10.0.0.5")])
        self.assertEqual([e for e in res.events if e[1] == "back"], [(UA, "back", "back from the archive (archived 1 day ago)")])

    def test_listed_without_presence_stays_archived(self):
        res = self.run_merge([self.archived()], [S(UA, "10.0.0.5", lt="static", presence=False)])
        self.assertEqual(res.rows[UA]["archived_ts"], NOW - 3 * DAY)
        self.assertFalse([e for e in res.events if e[1] == "back"])

    def test_archived_while_still_online_stays_archived(self):
        res = self.run_merge([row(UA, online=1, last_online=NOW - 60, archived_ts=NOW - 30)], [S(UA, "10.0.0.5")])
        self.assertEqual(res.rows[UA]["archived_ts"], NOW - 30)
        self.assertFalse([e for e in res.events if e[1] == "back"])

    def test_prune_archives_only_eligible_devices(self):
        old = NOW - 31 * DAY
        prev = [row("02:00:00:00:30:01", online=0, last_online=old, baseline=1),          # baseline is not spared
                row("02:00:00:00:30:02", online=0, last_online=None, first_seen=old),     # never online: first_seen
                row("02:00:00:00:30:03", online=0, last_online=old, name="Alex's iPad"),  # named
                row("02:00:00:00:30:04", online=0, last_online=old, acked=1),             # marked known
                row("02:00:00:00:30:05", online=0, last_online=NOW - 29 * DAY),           # not long enough
                row("02:00:00:00:30:06", online=0, last_online=old, archived_ts=NOW - DAY),  # archived already
                row("02:00:00:00:30:07", online=0, last_online=old)]                      # listed by a static lease
        res = self.run_merge(prev, [S("02:00:00:00:30:07", "10.0.0.7", lt="static", presence=False)], prune_days=30)
        got = {m: r["archived_ts"] for m, r in res.rows.items()}
        self.assertEqual(got, {"02:00:00:00:30:01": NOW, "02:00:00:00:30:02": NOW, "02:00:00:00:30:07": NOW})
        self.assertEqual(sorted(e for e in res.events if e[1] == "archived"),
                         [(m, "archived", "auto: not online for 31 days") for m in
                          ("02:00:00:00:30:01", "02:00:00:00:30:02", "02:00:00:00:30:07")])

    def test_prune_spares_an_online_device(self):
        res = self.run_merge([row(UA, online=1, last_online=NOW - 31 * DAY)], [S(UA, "10.0.0.5")], prune_days=30)
        self.assertIsNone(res.rows[UA]["archived_ts"])

    def test_prune_spares_a_device_restored_since_it_was_last_online(self):
        # "Restore to list" must hold until the device has been online again and then offline PRUNE_DAYS
        prev = [row(UA, online=0, last_online=NOW - 40 * DAY)]
        res = self.run_merge(prev, [], prune_days=30, restored={UA: NOW - 60})
        self.assertEqual(res.rows, {})
        self.assertFalse([e for e in res.events if e[1] == "archived"])
        # restored before its last time online: that restore is used up
        res = self.run_merge(prev, [], prune_days=30, restored={UA: NOW - 41 * DAY})
        self.assertEqual(res.rows[UA]["archived_ts"], NOW)

    def test_prune_off_by_default_and_never_on_the_first_run(self):
        prev = [row(UA, online=0, last_online=NOW - 400 * DAY)]
        self.assertEqual(self.run_merge(prev, []).rows, {})
        self.assertEqual(self.run_merge(prev, [], prune_days=1, first_run=True).rows, {})


class ConfigTests(unittest.TestCase):
    def cfg(self, value):
        saved = clean_env({**FW1_ENV, "DATA_DIR": "/tmp", "PRUNE_DAYS": value})
        try:
            return Config()
        finally:
            restore(saved)

    def test_prune_days(self):
        self.assertEqual(self.cfg("").prune_days, 0)
        self.assertEqual(self.cfg("90").prune_days, 90)
        self.assertNotIn("PRUNE_DAYS", " ".join(self.cfg("0").validate()))
        self.assertIn("PRUNE_DAYS must not be negative", self.cfg("-1").validate())
        self.assertIn("PRUNE_DAYS must be at most 3650", self.cfg("3651").validate())

    def test_documented(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        for f in (".env.example", "README.md"):
            with open(os.path.join(root, f), encoding="utf-8") as fh:
                self.assertIn("PRUNE_DAYS", fh.read(), f)


class ApiTests(WebTestCase):
    def events(self, mac, kind):
        return [r["detail"] for r in self.db.q("SELECT detail FROM events WHERE mac=? AND kind=?", (mac, kind))]

    def test_archive_and_restore(self):
        self.db.q("UPDATE devices SET mail_queued=1 WHERE mac=?", (MAC2,))
        status, body, _ = self.post(MAC2, {"archived": True})
        self.assertEqual(status, 200, body)
        ts = body["device"]["archived_ts"]
        self.assertIsInstance(ts, int)
        self.assertIsNone(self.db.device(MAC2)["mail_queued"])  # an archived device leaves the mail queue
        self.assertEqual(self.events(MAC2, "archived"), ["by 127.0.0.1"])
        # the same state again: no change, no event
        status, body, _ = self.post(MAC2, {"archived": True})
        self.assertEqual((status, body["device"]["archived_ts"]), (200, ts))
        self.assertEqual(self.events(MAC2, "archived"), ["by 127.0.0.1"])
        status, body, _ = self.post(MAC2, {"archived": False})
        self.assertEqual(status, 200)
        self.assertIsNone(body["device"]["archived_ts"])
        self.assertEqual(self.events(MAC2, "restored"), ["by 127.0.0.1"])
        self.post(MAC2, {"archived": False})
        self.assertEqual(self.events(MAC2, "restored"), ["by 127.0.0.1"])

    def test_archived_must_be_boolean(self):
        for v in ("yes", 1, 0, [], {}):
            with self.subTest(v=v):
                status, body, _ = self.post(MAC2, {"archived": v})
                self.assertEqual((status, body["error"]), (400, "archived must be boolean"))
        self.assertIsNone(self.db.device(MAC2)["archived_ts"])

    def test_post_rules_apply(self):
        status, _, _ = self.post(MAC2, {"archived": True}, ctype="text/plain")
        self.assertEqual(status, 415)
        status, _, _ = self.req("POST", f"/api/devices/{MAC2}", body=b'{"archived": true}',
                                headers={"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        self.assertIsNone(self.db.device(MAC2)["archived_ts"])

    def test_list_keeps_archived_stats_skip_them(self):
        before = self.get_json("/api/stats")[0]["stats"]
        self.post(MAC2, {"archived": True})
        devs, _ = self.get_json("/api/devices")
        by = {d["mac"]: d for d in devs["devices"]}
        self.assertIsInstance(by[MAC2]["archived_ts"], int)
        self.assertIsNone(by[MAC1]["archived_ts"])
        st = self.get_json("/api/stats")[0]["stats"]
        self.assertEqual(st["total"], before["total"] - 1)
        self.assertEqual(st["new"], before["new"] - 1)
        self.assertEqual(st["unacked"], before["unacked"] - 1)
        self.assertEqual(st["online"], before["online"] - 1)
        self.assertNotIn("IOT", [v["vlan"] for v in st["vlans"]])  # MAC2 was the only device there
        self.assertEqual(len(st["new_recent"]), len(before["new_recent"]))  # the arrivals chart keeps it

    def test_csv_has_archived_column(self):
        self.post(MAC2, {"archived": True})
        status, _, body = self.req("GET", "/api/devices.csv")
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        head = rows[0]
        self.assertEqual(head[head.index("private"):head.index("private") + 5], ["private", "archived", "note", "aliases", "watch"])
        ia = head.index("archived")
        by = {r[0]: r for r in rows[1:]}
        self.assertEqual(set(by), {MAC1, MAC2, MAC3})
        self.assertRegex(by[MAC2][ia], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}[+-]\d{4}$")
        self.assertEqual(by[MAC1][ia], "")


class CollectorTests(Base):
    def lease(self, mac, ip, online):
        return Fw1Sighting(mac=mac, ip=ip, hostname="", vendor="", vlan="LAN", iface="lan", source="dhcp",
                           lease_type="static", online=online)

    def test_static_lease_does_not_restore_presence_does(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1, **MAIL}, rows=[arp(DEV, "10.0.0.5")])
        col.run_once()  # baseline
        db.q("UPDATE devices SET archived_ts=?, online=0, last_online=last_online-? WHERE mac=?", (NOW, 2 * DAY, DEV))
        self.client.rows = [self.lease(DEV, "10.0.0.5", False)]
        with mock.patch("leasewatch.collector.notify.new_devices") as mail:
            col.run_once()
            self.assertEqual(db.device(DEV)["archived_ts"], NOW)
            self.client.rows = [arp(DEV, "10.0.0.5")]
            col.run_once()
        self.assertIsNone(db.device(DEV)["archived_ts"])
        kinds = [r["kind"] for r in db.q("SELECT kind FROM events WHERE mac=?", (DEV,))]
        self.assertEqual(kinds.count("back"), 1)
        self.assertNotIn("new", kinds)
        mail.assert_not_called()
        self.assertIsNone(db.device(DEV)["mail_queued"])

    def test_restore_by_hand_is_not_undone_by_prune(self):
        # the collector passes the restore events to the merge
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1, "PRUNE_DAYS": "30"}, rows=[arp(DEV, "10.0.0.5")])
        db.q("INSERT INTO devices(mac, first_seen, last_seen, last_online, baseline) VALUES(?,?,?,?,1)",
             (UA, NOW - 90 * DAY, NOW - 40 * DAY, NOW - 40 * DAY))
        col.run_once()  # baseline
        col.run_once()  # prune archives it
        self.assertIsNotNone(db.device(UA)["archived_ts"])
        db.update_user_fields(UA, None, None, None, archived=False)
        col.run_once()
        self.assertIsNone(db.device(UA)["archived_ts"])
        kinds = [r["kind"] for r in db.q("SELECT kind FROM events WHERE mac=? ORDER BY id", (UA,))]
        self.assertEqual(kinds, ["archived", "restored"])

    def test_prune_not_on_the_first_poll(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1, "PRUNE_DAYS": "1"}, rows=[arp(DEV, "10.0.0.5")])
        # a device stored while the baseline waited: long offline, not listed
        db.q("INSERT INTO devices(mac, first_seen, last_seen, last_online, baseline) VALUES(?,?,?,?,1)",
             (UA, NOW - 9 * DAY, NOW - 9 * DAY, NOW - 9 * DAY))
        col.run_once()
        self.assertIsNone(db.device(UA)["archived_ts"])
        col.run_once()
        self.assertIsNotNone(db.device(UA)["archived_ts"])
        self.assertIsNone(db.device(DEV)["archived_ts"])
        detail = [r["detail"] for r in db.q("SELECT detail FROM events WHERE mac=? AND kind='archived'", (UA,))]
        self.assertEqual(len(detail), 1)
        self.assertRegex(detail[0], r"^auto: not online for \d+ days$")


if __name__ == "__main__":
    unittest.main()
