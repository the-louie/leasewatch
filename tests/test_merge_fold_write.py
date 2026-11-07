"""The write side of a fold: the private row's history, events, seen and Wi-Fi rows move to the device, its `new`
event and its device row go, and an alias row takes its place. End to end through Collector.run_once with a fake
firewall. Synthetic data only."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_instances import FW1  # noqa: E402
import test_s4_merge  # noqa: E402
from test_s4_merge import DEV, MAIL, NEWP  # noqa: E402
from leasewatch.collector import HISTORY_PER_MAC  # noqa: E402

HOST = "alex-laptop"  # "laptop" alone is a generic name and never merges
T0 = 1_800_000_000


class FoldWriteTests(test_s4_merge.CollectorTests):
    # the parent's own tests are not run again here
    test_alias_sightings_land_on_the_device_and_no_mail = None
    test_private_new_device_without_merge_gets_no_mail = None

    def poll_at(self, col, ts, rows):
        with mock.patch("time.time", return_value=float(ts)):
            return self.poll(col, rows)

    def rows(self, db, table, mac):
        return [dict(r) for r in db.q(f"SELECT * FROM {table} WHERE mac=? ORDER BY rowid", (mac,))]

    def setup_candidate(self, extra=None):
        """Poll 1: DEV alone; poll 2: DEV still listed and NEWP with its hostname, so NEWP gets its own row."""
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1, **MAIL}, rows=[self.lease(DEV, host=HOST)])
        self.poll_at(col, T0, [self.lease(DEV, host=HOST)])
        self.poll_at(col, T0 + 120, [self.lease(DEV, host=HOST), self.lease(NEWP, "10.0.0.6", host=HOST)])
        self.assertIsNotNone(db.device(NEWP))  # rule (4): DEV was on the wire
        self.assertEqual(db.q("SELECT COUNT(*) n FROM aliases")[0]["n"], 0)
        with db.tx() as c:  # a second source and Wi-Fi under both keys, one SSID shared
            c.execute("INSERT INTO seen(mac,source,last_seen,last_present) VALUES(?,?,?,?)", (NEWP, "unifi", T0 + 100, T0 + 90))
            c.execute("UPDATE seen SET last_present=NULL WHERE mac=? AND source='fw1'", (DEV,))
            ins = ("INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) "
                   "VALUES(?,?,?,?,?,?,?)")
            c.execute(ins, (DEV, "home", T0 - 600, T0, 600, 40, "ap-old"))
            c.execute(ins, (NEWP, "home", T0 + 60, T0 + 120, 60, 4, "ap-new"))
            c.execute(ins, (NEWP, "guest", T0 + 60, T0 + 90, 30, 2, "ap-g"))
            if extra:
                extra(c)
        return col, db

    def test_fold_moves_the_rows(self):
        col, db = self.setup_candidate()
        p_hist = [r["id"] for r in self.rows(db, "history", NEWP)]
        p_events = self.rows(db, "events", NEWP)
        self.assertIn("new", [e["kind"] for e in p_events])
        kept = {e["id"] for e in p_events if e["kind"] != "new"}
        before = {t: db.q(f"SELECT COUNT(*) n FROM {t}")[0]["n"] for t in ("history", "events", "seen", "wifi_presence")}
        d_hist = len(self.rows(db, "history", DEV))
        # poll 3, 10 min later: DEV off the wire, NEWP listed with its lease hostname
        mail = self.poll_at(col, T0 + 720, [self.lease(NEWP, "10.0.0.6", host=HOST)])
        mail.assert_not_called()
        self.assertIsNone(db.device(NEWP))
        a = db.q("SELECT * FROM aliases")
        self.assertEqual([(r["mac"], r["device"], r["reason"], r["detail"], r["merged_ts"], r["last_seen"]) for r in a],
                         [(NEWP, DEV, "hostname", HOST, T0 + 720, T0 + 720)])
        with db.tx() as c:
            self.assertEqual(db._alias_owner(c, NEWP), DEV)
        self.assertEqual(db.device_detail(NEWP)["device"]["mac"], DEV)
        for t in ("history", "events", "seen", "wifi_presence"):
            self.assertEqual(self.rows(db, t, NEWP), [], t)
        # history: every row moved, plus this poll's row on DEV
        hist = [r["id"] for r in self.rows(db, "history", DEV)]
        self.assertTrue(set(p_hist) <= set(hist))
        self.assertEqual(len(hist), d_hist + len(p_hist) + 1)
        # events: all but `new` moved; the merged event names the fold
        ev = self.rows(db, "events", DEV)
        self.assertTrue(kept <= {e["id"] for e in ev})
        self.assertFalse(db.q("SELECT 1 FROM events WHERE kind='new' AND mac IN (?,?) AND id IN (%s)"
                              % ",".join("?" * len(p_events)), (NEWP, DEV, *[e["id"] for e in p_events if e["kind"] == "new"])))
        merged = [e["detail"] for e in ev if e["kind"] == "merged"]
        self.assertEqual(merged, [f"{NEWP} (hostname {HOST}, own row for 10 min)"])
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events")[0]["n"],
                         before["events"] - 1 + len([e for e in ev if e["ts"] == T0 + 720]))
        # seen: per source the later times; a NULL last_present only when both are NULL
        seen = {s["source"]: (s["last_seen"], s["last_present"]) for s in self.rows(db, "seen", DEV)}
        self.assertEqual(seen["unifi"], (T0 + 100, T0 + 90))
        self.assertEqual(seen["fw1"][0], T0 + 720)
        self.assertEqual(db.q("SELECT COUNT(*) n FROM seen")[0]["n"], 2)
        self.assertEqual(before["seen"], 3)
        # Wi-Fi: the shared SSID adds up, the other moves as it is
        wifi = {w["ssid"]: w for w in self.rows(db, "wifi_presence", DEV)}
        self.assertEqual({k: wifi["home"][k] for k in ("first_seen", "last_seen", "seconds_seen", "polls_seen", "last_ap")},
                         {"first_seen": T0 - 600, "last_seen": T0 + 120, "seconds_seen": 660, "polls_seen": 44,
                          "last_ap": "ap-new"})
        self.assertEqual((wifi["guest"]["seconds_seen"], wifi["guest"]["polls_seen"], wifi["guest"]["last_ap"]), (30, 2, "ap-g"))
        self.assertEqual(db.q("SELECT COUNT(*) n FROM wifi_presence")[0]["n"], before["wifi_presence"] - 1)
        self.assertEqual(db.q("SELECT COUNT(*) n FROM history")[0]["n"], before["history"] + 1)
        self.assertEqual([d["mac"] for d in db.q("SELECT mac FROM devices")], [DEV])

        # a later poll with NEWP listed again: the alias holds, nothing is folded or moved again
        snap = {t: db.q(f"SELECT COUNT(*) n FROM {t} WHERE kind='merged'" if t == "events" else f"SELECT COUNT(*) n FROM {t}")[0]["n"]
                for t in ("devices", "aliases", "events", "seen", "wifi_presence")}
        self.poll_at(col, T0 + 840, [self.lease(NEWP, "10.0.0.6", host=HOST)])
        self.assertEqual(snap, {t: db.q(f"SELECT COUNT(*) n FROM {t} WHERE kind='merged'" if t == "events" else f"SELECT COUNT(*) n FROM {t}")[0]["n"]
                                for t in ("devices", "aliases", "events", "seen", "wifi_presence")})
        self.assertIsNone(db.device(NEWP))
        self.assertEqual(db.q("SELECT last_seen FROM aliases WHERE mac=?", (NEWP,))[0]["last_seen"], T0 + 840)
        self.assertEqual(db.q("SELECT merged_ts FROM aliases WHERE mac=?", (NEWP,))[0]["merged_ts"], T0 + 720)

    def test_history_cap_after_the_move(self):
        def many(c):
            c.executemany("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                          [(NEWP, T0 + 1, "10.0.0.6", HOST, "LAN", "dynamic")] * (HISTORY_PER_MAC + 30))
            c.executemany("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                          [(DEV, T0 + 1, "10.0.0.5", HOST, "LAN", "dynamic")] * 50)
        col, db = self.setup_candidate(many)
        newest = max(r["id"] for r in self.rows(db, "history", NEWP))
        self.poll_at(col, T0 + 720, [self.lease(NEWP, "10.0.0.6", host=HOST)])
        self.assertIsNone(db.device(NEWP))
        hist = [r["id"] for r in self.rows(db, "history", DEV)]
        self.assertEqual(len(hist), HISTORY_PER_MAC)
        self.assertIn(newest, hist)  # the newest rows are kept
        self.assertEqual(self.rows(db, "history", NEWP), [])


if __name__ == "__main__":
    unittest.main()
