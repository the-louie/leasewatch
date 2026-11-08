"""The collector's Wi-Fi presence rows: the upsert, the retention and the WIFI_PRESENCE_DAYS setting. Synthetic data only."""
import os, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore, sources, swap_client
from _fixtures import FakeClient
from leasewatch.collector import Collector
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.fw1 import Sighting
from leasewatch.unifi import WifiInfo

MAC = "aa:bb:cc:dd:ee:01"
T0 = 1_800_000_000


def arp(mac, ip="10.0.0.5"):
    return Sighting(mac=mac, ip=ip, hostname="", vendor="Acme", vlan="Clients", iface="opt3", source="arp", lease_type="", online=True)


class WifiCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})

    def tearDown(self):
        self.db._conn.close(); self.tmp.cleanup(); restore(self._env)

    def build(self, days=None, macs=(MAC,)):
        if days is not None:
            os.environ["WIFI_PRESENCE_DAYS"] = str(days)
        os.environ.update(sources("unifi"))
        self.cfg = Config(); self.db = Database(self.cfg.db_path)
        self.client = FakeClient([arp(m) for m in macs])
        self.col = Collector(self.cfg, self.db, self.client)
        self.wifi = {m: WifiInfo(ssid="HomeNet", ap="ap-hall", signal=-50, radio="5 GHz") for m in macs}
        swap_client(self.col, "unifi", type("U", (), {"clients": lambda s: self.wifi})())

    def poll(self, at):
        with mock.patch("leasewatch.collector.time.time", lambda: at):
            self.col.run_once()

    def rows(self):
        return [tuple(r) for r in self.db.q(
            "SELECT mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap FROM wifi_presence ORDER BY mac, ssid")]

    def test_first_sighting(self):
        self.build(); self.poll(T0)
        self.assertEqual(self.rows(), [(MAC, "HomeNet", T0, T0, self.cfg.poll_seconds, 1, "ap-hall")])

    def test_second_poll_adds_the_real_gap(self):
        self.build(); self.poll(T0); self.poll(T0 + 120)
        self.assertEqual(self.rows(), [(MAC, "HomeNet", T0, T0 + 120, self.cfg.poll_seconds + 120, 2, "ap-hall")])

    def test_gap_over_the_cap_counts_one_poll(self):
        self.build(); p = self.cfg.poll_seconds
        self.poll(T0); self.poll(T0 + 2 * p + 60 + 60 + 1)  # one over the cap: 2 * poll + TIMEOUT (60) + 60
        self.assertEqual(self.rows()[0][4:6], (2 * p, 2))

    def test_missed_poll_after_a_timeout_is_bridged(self):
        # a poll that timed out ran TIMEOUT s, then the loop slept POLL_SECONDS: the next sighting is
        # 2 * poll + timeout + 2 s after the last
        self.build(); p = self.cfg.poll_seconds
        gap = 2 * p + 60 + 2
        self.poll(T0); self.poll(T0 + gap)
        self.assertEqual(self.rows()[0][4:6], (p + gap, 2))

    def test_cap_follows_the_longest_enabled_timeout(self):
        os.environ["LW_CONNECTOR__UNIFI__TIMEOUT"] = "10"
        os.environ["LW_CONNECTOR__FW1__TIMEOUT"] = "10"
        self.build(); p = self.cfg.poll_seconds
        cap = 2 * p + 10 + 60
        self.poll(T0); self.poll(T0 + cap)
        self.assertEqual(self.rows()[0][4:6], (p + cap, 2))
        self.poll(T0 + cap + cap + 1)
        self.assertEqual(self.rows()[0][4:6], (p + cap + p, 3))

    def test_clock_step_back_counts_one_poll(self):
        self.build(); p = self.cfg.poll_seconds
        self.poll(T0); self.poll(T0 - 500)
        self.assertEqual(self.rows()[0][3:6], (T0, 2 * p, 2))

    def test_clock_step_back_keeps_first_before_last(self):
        self.build(); self.poll(T0); self.poll(T0 - 3600)
        row = self.rows()[0]
        self.assertEqual((row[2], row[3]), (T0 - 3600, T0))

    def test_roaming_updates_last_ap(self):
        self.build(); self.poll(T0)
        self.wifi[MAC] = WifiInfo(ssid="HomeNet", ap="ap-attic")
        self.poll(T0 + 120)
        self.assertEqual(self.rows()[0][6], "ap-attic")

    def test_alias_observation_lands_under_the_device_key(self):
        alias = "02:00:00:00:00:09"
        self.build(); self.poll(T0)
        self.db.q("DELETE FROM wifi_presence")
        self.db.q("INSERT INTO aliases(mac,device,reason,detail,merged_ts,last_seen) VALUES(?,?,?,?,?,?)", (alias, MAC, "client-id", "", T0, T0))
        self.wifi = {alias: WifiInfo(ssid="HomeNet", ap="ap-hall")}
        self.client.sightings_data = [arp(alias)]
        self.poll(T0 + 120)
        self.assertEqual([r[0] for r in self.rows()], [MAC])

    def test_ssid_change_creates_a_second_row(self):
        self.build(); self.poll(T0)
        self.wifi[MAC] = WifiInfo(ssid="Guest", ap="ap-hall")
        self.poll(T0 + 120)
        self.assertEqual([(r[1], r[5]) for r in self.rows()], [("Guest", 1), ("HomeNet", 1)])

    def test_empty_ssid_writes_no_row(self):
        self.build(); self.wifi[MAC] = WifiInfo(ssid="", ap="ap-hall"); self.poll(T0)
        self.assertEqual(self.rows(), [])

    def test_since_is_written_once(self):
        self.build(); self.poll(T0); self.poll(T0 + 120)
        self.assertEqual(self.db.get_meta("wifi_presence_since"), str(T0))

    def test_retention_deletes_old_rows_only(self):
        self.build(days=30); self.poll(T0)
        ins = "INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) VALUES(?,?,?,?,1,1,'')"
        self.db.q(ins, ("old", "X", T0 - 40 * 86400, T0 - 31 * 86400))
        self.db.q(ins, ("new", "X", T0 - 40 * 86400, T0 - 29 * 86400))
        self.poll(T0 + 120)
        self.assertEqual(sorted(r[0] for r in self.rows()), [MAC, "new"])

    def test_forward_clock_step_deletes_nothing(self):
        self.build(days=30); self.poll(T0)
        self.poll(T0 + 100 * 86400)
        self.assertEqual(len(self.rows()), 1)  # the clamped prune reference moved at most a day
        self.assertEqual(self.rows()[0][5], 2)

    def test_zero_is_off(self):
        self.build(days=0); self.poll(T0)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.db.get_meta("wifi_presence_since"), "")
        self.db.q("INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) VALUES('x','S',?,?,1,1,'')", (T0, T0))
        self.poll(T0 + 120)
        self.assertEqual(self.rows(), [])

    def test_off_forgets_since_so_on_restarts_it(self):
        self.build(); self.poll(T0)
        self.assertEqual(self.db.get_meta("wifi_presence_since"), str(T0))
        self.col.cfg.wifi_presence_days = 0
        self.poll(T0 + 120)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.db.get_meta("wifi_presence_since"), "")
        self.col.cfg.wifi_presence_days = 365
        self.poll(T0 + 240)
        self.assertEqual(self.db.get_meta("wifi_presence_since"), str(T0 + 240))


class WifiConfigTests(unittest.TestCase):
    def setUp(self): self._env = clean_env({**FW1_ENV})
    def tearDown(self): restore(self._env)

    def problems(self, value):
        os.environ["WIFI_PRESENCE_DAYS"] = value
        return [p for p in Config().validate() if "WIFI_PRESENCE_DAYS" in p]

    def test_default_and_bounds(self):
        self.assertEqual(Config().wifi_presence_days, 365)
        for v in ("0", "365", "3650"):
            self.assertEqual(self.problems(v), [], v)
        for v in ("-1", "3651", "abc"):
            self.assertEqual(len(self.problems(v)), 1, v)

    def test_env_example_has_the_entry(self):
        path = os.path.join(os.path.dirname(__file__), "..", ".env.example")
        with open(path, encoding="utf-8") as f:
            self.assertIn("WIFI_PRESENCE_DAYS=365", f.read().splitlines())

    def test_startup_line_has_no_wifi_setting(self):
        from leasewatch.__main__ import startup_line
        self.assertNotIn("WIFI", startup_line(Config(), "1").upper())


if __name__ == "__main__":
    unittest.main()
