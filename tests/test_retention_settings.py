"""EVENT_DAYS and HISTORY_PER_DEVICE: defaults, validation, the collector's trims and the drawer's cap."""
import http.client
import json
import logging
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from _fixtures import S  # noqa: E402
from test_collector import FakeClient  # noqa: E402
from leasewatch.collector import EVENT_DAYS, HISTORY_PER_MAC, Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.db import Database  # noqa: E402
from leasewatch.web import serve  # noqa: E402

MAC = "aa:bb:cc:dd:ee:01"
DAY = 86400


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name, "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0"})

    def tearDown(self):
        restore(self._saved)
        self.tmp.cleanup()

    def build(self, **env):
        os.environ.update(env)
        self.cfg = Config()
        self.db = Database(self.cfg.db_path)
        self.addCleanup(self.db._conn.close)
        self.client = FakeClient([S(MAC, "10.0.0.5", "phone")])
        self.col = Collector(self.cfg, self.db, self.client)
        self.col.run_once()  # baseline


class ConfigTests(Base):
    def problems(self, **env):
        os.environ.update(env)
        return Config().validate()

    def test_defaults_equal_the_old_constants(self):
        cfg = Config()
        self.assertEqual((cfg.event_days, cfg.history_per_device), (365, 200))
        self.assertEqual((cfg.event_days, cfg.history_per_device), (EVENT_DAYS, HISTORY_PER_MAC))
        self.assertEqual([x for x in cfg.validate() if "EVENT_DAYS" in x or "HISTORY_PER" in x], [])

    def test_range_and_type_are_refused(self):
        self.assertIn("EVENT_DAYS must be at least 1", self.problems(EVENT_DAYS="0"))
        self.assertIn("EVENT_DAYS must be at most 3650", self.problems(EVENT_DAYS="3651"))
        self.assertIn("EVENT_DAYS must be a whole number", self.problems(EVENT_DAYS="1.5"))
        self.assertEqual([p for p in self.problems(EVENT_DAYS="1") if "EVENT_DAYS" in p], [])
        self.assertEqual([p for p in self.problems(EVENT_DAYS="3650") if "EVENT_DAYS" in p], [])
        os.environ.pop("EVENT_DAYS")
        for v in ("9", "1001"):
            self.assertIn("HISTORY_PER_DEVICE must be 10-1000", self.problems(HISTORY_PER_DEVICE=v))
        self.assertIn("HISTORY_PER_DEVICE must be a whole number", self.problems(HISTORY_PER_DEVICE="many"))
        for v in ("10", "1000"):
            self.assertEqual([p for p in self.problems(HISTORY_PER_DEVICE=v) if "HISTORY_PER_DEVICE" in p], [])


class CollectorTests(Base):
    def test_event_days_deletes_older_events_only(self):
        self.build(EVENT_DAYS="30")
        now = int(time.time())
        with self.db.tx() as c:
            c.executemany("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)",
                          [(now - 40 * DAY, MAC, "old", ""), (now - 10 * DAY, MAC, "recent", "")])
        self.col.run_once()
        kinds = [e["kind"] for e in self.db.events(MAC)]
        self.assertIn("recent", kinds)
        self.assertNotIn("old", kinds)

    def test_default_event_days_keeps_a_40_day_old_event(self):
        self.build()
        with self.db.tx() as c:
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (int(time.time()) - 40 * DAY, MAC, "old", ""))
        self.col.run_once()
        self.assertIn("old", [e["kind"] for e in self.db.events(MAC)])

    def test_history_per_device_caps_stored_rows(self):
        self.build(HISTORY_PER_DEVICE="10")
        with self.db.tx() as c:
            for i in range(30):
                c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                          (MAC, 1_000_000 + i, f"10.0.1.{i}", "x", "LAN", "dynamic"))
        self.client.sightings_data[0] = S(MAC, "10.0.9.9", "phone")  # an IP change writes a history row
        self.col.run_once()
        rows = self.db.history(MAC, 1000)
        self.assertEqual(len(rows), 10)
        self.assertEqual(rows[0]["ip"], "10.0.9.9")


class WarningTests(Base):
    def collector_logs(self, **env):
        os.environ.update(env)
        cfg = Config()
        db = Database(cfg.db_path)
        self.addCleanup(db._conn.close)
        with self.assertLogs("leasewatch.collector", level="WARNING") as cm:
            Collector(cfg, db, FakeClient([]))
            logging.getLogger("leasewatch.collector").warning("sentinel")
        return [m for m in cm.output if "sentinel" not in m]

    def test_warns_when_events_expire_before_the_prune_hold(self):
        out = self.collector_logs(EVENT_DAYS="30", PRUNE_DAYS="90")
        self.assertEqual(len(out), 1)
        self.assertIn("EVENT_DAYS=30", out[0])

    def test_silent_for_defaults_and_for_prune_off(self):
        self.assertEqual(self.collector_logs(), [])
        self.assertEqual(self.collector_logs(EVENT_DAYS="30"), [])
        self.assertEqual(self.collector_logs(EVENT_DAYS="90", PRUNE_DAYS="90"), [])


class DrawerTests(Base):
    def test_drawer_history_follows_the_setting(self):
        self.build(HISTORY_PER_DEVICE="10")
        with self.db.tx() as c:
            for i in range(10):
                c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                          (MAC, 1_000_000 + i, f"10.0.1.{i}", "x", "LAN", "dynamic"))
        srv = serve(self.cfg, self.db, "t")
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
            conn.request("GET", f"/api/devices/{MAC}")
            body = json.loads(conn.getresponse().read())
            conn.close()
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(timeout=5)
        self.assertEqual(len(body["history"]), 10)
        # the stored rows beyond the cap would not show: the cap is the setting, not 200
        with self.db.tx() as c:
            c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)", (MAC, 2_000_000, "10.9.9.9", "x", "LAN", "dynamic"))
        self.assertEqual(len(self.db.device_detail(MAC)["history"]), 10)


if __name__ == "__main__":
    unittest.main()
