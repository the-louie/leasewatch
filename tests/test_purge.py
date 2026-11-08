"""PURGE_DAYS: validation, the hard delete of long-archived unnamed devices, and its guards."""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from _fixtures import S, FakeClient, row  # noqa: E402
from leasewatch.collector import Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.db import Database  # noqa: E402

DAY = 86400
T0 = 1_800_000_000
ANCHOR = "aa:bb:cc:00:00:01"  # the device every poll lists, so no poll is empty
GONE = "aa:bb:cc:00:00:10"    # archived 200 days ago, unnamed: purged with PURGE_DAYS=180
TABLES = ("devices", "history", "events", "seen", "wifi_presence", "aliases")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})
        os.environ.pop("PURGE_DAYS", None)

    def tearDown(self):
        restore(self._saved)
        self.tmp.cleanup()

    def build(self, **env):
        os.environ.update(env)
        self.cfg = Config()
        self.db = Database(self.cfg.db_path)
        self.addCleanup(self.db._conn.close)
        self.client = FakeClient([S(ANCHOR, "10.0.0.2", "anchor")])
        self.col = Collector(self.cfg, self.db, self.client)

    def poll(self, at, col=None):
        with mock.patch("leasewatch.collector.time.time", lambda: at):
            return (col or self.col).run_once()

    def seed(self, mac, archived_days=200, **kw):
        """A stored device archived `archived_days` before T0 (None: not archived), with one row in every table."""
        r = row(mac, **{"first_seen": T0 - 400 * DAY, "last_seen": T0 - 300 * DAY, "last_online": T0 - 300 * DAY, "online": 0,
                        "archived_ts": None if archived_days is None else T0 - archived_days * DAY, **kw})
        alias = "02" + mac[2:]
        with self.db.tx() as c:
            c.execute(f"INSERT INTO devices({','.join(r)}) VALUES({','.join('?' * len(r))})", tuple(r.values()))
            c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                      (mac, T0 - 300 * DAY, "10.0.0.9", "", "Clients", ""))
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (T0 - 10 * DAY, mac, "archived", "auto"))
            c.execute("INSERT INTO seen(mac,source,last_seen,last_present) VALUES(?,?,?,?)", (mac, "fw1", T0 - 300 * DAY, None))
            c.execute("INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) "
                      "VALUES(?,?,?,?,?,?,?)", (mac, "HomeNet", T0 - 20 * DAY, T0 - 10 * DAY, 120, 1, "ap"))
            c.execute("INSERT INTO aliases(mac,device,reason,detail,merged_ts,last_seen) VALUES(?,?,?,?,?,?)",
                      (alias, mac, "hostname", "", T0 - 300 * DAY, T0 - 300 * DAY))

    def counts(self, mac):
        return {t: self.db.q(f"SELECT COUNT(*) FROM {t} WHERE {'device' if t == 'aliases' else 'mac'}=?", (mac,))[0][0]
                for t in TABLES}


class ConfigTests(Base):
    def problems(self, **env):
        os.environ.update(env)
        return [p for p in Config().validate() if "PURGE_DAYS" in p]

    def test_default_is_off(self):
        self.assertEqual(Config().purge_days, 0)
        self.assertEqual(self.problems(), [])

    def test_range_and_type_are_refused(self):
        self.assertEqual(self.problems(PURGE_DAYS="-1"), ["PURGE_DAYS must not be negative"])
        self.assertEqual(self.problems(PURGE_DAYS="3651"), ["PURGE_DAYS must be at most 3650"])
        self.assertEqual(self.problems(PURGE_DAYS="1.5"), ["PURGE_DAYS must be a whole number"])
        self.assertEqual(self.problems(PURGE_DAYS="soon"), ["PURGE_DAYS must be a whole number"])
        for v in ("0", "180", "3650"):
            self.assertEqual(self.problems(PURGE_DAYS=v), [])


class PurgeTests(Base):
    ONE = {"devices": 1, "history": 1, "events": 1, "seen": 1, "wifi_presence": 1, "aliases": 1}
    NONE = dict.fromkeys(TABLES, 0)

    def test_default_purges_nothing(self):
        self.build()
        self.poll(T0)
        self.seed(GONE)
        self.poll(T0 + 120)
        self.assertEqual(self.counts(GONE), self.ONE)

    def test_only_the_unnamed_unknown_offline_long_archived_device_is_purged(self):
        self.build(PURGE_DAYS="180")
        self.poll(T0)
        self.seed(GONE)
        keep = {"aa:bb:cc:00:00:21": {"name": "Printer"}, "aa:bb:cc:00:00:22": {"note": "the neighbour's"},
                "aa:bb:cc:00:00:23": {"acked": 1}, "aa:bb:cc:00:00:24": {"online": 1, "last_online": T0},
                "aa:bb:cc:00:00:25": {"archived_days": 100}, "aa:bb:cc:00:00:26": {"archived_days": None}}
        for mac, kw in keep.items():
            self.seed(mac, **kw)
        # another device's merged event names the purged MAC only in its detail
        with self.db.tx() as c:
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (T0, ANCHOR, "merged", f"{GONE} (hostname)"))
        self.poll(T0 + 120)
        self.assertEqual(self.counts(GONE), self.NONE)
        for mac in keep:
            self.assertEqual(self.counts(mac)["devices"], 1, mac)
            self.assertEqual(self.counts(mac)["history"], 1, mac)
        self.assertEqual(len(self.db.q("SELECT 1 FROM events WHERE mac=? AND kind='merged' AND detail LIKE ?",
                                       (ANCHOR, GONE + "%"))), 1)

    def test_a_device_back_from_the_archive_this_poll_is_not_purged(self):
        self.build(PURGE_DAYS="180")
        self.poll(T0)
        self.seed(GONE)
        self.client.sightings_data.append(S(GONE, "10.0.0.9", src="arp"))
        self.poll(T0 + 120)
        d = self.db.device(GONE)
        self.assertIsNotNone(d)
        self.assertIsNone(d["archived_ts"])
        self.assertIn("back", [e["kind"] for e in self.db.events(GONE)])

    def test_a_device_still_listed_offline_is_not_purged(self):
        self.build(PURGE_DAYS="180")
        self.poll(T0)
        listed = "aa:bb:cc:00:00:31"
        self.seed(GONE)
        self.seed(listed)
        # a static reservation: listed every poll, so last_seen moves, while it stays offline
        self.client.sightings_data.append(S(listed, "10.0.0.31", lt="static", online=False))
        self.poll(T0 + 120)
        d = self.db.device(listed)
        self.assertIsNotNone(d)
        self.assertEqual((d["online"], d["last_seen"]), (0, T0 + 120))
        self.assertIsNotNone(d["archived_ts"])
        self.assertEqual(self.counts(GONE), self.NONE)

    def test_never_at_the_first_poll(self):
        self.build(PURGE_DAYS="180")
        self.seed(GONE)
        self.assertTrue(self.poll(T0)["first_run"])
        self.assertEqual(self.counts(GONE)["devices"], 1)
        self.poll(T0 + 120)  # the rule matches: the second poll purges it
        self.assertEqual(self.counts(GONE), self.NONE)

    def test_a_forward_clock_jump_does_not_purge(self):
        self.build(PURGE_DAYS="180")
        self.poll(T0)
        self.seed(GONE, archived_days=100)  # 180 days only after the jump
        self.poll(T0 + 400 * DAY)  # the prune reference moves at most twice real time
        self.assertEqual(self.counts(GONE)["devices"], 1)
        fresh = Collector(self.cfg, self.db, self.client)  # a restart: at most a day past the stored reference
        self.poll(T0 + 400 * DAY + 120, fresh)
        self.assertEqual(self.counts(GONE)["devices"], 1)

    def test_info_lines_and_the_vacuum_hint(self):
        self.build(PURGE_DAYS="180")
        self.poll(T0)
        base = row("x", first_seen=T0 - 400 * DAY, last_seen=T0 - 300 * DAY, last_online=T0 - 300 * DAY, online=0,
                   archived_ts=T0 - 200 * DAY)
        # the hint counts rows, not devices: 20 devices with 60 history rows each are 1220 rows
        macs = [f"02:00:00:00:00:{i:02x}" for i in range(20)]
        with self.db.tx() as c:
            c.executemany(f"INSERT INTO devices({','.join(base)}) VALUES({','.join('?' * len(base))})",
                          [tuple({**base, "mac": mac}.values()) for mac in macs])
            c.executemany("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                          [(mac, T0 - 300 * DAY + k, "10.0.0.9", "", "Clients", "") for mac in macs for k in range(60)])
        with self.assertLogs("leasewatch", "INFO") as logs:
            self.poll(T0 + 120)
        lines = [r.getMessage() for r in logs.records]
        self.assertIn("purged 20 archived devices (1220 rows, PURGE_DAYS=180)", lines)
        self.assertIn('run "python -m leasewatch vacuum" to give the space back to the file system', lines)
        self.assertEqual(self.db.q("SELECT COUNT(*) FROM devices")[0][0], 1)  # the anchor

    def test_no_vacuum_hint_for_a_small_purge(self):
        self.build(PURGE_DAYS="180")
        self.poll(T0)
        self.seed(GONE)
        with self.assertLogs("leasewatch", "INFO") as logs:
            self.poll(T0 + 120)
        lines = [r.getMessage() for r in logs.records]
        self.assertIn("purged 1 archived devices (6 rows, PURGE_DAYS=180)", lines)
        self.assertFalse([x for x in lines if "vacuum" in x])


if __name__ == "__main__":
    unittest.main()
