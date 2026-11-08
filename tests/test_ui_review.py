"""The "Baseline, not checked" count: db.stats() and /api/stats."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.request

from _env import FW1_ENV, clean_env, restore
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.web import serve


def seed(db: Database) -> None:
    """5 devices: baseline acked, baseline unacked, baseline archived, plain unacked, plain acked."""
    for n in range(1, 6):
        db.q("INSERT INTO devices (mac, ip, first_seen, last_seen, baseline, acked, archived_ts) VALUES (?,?,?,?,?,?,?)",
             (f"02:00:00:00:00:{n:02x}", f"10.0.0.{n}", 1000, 1000,
              1 if n <= 3 else 0, 1 if n in (1, 5) else 0, 1000 if n == 3 else None))


class BaselineStatsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = Database(os.path.join(self.tmp, "t.db"))
        self.addCleanup(self.db._conn.close)
        seed(self.db)

    def test_counts_baseline_unacked_unarchived_only(self) -> None:
        st = self.db.stats(7)
        self.assertEqual(st["baseline_unchecked"], 1)
        self.assertEqual(st["total"], 4)  # the archived one is not in the cards
        self.assertEqual(st["unacked"], 1)  # the plain unacked one: the baseline ones are not "not yet known"

    def test_zero_when_all_checked(self) -> None:
        self.db.q("UPDATE devices SET acked=1")
        self.assertEqual(self.db.stats(7)["baseline_unchecked"], 0)

    def test_all_vlans_keeps_a_network_whose_only_device_is_archived(self) -> None:
        for n, v in ((1, "Zed"), (2, "Zed"), (3, "Aaa"), (4, "Mid"), (5, "")):  # device 3 is archived, 5 has no network
            self.db.q("UPDATE devices SET vlan=? WHERE mac=?", (v, f"02:00:00:00:00:{n:02x}"))
        st = self.db.stats(7)
        self.assertEqual(st["all_vlans"], ["Aaa", "Mid", "Zed"])
        self.assertEqual(sorted(x["vlan"] for x in st["vlans"]), ["", "Mid", "Zed"])  # the chips leave Aaa out

    def test_empty_db(self) -> None:
        empty = Database(os.path.join(self.tmp, "e.db"))
        self.addCleanup(empty._conn.close)
        self.assertEqual(empty.stats(7)["baseline_unchecked"], 0)


class BaselineApiTest(unittest.TestCase):
    def test_api_stats_exposes_it(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        saved = clean_env(dict(FW1_ENV, DATA_DIR=tmp, LISTEN_HOST="127.0.0.1", LISTEN_PORT="0", MAILGUN_KEY="",
                               MAILGUN_DOMAIN="", MAIL_TO="", POLL_SECONDS="120"))
        self.addCleanup(restore, saved)
        db = Database(Config().db_path)
        self.addCleanup(db._conn.close)
        seed(db)
        srv = serve(Config(), db, "9.9.9-test")
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        self.addCleanup(t.join, 5)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/api/stats", timeout=10) as r:
            self.assertEqual(json.load(r)["stats"]["baseline_unchecked"], 1)


if __name__ == "__main__":
    unittest.main()
