"""HostContext.device_ips(): ip -> the device's key MAC, for the stored rows (IPv4 and IPv6), this poll's sightings and
a merged alias. Synthetic data only."""
import unittest

from _case import EnvTmpCase
from _fixtures import FakeClient, S
from leasewatch.collector import Collector
from leasewatch.config import Config
from leasewatch.connectors import HostContext
from leasewatch.db import Database

A = "aa:bb:cc:dd:ee:01"
B = "aa:bb:cc:dd:ee:02"
ALIAS = "06:00:00:00:10:02"


class DeviceIpsTests(EnvTmpCase):
    def setUp(self):
        super().setUp()
        self.db = Database(Config().db_path)

    def tearDown(self):
        self.db._conn.close()

    def test_default_context_is_empty(self):
        self.assertEqual(HostContext().device_ips(), {})

    def test_two_devices_after_a_poll(self):
        c = FakeClient([S(A, "10.0.0.5"), S(B, "10.0.0.6")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.5": A, "10.0.0.6": B})

    def test_ip6_of_a_stored_row(self):
        c = FakeClient([S(A, "10.0.0.5")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        with self.db._conn:
            self.db._conn.execute("UPDATE devices SET ip6=? WHERE mac=?", ("fd00::5", A))
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.5": A, "fd00::5": A})

    def test_alias_ip_goes_to_the_device(self):
        c = FakeClient([S(A, "10.0.0.5")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        with self.db._conn:
            self.db._conn.execute(
                "INSERT INTO aliases(mac,device,reason,detail,merged_ts,last_seen) VALUES(?,?,?,?,?,?)",
                (ALIAS, A, "hostname", "phone", 1, 1))
        col._poll_ips = {"10.0.0.9": ALIAS, "fd00::9": ALIAS}
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.5": A, "10.0.0.9": A, "fd00::9": A})

    def test_stored_row_wins_over_the_poll(self):
        c = FakeClient([S(A, "10.0.0.5")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        col._poll_ips = {"10.0.0.5": B, "10.0.0.7": B}
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.5": A, "10.0.0.7": B})


if __name__ == "__main__":
    unittest.main()
