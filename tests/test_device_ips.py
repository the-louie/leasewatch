"""HostContext.device_ips(): ip -> the device's key MAC, for the stored rows (IPv4 and IPv6), this poll's sightings and
a merged alias. Synthetic data only."""
import threading
import unittest
from unittest import mock

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

    def test_ip6_of_a_stored_row_before_the_first_poll(self):
        c = FakeClient([S(A, "10.0.0.5")])
        Collector(Config(), self.db, c).run_once()
        with self.db._conn:
            self.db._conn.execute("UPDATE devices SET ip6=? WHERE mac=?", ("fd00::5", A))
        # a new process: the stored rows until its first poll
        col = Collector(Config(), self.db, c)
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
        col._refresh_ip_map()
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.5": A, "10.0.0.9": A, "fd00::9": A})

    def test_the_poll_wins_over_a_stored_row(self):
        c = FakeClient([S(B, "10.0.0.9")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        c.sightings_data = [S(A, "10.0.0.5"), S(B, "10.0.0.9")]
        col.run_once()
        # B took A's address; A is not listed but its row still has 10.0.0.5
        c.sightings_data = [S(B, "10.0.0.5")]
        col.run_once()
        self.assertEqual(self.db.device(A)["ip"], "10.0.0.5")
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.5": B})

    def test_online_and_newer_rows_win_between_stored_rows(self):
        c = FakeClient([S(A, "10.0.0.5"), S(B, "10.0.0.6")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        c.sightings_data = []
        with self.db._conn:  # two rows with one address: online beats offline, then the newer last_online
            self.db._conn.execute("UPDATE devices SET ip='10.0.0.7', online=0, last_online=200 WHERE mac=?", (A,))
            self.db._conn.execute("UPDATE devices SET ip='10.0.0.7', online=1, last_online=100 WHERE mac=?", (B,))
        col._poll_ips = {}
        col._refresh_ip_map()
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.7": B})
        with self.db._conn:
            self.db._conn.execute("UPDATE devices SET online=0")
        col._refresh_ip_map()
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.7": A})

    def test_archived_device_is_left_out(self):
        c = FakeClient([S(A, "10.0.0.5"), S(B, "10.0.0.6")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        with self.db._conn:
            self.db._conn.execute("UPDATE devices SET archived_ts=1 WHERE mac=?", (A,))
        c.sightings_data = [S(B, "10.0.0.6")]
        col.run_once()
        self.assertEqual(col._ctx.device_ips(), {"10.0.0.6": B})

    def test_calls_run_no_sql_and_share_one_snapshot(self):
        c = FakeClient([S(A, "10.0.0.5")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        with mock.patch.object(self.db, "q", wraps=self.db.q) as q:
            first, second = col._ctx.device_ips(), col._ctx.device_ips()
        self.assertEqual(q.call_count, 0)
        self.assertIs(first, second)
        self.assertEqual(first, {"10.0.0.5": A})
        with self.assertRaises(TypeError):  # read-only: a caller cannot change what the others read
            first["10.0.0.9"] = B

    def test_read_from_another_thread_during_polls(self):
        c = FakeClient([S(A, "10.0.0.5")])
        col = Collector(Config(), self.db, c)
        col.run_once()
        seen, errors, stop = [], [], threading.Event()

        def listen():
            while not stop.is_set():
                try:
                    seen.append(col._ctx.device_ips().get("10.0.0.5"))
                except Exception as e:  # noqa: BLE001 - reported by the assertion below
                    errors.append(e)
                    return
        t = threading.Thread(target=listen)
        t.start()
        try:
            c.sightings_data = [S(B, "10.0.0.5")]
            for _ in range(3):
                col.run_once()
        finally:
            stop.set()
            t.join(5)
        self.assertEqual(errors, [])
        self.assertLessEqual(set(seen), {A, B})
        self.assertEqual(col._ctx.device_ips().get("10.0.0.5"), B)


if __name__ == "__main__":
    unittest.main()
