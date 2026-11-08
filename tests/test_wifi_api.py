"""wifi_presence in the device list and the SSID list in /api/stats. Synthetic data only."""
import json
import re
import unittest

import test_web_edge_cases as QW

A, B, C = "02:00:00:00:20:01", "02:00:00:00:20:02", "02:00:00:00:20:03"


class WifiApiTests(QW.Base):
    def _dev(self, mac: str, **cols: object) -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO devices (mac, first_seen, last_seen) VALUES (?, 1, 1)", (mac,))
            for k, v in cols.items():
                c.execute(f"UPDATE devices SET {k}=? WHERE mac=?", (v, mac))

    def _wp(self, mac: str, ssid: str, last: int) -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO wifi_presence (mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) VALUES (?, ?, 5, ?, 600, 3, 'ap1')",
                      (mac, ssid, last))

    def get(self, path: str, inm: str | None = None) -> tuple[int, dict, bytes]:
        hdr = b"Host: 127.0.0.1\r\n" + (b"If-None-Match: " + inm.encode() + b"\r\n" if inm else b"")
        h = self.handler(path=path, headers=hdr)
        h.do_GET()
        head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        return int(lines[0].split()[1]), {k.lower(): v for k, _, v in (ln.partition(": ") for ln in lines[1:])}, body

    def _seed(self) -> None:
        self._dev(A, online=1, wifi_ssid="home")
        self._dev(B)
        self._dev(C)
        self._wp(A, "home", 100)
        self._wp(A, "guest", 200)
        self._wp(B, "guest", 50)

    def test_list_rows_carry_wifi_presence(self) -> None:
        self._seed()
        _, _, body = self.get("/api/devices")
        rows = {d["mac"]: d for d in json.loads(body)["devices"]}
        self.assertEqual(rows[A]["wifi_presence"], [
            {"ssid": "guest", "first_seen": 5, "last_seen": 200, "seconds_seen": 600},
            {"ssid": "home", "first_seen": 5, "last_seen": 100, "seconds_seen": 600}])
        self.assertEqual([w["ssid"] for w in rows[B]["wifi_presence"]], ["guest"])
        self.assertEqual(rows[C]["wifi_presence"], [])

    def test_statement_count_is_constant(self) -> None:
        def count() -> int:
            stmts: list[str] = []
            self.db._conn.set_trace_callback(stmts.append)
            try:
                self.get("/api/devices")
            finally:
                self.db._conn.set_trace_callback(None)
            return len(stmts)
        self._dev(A)
        self._wp(A, "home", 1)
        few = count()
        for i in range(50):
            m = f"02:00:01:00:00:{i:02x}"
            self._dev(m)
            self._wp(m, f"net{i % 3}", i)
        self.assertEqual(len(json.loads(self.get("/api/devices")[2])["devices"]), 51)
        self.assertEqual(count(), few)

    def test_stats_ssids_leave_out_archived_devices(self) -> None:
        self._dev(A, online=1, wifi_ssid="home")
        self._dev(B, online=1, wifi_ssid="home", archived_ts=50)
        self._wp(A, "home", 10)
        self._wp(B, "home", 10)
        self._wp(B, "only-archived", 10)
        ssids = json.loads(self.get("/api/stats")[2])["stats"]["ssids"]
        self.assertEqual(ssids, [{"ssid": "home", "devices_ever": 1, "devices_now": 1},
                                 {"ssid": "only-archived", "devices_ever": 0, "devices_now": 0}])

    def test_devices_and_presence_are_read_in_one_lock_hold(self) -> None:
        self._seed()
        owned: list[bool] = []
        orig = self.db._wifi_presence_all

        def spy(c):  # the last read: the lock must still be held
            owned.append(self.db._lock._is_owned())
            return orig(c)
        self.db._wifi_presence_all = spy
        try:
            st, _, body = self.get("/api/devices")
        finally:
            del self.db._wifi_presence_all
        self.assertEqual(st, 200)
        self.assertEqual(owned, [True])
        self.assertEqual(len(json.loads(body)["devices"]), 3)

    def test_stats_ssids(self) -> None:
        self._seed()
        self._dev("02:00:00:00:20:04", online=0, wifi_ssid="guest")  # not online: not counted as now
        _, _, body = self.get("/api/stats")
        self.assertEqual(json.loads(body)["stats"]["ssids"], [
            {"ssid": "guest", "devices_ever": 2, "devices_now": 0},
            {"ssid": "home", "devices_ever": 1, "devices_now": 1}])

    def test_detail_unchanged(self) -> None:
        self._seed()
        _, _, body = self.get(f"/api/devices/{A}")
        out = json.loads(body)
        self.assertNotIn("wifi_presence", out["device"])
        self.assertEqual(out["wifi_presence"][0], {"ssid": "guest", "first_seen": 5, "last_seen": 200, "seconds_seen": 600, "polls_seen": 3, "last_ap": "ap1"})

    def test_etag_moves_with_a_presence_row(self) -> None:
        self._dev(A)
        _, h, _ = self.get("/api/devices")
        tag = h["etag"]
        self.assertTrue(re.match(r'^W/"', tag))
        self.assertEqual(self.get("/api/devices", inm=tag)[0], 304)
        self._wp(A, "home", 9)
        st, h2, body = self.get("/api/devices", inm=tag)
        self.assertEqual(st, 200)
        self.assertNotEqual(h2["etag"], tag)
        self.assertEqual(json.loads(body)["devices"][0]["wifi_presence"][0]["ssid"], "home")


if __name__ == "__main__":
    unittest.main()
