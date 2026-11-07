"""The three Wi-Fi routes: /api/wifi/ssids, /api/wifi?ssid=, /api/wifi.csv?ssid=. Synthetic data only."""
import csv
import gzip
import io
import json
import os
import sys
import unittest
from urllib.parse import quote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_qa11_web as QW  # noqa: E402
from leasewatch import auth  # noqa: E402

A, B, C, D = "a8:00:00:00:30:01", "a8:00:00:00:30:02", "02:00:00:00:30:03", "a8:00:00:00:30:04"


class _Base(QW.Base):
    def _dev(self, mac: str, **cols: object) -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO devices (mac, first_seen, last_seen) VALUES (?, 1, 1)", (mac,))
            for k, v in cols.items():
                c.execute(f"UPDATE devices SET {k}=? WHERE mac=?", (v, mac))

    def _wp(self, mac: str, ssid: str, first: int = 5, last: int = 100, secs: int = 600, polls: int = 3, ap: str = "ap1") -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO wifi_presence (mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) VALUES (?,?,?,?,?,?,?)",
                      (mac, ssid, first, last, secs, polls, ap))

    def get(self, path: str, accept: str = "") -> tuple[int, dict, bytes]:
        hdr = b"Host: 127.0.0.1\r\n" + (f"Accept-Encoding: {accept}\r\n".encode() if accept else b"")
        h = self.handler(path=path, headers=hdr)
        h.do_GET()
        head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        return int(lines[0].split()[1]), {k.lower(): v for k, _, v in (ln.partition(": ") for ln in lines[1:])}, body

    def seed(self) -> None:
        self._dev(A, online=1, wifi_ssid="home", name="Alice", vendor="Acme", ip="10.0.0.1", wifi_alias="al")
        self._dev(B, online=1, wifi_ssid="guest", ip="10.0.0.2")
        self._dev(C, archived_ts=50)
        self._dev(D, online=0, wifi_ssid="home")
        self._wp(A, "home", first=10, last=300, secs=5400, polls=9, ap="ap-up")
        self._wp(A, "guest", first=20, last=200)
        self._wp(B, "guest", first=5, last=400)
        self._wp(C, "guest", first=15, last=250)
        self._wp(D, "home", first=30, last=350)


class SsidSummaryTests(_Base):
    def test_counts_order_and_since(self) -> None:
        self.seed()
        st, h, body = self.get("/api/wifi/ssids")
        self.assertEqual(st, 200)
        j = json.loads(body)
        self.assertIsNone(j["since"])
        # home: A and D; guest: A, B and archived C (not counted); the latest sighting counts every device
        self.assertEqual(j["ssids"], [
            {"ssid": "guest", "devices": 2, "devices_now": 1, "last_seen": 400},
            {"ssid": "home", "devices": 2, "devices_now": 1, "last_seen": 350}])  # a tie is ordered by name
        self.assertEqual(h["vary"], "Accept-Encoding")
        self.assertNotIn("etag", h)

    def test_since_from_meta(self) -> None:
        self.seed()
        self.db.set_meta("wifi_presence_since", "1234")
        self.assertEqual(json.loads(self.get("/api/wifi/ssids")[2])["since"], 1234)

    def test_empty(self) -> None:
        self.assertEqual(json.loads(self.get("/api/wifi/ssids")[2]), {"since": None, "ssids": []})

    def test_gzip_when_accepted(self) -> None:
        for i in range(60):
            mac = f"a8:00:00:00:31:{i:02x}"
            self._dev(mac)
            self._wp(mac, f"net-{i:03d}-" + "x" * 40)
        st, h, body = self.get("/api/wifi/ssids", accept="gzip")
        self.assertEqual((st, h["content-encoding"]), (200, "gzip"))
        self.assertEqual(len(json.loads(gzip.decompress(body))["ssids"]), 60)
        self.assertNotIn("content-encoding", self.get("/api/wifi/ssids")[1])


class SsidDevicesTests(_Base):
    def test_rows_order_and_fields(self) -> None:
        self.seed()
        st, h, body = self.get("/api/wifi?ssid=guest")
        self.assertEqual(st, 200)
        j = json.loads(body)
        self.assertEqual((j["ssid"], j["since"]), ("guest", None))
        self.assertEqual([d["mac"] for d in j["devices"]], [B, C, A])  # by first_seen on the SSID
        by = {d["mac"]: d for d in j["devices"]}
        self.assertEqual(by[C]["archived_ts"], 50)
        self.assertTrue(by[C]["private"])
        self.assertFalse(by[A]["private"])
        self.assertTrue(by[B]["on_now"])
        self.assertFalse(by[A]["on_now"])  # online, but its current SSID is another one
        self.assertEqual(set(by[A]), {"mac", "name", "wifi_alias", "hostname", "vendor", "ip", "private", "archived_ts", "online", "on_now",
                                      "first_seen", "last_seen", "seconds_seen", "polls_seen", "last_ap"})
        self.assertEqual((by[A]["name"], by[A]["wifi_alias"], by[A]["vendor"], by[A]["ip"]), ("Alice", "al", "Acme", "10.0.0.1"))
        self.assertEqual((by[A]["first_seen"], by[A]["last_seen"], by[A]["seconds_seen"], by[A]["polls_seen"], by[A]["last_ap"]),
                         (20, 200, 600, 3, "ap1"))
        self.assertEqual(h["vary"], "Accept-Encoding")

    def test_on_now_needs_online_and_matching_ssid(self) -> None:
        self.seed()
        by = {d["mac"]: d for d in json.loads(self.get("/api/wifi?ssid=home")[2])["devices"]}
        self.assertTrue(by[A]["on_now"])
        self.assertFalse(by[D]["on_now"])  # wifi_ssid matches but offline

    def test_alias_mac_presence_is_under_the_device(self) -> None:
        self._dev(A)
        with self.db.tx() as c:
            c.execute("INSERT INTO aliases (mac, device, reason, detail, merged_ts, last_seen) VALUES (?,?,?,?,?,?)",
                      ("02:00:00:00:30:99", A, "hostname", "x", 1, 1))
        self._wp(A, "home")
        macs = [d["mac"] for d in json.loads(self.get("/api/wifi?ssid=home")[2])["devices"]]
        self.assertEqual(macs, [A])

    def test_bad_ssid_parameter(self) -> None:
        for q in ("", "?other=1", "?ssid=a&ssid=b", "?ssid=" + "x" * 65):
            for path in ("/api/wifi", "/api/wifi.csv"):
                self.assertEqual(self.get(path + q)[0], 400, (path, q))
        self.assertEqual(self.get("/api/wifi?ssid=" + "x" * 64)[0], 200)

    def test_unknown_and_blank_ssid_are_empty(self) -> None:
        self.seed()
        self.assertEqual(json.loads(self.get("/api/wifi?ssid=nope")[2]), {"ssid": "nope", "since": None, "devices": []})
        self.assertEqual(json.loads(self.get("/api/wifi?ssid=")[2])["devices"], [])
        self.assertEqual(json.loads(self.get("/api/wifi?ssid=Home")[2])["devices"], [])  # exact, case included

    def test_spaces_and_ampersand_round_trip(self) -> None:
        name = " My Net & Co "
        self._dev(A)
        self._wp(A, name)
        self._wp(A, "My Net & Co")
        j = json.loads(self.get("/api/wifi?ssid=" + quote(name, safe=""))[2])
        self.assertEqual((j["ssid"], len(j["devices"])), (name, 1))
        self.assertEqual(len(json.loads(self.get("/api/wifi?ssid=" + quote("My Net & Co", safe=""))[2])["devices"]), 1)


class CsvTests(_Base):
    def rows(self, ssid: str) -> tuple[dict, bytes, list[list[str]]]:
        st, h, body = self.get("/api/wifi.csv?ssid=" + quote(ssid, safe=""))
        self.assertEqual(st, 200)
        return h, body, list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))

    def test_header_bom_and_disposition(self) -> None:
        self.seed()
        h, body, rows = self.rows("guest")
        self.assertTrue(body.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(rows[0], "mac,name,vendor,last_ip,private,archived,first_seen,last_seen,hours_seen,polls_seen,last_ap".split(","))
        self.assertEqual([r[0] for r in rows[1:]], [B, C, A])
        self.assertEqual(h["content-disposition"], 'attachment; filename="leasewatch-wifi.csv"')
        self.assertTrue(h["content-type"].startswith("text/csv"))
        self.assertNotIn("etag", h)
        self.assertNotIn("guest", h["content-disposition"])
        self.assertEqual(rows[2][4], "1")
        self.assertNotEqual(rows[2][5], "")  # archived
        self.assertEqual(rows[1][5], "")

    def test_hours_rounding(self) -> None:
        self._dev(A)
        self._dev(B)
        self._wp(A, "n", secs=5400)  # 1.5 h
        self._wp(B, "n", secs=1000, first=6)  # 0.277 h
        _, _, rows = self.rows("n")
        self.assertEqual([r[8] for r in rows[1:]], ["1.5", "0.3"])
        self.assertEqual(rows[1][9], "3")

    def test_formula_guard(self) -> None:
        self._dev(A, vendor="=cmd|' /c calc'!A0", name="@evil")
        self._wp(A, "n", ap="+ap")
        _, _, rows = self.rows("n")
        self.assertEqual((rows[1][1], rows[1][2], rows[1][10]), ("'@evil", "'=cmd|' /c calc'!A0", "'+ap"))


class LoginTests(_Base):
    env = {"AUTH_USER": "alex", "AUTH_PASSWORD_HASH": auth.make_hash("pw", 100_000)}

    def test_401_without_login(self) -> None:
        for p in ("/api/wifi/ssids", "/api/wifi?ssid=a", "/api/wifi.csv?ssid=a"):
            self.assertEqual(self.get(p)[0], 401, p)


if __name__ == "__main__":
    unittest.main()
