"""The API marks private (locally administered) MACs and lists the MACs merged into a device. Synthetic data
only: the universally administered MAC is from the documentation range 00:00:5e:00:53:xx (RFC 7042)."""
import csv
import io
import os
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_web import MAC1, S, WebTestCase  # noqa: E402

UA = "00:00:5e:00:53:01"     # universally administered (hardware) MAC
DEV = "02:00:00:00:10:01"    # private, sends a client-id
NEWP = "06:00:00:00:10:02"   # a new private MAC with the same client-id: merged into DEV
CID = "ff00000000000001"


class PrivateApiTests(WebTestCase):
    def setUp(self):
        super().setUp()
        self.client.sightings_data += [S(UA, "10.0.0.20", "printer"), replace(S(DEV, "10.0.0.21", "tablet"), client_id=CID)]
        self.collector.run_once()
        self.client.sightings_data.append(replace(S(NEWP, "10.0.0.22", "tablet"), client_id=CID))
        self.collector.run_once()
        self.assertEqual([r["mac"] for r in self.db.q("SELECT mac FROM aliases")], [NEWP])  # the seed merged

    def test_devices_list_has_private_flag(self):
        body, _ = self.get_json("/api/devices")
        flags = {d["mac"]: d["private"] for d in body["devices"]}
        self.assertIs(flags[UA], False)
        self.assertIs(flags[DEV], True)
        self.assertIs(flags[MAC1], True)  # aa:… is locally administered too
        self.assertNotIn(NEWP, flags)  # merged: no row of its own

    def test_detail_has_private_and_aliases(self):
        body, _ = self.get_json(f"/api/devices/{DEV}")
        self.assertIs(body["device"]["private"], True)
        self.assertEqual(len(body["aliases"]), 1)
        a = body["aliases"][0]
        self.assertEqual({k: a[k] for k in ("mac", "reason", "detail")}, {"mac": NEWP, "reason": "client-id", "detail": CID})
        self.assertIsInstance(a["merged_ts"], int)
        self.assertIsInstance(a["last_seen"], int)
        self.assertNotIn("device", a)  # the key is the URL's own MAC

    def test_detail_of_hardware_mac_without_aliases(self):
        body, _ = self.get_json(f"/api/devices/{UA}")
        self.assertIs(body["device"]["private"], False)
        self.assertEqual(body["aliases"], [])

    def test_post_answer_has_private_flag(self):
        status, body, _ = self.post(UA, {"name": "Printer"})
        self.assertEqual(status, 200)
        self.assertIs(body["device"]["private"], False)

    def test_csv_private_column(self):
        _, _, body = self.req("GET", "/api/devices.csv")
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        head = rows[0]
        ip = head.index("private")
        self.assertEqual(head[ip:ip + 5], ["private", "archived", "note", "aliases", "watch"])  # new columns are appended after
        col = {r[0]: r[ip] for r in rows[1:]}
        self.assertEqual(col[UA], "0")  # 0/1 as acked and online
        self.assertEqual(col[DEV], "1")


if __name__ == "__main__":
    unittest.main()
