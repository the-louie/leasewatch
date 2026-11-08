"""Merged alias MACs on every device row: the store, the API and the CSV. Synthetic data only."""
import csv
import io
import os
import tempfile
import unittest
from dataclasses import replace

from test_web import S, WebTestCase

from leasewatch.db import Database
from leasewatch.web import _CSV_HEADER

DEV = "02:00:00:00:10:01"
A1, A2 = "06:00:00:00:10:02", "0a:00:00:00:10:03"
PLAIN = "00:00:5e:00:53:01"
OLD_HEADER = ("mac,ip,name,hostname,vendor,vlan,lease_type,sources,online,link,switch_port,via,loc_source,wifi_ssid,wifi_ap,"
              "wifi_signal,first_seen,last_online,last_listed,acked,private,archived,note")


class StoreAliasTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db = Database(os.path.join(self._tmp.name, "t.db"))
        self.addCleanup(self.db._conn.close)

    def _add(self, mac: str, n: int) -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO devices (mac, ip, first_seen, last_seen) VALUES (?, '10.0.0.1', ?, ?)", (mac, n, n))

    def _alias(self, mac: str, dev: str, merged: int) -> None:
        with self.db.tx() as c:
            c.execute("INSERT INTO aliases (mac, device, reason, merged_ts, last_seen) VALUES (?, ?, 'client-id', ?, ?)", (mac, dev, merged, merged))

    def _statements(self) -> int:
        stmts: list[str] = []
        self.db._conn.set_trace_callback(stmts.append)
        try:
            self.db.devices()
        finally:
            self.db._conn.set_trace_callback(None)
        return len(stmts)

    def _fill(self, lo: int, hi: int) -> None:
        for i in range(lo, hi):
            m = f"02:00:00:01:{i // 256:02x}:{i % 256:02x}"
            self._add(m, 10 + i)
            self._alias(f"06:00:00:01:{i // 256:02x}:{i % 256:02x}", m, 10 + i)

    def test_rows_carry_aliases_newest_merge_first(self):
        self._add(DEV, 1)
        self._add(PLAIN, 2)
        self._alias(A1, DEV, 100)
        self._alias(A2, DEV, 200)
        rows = {d["mac"]: d for d in self.db.devices()}
        self.assertEqual(rows[DEV]["aliases"], [A2, A1])
        self.assertEqual(rows[PLAIN]["aliases"], [])

    def test_query_count_is_constant(self):
        self._fill(0, 2)
        few = self._statements()
        self._fill(2, 50)
        self.assertEqual(len(self.db.devices()), 50)
        self.assertEqual(self._statements(), few)
        self.assertLessEqual(few, 2)


class ApiAliasTests(WebTestCase):
    def setUp(self):
        super().setUp()
        self.client.sightings_data += [S(PLAIN, "10.0.0.20", "printer"), replace(S(DEV, "10.0.0.21", "tablet"), client_id="ff00000000000001")]
        self.collector.run_once()
        for m, ip in ((A1, "10.0.0.22"), (A2, "10.0.0.23")):
            self.client.sightings_data.append(replace(S(m, ip, "tablet"), client_id="ff00000000000001"))
            self.collector.run_once()
        self.assertEqual({r["mac"] for r in self.db.q("SELECT mac FROM aliases")}, {A1, A2})

    def test_list_rows_have_aliases(self):
        body, _ = self.get_json("/api/devices")
        rows = {d["mac"]: d for d in body["devices"]}
        self.assertEqual(sorted(rows[DEV]["aliases"]), [A1, A2])
        self.assertEqual(rows[PLAIN]["aliases"], [])

    def test_detail_keeps_its_rich_aliases(self):
        body, _ = self.get_json(f"/api/devices/{DEV}")
        self.assertEqual({a["mac"] for a in body["aliases"]}, {A1, A2})
        self.assertTrue(all(isinstance(a, dict) for a in body["aliases"]))

    def test_csv_aliases_column_is_last(self):
        _, _, body = self.req("GET", "/api/devices.csv")
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        head = rows[0]
        self.assertEqual(head, _CSV_HEADER)
        ia = head.index("aliases")
        self.assertIn("watch", head)
        self.assertLess(ia, head.index("watch"))  # appended in that order, after every older column
        self.assertEqual(",".join(head[:ia]), OLD_HEADER)  # no existing column moved
        by = {r[0]: r for r in rows[1:]}
        self.assertEqual(len(by[DEV][ia].split(" ")), 2)
        self.assertEqual(set(by[DEV][ia].split(" ")), {A1, A2})
        self.assertEqual(by[PLAIN][ia], "")


if __name__ == "__main__":
    unittest.main()
