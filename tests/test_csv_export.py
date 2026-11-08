"""The devices CSV columns baseline, acked_at and split_from: values, position and that import-csv ignores them."""
from __future__ import annotations

import csv
import io
import unittest

from test_web import MAC1, MAC2, MAC3, WebTestCase
from leasewatch.importer import parse_csv

BEFORE = ["mac", "ip", "name", "hostname", "vendor", "vlan", "lease_type", "sources", "online", "link", "switch_port", "via",
          "loc_source", "wifi_ssid", "wifi_ap", "wifi_signal", "first_seen", "last_online", "last_listed", "acked", "private",
          "archived", "note", "aliases", "watch", "tags"]
ORIGIN = "02:00:00:00:50:01"


class CsvExportColumnTests(WebTestCase):
    def export(self) -> tuple[list[str], dict[str, list[str]], bytes]:
        _, _, body = self.req("GET", "/api/devices.csv")
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        return rows[0], {r[0]: r for r in rows[1:]}, body

    def test_header_tail_and_older_columns_keep_their_positions(self) -> None:
        head, _, _ = self.export()
        self.assertEqual(head[-3:], ["baseline", "acked_at", "split_from"])
        self.assertEqual(head[:len(BEFORE)], BEFORE)
        self.assertEqual(len(head), len(BEFORE) + 3)

    def test_baseline_shows_1_and_a_newcomer_0(self) -> None:
        head, by, _ = self.export()
        i = head.index("baseline")
        self.assertEqual((by[MAC1][i], by[MAC2][i]), ("1", "0"))

    def test_acked_device_exports_its_ack_time(self) -> None:
        self.post(MAC2, {"acked": True})
        head, by, _ = self.export()
        i = head.index("acked_at")
        self.assertRegex(by[MAC2][i], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}[+-]\d{4}$")
        self.assertEqual(by[MAC3][i], "")

    def test_split_off_device_exports_its_origin(self) -> None:
        self.db.q("INSERT INTO devices (mac, first_seen, last_seen, split_from) VALUES (?, 100, 200, ?)", (ORIGIN, MAC1))
        head, by, _ = self.export()
        i = head.index("split_from")
        self.assertEqual(by[ORIGIN][i], MAC1)
        self.assertEqual(by[MAC1][i], "")

    def test_import_ignores_the_three_columns(self) -> None:
        self.post(MAC2, {"acked": True})
        _, _, body = self.export()
        plan = parse_csv(body)
        for col in ("baseline", "acked_at", "split_from"):
            self.assertIn(col, plan.ignored_columns)
        for r in plan.rows:
            self.assertFalse({"baseline", "acked_at", "split_from"} & set(r))


if __name__ == "__main__":
    unittest.main()
