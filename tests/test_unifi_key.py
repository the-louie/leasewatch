"""parse_integration_clients: Integration API client and device lists to the WifiInfo map."""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leasewatch.unifi import parse_integration_clients  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "unifi_integration")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)["data"]


class ParseIntegrationClients(unittest.TestCase):
    def setUp(self):
        self.devices = load("devices.json")

    def test_two_pages(self):
        out = parse_integration_clients(load("clients_p1.json") + load("clients_p2.json"), self.devices)
        self.assertEqual(set(out), {"02:00:00:00:00:21", "02:00:00:00:00:22", "02:00:00:00:00:23", "02:00:00:00:00:0a"})
        a = out["02:00:00:00:00:21"]
        self.assertEqual((a.alias, a.ap, a.wired, a.ssid, a.signal, a.radio, a.channel),
                         ("alex-laptop", "ap-hall", False, "", None, "", None))
        self.assertEqual(out["02:00:00:00:00:22"].alias, "")
        p = out["02:00:00:00:00:23"]
        self.assertTrue(p.wired)
        self.assertEqual(p.ap, "")
        g = out["02:00:00:00:00:0a"]
        self.assertEqual((g.ap, g.alias), ("", "guest-tablet"))

    def test_odd_page(self):
        out = parse_integration_clients(load("clients_odd.json"), self.devices)
        self.assertEqual(list(out), ["02:00:00:00:00:34"])
        self.assertEqual(out["02:00:00:00:00:34"].ap, "ap-hall")

    def test_bad_input_does_not_raise(self):
        self.assertEqual(parse_integration_clients(["x", None, 3], None), {})
        self.assertEqual(parse_integration_clients(None, None), {})
        out = parse_integration_clients([{"type": "WIRELESS", "name": "a", "macAddress": "02:00:00:00:00:01",
                                          "uplinkDeviceId": ["x"]}], ["junk", {"id": 5}, {"id": "d"}])
        self.assertEqual(out["02:00:00:00:00:01"].ap, "")

    def test_duplicate_mac_later_row_wins(self):
        row = {"type": "WIRELESS", "macAddress": "02:00:00:00:00:77", "uplinkDeviceId": "00000000-0000-4000-8000-000000000011"}
        out = parse_integration_clients([dict(row, name="first"), dict(row, name="second", macAddress="02:00:00:00:00:77".upper())],
                                        self.devices)
        self.assertEqual(len(out), 1)
        self.assertEqual(out["02:00:00:00:00:77"].alias, "second")


if __name__ == "__main__":
    unittest.main()
