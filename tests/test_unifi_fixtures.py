import json
import os
import re
import unittest

FIXDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "unifi_integration")
NAMES = ["sites", "clients_p1", "clients_p2", "clients_odd", "devices", "error_401", "info"]
PAGED = ["sites", "clients_p1", "clients_p2", "clients_odd", "devices"]
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def load(name):
    with open(os.path.join(FIXDIR, name + ".json"), encoding="utf-8") as fh:
        return json.load(fh)


class UnifiFixtureTests(unittest.TestCase):
    def test_all_load(self):
        for n in NAMES:
            self.assertIsInstance(load(n), dict, n)

    def test_page_envelope(self):
        for n in PAGED:
            page = load(n)
            self.assertEqual(set(page), {"offset", "limit", "count", "totalCount", "data"}, n)
            self.assertEqual(page["count"], len(page["data"]), n)

    def test_sites(self):
        for s in load("sites")["data"]:
            self.assertEqual(set(s), {"id", "internalReference", "name"})
            self.assertRegex(s["id"], UUID_RE)
        self.assertEqual(load("sites")["data"][0]["internalReference"], "default")
        self.assertEqual(load("sites")["data"][0]["name"], "Default")

    def test_clients_required_keys(self):
        for n in ("clients_p1", "clients_p2"):
            for c in load(n)["data"]:
                self.assertRegex(c["id"], UUID_RE)
                self.assertIsInstance(c["name"], str)
                self.assertIn(c["type"], ("WIRED", "WIRELESS", "VPN", "TELEPORT"))
                self.assertIn(c["access"]["type"], ("DEFAULT", "GUEST"))
                if c["access"]["type"] == "GUEST":
                    self.assertIsInstance(c["access"]["authorized"], bool)
                if c["type"] in ("WIRED", "WIRELESS"):
                    self.assertIn("macAddress", c)
                    self.assertRegex(c["uplinkDeviceId"], UUID_RE)
                else:
                    self.assertNotIn("macAddress", c)

    def test_vpn_teleport_present_without_mac(self):
        rows = load("clients_p2")["data"]
        kinds = {c["type"] for c in rows if "macAddress" not in c}
        self.assertEqual(kinds, {"VPN", "TELEPORT"})

    def test_devices(self):
        keys = {"id", "macAddress", "ipAddress", "name", "model", "state",
                "features", "interfaces", "firmwareUpdatable", "supported"}
        feats = {}
        for d in load("devices")["data"]:
            self.assertEqual(set(d), keys)
            feats[d["name"]] = d["features"]
        self.assertEqual(feats["ap-hall"], ["accessPoint"])
        self.assertEqual(feats["sw-rack"], ["switching"])
        self.assertIn(["gateway"], feats.values())

    def test_guest_uplink_missing_from_devices(self):
        ids = {d["id"] for d in load("devices")["data"]}
        guest = [c for c in load("clients_p2")["data"] if c["access"]["type"] == "GUEST"][0]
        self.assertNotIn(guest["uplinkDeviceId"], ids)
        self.assertEqual(guest["macAddress"], "02:00:00:00:00:0A")

    def test_total_count_consistent(self):
        p1, p2 = load("clients_p1"), load("clients_p2")
        self.assertEqual(p1["totalCount"], p2["totalCount"])
        self.assertEqual(p1["count"] + p2["count"], p1["totalCount"])
        self.assertEqual(p2["offset"], p1["offset"] + p1["count"])

    def test_odd_rows(self):
        rows = {c["id"][-2:]: c for c in load("clients_odd")["data"]}
        self.assertEqual(rows["31"]["type"], "MATTER")
        self.assertIsInstance(rows["32"]["macAddress"], int)
        self.assertIsInstance(rows["33"]["name"], list)
        self.assertEqual(rows["34"]["macAddress"], "02:00:00:00:00:34")

    def test_error_body(self):
        e = load("error_401")
        self.assertEqual(set(e), {"statusCode", "statusName", "code", "message",
                                  "timestamp", "requestPath", "requestId"})
        self.assertEqual(e["statusCode"], 401)
        self.assertEqual(load("info"), {"applicationVersion": "10.6.109"})

    def test_only_synthetic_macs(self):
        for n in NAMES:
            with open(os.path.join(FIXDIR, n + ".json"), encoding="utf-8") as fh:
                for mac in MAC_RE.findall(fh.read()):
                    self.assertTrue(mac.startswith("02:00:00:00:00:"), (n, mac))


if __name__ == "__main__":
    unittest.main()
