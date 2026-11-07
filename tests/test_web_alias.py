"""Alias MAC resolution in the web/db layer (synthetic data only)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_web import MAC2, WebTestCase  # noqa: E402

ALIAS = "02:00:00:00:30:99"  # synthetic private MAC merged into MAC2


class AliasResolutionTest(WebTestCase):
    """design-s4.md section 1 says an alias MAC resolves to its device for GET and POST."""

    def setUp(self):
        super().setUp()
        self.db.q("INSERT INTO aliases(mac,device,reason,detail,merged_ts,last_seen) VALUES(?,?,?,?,?,?)",
                  (ALIAS, MAC2, "hostname", "", 1, 1))

    def test_get_alias_returns_owning_device(self):
        data, _ = self.get_json(f"/api/devices/{ALIAS}")
        self.assertEqual(data["device"]["mac"], MAC2)
        self.assertEqual([a["mac"] for a in data["aliases"]], [ALIAS])

    def test_post_alias_updates_owning_device(self):
        status, parsed, _ = self.post(ALIAS, {"acked": True})
        self.assertEqual(status, 200, parsed)
        self.assertEqual(parsed["device"]["mac"], MAC2)
        self.assertEqual(self.db.device(MAC2)["acked"], 1)
        ev = [e for e in self.db.events(MAC2) if e["kind"] == "acked"]
        self.assertEqual(len(ev), 1)  # the event is keyed by the device MAC, not the alias


if __name__ == "__main__":
    unittest.main()
