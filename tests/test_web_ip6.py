"""The stable IPv6 address over HTTP: the ip6 event kind in the events filter, the field in the device JSON, the history rows."""
import unittest

from test_web import MAC2, WebTestCase

V6_OLD = "2001:db8:1::2"
V6_NEW = "2001:db8:2::2"


class Ip6WebTests(WebTestCase):
    def add_event(self) -> None:
        self.db.q("INSERT INTO events (ts, mac, kind, detail) VALUES (?, ?, 'ip6', ?)", (1000, MAC2, f"{V6_OLD} -> {V6_NEW}"))

    def test_events_filter_accepts_ip6(self):
        self.add_event()
        data, _ = self.get_json("/api/events?kind=ip6")
        self.assertEqual([(e["kind"], e["mac"], e["detail"]) for e in data["events"]], [("ip6", MAC2, f"{V6_OLD} -> {V6_NEW}")])

    def test_events_filter_with_no_ip6_event_is_empty(self):
        data, _ = self.get_json("/api/events?kind=ip6")
        self.assertEqual(data["events"], [])

    def test_events_filter_still_refuses_a_bad_kind(self):
        self.get_json("/api/events?kind=ip6!", expect=400)
        self.get_json("/api/events?kind=" + "a1" * 10 + "b", expect=400)  # 21 characters
        self.get_json("/api/events?kind=" + "a1" * 10)  # 20 characters

    def test_device_json_carries_the_stable_address(self):
        self.db.q("UPDATE devices SET ip6_stable=? WHERE mac=?", (V6_NEW, MAC2))
        listed, _ = self.get_json("/api/devices")
        self.assertEqual({d["mac"]: d["ip6_stable"] for d in listed["devices"]}[MAC2], V6_NEW)
        one, _ = self.get_json(f"/api/devices/{MAC2}")
        self.assertEqual(one["device"]["ip6_stable"], V6_NEW)

    def test_history_rows_carry_ip6(self):
        self.db.q("UPDATE history SET ip6=? WHERE mac=?", (V6_NEW, MAC2))
        one, _ = self.get_json(f"/api/devices/{MAC2}")
        self.assertEqual([h["ip6"] for h in one["history"]], [V6_NEW])


if __name__ == "__main__":
    unittest.main()
