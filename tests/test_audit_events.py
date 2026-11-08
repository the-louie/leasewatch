"""Audit events: a name or note change writes its own event, and every event written from the page names the actor."""
from __future__ import annotations

import json
import unittest

import test_web_edge_cases as QW
from test_ops_write import CREDS, HASH, _Base

MAC2 = "02:00:00:00:00:02"


class AuditTests(_Base):
    def events(self, mac: str = QW.MAC) -> list[tuple[str, str]]:
        return [(r["kind"], r["detail"]) for r in self.db.q("SELECT kind, detail FROM events WHERE mac=? ORDER BY id", (mac,))]

    def test_rename(self) -> None:
        self.assertEqual(self.post(body={"name": "kitchen"})[0], 200)
        self.assertEqual(self.events(), [("renamed", "(none) -> kitchen (by 127.0.0.1)")])
        self.post(body={"name": "hall"})
        self.assertEqual(self.events()[-1], ("renamed", "kitchen -> hall (by 127.0.0.1)"))
        self.post(body={"name": ""})
        self.assertEqual(self.events()[-1], ("renamed", "hall -> (none) (by 127.0.0.1)"))

    def test_same_value_no_event(self) -> None:
        self.post(body={"name": "kitchen", "note": "abc"})
        n = len(self.events())
        self.post(body={"name": "  kitchen\t", "note": "abc "})  # equal after cleaning
        self.assertEqual(len(self.events()), n)

    def test_note_lengths_only(self) -> None:
        self.post(body={"note": "secret text"})
        self.post(body={"note": "other secret"})
        ev = self.events()
        self.assertEqual(ev, [("note", "0 -> 11 chars (by 127.0.0.1)"),
                              ("note", "11 -> 12 chars (by 127.0.0.1)")])
        self.assertNotIn("secret", json.dumps(ev))

    def test_both_fields_two_events(self) -> None:
        self.post(body={"name": "a", "note": "b"})
        self.assertEqual(sorted(k for k, _ in self.events()), ["note", "renamed"])

    def test_long_name_cut(self) -> None:
        self.post(body={"name": "x" * 90})
        self.assertEqual(self.db.q("SELECT name FROM devices WHERE mac=?", (QW.MAC,))[0]["name"], "x" * 80)
        self.assertEqual(self.events()[-1][1], f"(none) -> {'x' * 40} (by 127.0.0.1)")
        self.post(body={"name": "x" * 95})  # same after the cut to 80
        self.assertEqual(len(self.events()), 1)
        self.post(body={"name": "y" * 90})
        self.assertEqual(self.events()[-1][1], f"{'x' * 40} -> {'y' * 40} (by 127.0.0.1)")

    def test_control_chars_cleaned(self) -> None:
        self.post(body={"name": "a\x07b\nc"})
        detail = self.events()[-1][1]
        self.assertEqual(detail, "(none) -> ab c (by 127.0.0.1)")
        self.assertFalse(any(ord(ch) < 32 and ch != " " for ch in detail))

    def test_ack_archive_name_actor(self) -> None:
        self.post(body={"acked": True})
        self.post(body={"acked": False})
        self.post(body={"archived": True})
        self.post(body={"archived": False})
        self.assertEqual(self.events(), [("acked", "by 127.0.0.1"), ("unacked", "by 127.0.0.1"),
                                         ("archived", "by 127.0.0.1"), ("restored", "by 127.0.0.1")])

    def test_forwarded_header_ignored(self) -> None:
        self.post(body={"acked": True}, extra=b"X-Forwarded-For: 6.6.6.6\r\n")
        self.assertEqual(self.events(), [("acked", "by 127.0.0.1")])

    def test_bulk(self) -> None:
        self.db.q("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,1)", (MAC2,))
        st, _, _ = self.post(path="/api/devices", body={"macs": [QW.MAC, MAC2], "acked": True})
        self.assertEqual(st, 200)
        self.assertEqual(self.events(), [("acked", "by 127.0.0.1")])
        self.assertEqual(self.events(MAC2), [("acked", "by 127.0.0.1")])

    def test_db_default_actor_empty(self) -> None:
        self.db.update_user_fields(QW.MAC, True, None, None)
        self.assertEqual(self.events(), [("acked", "")])


class AuditLoginTests(_Base):
    env = {"AUTH_USER": "alex", "AUTH_PASSWORD_HASH": HASH}

    def test_actor_has_user(self) -> None:
        auth = f"Authorization: {CREDS}\r\n".encode()
        self.post(body={"name": "tv", "acked": True}, extra=auth, client="10.0.0.5")
        rows = [(r["kind"], r["detail"]) for r in self.db.q("SELECT kind, detail FROM events ORDER BY id")]
        self.assertEqual(rows, [("acked", "by 10.0.0.5 alex"), ("renamed", "(none) -> tv (by 10.0.0.5 alex)")])


if __name__ == "__main__":
    unittest.main()
