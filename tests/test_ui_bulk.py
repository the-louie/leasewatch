"""POST /api/devices: mark known, archive or restore several devices in one all-or-nothing request."""
from __future__ import annotations

import json
import unittest
from unittest import mock

import test_ops_write as OW

MACS = [f"02:00:00:00:01:{n:02x}" for n in range(1, 4)]
ALIAS = "06:00:00:00:09:01"


class _Bulk(OW._Base):
    def setUp(self) -> None:
        super().setUp()
        for m in MACS:
            self.db.q("INSERT INTO devices(mac,first_seen,last_seen,mail_queued) VALUES(?,1,1,1)", (m,))

    def bulk(self, body: object, **kw: object) -> tuple[int, dict]:
        st, _, raw = self.post(path="/api/devices", body=body, **kw)
        return st, json.loads(raw)

    def rows(self) -> list[dict]:
        return [dict(r) for r in self.db.q("SELECT mac, acked, acked_at, archived_ts, mail_queued, name FROM devices WHERE mac LIKE '02:00:00:00:01:%' ORDER BY mac")]

    def events(self) -> list[tuple]:
        return [(r["mac"], r["kind"], r["detail"]) for r in self.db.q("SELECT mac, kind, detail FROM events ORDER BY id")]


class BulkTests(_Bulk):
    def test_three_acked_in_one_request(self) -> None:
        st, body = self.bulk({"macs": MACS, "acked": True})
        self.assertEqual((st, body), (200, {"changed": 3, "unchanged": 0}))
        acked = {r["mac"]: r for r in self.rows()}
        for m in MACS:
            self.assertEqual(acked[m]["acked"], 1)
            self.assertIsNotNone(acked[m]["acked_at"])
        self.assertEqual(sorted(self.events()), sorted((m, "acked", "by 127.0.0.1") for m in MACS))
        # the same state again: no event, counted as unchanged
        st, body = self.bulk({"macs": MACS, "acked": True})
        self.assertEqual((st, body), (200, {"changed": 0, "unchanged": 3}))
        self.assertEqual(len(self.events()), 3)

    def test_events_equal_those_of_single_posts(self) -> None:
        for m in MACS[:2]:
            self.assertEqual(self.post(path=f"/api/devices/{m}", body={"archived": True})[0], 200)
        single = [(k, d) for _, k, d in self.events()]
        self.db.q("DELETE FROM events")
        self.db.q("UPDATE devices SET archived_ts=NULL, mail_queued=1")
        self.assertEqual(self.bulk({"macs": MACS[:2], "archived": True}), (200, {"changed": 2, "unchanged": 0}))
        self.assertEqual([(k, d) for _, k, d in self.events()], single)
        rows = {r["mac"]: r for r in self.rows()}
        self.assertIsNotNone(rows[MACS[0]]["archived_ts"])
        self.assertIsNone(rows[MACS[0]]["mail_queued"])  # an archived device leaves the mail queue, as in the single path
        self.assertEqual(self.bulk({"macs": MACS[:2], "archived": False}), (200, {"changed": 2, "unchanged": 0}))
        self.assertEqual([k for _, k, _ in self.events()], ["archived", "archived", "restored", "restored"])
        self.assertIsNone({r["mac"]: r for r in self.rows()}[MACS[0]]["archived_ts"])

    def test_unknown_mac_is_404_and_nothing_changes(self) -> None:
        before, unknown = self.rows(), "02:00:00:00:0f:0f"
        st, body = self.bulk({"macs": [MACS[0], unknown, MACS[1]], "acked": True})
        self.assertEqual((st, body), (404, {"error": "unknown device", "unknown": [unknown]}))
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.events(), [])

    def test_alias_of_a_missing_device_is_404_single_and_bulk(self) -> None:
        self.db.q("INSERT INTO aliases(mac,device,reason,merged_ts,last_seen) VALUES(?,?,'hostname',1,1)", (ALIAS, "02:00:00:00:99:99"))
        self.assertEqual(self.post(path=f"/api/devices/{ALIAS}", body={"acked": True})[0], 404)
        st, body = self.bulk({"macs": [ALIAS, MACS[0]], "acked": True})
        self.assertEqual(st, 404)
        self.assertIn(ALIAS, json.dumps(body))
        self.assertEqual(self.events(), [])

    def test_alias_resolves_to_its_device_and_counts_once(self) -> None:
        self.db.q("INSERT INTO aliases(mac,device,reason,merged_ts,last_seen) VALUES(?,?,'hostname',1,1)", (ALIAS, MACS[0]))
        st, body = self.bulk({"macs": [ALIAS, MACS[0], MACS[1]], "acked": True})
        self.assertEqual((st, body), (200, {"changed": 2, "unchanged": 0}))
        self.assertEqual(sorted(self.events()), [(MACS[0], "acked", "by 127.0.0.1"), (MACS[1], "acked", "by 127.0.0.1")])

    def test_limits_and_shapes(self) -> None:
        many = [f"02:00:00:{n >> 8:02x}:{n & 0xff:02x}:00" for n in range(201)]
        cases = [
            ({"macs": many, "acked": True}, {"error": "macs must be a list of 1 to 200 MACs"}),
            ({"macs": [], "acked": True}, {"error": "macs must be a list of 1 to 200 MACs"}),
            ({"macs": MACS[0], "acked": True}, {"error": "macs must be a list of 1 to 200 MACs"}),
            ({"macs": [MACS[0], 7], "acked": True}, {"error": "bad mac", "index": 1}),
            ({"macs": ["0A:00:00:00:01:01"], "acked": True}, {"error": "bad mac", "index": 0}),
            ({"macs": [MACS[0] + "\n"], "acked": True}, {"error": "bad mac", "index": 0}),
            ({"macs": MACS, "acked": True, "archived": True}, {"error": "bulk takes acked or archived"}),
            ({"macs": MACS}, {"error": "bulk takes acked or archived"}),
            ({"macs": MACS, "acked": None}, {"error": "bulk takes acked or archived"}),
            ({"macs": MACS, "acked": True, "name": "x"}, {"error": "bulk takes acked or archived"}),
            ({"macs": MACS, "acked": "yes"}, {"error": "acked must be boolean"}),
            ({"macs": MACS, "archived": 1}, {"error": "archived must be boolean"}),
        ]
        for req, want in cases:
            with self.subTest(req=str(req)[:80]):
                self.assertEqual(self.bulk(req), (400, want))
        self.assertEqual(self.events(), [])

    def test_200_macs_fit_the_body_limit(self) -> None:
        many = [f"02:00:00:00:{n >> 8:02x}:{n & 0xff:02x}" for n in range(200)]
        for m in many:
            self.db.q("INSERT OR IGNORE INTO devices(mac,first_seen,last_seen) VALUES(?,1,1)", (m,))
        self.assertLess(len(json.dumps({"macs": many, "archived": True})), OW.web.MAX_BODY)
        self.assertEqual(self.bulk({"macs": many, "archived": True}), (200, {"changed": 200, "unchanged": 0}))

    def test_cross_site_and_wrong_type_refused(self) -> None:
        st, _ = self.bulk({"macs": MACS, "acked": True}, extra=b"Sec-Fetch-Site: cross-site\r\n")
        self.assertEqual(st, 403)
        self.assertEqual(self.events(), [])

    def test_etag_moves_after_a_bulk_post(self) -> None:
        tags = {p: self.get(p)[1]["etag"] for p in ("/api/devices", "/api/events")}
        self.assertEqual(self.bulk({"macs": MACS, "acked": True})[0], 200)
        for p, tag in tags.items():
            self.assertNotEqual(self.get(p)[1]["etag"], tag, p)

    def test_failure_rolls_back_everything(self) -> None:
        real = self.db._apply_user_fields
        calls = []

        def flaky(c, mac, *a):
            calls.append(mac)
            if len(calls) == 2:
                raise RuntimeError("disk on fire")
            return real(c, mac, *a)
        with mock.patch.object(self.db, "_apply_user_fields", flaky), self.assertLogs("leasewatch.web", "ERROR") as cm:
            st, body = self.bulk({"macs": MACS, "acked": True})
        self.assertEqual((st, body), (500, {"error": "internal error"}))
        self.assertIn("POST /api/devices failed", cm.output[0])
        self.assertEqual([r["acked"] for r in self.rows()], [0, 0, 0])
        self.assertEqual(self.events(), [])


class BulkReadOnlyTests(_Bulk):
    env = {"READ_ONLY": "1"}

    def test_refused(self) -> None:
        with self.assertLogs("leasewatch.web", "DEBUG"):
            self.assertEqual(self.bulk({"macs": MACS, "acked": True}), (403, {"error": "read-only"}))
        self.assertEqual(self.events(), [])


class BulkWriteAllowTests(_Bulk):
    env = {"WRITE_ALLOW": "10.0.1.0/24"}

    def tearDown(self) -> None:
        t = self.H.write_refusals._timer
        if t is not None:
            t.cancel()
        super().tearDown()

    def test_outside_refused_inside_allowed(self) -> None:
        with self.assertLogs("leasewatch.web", "WARNING"):  # the refusal is logged, as for a single POST
            self.assertEqual(self.bulk({"macs": MACS, "acked": True}, client="10.0.9.9"), (403, OW.REFUSED))
        self.assertEqual(self.events(), [])
        self.assertEqual(self.bulk({"macs": MACS, "acked": True}, client="10.0.1.7"), (200, {"changed": 3, "unchanged": 0}))


class BulkAuthTests(_Bulk):
    env = {"AUTH_USER": "alex", "AUTH_PASSWORD_HASH": OW.HASH}

    def test_login_required(self) -> None:
        self.assertEqual(self.bulk({"macs": MACS, "acked": True}), (401, {"error": "authentication required"}))
        self.assertEqual(self.events(), [])
        st, body = self.bulk({"macs": MACS, "acked": True}, extra=f"Authorization: {OW.CREDS}\r\n".encode())
        self.assertEqual((st, body), (200, {"changed": 3, "unchanged": 0}))


if __name__ == "__main__":
    unittest.main()
