"""POST /api/devices with tags_add and tags_remove: the same tags events as the single POST, all or nothing."""
from __future__ import annotations

import base64
import unittest

import test_ops_write as OW
import test_ui_bulk as UB
from leasewatch import auth

MACS = UB.MACS
REFUSED = UB.REFUSED
RO_PASSWORD = "look but do not touch"


class _Tags(UB._Bulk):
    def tags(self) -> dict[str, str]:
        return {r["mac"]: r["tags"] for r in self.db.q("SELECT mac, tags FROM devices WHERE mac LIKE '02:00:00:00:01:%'")}

    def set_tags(self, mac: str, tags: str) -> None:
        self.db.q("UPDATE devices SET tags=? WHERE mac=?", (tags, mac))


class BulkTagsTests(_Tags):
    def test_add_to_three_events_equal_single_posts(self) -> None:
        self.set_tags(MACS[1], "tv")
        for m in MACS:
            self.assertEqual(self.post(path=f"/api/devices/{m}", body={"tags": self.tags()[m] + ",iot"})[0], 200)
        single = self.events()
        self.db.q("DELETE FROM events")
        self.db.q("UPDATE devices SET tags=''")
        self.set_tags(MACS[1], "tv")
        self.assertEqual(self.bulk({"macs": MACS, "tags_add": "iot"}), (200, {"changed": 3, "unchanged": 0}))
        self.assertEqual(self.events(), single)
        self.assertEqual([d for _, k, d in self.events() if k == "tags"],
                         ["(none) -> iot (by 127.0.0.1)", "tv -> tv,iot (by 127.0.0.1)", "(none) -> iot (by 127.0.0.1)"])
        # the same again: nothing changes, no event
        self.assertEqual(self.bulk({"macs": MACS, "tags_add": "IoT"}), (200, {"changed": 0, "unchanged": 3}))
        self.assertEqual(len(self.events()), 3)

    def test_remove(self) -> None:
        self.set_tags(MACS[0], "a,iot,b")
        self.set_tags(MACS[1], "iot")
        self.assertEqual(self.bulk({"macs": MACS, "tags_remove": "iot"}), (200, {"changed": 2, "unchanged": 1}))
        self.assertEqual(self.tags(), {MACS[0]: "a,b", MACS[1]: "", MACS[2]: ""})
        self.assertEqual(self.events(), [(MACS[0], "tags", "a,iot,b -> a,b (by 127.0.0.1)"),
                                         (MACS[1], "tags", "iot -> (none) (by 127.0.0.1)")])

    def test_add_and_remove_together_keep_the_stored_order(self) -> None:
        self.set_tags(MACS[0], "old,x,keep")
        body = {"macs": MACS[:1], "tags_add": "new, keep", "tags_remove": "old"}
        self.assertEqual(self.bulk(body), (200, {"changed": 1, "unchanged": 0}))
        self.assertEqual(self.tags()[MACS[0]], "x,keep,new")
        self.assertEqual(self.events(), [(MACS[0], "tags", "old,x,keep -> x,keep,new (by 127.0.0.1)")])

    def test_acked_with_tags_add(self) -> None:
        self.set_tags(MACS[1], "iot")
        self.db.q("UPDATE devices SET acked=1 WHERE mac=?", (MACS[2],))
        self.assertEqual(self.bulk({"macs": MACS, "acked": True, "tags_add": "iot"}), (200, {"changed": 3, "unchanged": 0}))
        self.assertEqual(sorted(self.events()), sorted([
            (MACS[0], "acked", "by 127.0.0.1"), (MACS[0], "tags", "(none) -> iot (by 127.0.0.1)"),
            (MACS[1], "acked", "by 127.0.0.1"), (MACS[2], "tags", "(none) -> iot (by 127.0.0.1)")]))
        self.assertEqual([r["acked"] for r in self.rows()], [1, 1, 1])

    def test_full_device_fails_the_whole_request(self) -> None:
        eight = ",".join(f"t{n}" for n in range(8))
        self.set_tags(MACS[1], eight)
        st, body = self.bulk({"macs": MACS, "tags_add": "iot", "acked": True})
        self.assertEqual((st, body), (400, {"error": "at most 8 tags", "full": [MACS[1]]}))
        self.assertEqual(self.tags(), {MACS[0]: "", MACS[1]: eight, MACS[2]: ""})
        self.assertEqual([r["acked"] for r in self.rows()], [0, 0, 0])
        self.assertEqual(self.events(), [])
        # a tag it already has, or one removed in the same request, keeps it at 8
        self.assertEqual(self.bulk({"macs": MACS, "tags_add": "t3"}), (200, {"changed": 2, "unchanged": 1}))
        self.assertEqual(self.bulk({"macs": MACS[1:2], "tags_add": "iot", "tags_remove": "t0"}),
                         (200, {"changed": 1, "unchanged": 0}))

    def test_refusals(self) -> None:
        cases = [
            ({"macs": MACS, "tags_add": "iot", "tags_remove": "IoT"}, {"error": "a tag cannot be both added and removed"}),
            ({"macs": MACS, "tags_add": "tag!"}, {"error": "tag tag! contains a character that is not allowed"}),
            ({"macs": MACS, "tags_remove": "x" * 25}, {"error": f"tag {'x' * 25} is longer than 24 characters"}),
            ({"macs": MACS, "tags_add": ",".join("abcdefghi")}, {"error": "at most 8 tags"}),
            ({"macs": MACS, "tags_add": ["iot"]}, {"error": "tags_add must be a string"}),
            ({"macs": MACS, "tags_remove": "\ud800"}, {"error": "tags_remove must be valid Unicode text"}),
            ({"macs": MACS, "tags": "iot"}, {"error": REFUSED}),  # the first site
            ({"macs": MACS, "tags_add": "iot", "watch": True}, {"error": REFUSED}),
            ({"macs": MACS, "acked": True, "archived": True, "tags_add": "iot"}, {"error": REFUSED}),
            ({"macs": MACS, "tags_add": " , "}, {"error": REFUSED}),  # the second site: nothing left to do
            ({"macs": MACS, "acked": None, "tags_remove": None}, {"error": REFUSED}),
            ({"macs": ["bad"], "tags_add": "iot"}, {"error": "bad mac", "index": 0}),
        ]
        for req, want in cases:
            with self.subTest(req=str(req)[:80]):
                self.assertEqual(self.bulk(req), (400, want))
        self.assertEqual(self.events(), [])
        self.assertEqual(set(self.tags().values()), {""})

    def test_unknown_mac_is_404(self) -> None:
        unknown = "02:00:00:00:0f:0f"
        self.assertEqual(self.bulk({"macs": [MACS[0], unknown], "tags_add": "iot"}),
                         (404, {"error": "unknown device", "unknown": [unknown]}))
        self.assertEqual(self.events(), [])


class BulkTagsReadOnlyTests(_Tags):
    env = {"READ_ONLY": "1"}

    def test_refused(self) -> None:
        with self.assertLogs("leasewatch.web", "DEBUG"):
            self.assertEqual(self.bulk({"macs": MACS, "tags_add": "iot"}), (403, {"error": "read-only"}))
        self.assertEqual(self.events(), [])


class BulkTagsReadOnlyLoginTests(_Tags):
    env = {"AUTH_USER": "alex", "AUTH_PASSWORD_HASH": OW.HASH,
           "AUTH_RO_USER": "family", "AUTH_RO_PASSWORD_HASH": auth.make_hash(RO_PASSWORD, 100_000)}

    def test_ro_login_refused(self) -> None:
        ro = "Basic " + base64.b64encode(f"family:{RO_PASSWORD}".encode()).decode()
        st, body = self.bulk({"macs": MACS, "tags_add": "iot"}, extra=f"Authorization: {ro}\r\n".encode())
        self.assertEqual((st, body), (403, {"error": "read-only"}))
        self.assertEqual(self.events(), [])
        self.assertEqual(set(self.tags().values()), {""})
        st, body = self.bulk({"macs": MACS, "tags_add": "iot"}, extra=f"Authorization: {OW.CREDS}\r\n".encode())
        self.assertEqual((st, body), (200, {"changed": 3, "unchanged": 0}))


if __name__ == "__main__":
    unittest.main()
