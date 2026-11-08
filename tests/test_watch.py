"""devices.watch: the migration, the single POST and its events, the bulk refusal, the CSV column and the JSON field."""
from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import tempfile
import unittest

import test_web_edge_cases as QW
from test_ops_write import _Base
from leasewatch.db import Database


class MigrationTests(unittest.TestCase):
    def test_migration_adds_the_column_to_an_older_file(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "lw.sqlite3")
        db = Database(path)
        db.q("INSERT INTO devices(mac, first_seen, last_seen) VALUES(?,1,1)", (QW.MAC,))
        db._conn.close()
        con = sqlite3.connect(path)
        con.execute("ALTER TABLE devices DROP COLUMN watch")
        con.commit()
        con.close()
        db = Database(path)
        self.addCleanup(db._conn.close)
        self.assertEqual(dict(db.q("SELECT watch FROM devices")[0]), {"watch": 0})


class WatchTests(_Base):
    def events(self) -> list[tuple[str, str]]:
        return [(r["kind"], r["detail"]) for r in
                self.db.q("SELECT kind, detail FROM events WHERE mac=? AND kind IN ('watched','unwatched') ORDER BY id", (QW.MAC,))]

    def test_watch_unwatch_events(self) -> None:
        st, _, body = self.post(body={"watch": True})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["device"]["watch"], 1)
        self.assertEqual(self.events(), [("watched", "by 127.0.0.1")])
        self.post(body={"watch": True})  # the same state again writes nothing
        self.assertEqual(len(self.events()), 1)
        self.post(body={"watch": False})
        self.assertEqual(self.events(), [("watched", "by 127.0.0.1"), ("unwatched", "by 127.0.0.1")])
        self.assertEqual(self.db.q("SELECT watch FROM devices WHERE mac=?", (QW.MAC,))[0]["watch"], 0)

    def test_other_fields_leave_watch_alone(self) -> None:
        self.post(body={"watch": True})
        self.post(body={"name": "tv", "acked": True})
        self.assertEqual(self.db.q("SELECT watch FROM devices WHERE mac=?", (QW.MAC,))[0]["watch"], 1)

    def test_non_bool_400(self) -> None:
        for v in (1, "true", [], {}):
            with self.subTest(v=v):
                st, _, body = self.post(body={"watch": v})
                self.assertEqual((st, json.loads(body)), (400, {"error": "watch must be boolean"}))
        self.assertEqual(self.events(), [])

    def test_bulk_refuses_watch(self) -> None:
        for body in ({"macs": [QW.MAC], "watch": True}, {"macs": [QW.MAC], "acked": True, "watch": True}):
            with self.subTest(body=body):
                st, _, raw = self.post(path="/api/devices", body=body)
                self.assertEqual((st, json.loads(raw)), (400, {"error": "bulk takes acked or archived"}))
        self.assertEqual(self.db.q("SELECT watch, acked FROM devices WHERE mac=?", (QW.MAC,))[0]["watch"], 0)

    def test_csv_last_column_and_json(self) -> None:
        st, _, body = self.get("/api/devices")
        self.assertEqual(json.loads(body)["devices"][0]["watch"], 0)
        self.post(body={"watch": True})
        st, _, body = self.get("/api/devices.csv")
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        head = rows[0]
        self.assertLess(head.index("aliases"), head.index("watch"))
        self.assertEqual(rows[1][0], QW.MAC)
        self.assertEqual(rows[1][head.index("watch")], "1")
        st, _, body = self.get(f"/api/devices/{QW.MAC}")
        self.assertEqual(json.loads(body)["device"]["watch"], 1)


class ReadOnlyWatchTests(_Base):
    env = {"READ_ONLY": "1"}

    def test_read_only_403(self) -> None:
        st, _, body = self.post(body={"watch": True})
        self.assertEqual((st, json.loads(body)), (403, {"error": "read-only"}))
        self.assertEqual(self.db.q("SELECT watch FROM devices WHERE mac=?", (QW.MAC,))[0]["watch"], 0)


if __name__ == "__main__":
    unittest.main()
