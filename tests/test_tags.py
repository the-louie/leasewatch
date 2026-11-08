"""devices.tags: normalize_tags, the migration, the single POST and its event, the bulk refusal, the CSV column, the
JSON field, import_user_fields and the four places where tags count as named. Synthetic data only."""
from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_web_edge_cases as QW  # noqa: E402
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from _fixtures import NOW, S, FakeClient, row  # noqa: E402
from test_merge_fold import HOST, cand, target  # noqa: E402
from test_merge_private_mac import NEWP, lease  # noqa: E402
from test_ops_write import _Base  # noqa: E402
from leasewatch.collector import Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.connectors import Batch  # noqa: E402
from leasewatch.connectors.merge import MergeState, merge  # noqa: E402
from leasewatch.db import Database, normalize_tags  # noqa: E402

DAY = 86400
NINE = ",".join(f"t{i}" for i in range(9))


class NormalizeTests(unittest.TestCase):
    def test_table(self) -> None:
        for text, want in (("IoT, owner:Alex, iot", "iot,owner:alex"), ("my tag", "my-tag"), ("ÅÄÖ", "åäö"), ("", ""),
                           (" , ,", ""), ("a\x00b​, c", "ab,c"), ("v1.2_x", "v1.2_x"), ("x" * 24, "x" * 24),
                           (",".join(f"t{i}" for i in range(8)), ",".join(f"t{i}" for i in range(8)))):
            with self.subTest(text=text):
                self.assertEqual(normalize_tags(text), want)

    def test_combining_marks_and_nfc(self) -> None:
        nfd, nfc = "café", "café"
        self.assertEqual(normalize_tags(nfd), nfc)
        self.assertEqual(normalize_tags(nfc), nfc)
        self.assertEqual(normalize_tags("İstanbul"), "i̇stanbul")
        self.assertEqual(normalize_tags("हिंदी"), "हिंदी")
        self.assertEqual(normalize_tags("தமிழ்"), "தமிழ்")
        self.assertEqual(normalize_tags("straße, ไทย"), "straße,ไทย")
        self.assertEqual(normalize_tags("é" * 24), "é" * 24)  # 48 code points, 24 after NFC
        with self.assertRaises(ValueError):
            normalize_tags("é" * 25)
        for bad in ("́a", "tag!", "-iot", "_a"):  # a mark cannot start a tag
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_tags(bad)

    def test_refused(self) -> None:
        for text, msg in (("tag!", "tag tag! contains a character that is not allowed"),
                          ("-leading", "tag -leading contains a character that is not allowed"),
                          ("_x", "tag _x contains a character that is not allowed"),
                          ("x" * 25, f"tag {'x' * 25} is longer than 24 characters"),
                          (NINE, "at most 8 tags")):
            with self.subTest(text=text), self.assertRaises(ValueError) as cm:
                normalize_tags(text)
            self.assertEqual(str(cm.exception), msg)

    def test_idempotent(self) -> None:
        self.assertEqual(normalize_tags(normalize_tags("IoT, owner:Alex, my tag")), "iot,owner:alex,my-tag")


class MigrationTests(unittest.TestCase):
    def test_migration_adds_the_column_to_an_older_file(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "lw.sqlite3")
        db = Database(path)
        db.q("INSERT INTO devices(mac, first_seen, last_seen) VALUES(?,1,1)", (QW.MAC,))
        db._conn.close()
        con = sqlite3.connect(path)
        con.execute("ALTER TABLE devices DROP COLUMN tags")
        con.commit()
        con.close()
        db = Database(path)
        self.addCleanup(db._conn.close)
        self.assertEqual(dict(db.q("SELECT tags FROM devices")[0]), {"tags": ""})


class TagsApiTests(_Base):
    def events(self) -> list[tuple[str, str]]:
        return [(r["kind"], r["detail"]) for r in
                self.db.q("SELECT kind, detail FROM events WHERE mac=? AND kind='tags' ORDER BY id", (QW.MAC,))]

    def stored(self) -> str:
        return self.db.q("SELECT tags FROM devices WHERE mac=?", (QW.MAC,))[0]["tags"]

    def test_post_normalises_and_writes_one_event(self) -> None:
        st, _, body = self.post(body={"tags": "IoT, owner:Alex, iot"})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["device"]["tags"], "iot,owner:alex")
        self.assertEqual(self.stored(), "iot,owner:alex")
        self.assertEqual(self.events(), [("tags", "(none) -> iot,owner:alex (by 127.0.0.1)")])
        self.post(body={"tags": "IoT, owner:Alex, iot"})  # the same value again writes nothing
        self.assertEqual(len(self.events()), 1)
        self.post(body={"tags": ""})
        self.assertEqual(self.events()[-1], ("tags", "iot,owner:alex -> (none) (by 127.0.0.1)"))
        self.assertEqual(self.stored(), "")

    def test_other_fields_leave_tags_alone(self) -> None:
        self.post(body={"tags": "iot"})
        self.post(body={"name": "tv", "acked": True})
        self.assertEqual(self.stored(), "iot")

    def test_refusals_400(self) -> None:
        for body, msg in (({"tags": 5}, "tags must be a string"), ({"tags": ["iot"]}, "tags must be a string"),
                          ({"tags": NINE}, "at most 8 tags"),
                          ({"tags": "tag!"}, "tag tag! contains a character that is not allowed"),
                          ({"tags": "\ud800"}, "tags must be valid Unicode text")):
            with self.subTest(body=body):
                st, _, raw = self.post(body=body)
                self.assertEqual((st, json.loads(raw)), (400, {"error": msg}))
        self.assertEqual(self.events(), [])
        self.assertEqual(self.stored(), "")

    def test_bulk_refuses_tags(self) -> None:
        for body in ({"macs": [QW.MAC], "tags": "iot"}, {"macs": [QW.MAC], "acked": True, "tags": "iot"}):
            with self.subTest(body=body):
                st, _, raw = self.post(path="/api/devices", body=body)
                self.assertEqual((st, json.loads(raw)), (400, {"error": "bulk takes acked or archived"}))
        self.assertEqual(self.stored(), "")

    def test_csv_last_column_and_json(self) -> None:
        st, _, body = self.get("/api/devices")
        self.assertEqual(json.loads(body)["devices"][0]["tags"], "")
        self.post(body={"tags": "iot, owner:alex"})
        st, _, body = self.get("/api/devices.csv")
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig"))))
        head = rows[0]
        self.assertGreater(head.index("tags"), head.index("watch"))  # appended after watch; later columns may follow
        self.assertEqual(rows[1][0], QW.MAC)
        self.assertEqual(rows[1][head.index("tags")], "iot,owner:alex")
        st, _, body = self.get(f"/api/devices/{QW.MAC}")
        self.assertEqual(json.loads(body)["device"]["tags"], "iot,owner:alex")


class ImportTagsTests(unittest.TestCase):
    A, B = "02:00:00:00:40:01", "02:00:00:00:40:02"

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "lw.db"))
        for mac in (self.A, self.B):
            self.db.q("INSERT INTO devices (mac, first_seen, last_seen, online, baseline, acked) VALUES (?, 100, 100, 0, 0, 0)", (mac,))

    def tearDown(self) -> None:
        self.db.close()
        self.tmp.cleanup()

    def tags(self, mac: str) -> str:
        return self.db.q("SELECT tags FROM devices WHERE mac=?", (mac,))[0]["tags"]

    def test_fill_empty_then_overwrite(self) -> None:
        self.db.update_user_fields(self.A, None, None, None, tags="old")
        r = self.db.import_user_fields([{"mac": self.A, "tags": "New"}, {"mac": self.B, "tags": "IoT, iot"}])
        self.assertEqual((self.tags(self.A), self.tags(self.B)), ("old", "iot"))
        self.assertEqual((r.updated, r.unchanged, r.events), (1, 1, 1))
        r = self.db.import_user_fields([{"mac": self.A, "tags": "New"}], overwrite=True)
        self.assertEqual((self.tags(self.A), r.updated, r.events), ("new", 1, 1))
        self.assertEqual(self.db.q("SELECT detail FROM events WHERE mac=? AND kind='tags' ORDER BY id DESC", (self.A,))[0]["detail"],
                         "old -> new")


class _MergeBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._env = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name})

    def tearDown(self) -> None:
        self.tmp.cleanup()
        restore(self._env)


class ExemptionTests(_MergeBase):
    PRIV, HW = "02:00:00:00:40:01", "00:00:5e:00:53:41"

    def prune(self, prev, private=0, prune=0):
        os.environ["PRUNE_PRIVATE_DAYS"] = str(private)
        os.environ["PRUNE_DAYS"] = str(prune)
        res = merge({r["mac"]: r for r in prev}, {"fw1": Batch(sightings=[])}, Config(), NOW, MergeState())
        return [m for m, k, _ in res.events if k == "archived"]

    def off(self, days, mac, **kw):
        return row(mac, online=0, last_online=NOW - int(days * DAY), **kw)

    def test_tagged_candidate_is_not_folded(self) -> None:
        sightings = [lease(NEWP, host=HOST)]
        res = merge({r["mac"]: r for r in (target(), cand())}, {"fw1": Batch(sightings=sightings)}, Config(), NOW, MergeState())
        self.assertEqual(len(res.folds), 1)  # the untagged row folds: the case below differs only in tags
        res = merge({r["mac"]: r for r in (target(), cand(tags="iot"))}, {"fw1": Batch(sightings=sightings)}, Config(), NOW,
                    MergeState())
        self.assertEqual((res.folds, res.aliases), ([], []))
        self.assertIn(NEWP, res.rows)

    def test_prune_days_spares_a_tagged_row(self) -> None:
        self.assertEqual(self.prune([self.off(31, self.HW)], 0, 30), [self.HW])
        self.assertEqual(self.prune([self.off(31, self.HW, tags="iot")], 0, 30), [])

    def test_prune_private_days_spares_a_tagged_row(self) -> None:
        self.assertEqual(self.prune([self.off(8, self.PRIV)], 7, 0), [self.PRIV])
        self.assertEqual(self.prune([self.off(8, self.PRIV, tags="iot")], 7, 0), [])


class PurgeTagsTests(unittest.TestCase):
    T0 = 1_800_000_000
    ANCHOR, GONE, TAGGED = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:10", "aa:bb:cc:00:00:11"

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = clean_env({**FW1_ENV, "DATA_DIR": self.tmp.name, "PURGE_DAYS": "180"})
        self.cfg = Config()
        self.db = Database(self.cfg.db_path)
        self.col = Collector(self.cfg, self.db, FakeClient([S(self.ANCHOR, "10.0.0.2", "anchor")]))

    def tearDown(self) -> None:
        self.db._conn.close()
        restore(self._saved)
        self.tmp.cleanup()

    def poll(self, at: int) -> None:
        with mock.patch("leasewatch.collector.time.time", lambda: at):
            self.col.run_once()

    def test_a_tagged_row_is_not_purged(self) -> None:
        self.poll(self.T0)
        old = self.T0 - 300 * DAY
        for mac, tags in ((self.GONE, ""), (self.TAGGED, "iot")):
            self.db.q("INSERT INTO devices (mac, first_seen, last_seen, last_online, online, baseline, acked, archived_ts, tags) "
                      "VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?)", (mac, old, old, old, self.T0 - 200 * DAY, tags))
        self.poll(self.T0 + 120)
        self.assertIsNone(self.db.device(self.GONE))
        self.assertIsNotNone(self.db.device(self.TAGGED))


if __name__ == "__main__":
    unittest.main()
