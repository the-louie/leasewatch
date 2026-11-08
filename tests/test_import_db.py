"""Database.import_user_fields: the bulk write path of import-csv. Fill-empty keeps what is set and never clears,
restores or unwatches; overwrite applies every present field; one transaction; events come from the shared
user-field rules. Synthetic data only: private MACs."""
import os
import sqlite3
import tempfile
import threading
import unittest

from leasewatch.db import Database, ImportResult

A = "02:00:00:00:40:01"
B = "02:00:00:00:40:02"
ALIAS = "02:00:00:00:40:09"
GONE = "02:00:00:00:40:ff"


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.tmp.name, "lw.db"))
        for mac in (A, B):
            self.db.q("INSERT INTO devices (mac, first_seen, last_seen, online, baseline, acked) VALUES (?, 100, 100, 0, 0, 0)", (mac,))
        self.db.q("INSERT INTO aliases (mac, device, reason, detail, merged_ts, last_seen) VALUES (?, ?, 'client-id', 'x', 100, 100)", (ALIAS, A))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def dev(self, mac=A):
        return dict(self.db.q("SELECT * FROM devices WHERE mac=?", (mac,))[0])

    def kinds(self, mac=A):
        return [r["kind"] for r in self.db.q("SELECT kind FROM events WHERE mac=? ORDER BY id", (mac,))]

    def imp(self, rows, **kw):
        return self.db.import_user_fields(rows, **kw)

    def test_fill_empty_keeps_set_name_and_note_and_fills_empty(self):
        self.db.update_user_fields(A, None, "Old", "old note")
        r = self.imp([{"mac": A, "name": "New", "note": "new"}, {"mac": B, "name": "Fresh", "note": "n"}])
        self.assertEqual((self.dev()["name"], self.dev()["note"]), ("Old", "old note"))
        self.assertEqual((self.dev(B)["name"], self.dev(B)["note"]), ("Fresh", "n"))
        self.assertEqual((r.updated, r.unchanged), (1, 1))
        self.assertEqual(self.kinds(B), ["renamed", "note"])

    def test_overwrite_replaces(self):
        self.db.update_user_fields(A, None, "Old", "old note")
        r = self.imp([{"mac": A, "name": "New", "note": "new"}], overwrite=True)
        self.assertEqual((self.dev()["name"], self.dev()["note"]), ("New", "new"))
        self.assertEqual((r.updated, r.events), (1, 2))

    def test_acked(self):
        r = self.imp([{"mac": A, "acked": True}])
        self.assertEqual((self.dev()["acked"], r.updated, r.events), (1, 1, 1))
        self.assertEqual(self.kinds(), ["acked"])
        r = self.imp([{"mac": A, "acked": False}])
        self.assertEqual((self.dev()["acked"], r.unchanged, r.events), (1, 1, 0))
        r = self.imp([{"mac": A, "acked": False}], overwrite=True)
        self.assertEqual((self.dev()["acked"], r.updated), (0, 1))
        self.assertEqual(self.kinds(), ["acked", "unacked"])

    def test_archived(self):
        self.imp([{"mac": A, "archived": True}])
        self.assertIsNotNone(self.dev()["archived_ts"])
        r = self.imp([{"mac": A, "archived": False}])
        self.assertEqual((r.unchanged, r.events), (1, 0))
        self.assertIsNotNone(self.dev()["archived_ts"])
        self.imp([{"mac": A, "archived": False}], overwrite=True)
        self.assertIsNone(self.dev()["archived_ts"])
        self.assertEqual(self.kinds(), ["archived", "restored"])

    def test_watch(self):
        self.imp([{"mac": A, "watch": True}])
        self.assertEqual(self.dev()["watch"], 1)
        r = self.imp([{"mac": A, "watch": False}])
        self.assertEqual((self.dev()["watch"], r.events), (1, 0))
        self.imp([{"mac": A, "watch": False}], overwrite=True)
        self.assertEqual(self.dev()["watch"], 0)
        self.assertEqual(self.kinds(), ["watched", "unwatched"])

    def test_absent_keys_are_not_touched(self):
        self.db.update_user_fields(A, True, "Keep", None, watch=True)
        self.imp([{"mac": A, "note": "n"}], overwrite=True)
        d = self.dev()
        self.assertEqual((d["name"], d["acked"], d["watch"], d["note"]), ("Keep", 1, 1, "n"))

    def test_alias_lands_on_device(self):
        r = self.imp([{"mac": ALIAS, "name": "Via alias"}])
        self.assertEqual(self.dev()["name"], "Via alias")
        self.assertEqual((r.updated, r.unknown), (1, []))
        self.assertEqual(self.db.q("SELECT COUNT(*) n FROM devices")[0]["n"], 2)

    def test_unknown_listed_and_nothing_written(self):
        r = self.imp([{"mac": GONE, "name": "X", "acked": True}])
        self.assertEqual((r.unknown, r.updated, r.unchanged, r.events), ([GONE], 0, 0, 0))
        self.assertEqual(self.db.q("SELECT COUNT(*) n FROM devices")[0]["n"], 2)
        self.assertEqual(self.db.q("SELECT COUNT(*) n FROM events")[0]["n"], 0)

    def test_two_rows_one_device_last_wins(self):
        r = self.imp([{"mac": A, "name": "First"}, {"mac": ALIAS, "name": "Second"}])
        self.assertEqual(self.dev()["name"], "Second")
        self.assertEqual((r.duplicates, r.duplicate_rows), ([A], {A: 2}))
        self.assertEqual((r.updated, r.unchanged), (1, 0))
        self.assertEqual(self.kinds(), ["renamed"])

    def test_rows_for_one_device_merge_field_by_field(self):
        # a later empty or absent field keeps the earlier row's value; a later non-empty value wins
        rows = [{"mac": A, "name": "Kept", "note": "old", "archived": True, "acked": True},
                {"mac": ALIAS, "name": "", "note": "new", "archived": False},
                {"mac": A, "acked": False},
                {"mac": B, "name": "Other"}]
        r = self.imp(rows, overwrite=True)
        d = self.dev()
        self.assertEqual((d["name"], d["note"], d["archived_ts"] is not None, d["acked"]), ("Kept", "new", True, 0))
        self.assertEqual((r.duplicates, r.duplicate_rows), ([A], {A: 3}))
        self.assertEqual(self.dev(B)["name"], "Other")

    def test_empty_later_value_still_applies_when_alone(self):
        self.imp([{"mac": A, "name": "Set"}])
        self.imp([{"mac": A, "name": ""}, {"mac": A, "note": ""}], overwrite=True)
        self.assertEqual(self.dev()["name"], "")

    def test_second_identical_run_changes_nothing(self):
        rows = [{"mac": A, "name": "N", "note": "x", "acked": True, "archived": True, "watch": True}]
        self.assertEqual(self.imp(rows, overwrite=True).updated, 1)
        for ow in (False, True):
            r = self.imp(rows, overwrite=ow)
            self.assertEqual((r.updated, r.unchanged, r.events), (0, 1, 0))

    def test_name_cut_by_shared_cleaning(self):
        self.imp([{"mac": A, "name": "x" * 200}])
        self.assertEqual(self.dev()["name"], "x" * 80)

    def test_actor_in_event_detail(self):
        self.imp([{"mac": A, "name": "N", "acked": True, "watch": True}], actor="import-csv")
        details = [r["detail"] for r in self.db.q("SELECT detail FROM events WHERE mac=?", (A,))]
        self.assertEqual(len(details), 3)
        self.assertTrue(all("import-csv" in d for d in details), details)

    def test_failure_rolls_back_earlier_rows(self):
        with self.assertRaises(TypeError):
            self.imp([{"mac": A, "name": "Fine", "acked": True}, {"mac": B, "name": 123}])
        self.assertEqual((self.dev()["name"], self.dev()["acked"]), ("", 0))
        self.assertEqual(self.db.q("SELECT COUNT(*) n FROM events")[0]["n"], 0)

    def test_begins_immediate_and_waits_for_another_writer(self):
        sql = []
        self.db._c().set_trace_callback(sql.append)
        other = sqlite3.connect(os.path.join(self.tmp.name, "lw.db"), isolation_level=None, check_same_thread=False)
        try:
            other.execute("BEGIN IMMEDIATE")  # a poll holding the write lock
            other.execute("UPDATE devices SET last_seen=200 WHERE mac=?", (B,))
            t = threading.Timer(0.3, other.execute, ("COMMIT",))
            t.start()
            r = self.imp([{"mac": A, "name": "N"}])  # waits for the commit instead of "database is locked"
            t.join()
        finally:
            other.close()
            self.db._c().set_trace_callback(None)
        self.assertIn("BEGIN IMMEDIATE", sql)
        self.assertEqual((r.updated, self.dev()["name"], self.dev(B)["last_seen"]), (1, "N", 200))

    def test_result_type(self):
        self.assertEqual(self.imp([]), ImportResult(0, 0, [], [], 0))


if __name__ == "__main__":
    unittest.main()
