"""The `reset-baseline` command (leasewatch/maintenance.py)."""
import contextlib, io, os, sqlite3, sys, tempfile, unittest
from unittest import mock
from _env import clean_env, restore
import leasewatch.__main__ as m
from leasewatch import maintenance
from leasewatch.db import Database

# mac, baseline, acked, archived_ts, mail_queued
ROWS = [("02:00:00:00:00:01", 1, 0, None, None),
        ("02:00:00:00:00:02", 0, 1, None, 500),
        ("02:00:00:00:00:03", 0, 0, None, 600),
        ("02:00:00:00:00:04", 0, 1, 700, 800)]


class ResetBaselineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self._env = clean_env({"DATA_DIR": self.dir})
        self.addCleanup(restore, self._env)
        self.db_path = os.path.join(self.dir, "leasewatch.sqlite3")

    def make_db(self) -> None:
        db = Database(self.db_path)
        with db._lock:
            for mac, base, acked, arch, queued in ROWS:
                db._conn.execute("INSERT INTO devices(mac, first_seen, last_seen, baseline, acked, acked_at, archived_ts, mail_queued)"
                                 " VALUES (?,?,?,?,?,?,?,?)", (mac, 100, 200, base, acked, 300 if acked else None, arch, queued))
        db.close()

    def rows(self):
        con = sqlite3.connect(self.db_path)
        try:
            return con.execute("SELECT mac, baseline, acked, acked_at, archived_ts, mail_queued FROM devices ORDER BY mac").fetchall()
        finally:
            con.close()

    def meta(self):
        con = sqlite3.connect(self.db_path)
        try:
            r = con.execute("SELECT value FROM meta WHERE key='baseline_ts'").fetchone()
            return r[0] if r else None
        finally:
            con.close()

    def run_cmd(self, *argv: str, tty: bool = False, stdin: str = ""):
        lines, err = [], io.StringIO()
        fake = io.StringIO(stdin)
        fake.isatty = lambda: tty  # type: ignore[method-assign]
        with mock.patch.object(sys, "stdin", fake), contextlib.redirect_stderr(err):
            rc = maintenance.reset_baseline_cmd(list(argv), lines.append)
        return rc, lines, err.getvalue()

    def test_in_subcommands(self):
        self.assertIn("reset-baseline", m.SUBCOMMANDS)

    def test_needs_yes_without_tty(self):
        self.make_db()
        before = self.rows()
        rc, lines, err = self.run_cmd()
        self.assertEqual((rc, lines, err), (2, [], "reset-baseline: add --yes to confirm\n"))
        self.assertEqual(self.rows(), before)
        self.assertIsNone(self.meta())

    def test_yes_marks_non_archived(self):
        self.make_db()
        rc, lines, err = self.run_cmd("--yes")
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(lines, ["reset-baseline: 3 devices marked as baseline (2 were new)"])
        r = self.rows()
        self.assertEqual([x[1] for x in r], [1, 1, 1, 0])
        self.assertEqual([x[5] for x in r], [None, None, None, 800])
        self.assertEqual([x[2] for x in r], [0, 1, 0, 1])  # acks kept
        self.assertEqual(r[3][4], 700)  # archived row untouched
        self.assertTrue(self.meta().isdigit())

    def test_clear_acks(self):
        self.make_db()
        rc, lines, _ = self.run_cmd("--yes", "--clear-acks")
        self.assertEqual(rc, 0)
        self.assertEqual(lines, ["reset-baseline: 3 devices marked as baseline (2 were new), acks cleared"])
        r = self.rows()
        self.assertEqual([(x[2], x[3]) for x in r], [(0, None), (0, None), (0, None), (1, 300)])

    def test_include_archived(self):
        self.make_db()
        rc, lines, _ = self.run_cmd("--yes", "--include-archived")
        self.assertEqual(lines, ["reset-baseline: 4 devices marked as baseline (3 were new)"])
        r = self.rows()
        self.assertEqual([x[1] for x in r], [1, 1, 1, 1])
        self.assertEqual(r[3][5], None)
        self.assertEqual(r[3][4], 700)  # still archived

    def test_second_run_has_none_new(self):
        self.make_db()
        self.run_cmd("--yes")
        rc, lines, _ = self.run_cmd("--yes")
        self.assertEqual((rc, lines), (0, ["reset-baseline: 3 devices marked as baseline (0 were new)"]))

    def test_tty_prompt(self):
        self.make_db()
        before = self.rows()
        rc, lines, err = self.run_cmd(tty=True, stdin="n\n")
        self.assertEqual((rc, lines), (1, []))
        self.assertIn("Mark 3 devices as baseline? [y/N]", err)
        self.assertEqual(self.rows(), before)
        rc, lines, _ = self.run_cmd(tty=True, stdin="y\n")
        self.assertEqual((rc, lines), (0, ["reset-baseline: 3 devices marked as baseline (2 were new)"]))

    def test_missing_database(self):
        rc, lines, err = self.run_cmd("--yes")
        self.assertEqual((rc, lines), (1, []))
        self.assertTrue(err.startswith("reset-baseline failed: cannot open "), err)
        self.assertFalse(os.path.exists(self.db_path))

    def test_main_dispatch_and_version(self):
        self.make_db()
        live = Database(self.db_path)  # a running service's connection
        try:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = m.main(["reset-baseline", "--yes"])
            self.assertEqual((rc, err.getvalue()), (0, ""))
            self.assertEqual(out.getvalue(), "reset-baseline: 3 devices marked as baseline (2 were new)\n")
            self.assertEqual(live.get_meta("baseline_ts"), self.meta())
        finally:
            live.close()


if __name__ == "__main__":
    unittest.main()
