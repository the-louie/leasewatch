"""The `backup` and `vacuum` commands (leasewatch/maintenance.py)."""
import contextlib, io, os, re, sqlite3, stat, sys, tempfile, threading, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore
import leasewatch.__main__ as m
from leasewatch import maintenance
from leasewatch.config import Config
from leasewatch.db import Database

NAME_RE = re.compile(r"^leasewatch-\d{8}-\d{6}(-\d+)?\.sqlite3$")


class BackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self._env = clean_env({"DATA_DIR": self.dir})
        self.addCleanup(restore, self._env)
        self.db_path = os.path.join(self.dir, "leasewatch.sqlite3")

    def make_db(self, events: int = 5) -> None:
        db = Database(self.db_path)
        with db._lock:
            db._conn.executemany("INSERT INTO events(ts, mac, kind, detail) VALUES (?,?,?,?)",
                                 [(1000 + i, "02:00:00:00:00:01", "new", "row %d" % i) for i in range(events)])
        db.close()

    def cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = m.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def backups(self) -> list[str]:
        d = os.path.join(self.dir, "backups")
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def test_copy_roundtrip_and_properties(self):
        self.make_db(5)
        rc, out, err = self.cli("backup")
        self.assertEqual((rc, err), (0, ""))
        files = self.backups()
        self.assertEqual(len(files), 1)
        self.assertRegex(files[0], NAME_RE)
        path = os.path.join(self.dir, "backups", files[0])
        self.assertRegex(out, r"^backup: .+ \(\d+\.\d MB; 1 kept, 0 removed\)\n$")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
        con = sqlite3.connect(path)
        try:
            self.assertEqual(con.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            self.assertEqual(con.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(con.execute("SELECT count(*) FROM events").fetchone()[0], 5)
            self.assertEqual(con.execute("SELECT detail FROM events WHERE ts=1003").fetchone()[0], "row 3")
        finally:
            con.close()
        self.assertEqual(os.listdir(os.path.join(self.dir, "backups")), files)  # no .part, -wal or -shm left

    def test_keep_rotates_only_named_backups(self):
        self.make_db()
        bdir = os.path.join(self.dir, "backups")
        os.makedirs(bdir)
        old = [f"leasewatch-2026010{d}-120000.sqlite3" for d in range(1, 5)]
        for n in old + ["notes.txt", ".x.part"]:
            with open(os.path.join(bdir, n), "w") as f:
                f.write("x")
        rc, out, err = self.cli("backup", "--keep", "2")
        self.assertEqual(rc, 0, err)
        self.assertIn("2 kept, 3 removed", out)
        left = self.backups()
        self.assertEqual([f for f in left if NAME_RE.match(f)][0], old[-1])
        self.assertEqual(len([f for f in left if NAME_RE.match(f)]), 2)
        self.assertIn("notes.txt", left)
        self.assertIn(".x.part", left)

    def test_keep_zero_keeps_all_and_env_default(self):
        self.make_db()
        bdir = os.path.join(self.dir, "backups")
        os.makedirs(bdir)
        for d in range(1, 5):
            open(os.path.join(bdir, f"leasewatch-2026010{d}-120000.sqlite3"), "w").close()
        rc, out, _ = self.cli("backup", "--keep", "0")
        self.assertEqual(rc, 0)
        self.assertIn("5 kept, 0 removed", out)
        os.environ["BACKUP_KEEP"] = "1"
        rc, out, _ = self.cli("backup")
        self.assertIn("1 kept, 5 removed", out)

    def test_same_second_name_gets_suffix(self):
        self.make_db()
        with mock.patch.object(maintenance, "_stamp", lambda: "20261107-031500"):
            self.assertEqual(self.cli("backup")[0], 0)
            self.assertEqual(self.cli("backup")[0], 0)
            self.assertEqual(self.cli("backup", "--keep", "0")[0], 0)
        self.assertEqual(self.backups(), ["leasewatch-20261107-031500-1.sqlite3", "leasewatch-20261107-031500-2.sqlite3",
                                          "leasewatch-20261107-031500.sqlite3"])

    def test_suffix_ordering_in_rotation(self):
        self.make_db()
        with mock.patch.object(maintenance, "_stamp", lambda: "20261107-031500"):
            for _ in range(3):
                self.cli("backup", "--keep", "0")
            self.assertEqual(self.cli("backup", "--keep", "1")[0], 0)  # the newest is the -3 file
        self.assertEqual(self.backups(), ["leasewatch-20261107-031500-3.sqlite3"])

    def test_future_stamps_never_delete_the_new_backup(self):
        self.make_db()
        bdir = os.path.join(self.dir, "backups")
        os.makedirs(bdir)
        for d in range(1, 9):
            open(os.path.join(bdir, f"leasewatch-209901{d:02d}-120000.sqlite3"), "w").close()
        with mock.patch.object(maintenance, "_stamp", lambda: "20261107-031500"):
            rc, out, err = self.cli("backup", "--keep", "7")
        self.assertEqual((rc, err), (0, ""))
        self.assertIn("7 kept, 2 removed", out)
        left = self.backups()
        self.assertIn("leasewatch-20261107-031500.sqlite3", left)
        self.assertEqual(len(left), 7)
        self.assertNotIn("leasewatch-20990101-120000.sqlite3", left)

    def test_keep_one_keeps_only_the_new_file(self):
        self.make_db()
        bdir = os.path.join(self.dir, "backups")
        os.makedirs(bdir)
        open(os.path.join(bdir, "leasewatch-20990101-120000.sqlite3"), "w").close()
        rc, out, _ = self.cli("backup", "--keep", "1")
        self.assertEqual(rc, 0)
        self.assertIn("1 kept, 1 removed", out)
        self.assertEqual(len(self.backups()), 1)

    def test_bad_backup_keep_env_writes_nothing(self):
        self.make_db()
        for bad in ("-1", "1001", "abc"):
            os.environ["BACKUP_KEEP"] = bad
            rc, out, err = self.cli("backup")
            self.assertEqual((rc, out), (2, ""), bad)
            self.assertIn("backup: BACKUP_KEEP must be 0-1000", err)
            self.assertEqual(self.backups(), [], bad)
        os.environ["BACKUP_KEEP"] = "-1"
        self.assertEqual(self.cli("backup", "--keep", "3")[0], 0)  # --keep wins over the env value

    def test_parallel_runs_in_the_same_second(self):
        self.make_db()
        results = []
        with mock.patch.object(maintenance, "_stamp", lambda: "20261107-031500"):
            def run():
                out = []
                rc = maintenance.backup_cmd(["--keep", "0"], out.append)
                results.append((rc, out[0] if out else ""))
            threads = [threading.Thread(target=run) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual([r[0] for r in results], [0, 0], results)
        self.assertEqual(len(self.backups()), 2)
        self.assertEqual(len({r[1].split()[1] for r in results}), 2)

    def test_data_dir_with_doubled_leading_slash(self):
        self.make_db()
        os.environ["DATA_DIR"] = "/" + self.dir
        rc, out, err = self.cli("backup")
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(len(self.backups()), 1)

    def test_missing_db(self):
        rc, out, err = self.cli("backup")
        self.assertEqual((rc, out), (1, ""))
        self.assertRegex(err, r"^backup failed: cannot open .*leasewatch\.sqlite3: .+\n$")
        self.assertEqual(err.count("\n"), 1)
        self.assertEqual(os.listdir(self.dir), [])
        rc, out, err = self.cli("vacuum")
        self.assertEqual(rc, 1)
        self.assertTrue(err.startswith("vacuum failed: cannot open "))
        self.assertEqual(os.listdir(self.dir), [])

    def test_to_existing_file_and_keep_conflict(self):
        self.make_db()
        target = os.path.join(self.dir, "mine.sqlite3")
        open(target, "w").close()
        rc, _, err = self.cli("backup", "--to", target)
        self.assertEqual(rc, 2)
        self.assertEqual(err, f"backup: {target} exists\n")
        self.assertEqual(os.path.getsize(target), 0)
        rc, _, err = self.cli("backup", "--to", os.path.join(self.dir, "new.sqlite3"), "--keep", "2")
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "new.sqlite3")))
        self.assertEqual(self.cli("backup", "--keep", "5000")[0], 2)

    def test_to_path_writes_one_file(self):
        self.make_db()
        target = os.path.join(self.dir, "one.sqlite3")
        rc, out, err = self.cli("backup", "--to", target)
        self.assertEqual((rc, err), (0, ""))
        self.assertRegex(out, r"^backup: .*one\.sqlite3 \(\d+\.\d MB\)\n$")
        self.assertEqual(sorted(os.listdir(self.dir)), ["leasewatch.sqlite3", "one.sqlite3"])

    def test_backup_while_writing(self):
        self.make_db(100)
        stop = threading.Event()
        errors = []

        def writer():
            con = sqlite3.connect(self.db_path, timeout=5)
            try:
                con.execute("PRAGMA busy_timeout=5000")
                i = 0
                while not stop.is_set():
                    i += 1
                    con.execute("INSERT INTO events(ts, mac, kind, detail) VALUES (?,?,?,?)",
                                (5000 + i, "02:00:00:00:00:02", "ip", "x" * 200))
                    con.commit()
            except sqlite3.Error as e:
                errors.append(e)
            finally:
                con.close()

        t = threading.Thread(target=writer)
        t.start()
        try:
            rc, out, err = self.cli("backup")
        finally:
            stop.set()
            t.join()
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(errors, [])
        path = os.path.join(self.dir, "backups", self.backups()[0])
        con = sqlite3.connect(path)
        try:
            self.assertEqual(con.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertGreaterEqual(con.execute("SELECT count(*) FROM events").fetchone()[0], 100)
        finally:
            con.close()

    def test_backup_ignores_bad_connector_setting(self):
        self.make_db()
        os.environ["LW_CONNECTORS"] = "nope"  # no such instance settings: validate() would refuse
        self.assertEqual(self.cli("backup")[0], 0)

    def test_vacuum_shrinks(self):
        self.make_db(0)
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA busy_timeout=5000")
        con.executemany("INSERT INTO events(ts, mac, kind, detail) VALUES (?,?,?,?)",
                        [(i, "02:00:00:00:00:03", "new", "d" * 100) for i in range(20000)])
        con.commit()
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        con.execute("DELETE FROM events WHERE ts % 2 = 0")
        con.commit()
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        con.close()
        before = os.path.getsize(self.db_path)
        rc, out, err = self.cli("vacuum")
        self.assertEqual((rc, err), (0, ""))
        self.assertRegex(out, r"^vacuum: \d+\.\d MB -> \d+\.\d MB\n$")
        self.assertLess(os.path.getsize(self.db_path), before)
        self.assertFalse(os.path.exists(self.db_path + "-wal") and os.path.getsize(self.db_path + "-wal") > 0)
        self.assertEqual(self.cli("vacuum", "extra")[0], 2)

    def test_backup_keep_setting_validation(self):
        os.environ.update({"BACKUP_KEEP": "abc"})
        self.assertIn("BACKUP_KEEP must be a whole number", Config().validate())
        os.environ["BACKUP_KEEP"] = "1001"
        self.assertIn("BACKUP_KEEP must be 0-1000", Config().validate())
        os.environ["BACKUP_KEEP"] = "-1"
        self.assertIn("BACKUP_KEEP must be 0-1000", Config().validate())
        for ok in ("0", "7", "1000", ""):
            os.environ["BACKUP_KEEP"] = ok
            self.assertFalse([p for p in Config().validate() if "BACKUP_KEEP" in p], ok)
        del os.environ["BACKUP_KEEP"]
        self.assertEqual(Config().backup_keep, 7)


if __name__ == "__main__":
    unittest.main()
