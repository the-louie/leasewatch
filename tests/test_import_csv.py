"""The `import-csv` command (leasewatch/importer.py): the device CSV export read back, also as a spreadsheet saves it.
Synthetic data only: private MACs."""
import contextlib, csv, io, os, sqlite3, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore
import leasewatch.__main__ as m
from leasewatch import importer
from leasewatch.db import Database
from leasewatch.web import _CSV_HEADER, _csv_cell, _csv_row

A, B, C, D = "02:00:00:00:50:01", "02:00:00:00:50:02", "02:00:00:00:50:03", "02:00:00:00:50:04"
GONE = "02:00:00:00:50:ff"
# mac, name, note, acked, archived_ts, watch
SEED = [(A, "Printer", "=SUM(A1:A9)", 1, None, 1),
        (B, "Kids tablet", "line one\n=cmd|' /C calc'!A0\nend; @x", 0, 1_700_000_000, 0),
        (C, "", "", 1, None, 0),
        (D, "-dash name", "plain", 0, None, 1)]
WIPE = "UPDATE devices SET name='', note='', acked=0, acked_at=NULL, archived_ts=NULL, watch=0"


class UncellTests(unittest.TestCase):
    def test_inverse_of_the_export(self):
        for s in ["", "'", "x", "=1", "+1", "-1", "@a", "\tx", "\rx", "a;=b", 'a; "=b', "a;;=b", "a\r\n=b", "a\n+b",
                  "a\r=b", "a;\n=b", ";=", "\r\n\r\n-", "a\r\n\tb", "it's", "a;'b", "x\r\n", "a; b", '";=']:
            self.assertEqual(importer.uncell(_csv_cell(s)), s, repr(s))

    def test_typed_apostrophe_before_a_formula_character_is_lost(self):
        # the export leaves "'-x" as it is, and the reader cannot tell it from an exported "-x"
        self.assertEqual(_csv_cell("'-x"), "'-x")
        self.assertEqual(importer.uncell("'-x"), "-x")
        self.assertEqual(importer.uncell("it's"), "it's")


class ParseTests(unittest.TestCase):
    def test_values(self):
        text = ("mac,name,acked,watch,archived,extra\r\n"
                "02-00-00-00-50-01,'=x,yes,,2026-01-01T10:00+0100,z\r\n"
                f"{B},b,0,TRUE,,\r\n"
                f"{C},c,2,1,,\r\n"
                ",,,,,\r\n")
        plan = importer.parse_csv(text)
        self.assertEqual(plan.rows, [{"mac": A, "name": "=x", "acked": True, "archived": True},
                                     {"mac": B, "name": "b", "acked": False, "watch": True, "archived": False}])
        self.assertEqual(plan.bad, [(4, "acked is '2', not 0 or 1")])
        self.assertEqual(plan.ignored_columns, ["extra"])
        self.assertEqual(plan.total, 3)

    def test_no_mac_column(self):
        with self.assertRaisesRegex(ValueError, "no mac column"):
            importer.parse_csv("name,note\r\nx,y\r\n")

    def test_unknown_field(self):
        with self.assertRaisesRegex(ValueError, "unknown field"):
            importer.parse_csv("mac\r\n", ["name", "ip"])

    def test_not_utf8(self):
        with self.assertRaisesRegex(ValueError, "not UTF-8"):
            importer.parse_csv("mac;name\r\n02:00:00:00:50:01;Sk\xe5p\r\n".encode("cp1252"))

    def test_csv_error_is_a_value_error(self):
        with self.assertRaisesRegex(ValueError, "^line 2: field larger than field limit"):
            importer.parse_csv(f"mac,note\n{A},{'x' * 200_000}\n")

    def test_multiline_cell_keeps_the_line_numbers(self):
        plan = importer.parse_csv(f'mac,note\n{A},"a\nb"\nbad,x\n')
        self.assertEqual(plan.bad, [(4, "bad MAC 'bad'")])


class ImportCsvTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self._env = clean_env({"DATA_DIR": self.dir})
        self.addCleanup(restore, self._env)
        self.db_path = os.path.join(self.dir, "leasewatch.sqlite3")

    def make_db(self) -> None:
        db = Database(self.db_path)
        try:
            for mac, name, note, acked, arch, watch in SEED:
                db.q("INSERT INTO devices(mac, first_seen, last_seen, baseline, name, note, acked, acked_at, archived_ts, watch)"
                     " VALUES (?,?,?,0,?,?,?,?,?,?)", (mac, 100, 200, name, note, acked, 300 if acked else None, arch, watch))
        finally:
            db.close()

    def export(self) -> bytes:
        """The bytes GET /api/devices.csv sends."""
        db = Database(self.db_path)
        try:
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(_CSV_HEADER)
            for d in db.devices():
                w.writerow(_csv_row(d))
        finally:
            db.close()
        return buf.getvalue().encode("utf-8-sig")

    def sql(self, query: str, params: tuple = ()) -> list:
        con = sqlite3.connect(self.db_path)
        try:
            with con:
                return con.execute(query, params).fetchall()
        finally:
            con.close()

    def state(self) -> list:
        return self.sql("SELECT mac, name, note, acked, archived_ts IS NOT NULL, watch FROM devices ORDER BY mac")

    def write(self, data: bytes | str, name: str = "in.csv") -> str:
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data.encode("utf-8") if isinstance(data, str) else data)
        return path

    def run_cmd(self, *argv: str):
        lines, err = [], io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = importer.import_csv_cmd(list(argv), lines.append)
        return rc, lines, err.getvalue()

    def expected(self) -> list:
        return [(mac, name, note, acked, int(arch is not None), watch) for mac, name, note, acked, arch, watch in SEED]

    def test_round_trip_of_the_export(self):
        self.make_db()
        path = self.write(self.export())
        self.sql(WIPE)
        events = self.sql("SELECT count(*) FROM events")[0][0]
        rc, lines, err = self.run_cmd(path)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(lines, ["import-csv: 4 rows, 4 updated, 0 unchanged"])
        self.assertEqual(self.state(), self.expected())
        self.assertGreater(self.sql("SELECT count(*) FROM events")[0][0], events)
        # a second run finds everything in place
        self.assertEqual(self.run_cmd(path)[1], ["import-csv: 4 rows, 0 updated, 4 unchanged"])

    def test_swedish_excel_file(self):
        # "CSV UTF-8" from Excel with a ';' list separator: ';', CRLF, the BOM dropped by a later editor
        self.make_db()
        text = self.export().decode("utf-8-sig")
        rows = list(csv.reader(io.StringIO(text, newline="")))
        buf = io.StringIO()
        csv.writer(buf, delimiter=";", lineterminator="\r\n").writerows(rows)
        path = self.write(buf.getvalue())
        self.sql(WIPE)
        rc, lines, err = self.run_cmd(path)
        self.assertEqual((rc, lines, err), (0, ["import-csv: 4 rows, 4 updated, 0 unchanged"], ""))
        self.assertEqual(self.state(), self.expected())

    def test_formula_note_round_trips(self):
        self.make_db()
        data = self.export()
        self.assertIn(b"'=SUM(A1:A9)", data)
        path = self.write(data)
        self.sql(WIPE)
        self.run_cmd(path)
        self.assertEqual(self.sql("SELECT note FROM devices WHERE mac=?", (A,)), [("=SUM(A1:A9)",)])

    def test_note_typed_with_apostrophe_dash_loses_the_apostrophe(self):
        self.make_db()
        self.sql("UPDATE devices SET note=? WHERE mac=?", ("'-not a formula", A))
        path = self.write(self.export())
        self.sql(WIPE)
        self.run_cmd(path)
        self.assertEqual(self.sql("SELECT note FROM devices WHERE mac=?", (A,)), [("-not a formula",)])

    def test_mangled_and_unknown_macs(self):
        self.make_db()
        path = self.write(f"mac;name\r\n02:0:0:0:0:1;x\r\n2.0E+10;y\r\n{GONE};z\r\n{A};Printer\r\n")
        rc, lines, err = self.run_cmd(path)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(lines, ["import-csv: 4 rows, 0 updated, 1 unchanged, 1 unknown MAC, 2 skipped (bad row)",
                                 f"  unknown: {GONE}",
                                 "  skipped line 2: bad MAC '02:0:0:0:0:1'",
                                 "  skipped line 3: bad MAC '2.0E+10'"])

    def test_duplicates_counted(self):
        self.make_db()
        path = self.write(f"mac,note\r\n{C},one\r\n{C},two\r\n")  # one MAC twice: listed once, the later row wins
        rc, lines, _ = self.run_cmd(path)
        self.assertEqual(lines, ["import-csv: 2 rows, 1 updated, 0 unchanged, 1 duplicates"])
        self.assertEqual(self.sql("SELECT note FROM devices WHERE mac=?", (C,)), [("two",)])

    def test_dry_run_writes_nothing(self):
        self.make_db()
        path = self.write(self.export())
        self.sql(WIPE)
        before, events = self.state(), self.sql("SELECT count(*) FROM events")[0][0]
        rc, dry, err = self.run_cmd(path, "--dry-run")
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual((self.state(), self.sql("SELECT count(*) FROM events")[0][0]), (before, events))
        rc, real, _ = self.run_cmd(path)
        self.assertEqual(dry, ["import-csv (dry run): 4 rows, 4 updated, 0 unchanged"])
        self.assertEqual(real, ["import-csv: 4 rows, 4 updated, 0 unchanged"])

    def test_overwrite_replaces_a_name(self):
        self.make_db()
        path = self.write(f"mac,name\r\n{A},Laser printer\r\n")
        self.assertEqual(self.run_cmd(path)[1], ["import-csv: 1 rows, 0 updated, 1 unchanged"])
        self.assertEqual(self.sql("SELECT name FROM devices WHERE mac=?", (A,)), [("Printer",)])
        rc, lines, _ = self.run_cmd(path, "--overwrite")
        self.assertEqual(lines, ["import-csv: 1 rows, 1 updated, 0 unchanged"])
        self.assertEqual(self.sql("SELECT name FROM devices WHERE mac=?", (A,)), [("Laser printer",)])

    def test_fields_name_ignores_the_rest(self):
        self.make_db()
        path = self.write(self.export())
        self.sql(WIPE)
        self.assertEqual(self.run_cmd(path, "--fields", "name")[0], 0)
        self.assertEqual(self.state(), [(A, "Printer", "", 0, 0, 0), (B, "Kids tablet", "", 0, 0, 0),
                                        (C, "", "", 0, 0, 0), (D, "-dash name", "", 0, 0, 0)])

    def test_bad_fields_and_both_modes_are_usage_errors(self):
        path = self.write(f"mac\r\n{A}\r\n")
        rc, lines, err = self.run_cmd(path, "--fields", "name,ip")
        self.assertEqual((rc, lines), (2, []))
        self.assertIn("unknown field 'ip'", err)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            importer.import_csv_cmd([path, "--fill-empty", "--overwrite"], print)
        self.assertEqual(cm.exception.code, 2)

    def test_missing_db_is_refused_and_not_created(self):
        path = self.write(f"mac,name\r\n{A},x\r\n")
        rc, lines, err = self.run_cmd(path)
        self.assertEqual((rc, lines), (1, []))
        self.assertTrue(err.startswith("import-csv failed: no database at "), err)
        self.assertFalse(os.path.exists(self.db_path))

    def test_no_mac_column(self):
        self.make_db()
        rc, lines, err = self.run_cmd(self.write("name;note\r\nx;y\r\n"))
        self.assertEqual((rc, lines, err), (2, [], "import-csv: no mac column in the header\n"))

    def test_unreadable_and_not_utf8(self):
        self.make_db()
        rc, _, err = self.run_cmd(os.path.join(self.dir, "missing.csv"))
        self.assertEqual(rc, 2)
        self.assertTrue(err.startswith("import-csv: cannot read "), err)
        rc, _, err = self.run_cmd(self.write("mac;name\r\n02:00:00:00:50:01;Sk\xe5p\r\n".encode("cp1252")))
        self.assertEqual((rc, err), (2, "import-csv: not UTF-8 (save the file as CSV UTF-8)\n"))

    def test_too_many_rows(self):
        self.make_db()
        path = self.write("mac\n" + f"{A}\n" * 20_001)
        rc, lines, err = self.run_cmd(path)
        self.assertEqual((rc, lines, err), (2, [], "import-csv: more than 20000 rows\n"))
        self.assertEqual(self.run_cmd(self.write("mac\n" + f"{A}\n" * 20_000))[0], 0)

    def test_too_large(self):
        self.make_db()
        path = self.write("mac,note\n" + f"{A},{'x' * 900}\n" * 1200)
        self.assertEqual(self.run_cmd(path)[:3:2], (2, "import-csv: file larger than 1 MiB\n"))

    def test_only_the_first_twenty_details_are_listed(self):
        self.make_db()
        path = self.write("mac\n" + "".join(f"02:00:00:00:51:{i:02x}\n" for i in range(25)))
        rc, lines, _ = self.run_cmd(path)
        self.assertEqual(lines[0], "import-csv: 25 rows, 0 updated, 0 unchanged, 25 unknown MAC")
        self.assertEqual(len(lines), 21)

    def test_main_dispatch(self):
        self.assertIn("import-csv", m.SUBCOMMANDS)
        self.make_db()
        path = self.write(self.export())
        self.sql(WIPE)
        live = Database(self.db_path)  # a running service's connection
        try:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = m.main(["import-csv", path])
            self.assertEqual((rc, err.getvalue()), (0, ""))
            self.assertEqual(out.getvalue(), "import-csv: 4 rows, 4 updated, 0 unchanged\n")
            self.assertEqual(live.device(A)["name"], "Printer")
        finally:
            live.close()


if __name__ == "__main__":
    unittest.main()
