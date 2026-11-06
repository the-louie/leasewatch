"""QA 1.1 regression tests for the command line (`python -m leasewatch ...`, leasewatch/__main__.py)."""
import contextlib, io, logging, os, sqlite3, subprocess, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore
import leasewatch.__main__ as m
from leasewatch import switch

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
KEYS = {"TEST_AK": "test-auth-key", "TEST_PK": "test-priv-key"}
FLAGS = ("--host", "10.0.0.2", "--auth-key-env", "TEST_AK", "--priv-key-env", "TEST_PK")


def report(descr: str, walk_value: str) -> dict:
    return {"sysobjectid": "1.3.6.1.4.1.25506", "sysdescr": descr, "detected": "standard", "profile": "standard",
            "given": False, "walks": [("ifname (1.3.6.1.2.1.31.1.1.1.1)", [("1.3.6.1.2.1.31.1.1.1.1.1", walk_value)])]}


class CliTests(unittest.TestCase):
    def setUp(self):
        self._env = clean_env(KEYS)
        self.addCleanup(restore, self._env)
        root = logging.getLogger()  # main() calls basicConfig; keep the test run's handlers as they were
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)
        p = mock.patch.object(m, "_pysnmp_problem", lambda: "")
        p.start()
        self.addCleanup(p.stop)

    def cli(self, *argv: str) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = m.main(list(argv))
        return rc, buf.getvalue()

    def detect_with(self, rep: dict, *argv: str) -> tuple[int, str]:
        with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: rep):
            return self.cli("snmp-detect", *(argv or FLAGS))

    # R08, R12: device strings reach the terminal with ESC/BEL intact
    def test_control_characters_from_the_switch_are_escaped(self):
        rc, out = self.detect_with(report("Sw\x1b]0;x\x07\x1b[2J", "Gi1\x1b[1A\x1b[2Kfake"))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertIn("sysDescr:    Sw\\x1b]0;x\\x07\\x1b[2J", out)
        self.assertIn("= Gi1\\x1b[1A\\x1b[2Kfake", out)

    # R13, R109: a non-ASCII device value on an ASCII-only stdout
    def test_ascii_stdout_does_not_crash_on_a_non_ascii_value(self):
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="ascii", newline="\n")
        try:
            with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: report("HP Sw\xff 5130 –", "Port\xe9")), \
                    contextlib.redirect_stdout(out):
                rc = m.main(["snmp-detect", *FLAGS])
            out.flush()
            text = raw.getvalue().decode("ascii")
        finally:
            out.close()
        self.assertEqual(rc, 0, text)
        self.assertIn("sysDescr:    HP Sw\\xff 5130 \\u2013", text)
        self.assertIn("= Port\\xe9", text)

    # R07: `snmp-detect ... | head` closed the pipe
    def test_broken_pipe_is_not_a_traceback(self):
        class Gone(io.StringIO):
            def write(self, s):
                raise BrokenPipeError(32, "Broken pipe")

            def fileno(self):
                raise io.UnsupportedOperation("fileno")
        with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: report("Sw", "Gi1")), \
                contextlib.redirect_stdout(Gone()):
            rc = m.main(["snmp-detect", *FLAGS])
        self.assertEqual(rc, 0)

    def test_broken_pipe_at_exit_flush_prints_nothing(self):
        r, w = os.pipe()
        os.close(r)  # the reader is gone before the first write
        env = dict(os.environ, PYTHONPATH=ROOT)
        try:
            p = subprocess.run([sys.executable, "-m", "leasewatch", "snmp-profiles"], stdout=w, stderr=subprocess.PIPE,
                               env=env, cwd=ROOT, timeout=60)
        finally:
            os.close(w)
        self.assertEqual((p.returncode, p.stderr.decode()), (0, ""))

    # S01x: a key variable that is set but empty
    def test_empty_key_variable_is_named(self):
        os.environ["TEST_AK"] = ""
        rc, out = self.cli("snmp-detect", *FLAGS)
        self.assertEqual(rc, 2)
        self.assertEqual(out.strip(), "environment variable TEST_AK (from --auth-key-env) is not set or empty")

    # --host has no default key variable names: the operator names them
    def test_host_without_key_variable_flags_names_the_flag(self):
        os.environ.update({"TEST_AK": "test-auth-key", "TEST_PK": "test-priv-key"})
        rc, out = self.cli("snmp-detect", "--host", "10.0.0.2", "--priv-key-env", "TEST_PK")
        self.assertEqual((rc, out.strip()), (2, "--host needs --auth-key-env (the name of the environment variable that holds the key)"))
        rc, out = self.cli("snmp-detect", "--host", "10.0.0.2", "--auth-key-env", "TEST_AK")
        self.assertEqual((rc, out.strip()), (2, "--host needs --priv-key-env (the name of the environment variable that holds the key)"))

    # R11: the removed 1.0 switch variables are refused by name, never with their values
    def test_removed_switch_variables_are_named(self):
        os.environ.update({"SNMP_HOST": "10.0.0.2", "SNMP_AUTH_KEY": "test-auth-key"})
        rc, out = self.cli("snmp-detect", "switch")
        self.assertEqual(rc, 2)
        self.assertIn("config: SNMP_HOST, SNMP_AUTH_KEY are no longer supported: configure the switch as "
                      "LW_CONNECTORS=fw1,switch with LW_CONNECTOR__SWITCH__TYPE=snmp_switch", out)
        self.assertNotIn("test-auth-key", out)
        self.assertNotIn("10.0.0.2", out)

    # R10: parse and host-level problems of the instance
    def sw(self, **extra: str) -> None:
        os.environ.update({"LW_CONNECTORS": "sw", "LW_CONNECTOR__SW__TYPE": "snmp_switch", "LW_CONNECTOR__SW__HOST": "10.0.0.2",
                           "LW_CONNECTOR__SW__AUTH_KEY": "test-auth-key", "LW_CONNECTOR__SW__PRIV_KEY": "test-priv-key"})
        os.environ.update({f"LW_CONNECTOR__SW__{k}": v for k, v in extra.items()})

    def test_instance_with_a_type_typo_names_the_type(self):
        self.sw(TYPE="snmp-switch")
        rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 2)
        self.assertIn("connector sw: unknown type 'snmp-switch'", out)

    def test_instance_with_an_unreadable_key_file_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            self.sw(AUTH_KEY_FILE=os.path.join(d, "missing"))
            del os.environ["LW_CONNECTOR__SW__AUTH_KEY"]
            rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 2)
        self.assertIn("connector sw (snmp_switch): cannot read AUTH_KEY_FILE", out)

    def test_instance_with_a_bad_host_setting_is_not_probed(self):
        self.sw(TIMEOUT="x")
        probed = []
        with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: probed.append(n) or report("Sw", "Gi1")):
            rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual((rc, probed), (2, []), out)
        self.assertIn("TIMEOUT", out)

    # Z04/Z05: a removed 1.0 variable stops the server whatever the instance is called, so it stops snmp-detect for
    # every name, not only for the "switch" its hint happens to name
    def test_removed_variable_blocks_every_instance_name(self):
        for name in ("switch", "sw"):
            with self.subTest(name=name):
                for k in [k for k in os.environ if k.startswith("LW_CONNECTOR")]:
                    del os.environ[k]
                u = name.upper()
                os.environ.update({"LW_CONNECTORS": name, f"LW_CONNECTOR__{u}__TYPE": "snmp_switch",
                                   f"LW_CONNECTOR__{u}__HOST": "10.0.0.2", f"LW_CONNECTOR__{u}__AUTH_KEY": "test-auth-key",
                                   f"LW_CONNECTOR__{u}__PRIV_KEY": "test-priv-key", "SNMP_HOST": "10.0.0.9"})
                probed = []
                with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: probed.append(n) or report("Sw", "Gi1")):
                    rc, out = self.cli("snmp-detect", name)
                self.assertEqual((rc, probed), (2, []), out)
                self.assertIn("config: SNMP_HOST is no longer supported", out)
                self.assertNotIn("10.0.0.9", out)

    def test_a_good_instance_still_runs(self):
        self.sw()
        rc, out = self.detect_with(report("Sw", "Gi1"), "sw")
        self.assertEqual(rc, 0, out)
        self.assertIn("= Gi1", out)


class PysnmpProbeTests(unittest.TestCase):
    # R09: an import that fails with something other than ImportError
    def test_a_broken_pysnmp_install_is_not_a_traceback(self):
        saved = clean_env()
        self.addCleanup(restore, saved)
        root = logging.getLogger()
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)
        real = __import__

        def broken(name, *a, **k):
            if name.startswith("pysnmp"):
                raise AttributeError("module 'pyasn1' has no attribute 'x'")
            return real(name, *a, **k)
        buf = io.StringIO()
        with mock.patch("builtins.__import__", broken), contextlib.redirect_stdout(buf), \
                self.assertLogs("leasewatch", "WARNING") as logs:
            rc = m.main(["snmp-profiles"])
        self.assertEqual(rc, 0)
        self.assertIn("detection order:", buf.getvalue())
        self.assertIn("cannot be imported (AttributeError)", logs.output[0])


class Round2CliTests(unittest.TestCase):
    def setUp(self):
        self._env = clean_env(KEYS)
        self.addCleanup(restore, self._env)
        root = logging.getLogger()
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)
        p = mock.patch.object(m, "_pysnmp_problem", lambda: "")
        p.start()
        self.addCleanup(p.stop)

    def cli(self, *argv: str) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = m.main(list(argv))
        return rc, buf.getvalue()

    def sw(self, **env: str) -> None:
        os.environ.update({"LW_CONNECTOR__SW__TYPE": "snmp_switch", "LW_CONNECTOR__SW__HOST": "10.0.0.2",
                           "LW_CONNECTOR__SW__AUTH_KEY": "test-auth-key", "LW_CONNECTOR__SW__PRIV_KEY": "test-priv-key"})
        os.environ.update(env)

    # V70: a key variable that holds only whitespace is as empty as an unset one (the server strips it)
    def test_blank_key_variable_is_named(self):
        os.environ["TEST_AK"] = "  "
        rc, out = self.cli("snmp-detect", *FLAGS)
        self.assertEqual((rc, out.strip()), (2, "environment variable TEST_AK (from --auth-key-env) is not set or empty"))

    # V71: Ctrl-C during a subcommand
    def test_ctrl_c_is_not_a_traceback(self):
        def interrupted(argv):
            raise KeyboardInterrupt
        with mock.patch.object(m, "snmp_detect_cmd", interrupted):
            rc, _ = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 130)

    # V26: the reader went away at the final flush of a failed run
    def test_broken_pipe_keeps_a_failure_exit_code(self):
        class GoneAtFlush(io.StringIO):
            def flush(self):
                raise BrokenPipeError(32, "Broken pipe")

            def fileno(self):
                raise io.UnsupportedOperation("fileno")
        os.environ["TEST_AK"] = ""
        with contextlib.redirect_stdout(GoneAtFlush()):
            rc = m.main(["snmp-detect", *FLAGS])
        self.assertEqual(rc, 2)

    # V45: the parse problem that explains why the instance is missing
    def test_instance_not_in_the_list_names_the_cause(self):
        self.sw(LW_CONNECTORS="fw1", LW_CONNECTOR__FW1__TYPE="opnsense")
        rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 2)
        self.assertIn("config: LW_CONNECTOR__SW__AUTH_KEY set but sw is not in LW_CONNECTORS", out)

    def test_instance_with_an_invalid_list_name_names_the_cause(self):
        self.sw(LW_CONNECTORS="SW")
        rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 2)
        # Z01: the invalid name is the cause; "sw is not in LW_CONNECTORS" would contradict the SW the operator listed
        self.assertIn("config: LW_CONNECTORS: 'SW' is not a valid instance name", out)
        self.assertNotIn("not in LW_CONNECTORS", out)

    def test_instance_without_a_list_names_the_cause(self):
        self.sw()
        rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 2)
        self.assertIn("config: LW_CONNECTOR__SW__AUTH_KEY set but sw is not in LW_CONNECTORS", out)
        self.assertIn("config: LW_CONNECTORS is not set", out)

    # V46: two spellings of the same key variable; the server refuses to start, so the switch is not probed
    def test_case_duplicate_key_variable_is_not_probed(self):
        self.sw(LW_CONNECTORS="sw", LW_CONNECTOR__sw__AUTH_KEY="other-auth-key")
        probed = []
        with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: probed.append(n) or report("Sw", "Gi1")):
            rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual((rc, probed), (2, []), out)
        self.assertIn("differ only in case", out)

    def test_another_instances_problem_does_not_block_the_probe(self):
        self.sw(LW_CONNECTORS="sw", LW_CONNECTOR__FW2__TYPE="opnsense")
        with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: report("Sw", "Gi1")):
            rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 0, out)

    # W17: the BrokenPipeError path with a stdout that has no file descriptor must not leak /dev/null
    def test_broken_pipe_without_a_fileno_leaks_no_descriptor(self):
        class Gone(io.StringIO):
            def write(self, s):
                raise BrokenPipeError(32, "Broken pipe")

            def fileno(self):
                raise io.UnsupportedOperation("fileno")
        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: report("Sw", "Gi1")):
            for _ in range(5):
                with contextlib.redirect_stdout(Gone()):
                    self.assertEqual(m.main(["snmp-detect", *FLAGS]), 0)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    # W38: --help into a reader that has gone away
    def test_help_into_a_closed_pipe_prints_nothing(self):
        r, w = os.pipe()
        os.close(r)
        env = dict(os.environ, PYTHONPATH=ROOT)
        try:
            p = subprocess.run([sys.executable, "-m", "leasewatch", "snmp-detect", "--help"], stdout=w,
                               stderr=subprocess.PIPE, env=env, cwd=ROOT, timeout=60)
        finally:
            os.close(w)
        self.assertEqual((p.returncode, p.stderr.decode()), (0, ""))

    # W28a, W36: another instance's orphan line is the cause for this one too (LW_CONNECTORS unset)
    def test_without_a_list_another_instances_orphan_line_is_shown(self):
        self.sw(LW_CONNECTOR__AA__TYPE="unifi")
        rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 2)
        self.assertIn("LW_CONNECTORS is not set", out)

    # W28b: the list names the instance in a form the server rejects
    def test_an_invalid_list_name_is_shown_for_that_name(self):
        os.environ["LW_CONNECTORS"] = "SW"
        rc, out = self.cli("snmp-detect", "SW")
        self.assertEqual(rc, 2)
        self.assertIn("'SW' is not a valid instance name", out)

    # W35: the server refuses a name listed twice, so the switch is not probed
    def test_an_instance_listed_twice_is_not_probed(self):
        self.sw(LW_CONNECTORS="sw,sw")
        probed = []
        with mock.patch.object(switch.SwitchClient, "detect_report", lambda self, n: probed.append(n) or report("Sw", "Gi1")):
            rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual((rc, probed), (2, []), out)
        self.assertIn("config: LW_CONNECTORS: sw is listed twice", out)

    # W37: a TYPE typo does not hide the instance's other parse problems
    def test_a_type_typo_keeps_the_other_problems(self):
        self.sw(LW_CONNECTORS="sw", LW_CONNECTOR__SW__TYPE="snmp-switch", LW_CONNECTOR__sw__HOST="10.0.0.3")
        rc, out = self.cli("snmp-detect", "sw")
        self.assertEqual(rc, 2)
        self.assertIn("unknown type 'snmp-switch'", out)
        self.assertIn("differ only in case", out)


class Round2PysnmpProbeTests(unittest.TestCase):
    def setUp(self):
        saved = clean_env()
        self.addCleanup(restore, saved)
        root = logging.getLogger()
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)

    def profiles_with(self, exc: BaseException) -> str:
        real = __import__

        def failing(name, *a, **k):
            if name.startswith("pysnmp"):
                raise exc
            return real(name, *a, **k)
        buf = io.StringIO()
        with mock.patch("builtins.__import__", failing), contextlib.redirect_stdout(buf), \
                self.assertNoLogs("leasewatch", "ERROR"):
            self.assertEqual(m.main(["snmp-profiles"]), 0)
        return buf.getvalue().splitlines()[0]

    # V44: pysnmp is there but a module it needs is not (pysnmp 4.x on Python 3.12: "imp")
    def test_a_missing_dependency_is_not_called_not_installed(self):
        first = self.profiles_with(ModuleNotFoundError("No module named 'imp'", name="imp"))
        self.assertEqual(first, "pysnmp cannot be imported: no module imp (pysnmp 7 and its dependencies are needed)")

    def test_pysnmp_itself_missing_is_still_not_installed(self):
        self.assertEqual(self.profiles_with(ModuleNotFoundError("No module named 'pysnmp'", name="pysnmp")), m.NO_PYSNMP)

    # V25: a broken install is not followed by "not installed ... pip install"
    def test_a_broken_install_does_not_say_not_installed(self):
        first = self.profiles_with(AttributeError("module 'pyasn1' has no attribute 'x'"))
        self.assertNotIn("not installed", first)
        self.assertNotIn("pip install", first)

    # W34: a nameless ImportError comes from inside an installed pysnmp, so pip install does not help
    def test_a_nameless_import_error_is_not_called_not_installed(self):
        first = self.profiles_with(ImportError("pysnmp needs pyasn1>=0.6"))
        self.assertNotIn("not installed", first)
        self.assertNotIn("pip install", first)


    # Y02: "cannot import name" from inside an installed pysnmp is an ImportError naming pysnmp, not a missing one
    def test_a_missing_name_inside_pysnmp_is_not_called_not_installed(self):
        first = self.profiles_with(ImportError("cannot import name 'x' from 'pysnmp'", name="pysnmp"))
        self.assertNotIn("not installed", first)
        self.assertNotIn("pip install", first)

class Round4PysnmpProbeTests(unittest.TestCase):
    # X12: an installed pysnmp whose __init__ imports a missing submodule of its own is not "not installed"
    def test_a_damaged_pysnmp_package_is_not_called_not_installed(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "pysnmp"))
            with open(os.path.join(d, "pysnmp", "__init__.py"), "w") as f:
                f.write("import pysnmp.gone\n")
            env = dict(os.environ, PYTHONPATH=os.pathsep.join((d, ROOT)))
            out = subprocess.run([sys.executable, "-c", "from leasewatch.__main__ import _pysnmp_problem; print(_pysnmp_problem())"],
                                 cwd=d, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn("not installed", out.stdout)
        self.assertNotIn("pip install", out.stdout)
        self.assertIn("pysnmp cannot be imported", out.stdout)


if __name__ == "__main__":
    unittest.main()
