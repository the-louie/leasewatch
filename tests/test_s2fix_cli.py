"""Sprint 2 review fixes for the CLI helpers in leasewatch/__main__.py (check, collect, snmp-detect).

Synthetic data only: the fake connector of test_cli_check_collect, made-up hosts and keys, no network.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_cli_check_collect import CliBase, inst  # noqa: E402

import leasewatch.__main__ as m  # noqa: E402
from leasewatch.connectors import Batch, Sighting, registry  # noqa: E402


class Spec:
    def __init__(self, **settings: str) -> None:
        self.settings = settings


class Ctx:
    @staticmethod
    def redact(text: str) -> str:
        return text


class TestGlobalProblems(CliBase):
    """S2R02, S2R03: a problem that stops the server and belongs to no instance counts for every named command."""

    def test_malformed_variable_blocks_check_and_collect_of_a_name(self):
        self.env("dhcp1", inst("dhcp1"), {"LW_CONNECTOR__DHCP1_MODE": "x"})
        for argv in (("check", "dhcp1"), ("collect", "dhcp1")):
            rc, out, _ = self.cli(*argv)
            self.assertEqual(rc, 2, (argv, out))
            self.assertIn("config: LW_CONNECTOR__DHCP1_MODE is not of the form", out)

    def test_invalid_name_blocks_check_of_another_name(self):
        self.env("dhcp1,FW2", inst("dhcp1"))
        rc, out, _ = self.cli("check", "dhcp1")
        self.assertEqual(rc, 2, out)
        self.assertIn("config: LW_CONNECTORS: 'FW2' is not a valid instance name", out)

    def test_another_instances_orphan_variable_does_not_count(self):
        self.env("dhcp1", inst("dhcp1"), {"LW_CONNECTOR__ZZ__TYPE": "fakecli"})
        rc, out, _ = self.cli("check", "dhcp1")
        self.assertEqual(rc, 0, out)

    def test_snmp_detect_counts_a_load_problem(self):
        os.environ["LW_CONNECTORS_DIR"] = os.path.join(self.tmp, "missing")
        self.env("sw", {"LW_CONNECTOR__SW__TYPE": "snmp_switch", "LW_CONNECTOR__SW__HOST": "10.0.0.2",
                        "LW_CONNECTOR__SW__AUTH_KEY": "authkey-0123456789",
                        "LW_CONNECTOR__SW__PRIV_KEY": "privkey-0123456789"})
        ns = argparse.Namespace(host=None, instance="sw")
        conn, problems, err = m._detect_connector(ns)
        self.assertEqual(err, "")
        self.assertTrue(any("is not a directory" in p for p in problems), problems)


class TestInstanceNameKept(CliBase):
    """S2R04, S2R07, S2R12: an instance named like its host keeps its name; the client's label survives."""

    def test_check_and_collect_lines_keep_the_name(self):
        self.env("dhcp1", inst("dhcp1", "checkfail", URL="https://dhcp1"))
        rc, out, _ = self.cli("check")
        self.assertEqual((rc, out.splitlines()[1]), (1, "dhcp1 (fakecli): check failed: refused *** at https://<host>"))
        os.environ["LW_CONNECTOR__DHCP1__MODE"] = "collectfail"
        rc, out, _ = self.cli("collect", "dhcp1")
        self.assertEqual((rc, out), (1, "dhcp1 (fakecli): collect failed: refused *** at https://<host>\n"))
        os.environ["LW_CONNECTOR__DHCP1__MODE"] = "ok"
        rc, out, _ = self.cli("check")
        self.assertRegex(out.splitlines()[1], r"^dhcp1 \(fakecli\): ok \(\d+ ms\)$")

    def test_client_label_is_kept(self):
        mask = m._redactor(Ctx(), None, Spec(url="https://fw1/"))
        self.assertEqual(mask("fw1 /api/core/firmware/status: HTTP 401 from fw1"),
                         "fw1 /api/core/firmware/status: HTTP 401 from <host>")


class TestOwnRedact(unittest.TestCase):
    """S2R05, S2R46, S2R06, S2R47: the connector's own redact()."""

    def test_device_data_is_not_masked_by_the_connector(self):
        class C:
            def redact(self, text: str) -> str:
                return text.replace("admin", "<user>")
        self.assertEqual(m._redactor(Ctx(), C(), Spec(host="sw"), hosts=False)("port_name=admin"), "port_name=admin")

    def test_non_str_return_is_ignored(self):
        class C:
            def redact(self, text: str) -> None:
                return None
        self.assertEqual(m._redactor(Ctx(), C(), Spec(url="https://sw.example.lan"))("x sw.example.lan"), "x <host>")
        self.assertEqual(m._redactor(Ctx(), C(), Spec(), hosts=False)("x"), "x")


class TestClose(unittest.TestCase):
    """S2R08, S2R48: close() is bounded and never raises out of _close."""

    def test_hanging_close_is_abandoned(self):
        release = threading.Event()
        self.addCleanup(release.set)

        class C:
            def close(self) -> None:
                release.wait(10)
        t0 = time.monotonic()
        with self.assertLogs("leasewatch", "WARNING"):
            m._close(C(), "dhcp1", 1)
        self.assertLess(time.monotonic() - t0, 5)

    def test_raising_name_and_close(self):
        class C:
            @property
            def name(self) -> str:
                raise RuntimeError("name")

            def close(self) -> None:
                raise ValueError("close")
        with self.assertLogs("leasewatch", "WARNING") as cm:
            m._close(C(), "dhcp1", 1)
        self.assertIn("connector dhcp1: close() failed (ValueError)", cm.output[0])


class TestCheckMasksProblems(CliBase):
    """S2R09: check masks the URL host in problem texts, as collect does."""

    def test_problem_text_host_is_masked(self):
        cls = registry()["fakecli"]
        with mock.patch.object(cls, "validate", lambda self: ["cannot reach " + self.settings["url"]]):
            self.env("dhcp1", inst("dhcp1"))
            for argv in (("check",), ("check", "dhcp1")):
                rc, out, err = self.cli(*argv)
                self.assertEqual(rc, 2, out)
                self.assertIn("https://<host>", out)
                self.assertNoLeak(out, err)


class TestCheckBuildsOnce(CliBase):
    """S2R49: a named check builds each instance once and closes what it built."""

    def test_named_builds_once(self):
        cls = registry()["fakecli"]
        builds = []
        orig = cls.__init__

        def counting(self, *a, **k):
            builds.append(1)
            orig(self, *a, **k)
        with mock.patch.object(cls, "__init__", counting):
            self.env("dhcp1", inst("dhcp1"))
            before = len(builds)
            rc, out, _ = self.cli("check", "dhcp1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(builds) - before - _config_builds(self), len(cls.CLOSED))


def _config_builds(case: CliBase) -> int:
    """Builds that Config() itself makes (not the command's own)."""
    cls = registry()["fakecli"]
    n = []
    orig = cls.__init__

    def counting(self, *a, **k):
        n.append(1)
        orig(self, *a, **k)
    with mock.patch.object(cls, "__init__", counting):
        m.Config()
    return len(n)


class TestRecordLine(unittest.TestCase):
    """S2R10: only the declared fields are printed."""

    def test_subclass_extra_field_is_left_out(self):
        @dataclasses.dataclass(frozen=True)
        class S2(Sighting):
            note: str = ""
        line = m._record_line("sighting", S2("02:00:00:00:00:2a", "i", "dhcp", True, 1, note="x\nsighting mac=fake"))
        self.assertNotIn("note", line)
        self.assertNotIn("\n", line)


class Bad:
    def __str__(self) -> str:
        raise ZeroDivisionError


class TestOddStats(CliBase):
    """S2R11, S2R50: stats outside dict[str, int] never break --json or the human line."""

    def test_odd_stats(self):
        cls = registry()["fakecli"]
        stats = {("a", 1): 2, "bad": Bad(), "nan": float("nan"), "leases": 2}
        batch = Batch(sightings=[Sighting("02-00-00-00-00-2A", "", "dhcp", False, 1762400000)], stats=stats)
        with mock.patch.object(cls, "collect", lambda self: batch):
            self.env("dhcp1", inst("dhcp1"))
            rc, out, _ = self.cli("collect", "dhcp1", "--json")
            self.assertEqual(rc, 0, out)

            def no_constant(c: str) -> None:
                raise AssertionError(c)
            rep = json.loads(out, parse_constant=no_constant)
            self.assertEqual(rep["stats"]["leases"], 2)
            self.assertIn("('a', 1)", rep["stats"])
            self.assertEqual(rep["stats"]["bad"], "Bad")
            rc, out, _ = self.cli("collect", "dhcp1")
            self.assertEqual(rc, 0, out)


class TestTypesLine(unittest.TestCase):
    """S2R51: package metadata cannot add a line to the start log."""

    def test_control_characters_are_escaped(self):
        with mock.patch("leasewatch.connectors.type_help", lambda: "x 0.3.0\nERROR forged\x1b"):
            line = m.types_line()
        self.assertEqual(line, "connector types: x 0.3.0\\nERROR forged\\x1b")


if __name__ == "__main__":
    unittest.main()
