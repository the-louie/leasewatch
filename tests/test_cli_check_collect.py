"""`python -m leasewatch check [instance ...]` and `python -m leasewatch collect <instance> [--json]` (design §6).

The connector is synthetic: a package written into a temporary LW_CONNECTORS_DIR whose MODE setting picks the
behaviour (ok, a failing check() or collect(), an unexpected exception, a hang). Its failure texts deliberately
echo the password and the URL host, so the tests can assert that neither ever reaches stdout or stderr. No network.
"""
from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import sys
import tempfile
import unittest

from _env import clean_env, restore

import leasewatch.__main__ as m
from leasewatch.connectors import _reset_registry, registry

GROUP = "leasewatch.connectors.v1"
SECRET = "pw-Secret-0123456789"
FILE_SECRET = "file-Token-9876543210"
HOST = "dhcp.example.lan"

CONNECTOR_PY = '''"""A synthetic connector for the check/collect CLI tests."""
import threading
from leasewatch.connectors import Batch, ConnectorError, ConnectorInfo, Setting, SettingsMixin, Sighting
{prelude}

class Conn(SettingsMixin):
    INFO = ConnectorInfo(type={type!r}, version="0.3.0", api_version=1, produces=frozenset({{"sighting"}}),
                         settings=(Setting("url", required=True), Setting("password", required=True, secret=True),
                                   Setting("mode", default="ok")))
    RELEASE = threading.Event()  # set by the test's cleanup: ends a "hang"
    CLOSED = []

    def __init__(self, name, settings, ctx=None):
        self._init_settings(name, settings, ctx)

    def validate(self):
        return self._generic_problems()

    def _leak(self):
        return "refused " + self.settings["password"] + " at " + self.settings["url"]

    def check(self):
        mode = self.settings["mode"]
        if mode == "checkfail":
            raise ConnectorError(self._leak())
        if mode == "crash":
            raise ValueError(self._leak())
        if mode == "hang":
            self.RELEASE.wait(30)

    def collect(self):
        if self.settings["mode"] == "collectfail":
            raise ConnectorError(self._leak())
        if self.settings["mode"] == "notabatch":
            return {{}}
        return Batch(sightings=[Sighting("02-00-00-00-00-2A", "", "DHCP", False, 1762400000, ip="10.0.0.20",
                                         hostname="printer", lease_type="dynamic"),
                                Sighting("nope", "", "dhcp", False, 1762400000)],
                     stats={{"leases": 2}})

    def close(self):
        self.CLOSED.append(self.name)
'''


def make_dist(root: str, dist: str, pkg: str, type_: str, prelude: str = "") -> None:
    """root/dist/{pyproject.toml,pkg/} in LW_CONNECTORS_DIR layout, declaring one connector type."""
    base = os.path.join(root, dist, pkg)
    os.makedirs(base)
    with open(os.path.join(base, "__init__.py"), "w", encoding="utf-8") as f:
        f.write('"""Synthetic test package."""\n')
    with open(os.path.join(base, "connector.py"), "w", encoding="utf-8") as f:
        f.write(CONNECTOR_PY.format(type=type_, prelude=prelude))
    with open(os.path.join(root, dist, "pyproject.toml"), "w", encoding="utf-8") as f:
        f.write(f'[project]\nname = "{dist}"\nversion = "0.3.0"\n\n'
                f'[project.entry-points."{GROUP}"]\n{type_} = "{pkg}.connector:Conn"\n')


def inst(name: str, mode: str = "ok", type_: str = "fakecli", **extra: str) -> dict:
    up = name.upper()
    env = {f"LW_CONNECTOR__{up}__TYPE": type_, f"LW_CONNECTOR__{up}__URL": f"https://{HOST}",
           f"LW_CONNECTOR__{up}__PASSWORD": SECRET, f"LW_CONNECTOR__{up}__MODE": mode}
    env.update({f"LW_CONNECTOR__{up}__{k}": v for k, v in extra.items()})
    return env


class CliBase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.dir = os.path.join(tmp.name, "connectors")
        os.makedirs(self.dir)
        make_dist(self.dir, "lw-fakecli", "lwt_fakecli", "fakecli")
        saved = clean_env({"LW_CONNECTORS_DIR": self.dir})
        before = set(sys.modules)
        root = logging.getLogger()
        handlers, level = list(root.handlers), root.level
        root.handlers = []  # main() calls basicConfig: its handler must write to the captured stderr

        def undo() -> None:
            cls = registry().get("fakecli")
            if cls is not None:
                cls.RELEASE.set()
            root.handlers = handlers
            root.setLevel(level)
            restore(saved)
            for n in set(sys.modules) - before:
                if n.split(".")[0].startswith("lwt_"):
                    del sys.modules[n]
            _reset_registry()

        self.addCleanup(undo)

    def env(self, names: str, *instances: dict) -> None:
        os.environ["LW_CONNECTORS"] = names
        for i in instances:
            os.environ.update(i)

    def cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = m.main(list(argv))
        for h in logging.getLogger().handlers:
            h.flush()
        return rc, out.getvalue(), err.getvalue()

    def assertNoLeak(self, *texts: str) -> None:
        """No secret and no URL host: for error and problem texts."""
        for t in texts:
            for bad in (SECRET, FILE_SECRET, HOST):
                self.assertNotIn(bad, t)

    def assertNoSecret(self, *texts: str) -> None:
        """No secret: for any output (device data may legitimately name the source's host)."""
        for t in texts:
            for bad in (SECRET, FILE_SECRET):
                self.assertNotIn(bad, t)


class TestCheck(CliBase):
    def test_all_ok(self):
        self.env("dhcp1,dhcp2", inst("dhcp1"), inst("dhcp2"))
        rc, out, err = self.cli("check")
        lines = out.splitlines()
        self.assertEqual(rc, 0, out)
        self.assertTrue(lines[0].startswith("connector types: opnsense, snmp_switch, unifi (built-in); fakecli 0.3.0"),
                        lines[0])
        self.assertRegex(lines[1], r"^dhcp1 \(fakecli\): ok \(\d+ ms\)$")
        self.assertRegex(lines[2], r"^dhcp2 \(fakecli\): ok \(\d+ ms\)$")
        self.assertEqual(len(lines), 3)
        self.assertEqual(registry()["fakecli"].CLOSED, ["dhcp1", "dhcp2"])
        self.assertNoLeak(out, err)

    def test_check_failure_is_redacted_and_exit_1(self):
        self.env("dhcp1,dhcp2", inst("dhcp1", "checkfail"), inst("dhcp2"))
        rc, out, err = self.cli("check")
        self.assertEqual(rc, 1, out)
        self.assertIn("dhcp1 (fakecli): check failed: refused *** at https://<host>", out)
        self.assertRegex(out, r"dhcp2 \(fakecli\): ok \(\d+ ms\)")
        self.assertNoLeak(out, err)

    def test_unexpected_exception_shows_its_type_only(self):
        self.env("dhcp1", inst("dhcp1", "crash"))
        rc, out, err = self.cli("check")
        self.assertEqual(rc, 1)
        self.assertIn("dhcp1 (fakecli): check failed: ValueError\n", out)
        self.assertNoLeak(out, err)

    def test_timeout(self):
        self.env("dhcp1", inst("dhcp1", "hang", TIMEOUT="1"))
        rc, out, err = self.cli("check")
        self.assertEqual(rc, 1)
        self.assertIn("dhcp1 (fakecli): check failed: timed out after 1 s", out)

    def test_named_instances_only_and_unknown_name(self):
        self.env("dhcp1,dhcp2", inst("dhcp1"), inst("dhcp2", "checkfail"))
        rc, out, _ = self.cli("check", "dhcp1")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("dhcp2", out)
        rc, out, err = self.cli("check", "dhcp1", "nosuch")
        self.assertEqual(rc, 2)
        self.assertIn("nosuch: not configured (configured: dhcp1, dhcp2)", out)
        self.assertNoLeak(out, err)

    def test_config_problem_disables_the_instance_and_exit_2(self):
        self.env("dhcp1,dhcp2", inst("dhcp1"), inst("dhcp2", TIMEOUT="x"))
        rc, out, err = self.cli("check")
        self.assertEqual(rc, 2)
        self.assertIn("config: connector dhcp2 (fakecli): TIMEOUT must be an integer", out)
        self.assertIn("dhcp2 (fakecli): disabled: connector dhcp2 (fakecli): TIMEOUT must be an integer", out)
        self.assertRegex(out, r"dhcp1 \(fakecli\): ok \(\d+ ms\)")
        # with names, another instance's problem is not shown and does not count
        rc, out, _ = self.cli("check", "dhcp1")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("config:", out)

    def test_lw_connectors_unset_is_exit_2(self):
        rc, out, _ = self.cli("check")
        self.assertEqual(rc, 2)
        self.assertIn("config: LW_CONNECTORS is not set", out)

    def test_secret_file_value_never_printed(self):
        path = os.path.join(self.tmp, "password")
        with open(path, "w", encoding="utf-8") as f:
            f.write(FILE_SECRET + "\n")
        env = inst("dhcp1", "checkfail")
        del env["LW_CONNECTOR__DHCP1__PASSWORD"]
        env["LW_CONNECTOR__DHCP1__PASSWORD_FILE"] = path
        self.env("dhcp1", env)
        rc, out, err = self.cli("check")
        self.assertEqual(rc, 1, out)
        self.assertIn("check failed: refused *** at https://<host>", out)
        self.assertNoLeak(out, err)

    def test_unused_broken_plugin_is_shown(self):
        make_dist(self.dir, "lw-broken", "lwt_broken", "brokencli", prelude="import lwt_does_not_exist")
        self.env("dhcp1", inst("dhcp1"))
        rc, out, err = self.cli("check")
        self.assertEqual(rc, 0, out)  # an unused broken plugin does not stop the server either
        self.assertIn("plugin: brokencli not loaded: ModuleNotFoundError in lwt_broken.connector "
                      "(from LW_CONNECTORS_DIR lw-broken)", out)

    def test_plugin_with_a_built_in_name_is_shown_as_refused(self):
        make_dist(self.dir, "lw-fakefw", "lwt_fakefw", "opnsense")
        self.env("dhcp1", inst("dhcp1"))
        rc, out, err = self.cli("check")
        self.assertEqual(rc, 0, out)  # the built-in stays; nothing configured uses the plugin
        self.assertIn("plugin: opnsense refused: conflicts with the built-in type opnsense; declared by "
                      "LW_CONNECTORS_DIR lw-fakefw", out)
        self.assertNotIn("not loaded", out)

    def test_used_broken_plugin_is_exit_2(self):
        make_dist(self.dir, "lw-broken", "lwt_broken", "brokencli", prelude="import lwt_does_not_exist")
        self.env("dhcp1,dhcp2", inst("dhcp1"), inst("dhcp2", type_="brokencli"))
        rc, out, err = self.cli("check")
        self.assertEqual(rc, 2)
        self.assertIn("dhcp2 (brokencli): disabled: connector dhcp2 (brokencli): cannot be loaded: ", out)
        self.assertNoLeak(out, err)

    def test_load_problem_is_exit_2(self):
        os.environ["LW_CONNECTORS_DIR"] = os.path.join(self.tmp, "missing")
        self.env("dhcp1", inst("dhcp1"))
        rc, out, _ = self.cli("check")
        self.assertEqual(rc, 2)
        self.assertIn(f"config: LW_CONNECTORS_DIR {os.path.join(self.tmp, 'missing')} is not a directory", out)
        # with names too: a load problem is global
        rc, out, _ = self.cli("check", "dhcp1")
        self.assertEqual(rc, 2)
        self.assertIn("is not a directory", out)

    def test_broken_pipe(self):
        class Gone(io.StringIO):
            def write(self, s):
                raise BrokenPipeError(32, "Broken pipe")

            def fileno(self):
                raise io.UnsupportedOperation("fileno")
        self.env("dhcp1", inst("dhcp1"))
        with contextlib.redirect_stdout(Gone()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(m.main(["check"]), 0)
            self.assertEqual(m.main(["collect", "dhcp1", "--json"]), 0)


class TestCollect(CliBase):
    def json_cli(self, *argv: str) -> tuple[int, dict, str]:
        rc, out, err = self.cli("collect", *argv, "--json")
        self.assertNoSecret(out)
        rep = json.loads(out)  # fails on anything but exactly one object
        self.assertNoLeak(err, rep["error"], *rep["problems"])
        return rc, rep, out  # json.loads fails on anything but exactly one object

    def test_json_success_is_the_normalised_batch(self):
        self.env("dhcp1", inst("dhcp1"))
        rc, rep, _ = self.json_cli("dhcp1")
        self.assertEqual(rc, 0)
        self.assertEqual({k: rep[k] for k in ("instance", "type", "ok", "phase", "error", "problems", "attachments")},
                         {"instance": "dhcp1", "type": "fakecli", "ok": True, "phase": "collect", "error": "",
                          "problems": [], "attachments": []})
        self.assertIsInstance(rep["ms"], int)
        self.assertEqual(rep["stats"], {"leases": 2, "dropped": 1})
        self.assertEqual(rep["sightings"], [{
            "mac": "02:00:00:00:00:2a", "source": "dhcp1", "kind": "dhcp", "presence": False,
            "observed_at": 1762400000, "ip": "10.0.0.20", "hostname": "printer", "vendor": "", "network": "",
            "iface": "", "lease_type": "dynamic", "client_id": "", "label": "", "ip6": ""}])
        self.assertEqual(registry()["fakecli"].CLOSED, ["dhcp1"])

    def test_json_check_failure(self):
        self.env("dhcp1", inst("dhcp1", "checkfail"))
        rc, rep, _ = self.json_cli("dhcp1")
        self.assertEqual(rc, 1)
        self.assertEqual((rep["ok"], rep["phase"], rep["error"]), (False, "check", "refused *** at https://<host>"))
        self.assertEqual((rep["sightings"], rep["attachments"]), ([], []))

    def test_json_collect_failure(self):
        self.env("dhcp1", inst("dhcp1", "collectfail"))
        rc, rep, _ = self.json_cli("dhcp1")
        self.assertEqual(rc, 1)
        self.assertEqual((rep["ok"], rep["phase"], rep["error"]), (False, "collect", "refused *** at https://<host>"))

    def test_json_not_a_batch(self):
        self.env("dhcp1", inst("dhcp1", "notabatch"))
        rc, rep, _ = self.json_cli("dhcp1")
        self.assertEqual((rc, rep["phase"], rep["error"]), (1, "collect", "collect() did not return a Batch"))

    def test_json_timeout(self):
        self.env("dhcp1", inst("dhcp1", "hang", TIMEOUT="1"))
        rc, rep, _ = self.json_cli("dhcp1")
        self.assertEqual((rc, rep["phase"], rep["error"]), (1, "check", "timed out after 1 s"))

    def test_json_unknown_instance(self):
        self.env("dhcp1", inst("dhcp1"))
        rc, rep, _ = self.json_cli("nosuch")
        self.assertEqual(rc, 2)
        self.assertEqual((rep["ok"], rep["phase"], rep["error"]), (False, "validate", "not configured (configured: dhcp1)"))

    def test_json_config_problem(self):
        self.env("dhcp1", inst("dhcp1", TIMEOUT="x"))
        rc, rep, _ = self.json_cli("dhcp1")
        self.assertEqual(rc, 2)
        self.assertEqual((rep["ok"], rep["phase"]), (False, "validate"))
        self.assertEqual(rep["problems"], ["connector dhcp1 (fakecli): TIMEOUT must be an integer"])
        self.assertEqual(rep["ms"], 0)  # not probed

    def test_json_load_problem(self):
        os.environ["LW_CONNECTORS_DIR"] = os.path.join(self.tmp, "missing")
        self.env("dhcp1", inst("dhcp1"))
        rc, rep, _ = self.json_cli("dhcp1")
        self.assertEqual((rc, rep["ok"]), (2, False))
        self.assertTrue(any("is not a directory" in p for p in rep["problems"]), rep)

    def test_human_output(self):
        self.env("dhcp1", inst("dhcp1"))
        rc, out, err = self.cli("collect", "dhcp1")
        self.assertEqual(rc, 0, out)
        lines = out.splitlines()
        self.assertRegex(lines[0], r"^dhcp1 \(fakecli\): 1 sightings, 0 attachments, \d+ ms$")
        self.assertEqual(lines[1], "stats: dropped=1 leases=2")
        self.assertEqual(lines[2], "sighting mac=02:00:00:00:00:2a source=dhcp1 kind=dhcp presence=False "
                                   "observed_at=1762400000 ip=10.0.0.20 hostname=printer lease_type=dynamic")
        self.assertEqual(len(lines), 3)
        self.assertNoSecret(out)
        self.assertNoLeak(err)

    def test_sighting_with_the_host_ip_is_not_masked(self):
        # the host mask is for error texts only: a firewall lists its own address in its ARP table
        self.env("dhcp1", inst("dhcp1", URL="https://10.0.0.20"))
        rc, rep, _ = self.json_cli("dhcp1")
        self.assertEqual((rc, rep["sightings"][0]["ip"]), (0, "10.0.0.20"))
        rc, out, err = self.cli("collect", "dhcp1")
        self.assertEqual(rc, 0, out)
        self.assertIn(" ip=10.0.0.20 ", out.splitlines()[2])
        self.assertNoSecret(out)
        self.assertNoLeak(err)

    def test_error_masks_the_host_ip(self):
        self.env("dhcp1", inst("dhcp1", "collectfail", URL="https://10.0.0.20"))
        rc, rep, out = self.json_cli("dhcp1")
        self.assertEqual((rc, rep["error"]), (1, "refused *** at https://<host>"))
        self.assertNotIn("10.0.0.20", out)

    def test_human_failure(self):
        self.env("dhcp1", inst("dhcp1", "collectfail"))
        rc, out, err = self.cli("collect", "dhcp1")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "dhcp1 (fakecli): collect failed: refused *** at https://<host>\n")
        self.assertNoLeak(out, err)

    def test_no_instance_is_a_usage_error(self):
        rc, out, _ = self.cli("collect")
        self.assertEqual((rc, out), (2, ""))


class TestUnifiApiKey(CliBase):
    """The built-in unifi connector with AUTH=apikey against the local stub console of test_unifi_key."""

    def setUp(self) -> None:
        super().setUp()
        from test_unifi_key import Console
        self.con = Console()
        self.addCleanup(self.con.close)
        self.env("unifi", inst("unifi", type_="unifi", URL=self.con.url, AUTH="apikey", API_KEY=self.key(),
                               PLATFORM="unifi_os", VERIFY_TLS="0"))
        for k in ("PASSWORD", "MODE"):  # inst() sets the synthetic connector's settings
            os.environ.pop(f"LW_CONNECTOR__UNIFI__{k}")

    @staticmethod
    def key() -> str:
        from test_unifi_key import KEY
        return KEY

    def test_check(self):
        rc, out, err = self.cli("check", "unifi")
        self.assertEqual(rc, 0, out + err)
        self.assertRegex(out.splitlines()[-1], r"^unifi \(unifi\): ok \(\d+ ms\)$")
        self.assertNotIn(self.key(), out + err)

    def test_collect_json(self):
        rc, out, err = self.cli("collect", "unifi", "--json")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn(self.key(), out + err)
        rep = json.loads(out)
        self.assertEqual((rep["ok"], rep["stats"]), (True, {"clients": 4, "ssid_unavailable": 1, "dropped": 0}))  # the host adds "dropped"; key mode reports no SSIDs
        self.assertEqual(len(rep["attachments"]), 4)
        for a in rep["attachments"]:
            self.assertEqual((a["ssid"], a["signal"], a["present"]), ("", None, True))
        self.assertEqual({a["link"] for a in rep["attachments"]}, {"wifi", "wired"})


if __name__ == "__main__":
    unittest.main()
