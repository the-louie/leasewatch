"""Third-party connector loading: installed entry points and LW_CONNECTORS_DIR packages.

Every plugin here is synthetic and written into a temporary directory by the test itself: a package directory with a
pyproject.toml (LW_CONNECTORS_DIR) or a fake *.dist-info next to a package on sys.path (entry point). Package names
start with "lwt_" so the cleanup can drop them from sys.modules. No test patches the registry: changing
LW_CONNECTORS_DIR or sys.path is enough for registry() to rebuild.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock

from _env import FW1_ENV, clean_env, restore

from leasewatch.config import Config
from leasewatch.connectors import (_reset_registry, instances_context, load_problems, registry,
                                   type_origins)
from leasewatch.connectors.opnsense import OpnsenseConnector

GROUP = "leasewatch.connectors.v1"

CONNECTOR_PY = '''"""A synthetic connector for the loader tests."""
from leasewatch.connectors import Batch, ConnectorInfo, Setting, SettingsMixin
{prelude}

class Conn(SettingsMixin):
    INFO = ConnectorInfo(type={type!r}, version="0.3.0", api_version={api}, produces=frozenset({{"sighting"}}),
                         settings=(Setting("url", required=True), Setting("password", required=True, secret=True)))

    def __init__(self, name, settings, ctx=None):
        self._init_settings(name, settings, ctx)

    def validate(self):
        return self._generic_problems()

    def check(self):
        pass

    def collect(self):
        return Batch()

    def close(self):
        pass
'''


def write_package(base: str, pkg: str, type_: str, api: int = 1, prelude: str = "") -> None:
    """base/pkg/{__init__,connector}.py with one connector class Conn whose describe().type is type_."""
    os.makedirs(os.path.join(base, pkg), exist_ok=True)
    with open(os.path.join(base, pkg, "__init__.py"), "w", encoding="utf-8") as f:
        f.write('"""Synthetic test package."""\n')
    with open(os.path.join(base, pkg, "connector.py"), "w", encoding="utf-8") as f:
        f.write(CONNECTOR_PY.format(type=type_, api=api, prelude=prelude))


def make_dir_dist(root: str, dist: str, pkg: str, type_: str, *, group: str = GROUP, api: int = 1,
                  prelude: str = "", value: str = "") -> str:
    """A distribution in LW_CONNECTORS_DIR layout: root/dist/{pyproject.toml,pkg/}."""
    base = os.path.join(root, dist)
    write_package(base, pkg, type_, api, prelude)
    with open(os.path.join(base, "pyproject.toml"), "w", encoding="utf-8") as f:
        f.write(f'[project]\nname = "{dist}"\nversion = "0.3.0"\n\n'
                f'[project.entry-points."{group}"]\n{type_} = "{value or pkg + ".connector:Conn"}"\n')
    return base


def make_ep_dist(site: str, dist: str, pkg: str, type_: str, *, group: str = GROUP, api: int = 1,
                 prelude: str = "") -> None:
    """An installed distribution: site/<dist>-0.3.0.dist-info (METADATA, entry_points.txt) next to site/pkg/."""
    write_package(site, pkg, type_, api, prelude)
    info = os.path.join(site, f"{dist.replace('-', '_')}-0.3.0.dist-info")
    os.makedirs(info)
    with open(os.path.join(info, "METADATA"), "w", encoding="utf-8") as f:
        f.write(f"Metadata-Version: 2.1\nName: {dist}\nVersion: 0.3.0\n")
    with open(os.path.join(info, "entry_points.txt"), "w", encoding="utf-8") as f:
        f.write(f"[{group}]\n{type_} = {pkg}.connector:Conn\n")


def instance(name: str, type_: str, password: str = "pw-0123456789") -> dict:
    up = name.upper()
    return {f"LW_CONNECTOR__{up}__TYPE": type_, f"LW_CONNECTOR__{up}__URL": "https://dhcp.example.lan",
            f"LW_CONNECTOR__{up}__PASSWORD": password}


class LoaderBase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = os.path.join(tmp.name, "connectors")
        self.site = os.path.join(tmp.name, "site")
        os.makedirs(self.dir)
        os.makedirs(self.site)
        saved_env = clean_env()
        saved_path = list(sys.path)
        saved_cwd = os.getcwd()
        before = set(sys.modules)

        def undo() -> None:
            os.chdir(saved_cwd)
            sys.path[:] = saved_path
            restore(saved_env)
            for name in set(sys.modules) - before:
                if name.split(".")[0].startswith("lwt_"):
                    del sys.modules[name]
            _reset_registry()

        self.addCleanup(undo)

    def use_dir(self) -> None:
        os.environ["LW_CONNECTORS_DIR"] = self.dir

    def use_site(self) -> None:
        sys.path.append(self.site)

    def cfg(self, env: dict) -> Config:
        os.environ.update(env)
        return Config()

    def main_rc(self) -> tuple[int, list[str]]:
        """main() on the server path, which must stop at the config check (exit 2) in these tests."""
        from leasewatch.__main__ import main
        # basicConfig would add a stderr handler to the root logger for the rest of the run
        with mock.patch("logging.basicConfig"), self.assertLogs("leasewatch", "ERROR") as logs:
            rc = main([])
        return rc, logs.output


class TestLoad(LoaderBase):
    def test_package_from_connectors_dir_is_loaded(self):
        make_dir_dist(self.dir, "lw-dirdemo", "lwt_dirdemo", "dirdemo")
        self.use_dir()
        path = list(sys.path)
        self.assertIn("dirdemo", registry())
        self.assertEqual(registry()["dirdemo"].__module__, "lwt_dirdemo.connector")
        self.assertEqual(sys.path, path)  # imported by spec from the dist dir, never through sys.path
        origin = type_origins()["dirdemo"]
        self.assertEqual((origin.kind, origin.dist, origin.version), ("LW_CONNECTORS_DIR", "lw-dirdemo", "0.3.0"))
        self.assertEqual(load_problems(), [])
        cfg = self.cfg({"LW_CONNECTORS": "dhcp1", **instance("dhcp1", "dirdemo")})
        self.assertEqual(cfg.validate(), [])

    def test_package_from_entry_point_is_loaded(self):
        make_ep_dist(self.site, "lw-epdemo", "lwt_epdemo", "epdemo")
        self.use_site()
        self.assertIn("epdemo", registry())
        origin = type_origins()["epdemo"]
        self.assertEqual((origin.kind, origin.dist, origin.version), ("entry point", "lw-epdemo", "0.3.0"))
        cfg = self.cfg({"LW_CONNECTORS": "dhcp1", **instance("dhcp1", "epdemo")})
        self.assertEqual(cfg.validate(), [])

    def test_same_distribution_twice_on_sys_path_is_one_declaration(self):
        make_ep_dist(self.site, "lw-epdemo", "lwt_epdemo", "epdemo")
        sys.path += [self.site, self.site + os.sep]
        self.assertIn("epdemo", registry())
        self.assertEqual(load_problems(), [])

    def test_types_line_lists_every_origin(self):
        from leasewatch.__main__ import types_line
        make_dir_dist(self.dir, "lw-dirdemo", "lwt_dirdemo", "dirdemo")
        make_ep_dist(self.site, "lw-epdemo", "lwt_epdemo", "epdemo")
        self.use_dir()
        self.use_site()
        self.assertEqual(types_line(), "connector types: opnsense, snmp_switch, unifi (built-in); "
                                       "epdemo 0.3.0 (lw-epdemo 0.3.0, entry point); "
                                       f"dirdemo 0.3.0 (lw-dirdemo 0.3.0, LW_CONNECTORS_DIR {self.dir})")

    def test_type_help_lists_loaded_plugin_types(self):
        # the `type` help and the unknown-type problem name every loaded type, not only the built-ins
        from leasewatch.connectors import HOST_SETTINGS, InstanceSpec, instance_problems, type_help
        make_dir_dist(self.dir, "lw-dirdemo", "lwt_dirdemo", "dirdemo")
        self.use_dir()
        self.assertEqual(type_help(), "opnsense, snmp_switch, unifi (built-in); "
                                      f"dirdemo 0.3.0 (lw-dirdemo 0.3.0, LW_CONNECTORS_DIR {self.dir})")
        self.assertNotIn("opnsense", HOST_SETTINGS[0].help)  # no literal list that would miss the plugins
        self.assertEqual(instance_problems(InstanceSpec("x", "nosuch")),
                         ["connector x: unknown type 'nosuch' (known: dirdemo, opnsense, snmp_switch, unifi)"])

    def test_types_line_with_built_ins_only(self):
        from leasewatch.__main__ import types_line
        self.assertEqual(types_line(), "connector types: opnsense, snmp_switch, unifi (built-in)")

    def test_relative_dir_is_resolved(self):
        make_dir_dist(self.dir, "lw-dirdemo", "lwt_dirdemo", "dirdemo")
        os.chdir(os.path.dirname(self.dir))
        os.environ["LW_CONNECTORS_DIR"] = "connectors"
        self.assertIn("dirdemo", registry())
        self.assertEqual(type_origins()["dirdemo"].location, os.path.realpath(self.dir))

    def test_skipped_entries_in_the_dir(self):
        make_dir_dist(self.dir, ".hidden", "lwt_hidden", "hidden")
        make_dir_dist(self.dir, "_off", "lwt_off", "off")
        os.makedirs(os.path.join(self.dir, "no-pyproject"))
        with open(os.path.join(self.dir, "loose.py"), "w", encoding="utf-8") as f:
            f.write("raise SystemExit('a loose file must never run')\n")
        self.use_dir()
        self.assertEqual(sorted(registry()), ["opnsense", "snmp_switch", "unifi"])
        self.assertEqual(load_problems(), [])


class TestVersion(LoaderBase):
    def test_other_api_group_is_never_imported_and_warned(self):
        make_dir_dist(self.dir, "lw-v2", "lwt_v2", "vtwo", group="leasewatch.connectors.v2")
        make_ep_dist(self.site, "lw-v2ep", "lwt_v2ep", "vtwoep", group="leasewatch.connectors.v2")
        self.use_dir()
        self.use_site()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING") as logs:
            reg = registry()
        self.assertNotIn("vtwo", reg)
        self.assertNotIn("vtwoep", reg)
        self.assertNotIn("lwt_v2", sys.modules)
        self.assertNotIn("lwt_v2ep", sys.modules)
        text = "\n".join(logs.output)
        self.assertIn("lw-v2", text)
        self.assertIn("lw-v2ep", text)
        self.assertIn("connector API 2", text)
        self.assertEqual(load_problems(), [])  # a warning, not a start problem
        cfg = self.cfg({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **instance("dhcp1", "vtwo")})
        problems = [p for p in cfg.validate() if "dhcp1" in p]
        self.assertEqual(len(problems), 1)
        self.assertIn("for connector API 2; this host has 1", problems[0])

    def test_describe_api_version_mismatch_is_refused(self):
        make_dir_dist(self.dir, "lw-old", "lwt_old", "olddemo", api=2)
        self.use_dir()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING") as logs:
            self.assertNotIn("olddemo", registry())
        self.assertIn("written for connector API 2, this host has 1", "\n".join(logs.output))
        cfg = self.cfg({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **instance("dhcp1", "olddemo")})
        self.assertIn("connector dhcp1 (olddemo): cannot be loaded: written for connector API 2, this host has 1 "
                      "(from LW_CONNECTORS_DIR lw-old)", cfg.validate())

    def test_describe_type_differs_from_the_declared_name(self):
        make_dir_dist(self.dir, "lw-odd", "lwt_odd", "otherdemo")
        with open(os.path.join(self.dir, "lw-odd", "pyproject.toml"), "a", encoding="utf-8") as f:
            f.write('wrongname = "lwt_odd.connector:Conn"\n')
        self.use_dir()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING"):
            reg = registry()
        self.assertIn("otherdemo", reg)
        self.assertNotIn("wrongname", reg)


class TestDuplicates(LoaderBase):
    def test_duplicate_of_a_built_in_is_refused_and_the_built_in_kept(self):
        make_dir_dist(self.dir, "lw-fake-fw", "lwt_fakefw", "opnsense")
        make_ep_dist(self.site, "lw-fake-unifi", "lwt_fakeunifi", "unifi")
        self.use_dir()
        self.use_site()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING") as logs:
            reg = registry()
        self.assertIs(reg["opnsense"], OpnsenseConnector)
        self.assertEqual(type_origins()["opnsense"].kind, "built-in")
        self.assertNotIn("lwt_fakefw", sys.modules)  # refused before any plugin code ran
        self.assertNotIn("lwt_fakeunifi", sys.modules)
        text = "\n".join(logs.output)
        self.assertIn("conflicts with the built-in type opnsense; give the connector another type name", text)
        self.assertIn("conflicts with the built-in type unifi", text)
        from leasewatch.connectors import refused_types
        refused = refused_types()
        self.assertEqual(sorted(refused), ["opnsense", "unifi"])
        self.assertEqual(refused["opnsense"], "conflicts with the built-in type opnsense; declared by "
                                              "LW_CONNECTORS_DIR lw-fake-fw")
        self.assertTrue(refused["unifi"].startswith("conflicts with the built-in type unifi; declared by entry point "
                                                    "lw-fake-unifi"))
        cfg = self.cfg(FW1_ENV)
        self.assertEqual(cfg.validate(), [])  # a stray package never takes the firewall connector away

    def test_duplicate_between_two_plugins_is_an_error_naming_both(self):
        make_dir_dist(self.dir, "lw-dup-a", "lwt_dupa", "dupdemo")
        make_ep_dist(self.site, "lw-dup-b", "lwt_dupb", "dupdemo")
        self.use_dir()
        self.use_site()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING"):
            self.assertNotIn("dupdemo", registry())
        self.assertNotIn("lwt_dupa", sys.modules)
        self.assertNotIn("lwt_dupb", sys.modules)
        os.environ.update({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **instance("dhcp1", "dupdemo")})
        rc, logs = self.main_rc()
        self.assertEqual(rc, 2)
        self.assertTrue(any("connector dhcp1 (dupdemo): cannot be loaded: type dupdemo is provided twice: "
                            "entry point lw-dup-b 0.3.0 and LW_CONNECTORS_DIR lw-dup-a; remove one" in line
                            for line in logs), logs)

    def test_duplicate_between_two_dir_packages(self):
        make_dir_dist(self.dir, "lw-dup-a", "lwt_dupa", "dupdemo")
        make_dir_dist(self.dir, "lw-dup-b", "lwt_dupb", "dupdemo")
        self.use_dir()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING"):
            self.assertNotIn("dupdemo", registry())
        cfg = self.cfg({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **instance("dhcp1", "dupdemo")})
        self.assertIn("connector dhcp1 (dupdemo): cannot be loaded: type dupdemo is provided twice: "
                      "LW_CONNECTORS_DIR lw-dup-a and LW_CONNECTORS_DIR lw-dup-b; remove one", cfg.validate())

    def test_unused_duplicate_does_not_stop_the_start(self):
        make_dir_dist(self.dir, "lw-dup-a", "lwt_dupa", "dupdemo")
        make_dir_dist(self.dir, "lw-dup-b", "lwt_dupb", "dupdemo")
        self.use_dir()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING"):
            cfg = self.cfg(FW1_ENV)
        self.assertEqual(cfg.validate(), [])


class TestIsolation(LoaderBase):
    def test_broken_unused_plugin_is_a_warning_and_the_others_load(self):
        make_dir_dist(self.dir, "lw-broken", "lwt_broken", "brokendemo", prelude="import lwt_does_not_exist")
        make_dir_dist(self.dir, "lw-exits", "lwt_exits", "exitdemo", prelude="raise SystemExit(3)")
        make_dir_dist(self.dir, "lw-dirdemo", "lwt_dirdemo", "dirdemo")
        self.use_dir()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING") as logs:
            cfg = self.cfg(FW1_ENV)
        self.assertEqual({r.levelname for r in logs.records}, {"WARNING"})
        text = "\n".join(logs.output)
        self.assertIn("ModuleNotFoundError in lwt_broken.connector (from LW_CONNECTORS_DIR lw-broken)", text)
        self.assertIn("SystemExit in lwt_exits.connector (from LW_CONNECTORS_DIR lw-exits)", text)
        self.assertIn("dirdemo", registry())
        self.assertNotIn("brokendemo", registry())
        self.assertNotIn("lwt_broken", sys.modules)  # a failed package does not stay half-imported
        self.assertEqual(cfg.validate(), [])

    def test_broken_plugin_used_by_an_instance_stops_the_start(self):
        make_dir_dist(self.dir, "lw-broken", "lwt_broken", "brokendemo", prelude="import lwt_does_not_exist")
        self.use_dir()
        os.environ.update({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **instance("dhcp1", "brokendemo")})
        with self.assertLogs("leasewatch.connectors.loader", "WARNING"):
            rc, logs = self.main_rc()
        self.assertEqual(rc, 2)
        self.assertIn("ERROR:leasewatch:config: connector dhcp1 (brokendemo): cannot be loaded: ModuleNotFoundError "
                      "in lwt_broken.connector (from LW_CONNECTORS_DIR lw-broken)", logs)

    def test_entry_point_that_is_not_a_connector_class(self):
        make_ep_dist(self.site, "lw-notcls", "lwt_notcls", "notcls")
        with open(os.path.join(self.site, "lwt_notcls", "connector.py"), "a", encoding="utf-8") as f:
            f.write("Conn = 42\n")
        self.use_site()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING") as logs:
            self.assertNotIn("notcls", registry())
        self.assertIn("not a connector class", "\n".join(logs.output))

    def test_connectors_dir_that_is_not_a_directory_stops_the_start(self):
        os.environ["LW_CONNECTORS_DIR"] = os.path.join(self.dir, "missing")
        cfg = self.cfg(FW1_ENV)
        self.assertIn(f"LW_CONNECTORS_DIR {os.path.join(self.dir, 'missing')} is not a directory", cfg.validate())

    def test_unreadable_pyproject_stops_the_start(self):
        base = make_dir_dist(self.dir, "lw-bad-toml", "lwt_badtoml", "badtoml")
        with open(os.path.join(base, "pyproject.toml"), "a", encoding="utf-8") as f:
            f.write("[[[ not toml\n")
        self.use_dir()
        cfg = self.cfg(FW1_ENV)
        self.assertTrue(any(p.startswith("LW_CONNECTORS_DIR lw-bad-toml: pyproject.toml cannot be read")
                            for p in cfg.validate()), cfg.validate())


class TestSafety(LoaderBase):
    def test_package_shadowing_a_stdlib_module_is_refused(self):
        import json
        make_dir_dist(self.dir, "lw-json", "json", "jsondemo", prelude="raise SystemExit('must not run')")
        self.use_dir()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING"):
            self.assertNotIn("jsondemo", registry())
        self.assertIs(sys.modules["json"], json)
        self.assertIn("LW_CONNECTORS_DIR lw-json: package json would shadow another module", load_problems())

    def test_package_named_leasewatch_is_refused(self):
        make_dir_dist(self.dir, "lw-self", "leasewatch", "selfdemo", value="leasewatch.connector:Conn")
        self.use_dir()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING"):
            self.assertNotIn("selfdemo", registry())
        self.assertIn("LW_CONNECTORS_DIR lw-self: package leasewatch would shadow another module", load_problems())

    def test_package_shadowing_an_importable_module_is_refused(self):
        make_dir_dist(self.dir, "lw-shadow", "lwt_shadow", "shadowdemo", prelude="raise SystemExit('must not run')")
        write_package(self.site, "lwt_shadow", "elsewhere")
        self.use_site()
        self.use_dir()
        with self.assertLogs("leasewatch.connectors.loader", "WARNING"):
            self.assertNotIn("shadowdemo", registry())
        self.assertNotIn("lwt_shadow", sys.modules)
        self.assertIn("LW_CONNECTORS_DIR lw-shadow: package lwt_shadow would shadow another module", load_problems())

    def test_cwd_is_never_scanned(self):
        cwd = os.path.dirname(self.dir)
        make_ep_dist(cwd, "lw-cwd-ep", "lwt_cwdep", "cwdep")
        make_dir_dist(cwd, "lw-cwd-dir", "lwt_cwddir", "cwddir")
        os.chdir(cwd)
        sys.path[:0] = ["", cwd]  # what `python -m` and `python -c` put first
        reg = registry()
        self.assertNotIn("cwdep", reg)
        self.assertNotIn("cwddir", reg)
        self.assertNotIn("lwt_cwdep", sys.modules)


class TestSecrets(LoaderBase):
    def test_secret_file_of_a_plugin_type_is_read_and_redacted(self):
        # Config() must see the plugin types before it reads <KEY>_FILE, or PASSWORD_FILE is "unknown"
        make_dir_dist(self.dir, "lw-dirdemo", "lwt_dirdemo", "dirdemo")
        secret = "pl-Secret-0123456789"
        path = os.path.join(os.path.dirname(self.dir), "password")
        with open(path, "w", encoding="utf-8") as f:
            f.write(secret + "\n")
        env = instance("dhcp1", "dirdemo")
        del env["LW_CONNECTOR__DHCP1__PASSWORD"]
        env["LW_CONNECTOR__DHCP1__PASSWORD_FILE"] = path
        self.use_dir()
        cfg = self.cfg({"LW_CONNECTORS": "dhcp1", **env})
        self.assertEqual(cfg.validate(), [])
        self.assertEqual(cfg.instances[0].settings["password"], secret)
        self.assertEqual(instances_context(cfg.instances).redact(f"login failed for {secret}"), "login failed for ***")


class TestRebuild(LoaderBase):
    def test_registry_follows_the_environment_without_patching(self):
        make_dir_dist(self.dir, "lw-dirdemo", "lwt_dirdemo", "dirdemo")
        self.use_dir()
        first = registry()["dirdemo"]
        del os.environ["LW_CONNECTORS_DIR"]
        self.assertNotIn("dirdemo", registry())
        self.assertNotIn("lwt_dirdemo", sys.modules)  # the previous load's dir modules are dropped
        self.use_dir()
        again = registry()["dirdemo"]
        self.assertIsNot(again, first)
        self.assertIs(registry(), registry())  # an unchanged key keeps the cache

    def test_sys_path_change_rebuilds(self):
        make_ep_dist(self.site, "lw-epdemo", "lwt_epdemo", "epdemo")
        self.assertNotIn("epdemo", registry())
        self.use_site()
        self.assertIn("epdemo", registry())
        sys.path.remove(self.site)
        self.assertNotIn("epdemo", registry())


if __name__ == "__main__":
    unittest.main()
