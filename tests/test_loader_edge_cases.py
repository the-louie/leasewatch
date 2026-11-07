"""Edge cases of the connector loader: malformed plugin info, pyproject failures, entry points, conflicts and shadows.

Every plugin is synthetic, written into a temporary directory by the test; the helpers come from test_loader.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV  # noqa: E402
from test_loader import GROUP, LoaderBase, instance, make_dir_dist, make_ep_dist  # noqa: E402

from leasewatch.connectors.opnsense import OpnsenseConnector  # noqa: E402

from leasewatch.connectors import _reset_registry, broken_types, load_problems, registry  # noqa: E402

LOG = "leasewatch.connectors.loader"


def write_pyproject(base: str, body: str) -> None:
    with open(os.path.join(base, "pyproject.toml"), "w", encoding="utf-8") as f:
        f.write('[project]\nname = "x"\nversion = "1"\n\n' + body)


class TestMalformedInfo(LoaderBase):
    def test_settings_none_is_a_broken_type_not_a_traceback(self):
        # S2R16, S2R28: Config() iterated describe().settings and raised TypeError
        base = make_dir_dist(self.dir, "lw-badset", "lwt_badset", "badset")
        with open(os.path.join(base, "lwt_badset", "connector.py"), "a", encoding="utf-8") as f:
            f.write("Conn.INFO = ConnectorInfo('badset', '1', 1, None, None)\n")
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            cfg = self.cfg({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **instance("dhcp1", "badset")})
        self.assertNotIn("badset", registry())
        self.assertTrue(any(p.startswith("connector dhcp1 (badset): cannot be loaded: describe()")
                            for p in cfg.validate()), cfg.validate())


class TestKeyAndCwd(LoaderBase):
    def test_relative_dir_follows_chdir(self):
        # S2R17: the cache key ignored the working directory a relative LW_CONNECTORS_DIR is resolved against
        a, b = os.path.join(self.dir, "a"), os.path.join(self.dir, "b")
        make_dir_dist(os.path.join(a, "connectors"), "lw-a", "lwt_ka", "typea")
        make_dir_dist(os.path.join(b, "connectors"), "lw-b", "lwt_kb", "typeb")
        os.environ["LW_CONNECTORS_DIR"] = "connectors"
        os.chdir(a)
        self.assertIn("typea", registry())
        os.chdir(b)
        self.assertIn("typeb", registry())
        self.assertNotIn("typea", registry())


class TestPyprojectFailures(LoaderBase):
    def test_deeply_nested_toml_names_the_entry_and_keeps_the_others(self):
        # S2R18, S2R24: RecursionError from tomllib reached load()'s catch-all and dropped every plugin
        base = make_dir_dist(self.dir, "aaa", "lwt_aaa", "aaat")
        write_pyproject(base, "x = " + "[" * 5000 + "]" * 5000 + "\n")
        make_dir_dist(self.dir, "good", "lwt_good", "goodt")
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            self.assertIn("goodt", registry())
        self.assertIn("LW_CONNECTORS_DIR aaa: pyproject.toml cannot be read (RecursionError)", load_problems())
        self.assertFalse(any("connector loading failed" in p for p in load_problems()), load_problems())

    def test_huge_api_number_is_one_ignored_group(self):
        # S2R25 (and S2R24's ValueError): int() of > 4300 digits failed the whole load
        base = make_dir_dist(self.dir, "huge", "lwt_huge", "huget")
        write_pyproject(base, f'[project.entry-points."leasewatch.connectors.v{"9" * 5000}"]\nhuget = "lwt_huge.c:C"\n')
        make_dir_dist(self.dir, "good", "lwt_good", "goodt")
        self.use_dir()
        self.assertIn("goodt", registry())
        self.assertEqual(load_problems(), [])

    def test_group_spellings_of_api_1_are_not_the_group(self):
        # S2R22: v01 and a non-ASCII digit counted as API 1
        for i, group in enumerate(("leasewatch.connectors.v01", "leasewatch.connectors.v١")):
            make_dir_dist(self.dir, f"lw-g{i}", f"lwt_g{i}", f"gtype{i}", group=group)
        self.use_dir()
        self.assertNotIn("gtype0", registry())
        self.assertNotIn("gtype1", registry())
        self.assertNotIn("lwt_g0", sys.modules)

    def test_spaces_around_the_colon_are_accepted_as_for_pip(self):
        # S2R26
        make_dir_dist(self.dir, "lw-sp", "lwt_sp", "sptype", value="lwt_sp.connector : Conn")
        self.use_dir()
        self.assertIn("sptype", registry())
        self.assertEqual(load_problems(), [])

    def test_type_name_with_a_trailing_newline_is_refused(self):
        # S2R60: `$` matched before a trailing "\n"
        base = make_dir_dist(self.dir, "lw-nl", "lwt_nl", "nltype")
        write_pyproject(base, f'[project.entry-points."{GROUP}"]\n"nltype\\n" = "lwt_nl.connector:Conn"\n')
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            self.assertNotIn("nltype\n", registry())
        self.assertTrue(any("entry point 'nltype\\n' is not" in p for p in load_problems()), load_problems())


class TestCatchAll(LoaderBase):
    def test_a_loader_failure_leaves_only_the_built_ins_and_no_modules(self):
        # S2R19: the catch-all kept partly registered types and untracked dir modules
        make_dir_dist(self.dir, "lw-one", "lwt_one", "onetype")
        make_dir_dist(self.dir, "lw-two", "lwt_two", "twotype")
        self.use_dir()
        from leasewatch.connectors import loader
        real, calls = loader.replace, []

        def flaky(*a, **kw):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("synthetic loader bug")
            return real(*a, **kw)
        with mock.patch.object(loader, "replace", flaky), self.assertLogs(LOG, "ERROR"):
            reg = registry()
        self.assertEqual(sorted(reg), ["opnsense", "snmp_switch", "unifi"])
        self.assertNotIn("lwt_one", sys.modules)
        self.assertNotIn("lwt_two", sys.modules)
        _reset_registry()
        self.assertIn("onetype", registry())
        self.assertIn("twotype", registry())
        self.assertEqual(load_problems(), [])

    def test_other_base_exception_from_a_plugin_is_a_plugin_failure(self):
        # S2R30: CancelledError (a BaseException) left load() and stopped the host
        make_dir_dist(self.dir, "lw-cancel", "lwt_cancel", "canceltype",
                      prelude="import asyncio\nraise asyncio.CancelledError()")
        make_dir_dist(self.dir, "lw-ok", "lwt_ok", "oktype")
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            reg = registry()
        self.assertIn("oktype", reg)
        self.assertIn("CancelledError in lwt_cancel.connector", broken_types()["canceltype"])
        self.assertNotIn("lwt_cancel", sys.modules)

    def test_keyboard_interrupt_still_stops_but_leaves_nothing_behind(self):
        # S2R55: the half-imported package stayed in sys.modules and later loads called it a shadow
        base = make_dir_dist(self.dir, "lw-ki", "lwt_ki", "kitype", prelude="raise KeyboardInterrupt")
        self.use_dir()
        with self.assertRaises(KeyboardInterrupt):
            registry()
        self.assertNotIn("lwt_ki", sys.modules)
        make_dir_dist(self.dir, "lw-ki", "lwt_ki", "kitype")  # rewritten without the interrupt
        os.utime(os.path.join(base, "lwt_ki", "connector.py"), (1, 1))  # a new mtime: no stale bytecode
        self.assertIn("kitype", registry())
        self.assertEqual(load_problems(), [])


class TestUnload(LoaderBase):
    def test_submodule_imported_after_the_load_is_dropped_too(self):
        # S2R20
        base = make_dir_dist(self.dir, "lw-lazy", "lwt_lazy", "lazytype")
        with open(os.path.join(base, "lwt_lazy", "late.py"), "w", encoding="utf-8") as f:
            f.write("V = 1\n")
        self.use_dir()
        registry()
        import lwt_lazy.late  # noqa: F401  (what a plugin's collect() may do)
        _reset_registry()
        self.assertNotIn("lwt_lazy.late", sys.modules)


class TestEntryPoints(LoaderBase):
    def test_unreadable_metadata_names_the_distribution(self):
        # S2R21
        make_ep_dist(self.site, "lw-badmeta", "lwt_badmeta", "badmeta")
        with open(os.path.join(self.site, "lw_badmeta-0.3.0.dist-info", "entry_points.txt"), "a",
                  encoding="utf-8") as f:
            f.write("broken\n")
        self.use_site()
        with self.assertLogs(LOG, "WARNING") as logs:
            registry()
        self.assertIn("lw-badmeta", "\n".join(logs.output))

    def test_other_api_warning_once_per_distribution(self):
        # S2R58
        make_ep_dist(self.site, "lw-v2ep", "lwt_v2ep", "vtwoep", group="leasewatch.connectors.v2")
        sys.path += [self.site, self.site + os.sep]
        with self.assertLogs(LOG, "WARNING") as logs:
            registry()
        self.assertEqual(sum("lw-v2ep" in line for line in logs.output), 1, logs.output)

    def test_dist_name_spellings_are_one_distribution(self):
        # S2R59
        one, two = os.path.join(self.site, "one"), os.path.join(self.site, "two")
        make_ep_dist(one, "lw_b", "lwt_b", "btype")
        make_ep_dist(two, "lw-b", "lwt_b", "btype")
        sys.path += [one, two]
        self.assertIn("btype", registry())

    def test_malformed_value_still_counts_as_a_declaration(self):
        # S2R61
        make_ep_dist(self.site, "lw-e", "lwt_e", "dupy")
        path = os.path.join(self.site, "lw_e-0.3.0.dist-info", "entry_points.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"[{GROUP}]\ndupy = lwt_e.connector:Conn:X\n")
        make_dir_dist(self.dir, "c-dist", "lwt_c", "dupy")
        self.use_site()
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            self.assertNotIn("dupy", registry())
        self.assertIn("provided twice", broken_types()["dupy"])

    def test_other_api_type_name_cannot_forge_a_log_line(self):
        # S2R57
        base = make_dir_dist(self.dir, "lw-forge", "lwt_forge", "forge")
        write_pyproject(base, '[project.entry-points."leasewatch.connectors.v2"]\n'
                              '"x\\nERROR forged line" = "lwt_forge.connector:Conn"\n')
        self.use_dir()
        with self.assertLogs(LOG, "WARNING") as logs:
            registry()
        self.assertFalse(any("\n" in r.getMessage() for r in logs.records), logs.output)
        self.assertEqual(broken_types(), {})


class TestConflictsAndShadows(LoaderBase):
    def test_installed_and_mounted_stops_the_start(self):
        # S2T07..S2T11: every duplicate is an error, whatever the dist names say; no name-based exemption
        for dir_name in ("lw-same", "lw-other"):
            with self.subTest(dir_name=dir_name):
                _reset_registry()
                make_ep_dist(os.path.join(self.site, dir_name), "lw-same", "lwt_same", "same")
                make_dir_dist(os.path.join(self.dir, dir_name), dir_name, "lwt_same", "same")
                sys.path.append(os.path.join(self.site, dir_name))
                os.environ["LW_CONNECTORS_DIR"] = os.path.join(self.dir, dir_name)
                with self.assertLogs(LOG, "WARNING"):
                    self.assertNotIn("same", registry())
                self.assertIn("provided twice", broken_types()["same"])
                self.assertIn(f"LW_CONNECTORS_DIR {dir_name}: package lwt_same would shadow another module",
                              load_problems())
                sys.path.remove(os.path.join(self.site, dir_name))

    def test_installed_name_does_not_exempt_a_stdlib_shadow(self):
        # S2T09, S2T10
        make_ep_dist(self.site, "lw-x", "lwt_x", "tx")
        make_dir_dist(self.dir, "lw-x", "json", "tx", prelude="raise SystemExit('must not run')")
        self.use_site()
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            registry()
        self.assertIn("LW_CONNECTORS_DIR lw-x: package json would shadow another module", load_problems())

    def test_shadowing_declaration_still_counts_in_the_duplicate_check(self):
        # S2R27
        make_dir_dist(self.dir, "a-dist", "json", "dupx", prelude="raise SystemExit('must not run')")
        make_dir_dist(self.dir, "b-dist", "lwt_bx", "dupx")
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            self.assertNotIn("dupx", registry())
        self.assertIn("provided twice", broken_types()["dupx"])

    def test_same_package_in_two_entries_names_the_clash(self):
        # S2R29
        base = make_dir_dist(self.dir, "a", "lwt_foo", "ta")
        with open(os.path.join(base, "lwt_foo", "__init__.py"), "a", encoding="utf-8") as f:
            f.write("raise ValueError('synthetic')\n")  # the package itself fails, not only its submodule
        make_dir_dist(self.dir, "b", "lwt_foo", "tb")
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            registry()
        self.assertIn("another LW_CONNECTORS_DIR entry", broken_types()["tb"])

    def test_namespace_package_says_init_is_missing(self):
        # S2R62
        base = make_dir_dist(self.dir, "lw-ns", "lwt_ns", "nstype")
        os.remove(os.path.join(base, "lwt_ns", "__init__.py"))
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            registry()
        self.assertIn("package lwt_ns has no __init__.py", broken_types()["nstype"])



class TestWalkShadowsAndDistributions(LoaderBase):
    """Drops during the walk, shadowed types, broken settings and distribution names."""

    def test_drop_survives_a_module_import_during_the_walk(self):
        # S2S10: _drop walked the live sys.modules; another thread's first import raised RuntimeError
        from leasewatch.connectors import loader
        sys.modules["lwt_walk"] = sys.modules["os"]
        self.addCleanup(sys.modules.pop, "lwt_churn", None)

        class Churn(set):
            def __contains__(self, name):  # a first-time import elsewhere, in the middle of the walk
                sys.modules.setdefault("lwt_churn", sys.modules["os"])
                return super().__contains__(name)
        loader._drop(Churn({"lwt_walk"}))
        self.assertNotIn("lwt_walk", sys.modules)

    def test_space_inside_the_module_name_is_refused(self):
        # S2S11: removing every space turned "lwt_ sv.connector:Conn" into the valid lwt_sv
        make_dir_dist(self.dir, "lw-sv", "lwt_sv", "svtype", value="lwt_ sv.connector:Conn")
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            self.assertNotIn("svtype", registry())
        self.assertTrue(any("entry point 'svtype' is not" in p for p in load_problems()), load_problems())

    def test_shadow_stops_the_start_for_a_duplicate_type(self):
        # S2S12 case B: the duplicate check dropped the declaration before the shadow check saw it
        make_dir_dist(self.dir, "a-dist", "json", "dupx", prelude="raise SystemExit('must not run')")
        make_dir_dist(self.dir, "b-dist", "lwt_bx", "dupx")
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            self.assertNotIn("dupx", registry())
        self.assertIn("LW_CONNECTORS_DIR a-dist: package json would shadow another module", load_problems())
        self.assertIn("provided twice", broken_types()["dupx"])

    def test_shadow_stops_the_start_for_a_built_in_type_name(self):
        # S2S12 case C
        make_dir_dist(self.dir, "a-dist", "json", "opnsense", prelude="raise SystemExit('must not run')")
        self.use_dir()
        with self.assertLogs(LOG, "WARNING"):
            reg = registry()
        self.assertIs(reg["opnsense"], OpnsenseConnector)
        self.assertIn("LW_CONNECTORS_DIR a-dist: package json would shadow another module", load_problems())

    def _info_type(self, type_: str, info: str) -> None:
        base = make_dir_dist(self.dir, f"lw-{type_}", f"lwt_{type_}", type_)
        with open(os.path.join(base, f"lwt_{type_}", "connector.py"), "a", encoding="utf-8") as f:
            f.write(f"Conn.INFO = ConnectorInfo({info})\n")
        self.use_dir()

    def test_unhashable_setting_key_is_a_broken_type(self):
        # S2S13: Setting(['a']) passed the shape check and Config() raised TypeError in secret_keys
        self._info_type("keyl", "'keyl', '1', 1, frozenset({'sighting'}), (Setting(['a']),)")
        with self.assertLogs(LOG, "WARNING"):
            cfg = self.cfg({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **instance("dhcp1", "keyl")})
        self.assertIn("settings is not a tuple of Setting", broken_types()["keyl"])
        self.assertTrue(any(p.startswith("connector dhcp1 (keyl): cannot be loaded") for p in cfg.validate()))

    def test_non_int_setting_bound_is_a_broken_type(self):
        # S2T12: min="0" passed the shape check and Config() raised TypeError at n < s.min
        for bound in ("min='0'", "max=1.5", "min=True"):
            with self.subTest(bound=bound):
                _reset_registry()
                for k in [k for k in os.environ if k.startswith("LW_CONNECTOR")]:
                    del os.environ[k]
                self._info_type(f"bnd{len(bound)}", f"'bnd{len(bound)}', '1', 1, frozenset({{'sighting'}}), "
                                                      f"(Setting('a', kind='int', {bound}),)")
                with self.assertLogs(LOG, "WARNING"):
                    cfg = self.cfg({**FW1_ENV, "LW_CONNECTORS": "fw1,dhcp1", **instance("dhcp1", f"bnd{len(bound)}"),
                                    "LW_CONNECTOR__DHCP1__A": "5"})
                self.assertIn("settings is not a tuple of Setting", broken_types()[f"bnd{len(bound)}"])
                self.assertTrue(any("cannot be loaded" in p for p in cfg.validate()))

    def test_tuple_produces_and_roles_are_accepted(self):
        # S2S14: the published contract test accepts tuples (set(...)), so the loader must too
        self._info_type("tupl", "'tupl', '1', 1, ('sighting',), (Setting('url'),), ('controller',)")
        self.assertIn("tupl", registry())
        self.assertNotIn("tupl", broken_types())

    def test_distribution_names_cannot_forge_a_log_line(self):
        # S2S28, S2S30: the dist name and the dir entry were logged with %s and stored with their newline
        base = make_dir_dist(self.dir, "a\nERROR forged entry", "lwt_fe", "okname", group="leasewatch.connectors.v2")
        write_pyproject(base, '[project.entry-points."leasewatch.connectors.v2"]\nokname = "lwt_fe.connector:Conn"\n')
        make_ep_dist(self.site, "lw-n", "lwt_fn", "BAD")
        make_ep_dist(os.path.join(self.site, "v2"), "lw-m", "lwt_fm", "ntype", group="leasewatch.connectors.v2")
        for meta in (os.path.join(self.site, "lw_n-0.3.0.dist-info", "METADATA"),
                     os.path.join(self.site, "v2", "lw_m-0.3.0.dist-info", "METADATA")):
            with open(meta, encoding="utf-8") as f:
                text = f.read()
            with open(meta, "w", encoding="utf-8") as f:
                f.write(text.replace("Name: lw-", "Name: lw-x\n ERROR forged dist "))
        self.use_dir()
        self.use_site()
        sys.path.append(os.path.join(self.site, "v2"))
        with self.assertLogs(LOG, "WARNING") as logs:
            registry()
        self.assertEqual(len([r for r in logs.records if "forged" in r.getMessage()]), 3, logs.output)
        self.assertFalse(any("\n" in r.getMessage() for r in logs.records), logs.output)
        self.assertFalse(any("\n" in why for why in broken_types().values()), broken_types())

    def test_two_nameless_distributions_are_two_declarations(self):
        # S2S29: both got the dedup key "?" and the type loaded instead of being refused as provided twice
        for sub in ("e", "f"):
            info = os.path.join(self.site, sub, f"{sub}-1.dist-info")
            os.makedirs(info)
            with open(os.path.join(info, "METADATA"), "w", encoding="utf-8") as f:
                f.write("Metadata-Version: 2.1\nVersion: 1\n")
            with open(os.path.join(info, "entry_points.txt"), "w", encoding="utf-8") as f:
                f.write(f"[{GROUP}]\nt9 = lwt_t9.connector:Conn\n")
            sys.path.append(os.path.join(self.site, sub))
        with self.assertLogs(LOG, "WARNING"):
            self.assertNotIn("t9", registry())
        self.assertIn("provided twice", broken_types()["t9"])

    def _decls(self, *names: str) -> list:
        # a fixed path, so the scan index of each distribution is known: the first one is 0
        from leasewatch.connectors import loader
        path = []
        for i, name in enumerate(names):
            sub = os.path.join(self.site, f"d{i}")
            info = os.path.join(sub, f"d{i}-1.dist-info")
            os.makedirs(info)
            with open(os.path.join(info, "METADATA"), "w", encoding="utf-8") as f:
                f.write(f"Metadata-Version: 2.1\nName: {name}\nVersion: 1\n")
            with open(os.path.join(info, "entry_points.txt"), "w", encoding="utf-8") as f:
                f.write(f"[{GROUP}]\nt9 = lwt_t9.connector:Conn\n")
            path.append(sub)
        return loader._entry_point_decls(path, {})

    def test_nameless_key_cannot_meet_a_dist_named_like_its_index(self):
        # S2T21, S2T22: the nameless dist's key was str(i), the same as a dist named "0"
        self.assertEqual(len(self._decls("", "0")), 2)

    def test_blank_name_is_nameless(self):
        # S2T20: a Name of only whitespace became "" and merged with another blank one
        decls = self._decls("\x0b", "\x0c")
        self.assertEqual([d.origin.dist for d in decls], ["?", "?"])


if __name__ == "__main__":
    unittest.main()
