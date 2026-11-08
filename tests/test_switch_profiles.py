"""SNMP profiles: loader, detection, build_snapshot quirks, and one golden snapshot per built-in profile.

The switches are FakeWalker objects serving tests/fixtures/snmp/<profile>.snmprec (synthetic, hand-written) through a
fake pysnmp module. Per-VLAN SNMPv3 contexts are files named <profile>@<context>.snmprec.
Regenerate the golden files with UPDATE_GOLDEN=1 python3 -m unittest tests.test_switch_profiles, then review the diff.
"""
import asyncio, contextlib, io, json, logging, os, sys, tempfile, types, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from _env import clean_env, restore, sources
from leasewatch import snmp_profiles
from leasewatch.__main__ import main
from leasewatch.snmp_profiles import ProfileError
from leasewatch.switch import SwitchClient, build_snapshot, short_ifname

FIXTURES = Path(__file__).parent / "fixtures" / "snmp"
CFG = SimpleNamespace(snmp_host="10.0.0.2", snmp_user="leasewatch", snmp_auth="SHA", snmp_auth_key="test-auth", snmp_priv_key="test-priv")
PRIVATE_OID = "1.3.6.1.4.1.32473.1.1"  # stand-in private table in edgeswitch.snmprec
EndOfMibView = type("EndOfMibView", (), {})
NoSuchObject = type("NoSuchObject", (), {})


def _otuple(oid: str) -> tuple:
    return tuple(int(x) for x in oid.split("."))


class FakeWalker:
    """An agent over .snmprec files: GET, GETNEXT and GETBULK per SNMPv3 context ("" = default)."""

    def __init__(self, name: str):
        self.tables = {"": self._read(FIXTURES / f"{name}.snmprec")}
        for f in FIXTURES.glob(f"{name}@*.snmprec"):
            self.tables[f.stem.split("@", 1)[1]] = self._read(f)

    @staticmethod
    def _read(path: Path) -> list:
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            oid, typ, val = line.split("|", 2)
            v = int(val) if typ in ("2", "65", "66", "67") else bytes.fromhex(val) if typ == "4x" else val
            rows.append((_otuple(oid), oid, v))
        return sorted(rows)

    def get(self, oid: str, context: str = ""):
        return next((v for t, o, v in self.tables.get(context, []) if o == oid), NoSuchObject())

    def next(self, oid: str, context: str = ""):
        cur = _otuple(oid)
        return next(((o, v) for t, o, v in self.tables.get(context, []) if t > cur), (oid, EndOfMibView()))


class FakePysnmp:
    """Installs a fake pysnmp.hlapi.v3arch.asyncio backed by a FakeWalker; records every request."""
    MODS = ("pysnmp", "pysnmp.hlapi", "pysnmp.hlapi.v3arch", "pysnmp.hlapi.v3arch.asyncio")

    def __init__(self, walker: FakeWalker):
        self.walker, self.calls, self.targets = walker, [], []

    def __enter__(self):
        self._saved = {k: sys.modules.get(k) for k in self.MODS}
        for k in self.MODS:
            sys.modules[k] = types.ModuleType(k)
        m = sys.modules["pysnmp.hlapi.v3arch.asyncio"]
        w, calls, targets = self.walker, self.calls, self.targets
        m.ContextData = lambda contextEngineId=None, contextName="": contextName
        m.ObjectIdentity = lambda oid: oid
        m.ObjectType = lambda ident: ident
        m.UsmUserData = lambda *a, **k: None
        m.usmAesCfb128Protocol = m.usmHMAC192SHA256AuthProtocol = m.usmHMACSHAAuthProtocol = object()
        m.SnmpEngine = type("SnmpEngine", (), {"close_dispatcher": lambda self: None})

        class UdpTransportTarget:
            @staticmethod
            async def create(addr, timeout, retries):
                targets.append((addr, timeout, retries))
                return None
        m.UdpTransportTarget = UdpTransportTarget

        async def next_cmd(eng, user, tgt, ctx, oid):
            calls.append(("next", ctx, oid))
            return None, 0, 0, [w.next(oid, ctx)]

        async def bulk_cmd(eng, user, tgt, ctx, non_rep, reps, oid):
            calls.append(("bulk", ctx, oid))
            out = []
            for _ in range(reps):
                o, v = w.next(oid, ctx)
                out.append((o, v))
                if isinstance(v, EndOfMibView):
                    break
                oid = o
            return None, 0, 0, out

        async def get_cmd(eng, user, tgt, ctx, *oids):
            calls.append(("get", ctx, oids))
            return None, 0, 0, [(o, w.get(o, ctx)) for o in oids]
        m.next_cmd, m.bulk_cmd, m.get_cmd = next_cmd, bulk_cmd, get_cmd
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


class PrivateClient(SwitchClient):
    """A subclass for fdb.strategy "private", as a vendor plug-in would write it."""

    def fdb_decoder(self, rows):
        out = []
        for idx, ifindex in rows[PRIVATE_OID]:
            p = idx.split(".")
            out.append((":".join(f"{int(x):02x}" for x in p[1:]), int(p[0]), int(ifindex)))
        return out


def summary(client: SwitchClient, snap) -> dict:
    return {
        "profile": client.profile_name,
        "ports": {str(i): {"name": p.name, "neighbor": p.neighbor, "macs": p.macs, "uplink": p.uplink} for i, p in sorted(snap.ports.items())},
        "macs": {mac: {"ifindex": i, "vlan": v, "describe": list(snap.describe(mac))} for mac, (i, v) in sorted(snap.by_mac.items())},
    }


def run(name: str, client: SwitchClient):
    with FakePysnmp(FakeWalker(name)) as fake:
        snap = client.snapshot()
    return snap, fake


def edgeswitch_client() -> SwitchClient:
    prof = snmp_profiles.load("edgeswitch")
    prof["fdb"]["private_oids"] = [PRIVATE_OID]
    return PrivateClient(CFG, prof)


class GoldenTests(unittest.TestCase):
    def check(self, name: str, client: SwitchClient):
        snap, _ = run(name, client)
        got = summary(client, snap)
        path = FIXTURES / f"{name}.json"
        if os.environ.get("UPDATE_GOLDEN") == "1":
            path.write_text(json.dumps(got, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.assertEqual(got, json.loads(path.read_text(encoding="utf-8")))
        return got

    def test_every_builtin_profile_has_a_golden_snapshot(self):
        for name in snmp_profiles.BUILTIN:
            with self.subTest(profile=name):
                # detection from the fixture's sysObjectID/sysDescr picks the profile, except edgeswitch (by name only)
                got = self.check(name, edgeswitch_client() if name == "edgeswitch" else SwitchClient(CFG))
                self.assertEqual(got["profile"], name)
                self.assertEqual(len(got["macs"]), 3)  # the port-0 self MAC is never a device
                self.assertTrue(any(p["neighbor"] == "sw-attic" and p["uplink"] for p in got["ports"].values()))

    def test_comware_golden_matches_the_1_0_short_names(self):
        got = json.loads((FIXTURES / "comware.json").read_text(encoding="utf-8"))
        self.assertEqual(got["macs"]["02:00:00:00:00:02"]["describe"], ["XGE1/0/2", "sw-attic"])
        self.assertEqual(got["macs"]["02:00:00:00:00:01"]["describe"], ["GE1/0/1", ""])


class ClientTests(unittest.TestCase):
    def test_detection_is_cached_and_uses_profile_transport_settings(self):
        c = SwitchClient(CFG)
        self.assertEqual(c.profile_name, "")
        with FakePysnmp(FakeWalker("comware")) as fake:
            c.snapshot(); c.snapshot()
        self.assertEqual(sum(1 for k, *_ in fake.calls if k == "get"), 1)
        self.assertEqual(fake.targets[0], (("10.0.0.2", 161), 4, 1))
        self.assertEqual(c.profile_name, "comware")

    def test_detected_profile_with_other_timeout_gets_a_new_target(self):
        slow = snmp_profiles.load("routeros")
        slow["snmp"].update(timeout=9, retries=3)
        real = snmp_profiles.load
        with mock.patch("leasewatch.switch.snmp_profiles.load", side_effect=lambda n: slow if n == "routeros" else real(n)):
            snap, fake = run("routeros", SwitchClient(CFG))
        self.assertEqual([t[1:] for t in fake.targets], [(4, 1), (9, 3)])

    def test_cisco_per_vlan_walks_each_operational_vlan_context(self):
        snap, fake = run("cisco_ios", SwitchClient(CFG))
        contexts = {ctx for kind, ctx, _ in fake.calls}
        self.assertEqual(contexts, {"", "vlan-1", "vlan-10"})  # not 30 (state 2), not 1002 (skipped)
        fdb_oid = "1.3.6.1.2.1.17.4.3.1.2"
        self.assertEqual({ctx for kind, ctx, oid in fake.calls if oid == fdb_oid}, {"vlan-1", "vlan-10"})
        self.assertEqual(snap.by_mac["02:00:00:00:00:03"], (10102, 10))

    def test_bulk_uses_bulk_cmd_except_no_bulk_and_gives_the_same_snapshot(self):
        prof = snmp_profiles.load("standard")
        prof["snmp"].update(bulk=True, max_repetitions=2, no_bulk=["ifname"])
        c = SwitchClient(CFG, prof)
        snap, fake = run("standard", c)
        ifname = prof["oids"]["ifname"]
        self.assertTrue(all(k == "next" for k, _, oid in fake.calls if oid.startswith(ifname)))
        self.assertIn(("bulk", "", prof["oids"]["fdb_port"]), fake.calls)
        self.assertFalse(any(k == "get" for k, *_ in fake.calls))  # a given profile is not detected
        want = json.loads((FIXTURES / "standard.json").read_text(encoding="utf-8"))
        self.assertEqual(summary(c, snap), want)

    def test_keep_status_walks_the_status_column(self):
        prof = snmp_profiles.load("standard")
        prof["fdb"]["keep_status"] = [3]
        snap, fake = run("standard", SwitchClient(CFG, prof))
        self.assertIn(("next", "", prof["oids"]["fdb_status"]), fake.calls)
        self.assertEqual(sorted(snap.by_mac), ["02:00:00:00:00:01", "02:00:00:00:00:02"])  # :03 is mgmt(5)

    def test_private_strategy_needs_a_decoder(self):
        with self.assertRaises(NotImplementedError):
            run("edgeswitch", SwitchClient(CFG, snmp_profiles.load("edgeswitch")))

    def test_routeros_does_not_walk_the_local_port_table(self):
        _, fake = run("routeros", SwitchClient(CFG))
        self.assertFalse(any(oid == "1.0.8802.1.1.2.1.3.7.1.3" for _, _, oid in fake.calls))


class BulkWalkTests(unittest.TestCase):
    """The GETBULK walk obeys the same end rules as the GETNEXT walk (see test_enrichers.WalkTests)."""
    BASE = "1.3.6.1.2.1.31.1.1.1.1"

    def walk(self, pages):
        calls = []
        with FakePysnmp(FakeWalker("standard")):
            m = sys.modules["pysnmp.hlapi.v3arch.asyncio"]

            async def bulk_cmd(eng, user, tgt, ctx, non_rep, reps, oid):
                calls.append(oid)
                if len(calls) > len(pages):
                    raise AssertionError("walk did not terminate")
                vbs, stat = pages[len(calls) - 1]
                return None, stat, 0, vbs
            m.bulk_cmd = bulk_cmd
            out = asyncio.run(SwitchClient(None, snmp_profiles.load("standard"))._bulk_walk(None, None, None, self.BASE))
        return out, calls

    def test_pages_continue_from_the_last_oid(self):
        b = self.BASE
        out, calls = self.walk([([(b + ".1", "a"), (b + ".2", "b")], 0), ([(b + ".10", "c"), ("1.3.6.1.2.1.31.1.1.1.2.1", 5)], 0)])
        self.assertEqual(out, [("1", "a"), ("2", "b"), ("10", "c")])
        self.assertEqual(calls, [b, b + ".2"])

    def test_stops_when_the_oid_does_not_advance(self):
        b = self.BASE
        out, _ = self.walk([([(b + ".9", "a"), (b + ".9", "a")], 0)])
        self.assertEqual(out, [("9", "a")])

    def test_stops_at_end_of_mib_view_and_on_an_empty_page(self):
        self.assertEqual(self.walk([([(self.BASE + ".1", EndOfMibView())], 0)])[0], [])
        self.assertEqual(self.walk([([], 0)])[0], [])

    def test_error_status_raises(self):
        with self.assertRaisesRegex(RuntimeError, "status 2"):
            self.walk([([(self.BASE + ".1", "a")], 2)])


class LoaderTests(unittest.TestCase):
    def user_file(self, data) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data if isinstance(data, str) else json.dumps(data))
        self.addCleanup(os.unlink, path)
        return path

    def test_every_builtin_loads_and_extends_standard(self):
        std = snmp_profiles.load("standard")
        for name in snmp_profiles.BUILTIN:
            p = snmp_profiles.load(name)
            self.assertEqual((p["profile"], p["api_version"]), (name, 1))
            self.assertTrue(set(std["oids"]) <= set(p["oids"]), name)  # oids merged, not replaced
            self.assertTrue(p["_source"])

    def test_extends_merges_one_level_and_does_not_inherit_match(self):
        path = self.user_file({"profile": "mine", "api_version": 1, "extends": "comware", "oids": {"ifname": "1.3.6.1.2.1.2.2.1.2"},
                               "fdb": {"keep_status": [3]}})
        p = snmp_profiles.load_file(path)
        self.assertEqual(p["oids"]["ifname"], "1.3.6.1.2.1.2.2.1.2")
        self.assertEqual(p["oids"]["fdb_port"], "1.3.6.1.2.1.17.7.1.2.2.1.2")
        self.assertEqual((p["fdb"]["keep_status"], p["fdb"]["strategy"]), ([3], "qbridge"))
        self.assertEqual(p["port_name"]["short"]["GigabitEthernet"], "GE")  # from comware
        self.assertEqual(p["match"], {"sysobjectid_prefix": [], "sysdescr_regex": []})
        self.assertFalse(snmp_profiles.matches(p, "1.3.6.1.4.1.25506.1", ""))

    def test_load_returns_a_copy(self):
        snmp_profiles.load("comware")["oids"]["ifname"] = "changed"
        self.assertEqual(snmp_profiles.load("comware")["oids"]["ifname"], "1.3.6.1.2.1.31.1.1.1.1")

    def test_bad_profiles_are_rejected(self):
        for data in ({"profile": "x", "api_version": 2, "extends": "standard"},
                     {"profile": "x", "extends": "standard"},
                     {"profile": "x", "api_version": 1, "extends": "x"},
                     {"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"strategy": "magic"}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"index_fix": "guess"}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "bridge_port_map": {"name_match": ["no-placeholder"]}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "match": {"sysdescr_regex": ["("]}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "snmp": {"max_repetitions": 500}},
                     {"profile": "x", "api_version": 1},
                     {"profile": "x", "api_version": "1", "extends": "standard"},
                     {"profile": "x", "api_version": 1, "extends": "standard", "oids": {"ifname": 5}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "oids": ["1.3"]},
                     {"profile": "x", "api_version": 1, "extends": "standard", "port_name": {"short": {"GigabitEthernet": 1}}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "bridge_port_map": {"name_match": ["ge{port}{0}"]}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "bridge_port_map": {"name_match": ["ge{port.real}"]}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "bridge_port_map": {"name_match": ["ge{port"]}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "snmp": {"bulk": "yes"}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "snmp": {"no_bulk": "ifname"}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "snmp": {"allow_unordered": [1]}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "snmp": {"timeout": "4"}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "snmp": {"retries": 1.5}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "snmp": {"max_repetitions": "10"}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"keep_status": ["3"]}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"keep_status": 3}},
                     {"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"index_fix": "row_number"}},
                     "[1, 2]", "{not json", "[" * 100000):
            with self.subTest(data=data), self.assertRaises(ProfileError):
                snmp_profiles.load_file(self.user_file(data))
        for name in ("nope", "../standard", "", None):
            with self.subTest(name=name), self.assertRaises(ProfileError):
                snmp_profiles.load(name)
        with self.assertRaises(ProfileError):
            snmp_profiles.load_file("/nonexistent/profile.json")

    def test_unknown_keys_are_named(self):
        for data, key in (({"fdb": {"stratgy": "qbridge"}}, "fdb.stratgy"), ({"uplinks": {}}, "'uplinks'"),
                          ({"snmp": {"timout": 5}}, "snmp.timout")):
            with self.subTest(key=key), self.assertRaisesRegex(ProfileError, f"unknown key {key}"):
                snmp_profiles.load_file(self.user_file({"profile": "x", "api_version": 1, "extends": "standard", **data}))
        row = {"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"strategy": "bridge", "index_fix": "row_number"}}
        self.assertEqual(snmp_profiles.load_file(self.user_file(row))["fdb"]["index_fix"], "row_number")

    def test_new_value_checks(self):
        for data, msg in (({"fdb": {"private_oids": "1.3.6.1.4.1.32473"}}, "fdb.private_oids must be a string list"),
                          ({"fdb": {"private_oids": [1]}}, "fdb.private_oids must be a string list"),
                          ({"uplink": {"lldp_neighbor": "yes"}}, "uplink.lldp_neighbor must be true or false"),
                          ({"fdb": {"context_prefix": 5}}, "fdb.context_prefix must be a string"),
                          ({"match": {"sysobjectid_prefix": [1]}}, "match.sysobjectid_prefix must be a string list"),
                          ({"match": {"sysdescr_regex": [None]}}, "match.sysdescr_regex must be a string list")):
            with self.subTest(msg=msg), self.assertRaisesRegex(ProfileError, msg):
                snmp_profiles.load_file(self.user_file({"profile": "x", "api_version": 1, "extends": "standard", **data}))

    def test_without_extends_every_standard_key_is_required(self):
        full = {k: v for k, v in snmp_profiles.load("standard").items() if not k.startswith("_")}
        self.assertEqual(snmp_profiles.load_file(self.user_file(full))["profile"], "standard")
        del full["oids"]["ifname"]
        with self.assertRaisesRegex(ProfileError, "missing key oids.ifname"):
            snmp_profiles.load_file(self.user_file(full))

    def test_problems_name_the_key_keep_earlier_ones_and_never_quote_python(self):
        with self.assertRaises(ProfileError) as cm:
            snmp_profiles.load_file(self.user_file({"profile": "x", "api_version": 1, "extends": "standard", "uplinks": {}, "fdb": None}))
        self.assertIn("unknown key 'uplinks'", str(cm.exception))
        self.assertIn("fdb must be an object", str(cm.exception))
        self.assertNotIn("NoneType", str(cm.exception))
        with self.assertRaises(ProfileError) as cm:
            snmp_profiles.load_file(self.user_file({"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"strategy": "magic"},
                                                    "match": {"sysdescr_regex": ["ok", "("]}}))
        self.assertIn("fdb.strategy 'magic'", str(cm.exception))
        self.assertIn("match.sysdescr_regex entry 2 is not a valid regular expression", str(cm.exception))
        self.assertNotIn("unterminated", str(cm.exception))  # re.error's own text

    def test_regex_overflow_and_deep_nesting_are_named_problems(self):
        for rx in ("a{99999999999}", "(" * 2000 + ")" * 2000):
            with self.subTest(rx=rx[:20]), self.assertRaises(ProfileError) as cm:
                snmp_profiles.load_file(self.user_file({"profile": "x", "api_version": 1, "extends": "standard",
                                                        "match": {"sysdescr_regex": ["ok", rx]}}))
            self.assertIn("match.sysdescr_regex entry 2 is not a valid regular expression", str(cm.exception))

    def test_snmp_numbers_must_be_finite_and_integers_where_required(self):
        for snmp in ({"timeout": "NaN"}, {"timeout": "Infinity"}, {"timeout": "-Infinity"}, {"retries": 1.5},
                     {"retries": "Infinity"}, {"max_repetitions": 10.0}, {"max_repetitions": "NaN"}):
            # NaN/Infinity are what Python's json reads from a file; written raw so json.dumps does not quote them
            body = ", ".join(f'"{k}": {v}' for k, v in snmp.items())
            data = '{"profile": "x", "api_version": 1, "extends": "standard", "snmp": {' + body + '}}'
            with self.subTest(snmp=snmp), self.assertRaisesRegex(ProfileError, "snmp\\.(timeout|max_repetitions)"):
                snmp_profiles.load_file(self.user_file(data))

    def test_extends_that_is_not_a_name_names_the_key(self):
        for parent in ({"profile": "standard"}, "../standard", "/etc/standard.json", 5):
            with self.subTest(parent=parent), self.assertRaises(ProfileError) as cm:
                snmp_profiles.load_file(self.user_file({"profile": "x", "api_version": 1, "extends": parent}))
            self.assertIn("extends must be a built-in profile name", str(cm.exception))
            self.assertNotIn("/etc", str(cm.exception))

    def test_duplicate_keys_are_reported(self):
        data = '{"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"strategy": "bridge", "strategy": "qbridge"}}'
        with self.assertRaisesRegex(ProfileError, "duplicate key 'strategy'"):
            snmp_profiles.load_file(self.user_file(data))

    def test_duplicate_key_message_is_truncated(self):
        long = "k" * 5000
        data = '{"profile": "x", "api_version": 1, "%s": 1, "%s": 2}' % (long, long)
        with self.assertRaises(ProfileError) as cm:
            snmp_profiles.load_file(self.user_file(data))
        self.assertIn("duplicate key '" + "k" * 40 + "'", str(cm.exception))
        self.assertNotIn("k" * 41, str(cm.exception))

    def test_profile_file_must_be_a_small_regular_file(self):
        d = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, d)
        with self.assertRaisesRegex(ProfileError, "not a regular file"):
            snmp_profiles.load_file(d)
        big = '{"profile": "x", "api_version": 1, "extends": "standard", "pad": "' + "SECRETPAD" * 30000 + '"}'
        with self.assertRaises(ProfileError) as cm:
            snmp_profiles.load_file(self.user_file(big))
        self.assertIn("larger than 256 KiB", str(cm.exception))
        self.assertNotIn("SECRETPAD", str(cm.exception))

    def test_huge_integer_timeout_gets_the_timeout_message(self):
        data = '{"profile": "x", "api_version": 1, "extends": "standard", "snmp": {"timeout": 1' + "0" * 400 + '}}'
        with self.assertRaisesRegex(ProfileError, "snmp.timeout must be a number > 0"):
            snmp_profiles.load_file(self.user_file(data))

    def test_standard_source_names_every_partial_short_name_hit(self):
        p = snmp_profiles.load("standard")
        for cisco in ("TwoGigabitEthernet", "FiveGigabitEthernet", "TenGigabitEthernet", "FortyGigabitEthernet", "AppGigabitEthernet"):
            short = short_ifname(cisco, p["port_name"]["short"])
            with self.subTest(cisco=cisco):
                self.assertIn(f"'{cisco}' -> '{short}'", p["_source"])

    def test_a_file_may_share_the_name_of_the_builtin_it_extends(self):
        p = snmp_profiles.load_file(self.user_file({"profile": "comware", "api_version": 1, "extends": "comware", "uplink": {"min_macs": 9}}))
        self.assertEqual((p["profile"], p["uplink"]["min_macs"]), ("comware", 9))

    def test_detect(self):
        d = snmp_profiles.detect
        self.assertEqual(d("1.3.6.1.4.1.25506.11.1.1", "anything"), "comware")
        self.assertEqual(d(".1.3.6.1.4.1.25506.11.1.1", ""), "comware")
        self.assertEqual(d("1.3.6.1.4.1.255061.1", ""), "standard")  # prefix on an arc boundary only
        self.assertEqual(d("1.3.6.1.4.1.9.1.1", "Cisco IOS Software"), "cisco_ios")
        self.assertEqual(d("1.3.6.1.4.1.9.1.1", "Cisco Adaptive Security Appliance"), "standard")  # both lists must match
        self.assertEqual(d("1.3.6.1.4.1.14988.1", ""), "routeros")
        self.assertEqual(d("1.3.6.1.4.1.11863.5.1", ""), "jetstream")
        self.assertEqual((d("1.3.6.1.4.1.890.1.5.8.1", "GS1900"), d("1.3.6.1.4.1.890.1.5.8.1", "USG")), ("zynos", "standard"))
        self.assertEqual(d("1.3.6.1.4.1.4413.1", "EdgeSwitch 24"), "standard")  # edgeswitch only by name
        self.assertEqual(d("", ""), "standard")

    def test_detect_is_first_match_in_fixed_order(self):
        self.assertEqual(snmp_profiles.DETECT_ORDER[0], "comware")
        anything = {"match": {"sysobjectid_prefix": ["1.3.6.1.4.1"]}}
        with mock.patch.object(snmp_profiles, "load", return_value=anything) as load:
            self.assertEqual(snmp_profiles.detect("1.3.6.1.4.1.2", ""), "comware")
        load.assert_called_once_with("comware")

    def test_ignored_keys_exist_in_the_standard_schema(self):
        std = snmp_profiles.load("standard")
        for key in snmp_profiles.IGNORED_KEYS:
            section, name = key.split(".")
            self.assertIn(name, std[section])


class BuildSnapshotProfileTests(unittest.TestCase):
    NAMES = [("1", "port1"), ("2", "port2")]

    def setUp(self):
        # these rows often have no dot1dBasePortIfIndex on purpose; its warning is tested in test_enrichers
        lg = logging.getLogger("leasewatch.switch")
        self.addCleanup(lg.setLevel, lg.level)
        lg.setLevel(logging.ERROR)

    def prof(self, name="standard", **sections):
        p = snmp_profiles.load(name)
        for sec, vals in sections.items():
            p[sec].update(vals)
        return p

    def test_index_fixes(self):
        rows = [("10.6.2.0.0.0.0.1", 1), ("10.2.0.0.0.0.2", 2)]
        none = build_snapshot(rows, [], self.NAMES, [], profile=self.prof())
        self.assertEqual(none.by_mac, {"02:00:00:00:00:02": (2, 10)})  # 8-part index dropped
        lb = build_snapshot(rows, [], self.NAMES, [], profile=self.prof(fdb={"index_fix": "length_byte"}))
        self.assertEqual(lb.by_mac, {"02:00:00:00:00:01": (1, 10), "02:00:00:00:00:02": (2, 10)})
        bad = build_snapshot([("10.7.2.0.0.0.0.1", 1)], [], self.NAMES, [], profile=self.prof(fdb={"index_fix": "length_byte"}))
        self.assertEqual(bad.by_mac, {})  # only a 6 is a length octet
        zy = build_snapshot([("10.7.2.0.0.0.0.1", 1), ("x.2.0.0.0.0.2", 1)], [], self.NAMES, [], profile=self.prof("zynos"))
        self.assertEqual(zy.by_mac, {"02:00:00:00:00:01": (1, 10)})
        rn = build_snapshot([("0.1", 2), ("0.2", 1), ("0.3", 1)], [], self.NAMES, [], profile=self.prof(fdb={"index_fix": "row_number"}),
                            fdb_address=[("0.1", "02:00:00:00:00:0a"), ("0.2", "02:00:00:00:00:0b")])
        self.assertEqual(rn.by_mac, {"02:00:00:00:00:0a": (2, 0), "02:00:00:00:00:0b": (1, 0)})  # row 3 has no address

    def test_jetstream_offset_and_name_match(self):
        names = [("49153", "gigabitEthernet1/0/1"), ("7", "gigabitEthernet1/0/3")]
        s = build_snapshot([("1.2.0.0.0.0.1", 1), ("1.2.0.0.0.0.3", 3), ("1.2.0.0.0.0.4", 4)], [("1", 99)], names, [], profile=self.prof("jetstream"))
        self.assertEqual(s.by_mac["02:00:00:00:00:01"], (49153, 1))  # identity strategy: dot1dBasePortIfIndex ignored
        self.assertEqual(s.by_mac["02:00:00:00:00:03"], (7, 1))      # offset missed, name matched
        self.assertEqual(s.by_mac["02:00:00:00:00:04"], (49156, 1))  # neither: offset kept (fallback identity)
        drop = build_snapshot([("1.2.0.0.0.0.4", 4)], [], names, [], profile=self.prof("jetstream", bridge_port_map={"fallback": "drop"}))
        self.assertEqual(drop.by_mac, {})

    def test_baseport_map_still_wins_over_offset(self):
        s = build_snapshot([("1.2.0.0.0.0.1", 1)], [("1", 5)], [], [], profile=self.prof(bridge_port_map={"offset": 100}))
        self.assertEqual(s.by_mac["02:00:00:00:00:01"], (5, 1))

    def test_keep_status(self):
        rows = [("1.2.0.0.0.0.1", 1), ("1.2.0.0.0.0.2", 1), ("1.2.0.0.0.0.3", 1), ("1.2.0.0.0.0.4", 0)]
        status = [("1.2.0.0.0.0.1", 3), ("1.2.0.0.0.0.2", 4), ("1.2.0.0.0.0.4", 3), ("1.2.0.0.0.0.9", "x")]
        s = build_snapshot(rows, [], self.NAMES, [], profile=self.prof(fdb={"keep_status": [3]}), fdb_status=status)
        self.assertEqual(sorted(s.by_mac), ["02:00:00:00:00:01", "02:00:00:00:00:03"])  # :03 has no status row; :04 port 0
        s = build_snapshot(rows, [], self.NAMES, [], profile=self.prof(), fdb_status=status)
        self.assertEqual(len(s.by_mac), 3)  # empty keep_status: no filter

    def test_short_names_come_from_the_profile(self):
        names = [("1", "GigabitEthernet1/0/1")]
        rows = [("1.2.0.0.0.0.1", 1)]
        self.assertEqual(build_snapshot(rows, [], names, [], profile=self.prof()).describe("02:00:00:00:00:01")[0], "GE1/0/1")
        self.assertEqual(build_snapshot(rows, [], names, [], profile=self.prof("comware")).describe("02:00:00:00:00:01")[0], "GE1/0/1")
        self.assertNotIn("port_name", json.loads((Path(snmp_profiles.__file__).parent / "comware.json").read_text()))  # inherits
        self.assertEqual(build_snapshot(rows, [], names, []).describe("02:00:00:00:00:01")[0], "GE1/0/1")  # None = 1.0
        mine = self.prof(port_name={"short": {"GigabitEthernet": "Gi"}})
        self.assertEqual(build_snapshot(rows, [], names, [], profile=mine).describe("02:00:00:00:00:01")[0], "Gi1/0/1")
        self.assertEqual((short_ifname("FortyGigE1/0/1"), short_ifname("GigabitEthernet1", {})), ("FGE1/0/1", "GigabitEthernet1"))

    def test_standard_short_names_are_generic_and_leave_other_vendors_alone(self):
        short = self.prof()["port_name"]["short"]
        cases = {"Ten-GigabitEthernet1/0/49": "XGE1/0/49", "GigabitEthernet0/1": "GE0/1", "FortyGigE1/0/53": "FGE1/0/53",
                 "HundredGigE1/0/1": "HGE1/0/1", "TwentyFiveGigE1/0/1": "TGE1/0/1", "Bridge-Aggregation2": "BAGG2",
                 "Port-channel1": "Po1",
                 # not shortened: lower-case JetStream names, FastEthernet, already short names (no "Ethernet" key)
                 "gigabitEthernet1/0/1": "gigabitEthernet1/0/1", "FastEthernet0/1": "FastEthernet0/1", "ether1": "ether1",
                 "Ethernet1": "Ethernet1"}
        for long, want in cases.items():
            self.assertEqual(short_ifname(long, short), want, long)
        for name in snmp_profiles.BUILTIN:
            self.assertEqual(self.prof(name)["port_name"]["short"], short, name)

    def test_drop_fallback_keeps_an_offset_that_hits_an_interface(self):
        names = [("49156", "port4")]
        s = build_snapshot([("1.2.0.0.0.0.4", 4), ("1.2.0.0.0.0.5", 5)], [], names, [],
                           profile=self.prof("jetstream", bridge_port_map={"fallback": "drop"}))
        self.assertEqual(s.by_mac, {"02:00:00:00:00:04": (49156, 1)})  # :05 -> 49157: no interface, dropped

    def test_lldp_local_port_and_uplink_settings(self):
        names = [("14", "ge14"), ("3", "ge3")]
        auto = build_snapshot([], [], names, [("1.3.1", "ap-hall")], [("3", "ge14")], profile=self.prof())
        self.assertEqual(auto.ports[14].neighbor, "ap-hall")
        ifx = build_snapshot([], [], names, [("1.3.1", "ap-hall")], [("3", "ge14")], profile=self.prof("routeros"))
        self.assertEqual((ifx.ports[3].neighbor, ifx.ports[14].neighbor), ("ap-hall", ""))
        rows = [(f"1.2.0.0.0.0.{i}", 14) for i in range(3)]
        self.assertTrue(build_snapshot(rows, [], names, [], profile=self.prof(uplink={"min_macs": 3})).ports[14].uplink)
        self.assertFalse(build_snapshot(rows, [], names, [], profile=self.prof()).ports[14].uplink)
        no_lldp = build_snapshot([], [], names, [("1.3.1", "ap-hall")], profile=self.prof(uplink={"lldp_neighbor": False}))
        self.assertEqual((no_lldp.ports[3].neighbor, no_lldp.ports[3].uplink), ("ap-hall", False))


def add_rows(walker: FakeWalker, rows: list, context: str = "") -> FakeWalker:
    """Extra (oid, value) rows in one context of a FakeWalker."""
    walker.tables[context] = sorted(walker.tables.get(context, []) + [(_otuple(o), o, v) for o, v in rows])
    return walker


VTP = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"


class PerVlanFallbackTests(unittest.TestCase):
    """cisco_per_vlan without usable vlan-N contexts reads Q-BRIDGE for that poll (standard.snmprec has Q-BRIDGE)."""

    def walker(self, vlans=(10, 20)):
        return add_rows(FakeWalker("standard"), [(f"{VTP}.1.{v}", 1) for v in vlans])

    def run_cisco(self, walker, fail_contexts=False, c=None):
        c = c or SwitchClient(CFG, snmp_profiles.load("cisco_ios"))
        with FakePysnmp(walker) as fake:
            if fail_contexts:
                m, inner = sys.modules["pysnmp.hlapi.v3arch.asyncio"], sys.modules["pysnmp.hlapi.v3arch.asyncio"].next_cmd

                async def next_cmd(eng, user, tgt, ctx, oid):
                    if ctx:  # what an agent says for a context it does not have
                        return "unknownContextName", 0, 0, []
                    return await inner(eng, user, tgt, ctx, oid)
                m.next_cmd = next_cmd
            snap = c.snapshot()
        return snap, fake

    def standard_macs(self):
        return {mac: tuple(v[k] for k in ("ifindex", "vlan")) for mac, v in json.loads((FIXTURES / "standard.json").read_text())["macs"].items()}

    def test_all_contexts_failing_falls_back_once_with_one_warning(self):
        c = SwitchClient(CFG, snmp_profiles.load("cisco_ios"), name="core-sw")
        with self.assertLogs("leasewatch.switch", "WARNING") as logs:
            snap, fake = self.run_cisco(self.walker(), fail_contexts=True, c=c)
            snap2, _ = self.run_cisco(self.walker(), fail_contexts=True, c=c)
        self.assertEqual((snap.strategy, snap2.strategy), ("qbridge", "qbridge"))
        self.assertEqual(snap.by_mac, self.standard_macs())
        self.assertEqual(len([r for r in logs.output if "per-VLAN contexts unavailable, using Q-BRIDGE" in r]), 1)
        self.assertIn("core-sw: snmp profile cisco_ios: per-VLAN", logs.output[0])
        self.assertEqual([oid for k, ctx, oid in fake.calls if ctx == "" and oid == "1.3.6.1.2.1.17.7.1.2.2.1.2"], ["1.3.6.1.2.1.17.7.1.2.2.1.2"])

    def test_the_fallback_warning_is_once_per_instance(self):
        with self.assertLogs("leasewatch.switch", "WARNING") as logs:
            for name in ("sw-a", "sw-b"):  # a second switch instance must not be silenced by the first
                self.run_cisco(self.walker(), fail_contexts=True, c=SwitchClient(CFG, snmp_profiles.load("cisco_ios"), name=name))
        warned = [r for r in logs.output if "per-VLAN contexts unavailable" in r]
        self.assertEqual(len(warned), 2)
        self.assertIn("sw-a", warned[0])
        self.assertIn("sw-b", warned[1])

    def test_contexts_without_rows_and_an_empty_vlan_list_fall_back(self):
        for vlans in ((10,), ()):  # vlan-10 not in the fixture = 0 rows; no VTP rows = no VLAN at all
            with self.subTest(vlans=vlans), self.assertLogs("leasewatch.switch", "WARNING"):
                snap, _ = self.run_cisco(self.walker(vlans))
                self.assertEqual((snap.strategy, snap.by_mac), ("qbridge", self.standard_macs()))

    def test_per_vlan_rows_keep_the_strategy_and_a_partial_failure_still_fails(self):
        snap, _ = run("cisco_ios", c := SwitchClient(CFG))
        self.assertEqual(snap.strategy, "cisco_per_vlan")
        self.assertFalse(c._per_vlan_warned)
        w = add_rows(self.walker((10, 20)), [("1.3.6.1.2.1.17.4.3.1.2.2.0.0.0.0.9", 1)], "vlan-10")
        c = SwitchClient(CFG, snmp_profiles.load("cisco_ios"))
        with FakePysnmp(w):
            m, inner = sys.modules["pysnmp.hlapi.v3arch.asyncio"], sys.modules["pysnmp.hlapi.v3arch.asyncio"].next_cmd

            async def next_cmd(eng, user, tgt, ctx, oid):
                return ("unknownContextName", 0, 0, []) if ctx == "vlan-20" else await inner(eng, user, tgt, ctx, oid)
            m.next_cmd = next_cmd
            with self.assertRaisesRegex(RuntimeError, "^snmp context vlan-20: snmp walk .*unknownContextName"):
                c.snapshot()  # the error names the VLAN whose context is missing

    def test_a_vlan_in_two_vtp_domains_is_walked_once(self):
        w = add_rows(FakeWalker("cisco_ios"), [(f"{VTP}.2.10", 1)])
        snap, fake = run_walker(w, SwitchClient(CFG))
        fdb_oid = "1.3.6.1.2.1.17.4.3.1.2"
        self.assertEqual(sum(1 for k, ctx, oid in fake.calls if ctx == "vlan-10" and oid == fdb_oid), 1)


def run_walker(walker: FakeWalker, client: SwitchClient):
    with FakePysnmp(walker) as fake:
        snap = client.snapshot()
    return snap, fake


class DetectionFailureTests(unittest.TestCase):
    def test_a_failing_detection_get_uses_standard_and_retries(self):
        c = SwitchClient(CFG)
        with FakePysnmp(FakeWalker("comware")) as fake, self.assertLogs("leasewatch.switch", "WARNING") as logs:
            async def get_cmd(eng, user, tgt, ctx, *oids):
                fake.calls.append(("get", ctx, oids))
                return None, 2, 0, []  # e.g. an authorization error status for sysObjectID
            sys.modules["pysnmp.hlapi.v3arch.asyncio"].get_cmd = get_cmd
            snap = c.snapshot(); c.snapshot()
        self.assertEqual(c.profile_name, "standard")
        self.assertEqual(len(snap.by_mac), 3)
        self.assertEqual(sum(1 for k, *_ in fake.calls if k == "get"), 2)  # not cached: tried again next poll
        self.assertEqual(len([r for r in logs.output if "detection failed" in r]), 1)
        with FakePysnmp(FakeWalker("comware")):
            c.snapshot()
        self.assertEqual(c.profile_name, "comware")  # a later working GET still detects

    def test_values_missing_from_the_view_detect_standard(self):
        w = FakeWalker("comware")
        w.tables[""] = [r for r in w.tables[""] if not r[1].startswith("1.3.6.1.2.1.1.")]
        snap, _ = run_walker(w, c := SwitchClient(CFG))
        self.assertEqual((c.profile_name, len(snap.by_mac)), ("standard", 3))


class RowValueTests(unittest.TestCase):
    def test_non_integer_status_is_a_runtimeerror(self):
        prof = snmp_profiles.load("standard")
        prof["fdb"]["keep_status"] = [3]
        w = add_rows(FakeWalker("standard"), [("1.3.6.1.2.1.17.7.1.2.2.1.3.10.2.0.0.0.0.9", b"x")])
        with self.assertRaisesRegex(RuntimeError, "non-integer"):
            run_walker(w, SwitchClient(CFG, prof))

    def test_an_integer_address_is_skipped_not_a_zero_mac(self):
        prof = snmp_profiles.load("standard")
        prof["fdb"].update(strategy="bridge", index_fix="row_number")
        w = add_rows(FakeWalker("standard"), [("1.3.6.1.2.1.17.4.3.1.1.1", bytes.fromhex("02000000000a")),
                                              ("1.3.6.1.2.1.17.4.3.1.1.2", 5),
                                              ("1.3.6.1.2.1.17.4.3.1.2.1", 1), ("1.3.6.1.2.1.17.4.3.1.2.2", 2)])
        snap, _ = run_walker(w, SwitchClient(CFG, prof))
        self.assertEqual(snap.by_mac, {"02:00:00:00:00:0a": (1, 0)})


class ClientSignatureTests(unittest.TestCase):
    def test_init_is_annotated(self):
        self.assertEqual(SwitchClient.__init__.__annotations__.get("return"), "None")  # postponed annotations: text


class MinMacsTests(unittest.TestCase):
    def test_override_applies_to_the_snapshot_not_the_cached_profile(self):
        c = SwitchClient(CFG, min_macs=1)
        snap, _ = run("standard", c)
        self.assertTrue(snap.ports[1].uplink)  # one MAC, no LLDP: an uplink only because of the override
        self.assertEqual(c.profile["uplink"]["min_macs"], 6)
        self.assertFalse(run("standard", SwitchClient(CFG))[0].ports[1].uplink)


class NoPysnmp:
    """Makes `import pysnmp...` raise ImportError (a None entry in sys.modules does that)."""

    def __enter__(self):
        self._saved = {k: sys.modules.get(k) for k in FakePysnmp.MODS}
        for k in FakePysnmp.MODS:
            sys.modules[k] = None
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def cli(*argv: str) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(list(argv))
    return rc, buf.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        # snmp-detect reads SNMP_* through Config(): the developer's own variables must not reach it
        self.addCleanup(restore, clean_env({"TEST_AK": "test-auth", "TEST_PK": "test-priv"}))
        root = logging.getLogger()  # main() may call basicConfig; keep the test run's handlers as they were
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)

    def test_snmp_profiles_lists_every_builtin_with_its_rule(self):
        with NoPysnmp():
            rc, out = cli("snmp-profiles")
        self.assertEqual(rc, 0)
        self.assertIn("pysnmp not installed", out)
        for name in snmp_profiles.BUILTIN:
            self.assertRegex(out, rf"(?m)^{name} ")
        self.assertIn("sysObjectID 1.3.6.1.4.1.25506.*", out)
        self.assertIn("by name only", out)
        with FakePysnmp(FakeWalker("standard")):
            self.assertNotIn("pysnmp not installed", cli("snmp-profiles")[1])

    def test_snmp_detect_without_pysnmp(self):
        with NoPysnmp():
            rc, out = cli("snmp-detect", "--host", "10.0.0.2")
        self.assertEqual((rc, out.strip()), (1, "pysnmp not installed: the SNMP switch connector and snmp-detect need it (pip install pysnmp)"))

    def test_snmp_detect_with_flags_reads_keys_from_env_names(self):
        with FakePysnmp(FakeWalker("comware")) as fake:
            rc, out = cli("snmp-detect", "--host", "10.0.0.2", "--auth-key-env", "TEST_AK", "--priv-key-env", "TEST_PK", "--rows", "2")
        self.assertEqual(rc, 0, out)
        self.assertIn("sysObjectID: 1.3.6.1.4.1.25506", out)
        self.assertIn("profile:     comware (detected)", out)
        self.assertIn("walk fdb_port (1.3.6.1.2.1.17.7.1.2.2.1.2):", out)
        self.assertIn("walk lldp_rem_sysname", out)
        fdb = out.split("walk fdb_port")[1].split("walk ")[0]
        self.assertEqual(fdb.count(" = "), 2)  # --rows 2
        self.assertNotIn("test-auth", out)
        self.assertEqual(fake.targets[0][0], ("10.0.0.2", 161))

    def test_snmp_detect_reports_any_snmp_exception_as_one_line(self):
        PySnmpError = type("PySnmpError", (Exception,), {})
        with FakePysnmp(FakeWalker("comware")):
            class UdpTransportTarget:
                @staticmethod
                async def create(addr, timeout, retries):
                    raise PySnmpError(f"Bad IPv4/UDP transport address {addr[0]}@161: no such host")
            sys.modules["pysnmp.hlapi.v3arch.asyncio"].UdpTransportTarget = UdpTransportTarget
            rc, out = cli("snmp-detect", "--host", "10.0.0.2", "--auth-key-env", "TEST_AK", "--priv-key-env", "TEST_PK")
        self.assertEqual((rc, out.strip()), (1, "snmp error: Bad IPv4/UDP transport address <host>@161: no such host"))

    def test_snmp_detect_masks_host_user_and_keys_in_every_error_line(self):
        os.environ.update({"TEST_AK": "auth-K3y'x", "TEST_PK": "priv\\K3y"})  # repr() escapes these two differently
        PySnmpError = type("PySnmpError", (Exception,), {})
        leak = "10.0.0.2 user netmon keys auth-K3y'x priv\\K3y " + repr("auth-K3y'x priv\\K3y")
        flags = ("--host", "10.0.0.2", "--user", "netmon", "--auth-key-env", "TEST_AK", "--priv-key-env", "TEST_PK")
        with FakePysnmp(FakeWalker("comware")):
            m = sys.modules["pysnmp.hlapi.v3arch.asyncio"]
            inner = m.next_cmd

            async def next_cmd(eng, user, tgt, ctx, oid):  # every walk fails with an indication naming everything
                return PySnmpError(leak), 0, 0, []
            m.next_cmd = m.bulk_cmd = next_cmd
            rc1, out1 = cli("snmp-detect", *flags)
            m.next_cmd = inner

            class UdpTransportTarget:
                @staticmethod
                async def create(addr, timeout, retries):
                    raise PySnmpError(leak)
            m.UdpTransportTarget = UdpTransportTarget
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc2, out2 = cli("snmp-detect", *flags)
        self.assertEqual((rc1, rc2), (0, 1), out1 + out2)
        self.assertIn("  error: snmp walk", out1)
        self.assertTrue(out2.startswith("snmp error: "), out2)
        for out in (out1, out2, err.getvalue()):
            for secret in ("10.0.0.2", "netmon", "auth-K3y", "priv", "K3y"):
                self.assertNotIn(secret, out)
        self.assertIn("<host> user <user> keys *** ***", out2)

    def test_snmp_detect_missing_key_env_is_a_config_problem(self):
        with FakePysnmp(FakeWalker("comware")):
            rc, out = cli("snmp-detect", "--host", "10.0.0.2", "--auth-key-env", "TEST_NOPE")
        self.assertEqual(rc, 2)
        self.assertIn("environment variable TEST_NOPE (from --auth-key-env) is not set", out)

    def test_snmp_detect_unset_key_env_names_the_variable(self):
        os.environ.pop("UNSET_X", None)
        os.environ["TEST_PK"] = "test-priv"
        with FakePysnmp(FakeWalker("comware")):
            rc, out = cli("snmp-detect", "--host", "10.0.0.2", "--auth-key-env", "UNSET_X", "--priv-key-env", "TEST_PK")
        self.assertEqual(rc, 2)
        self.assertIn("environment variable UNSET_X (from --auth-key-env) is not set", out)

    def test_snmp_detect_by_instance_uses_its_settings(self):
        os.environ.update({**sources("switch"), "LW_CONNECTOR__SWITCH__HOST": "10.0.0.3",
                           "LW_CONNECTOR__SWITCH__AUTH_KEY": "test-auth", "LW_CONNECTOR__SWITCH__PRIV_KEY": "test-priv"})
        with FakePysnmp(FakeWalker("cisco_ios")) as fake:
            rc, out = cli("snmp-detect", "switch")
            self.assertEqual(rc, 0, out)
            self.assertEqual(fake.targets[0][0], ("10.0.0.3", 161))
            self.assertIn("profile:     cisco_ios (detected)", out)
            self.assertIn("context vlan-1:", out)
            rc, out = cli("snmp-detect", "nope")
        self.assertEqual(rc, 2)
        self.assertIn("no snmp_switch instance 'nope'", out)

    def test_snmp_detect_shows_the_profile_file_error_on_the_terminal(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump({"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"strategy": "magic"}}, f)
        self.addCleanup(os.unlink, path)
        with FakePysnmp(FakeWalker("standard")):
            rc, out = cli("snmp-detect", "--host", "10.0.0.2", "--auth-key-env", "TEST_AK", "--priv-key-env", "TEST_PK", "--profile-file", path)
        self.assertEqual(rc, 2)
        self.assertIn("PROFILE_FILE is not a valid snmp profile", out)
        self.assertIn("fdb.strategy 'magic'", out)

    def test_no_subcommand_keeps_the_server_path(self):
        import leasewatch.__main__ as m
        with mock.patch.object(m, "Config", side_effect=RuntimeError("server path")):
            with self.assertRaisesRegex(RuntimeError, "server path"):
                main([])
            with self.assertRaisesRegex(RuntimeError, "server path"):
                main(["--unknown"])  # unknown arguments were ignored before, and still are


if __name__ == "__main__":
    unittest.main()
