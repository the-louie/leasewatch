"""SNMP profile loader: regression tests for operator profile files (encoding, nesting, keys, values, messages)."""
import json, os, pathlib, sys, tempfile, threading, unittest
from pathlib import Path
from unittest import mock
import _env  # noqa: F401  # the repo root on the path and the network guard, also when this module runs on its own
from leasewatch import snmp_profiles
from leasewatch.snmp_profiles import ProfileError
from leasewatch.switch import short_ifname


class ProfileFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, data: object, name: str = "p.json") -> Path:
        path = Path(self.tmp.name, name)
        path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
        return path

    def deep(self, depth: int, extends: bool) -> Path:
        o = {"profile": "x", "api_version": 1, "deep": "__D__"}
        if extends:
            o["extends"] = "standard"
        return self.write(json.dumps(o).replace('"__D__"', "[" * depth + "]" * depth).encode())

    def error(self, path: Path) -> str:
        with self.assertRaises(ProfileError) as cm:
            snmp_profiles.load_file(path)
        return str(cm.exception)

    def test_utf8_bom_is_accepted(self) -> None:
        path = self.write(b"\xef\xbb\xbf" + json.dumps({"profile": "x", "api_version": 1, "extends": "standard"}).encode())
        self.assertEqual(snmp_profiles.load_file(path)["profile"], "x")

    def test_syntax_error_names_line_and_column(self) -> None:
        msg = self.error(self.write(b'{"a": 1,\n "b": 2,,}'))
        self.assertIn("line 2 column", msg)

    def test_deep_nesting_is_profile_error(self) -> None:
        for extends in (True, False):
            for depth in (600, 1000):
                with self.subTest(extends=extends, depth=depth):
                    self.error(self.deep(depth, extends))

    def test_comment_key_inside_section_is_allowed(self) -> None:
        p = snmp_profiles.load_file(self.write({"profile": "x", "api_version": 1, "extends": "standard", "fdb": {"_comment": "why"}}))
        self.assertEqual(p["fdb"]["_comment"], "why")

    def test_non_numeric_oid_is_rejected(self) -> None:
        for bad in ("not an oid", "1.3.6.l.2.1.17.7.1.2.2.1.2", "", "1..3"):
            with self.subTest(bad=bad):
                msg = self.error(self.write({"profile": "x", "api_version": 1, "extends": "standard", "oids": {"fdb_port": bad}}))
                self.assertIn("oids", msg)
        p = snmp_profiles.load_file(self.write({"profile": "x", "api_version": 1, "extends": "standard", "oids": {"fdb_port": "1.3.6.1.4.1.32473.1"}}))
        self.assertEqual(p["oids"]["fdb_port"], "1.3.6.1.4.1.32473.1")

    def test_empty_short_key_is_rejected(self) -> None:
        msg = self.error(self.write({"profile": "x", "api_version": 1, "extends": "standard", "port_name": {"short": {"": "X", "GigabitEthernet": "GE"}}}))
        self.assertIn("port_name.short", msg)

    def test_fifo_swapped_in_after_check_does_not_block(self) -> None:
        path = self.write({"profile": "x", "api_version": 1, "extends": "standard"})
        orig_stat, orig_open = pathlib.Path.stat, snmp_profiles.os.open
        swapped: list = []

        def swap(p: object) -> None:
            # once, at whichever of stat()/open() runs first: covers today's os.open and a stat()-then-open() variant
            if not swapped and Path(p) == path:
                swapped.append(True)
                os.unlink(path)
                os.mkfifo(path)

        def stat_then_swap(p: Path, *a: object, **k: object) -> object:
            r = orig_stat(p, *a, **k)
            swap(p)
            return r

        def swap_then_open(p: object, *a: object, **k: object) -> int:
            swap(p)
            return orig_open(p, *a, **k)

        out: list = []

        def run() -> None:
            try:
                out.append(snmp_profiles.load_file(path))
            except ProfileError as e:
                out.append(e)

        with mock.patch.object(pathlib.Path, "stat", stat_then_swap), mock.patch.object(snmp_profiles.os, "open", swap_then_open):
            t = threading.Thread(target=run, daemon=True)
            t.start()
            t.join(3)
        blocked = t.is_alive()
        if blocked:  # free the reader so the thread ends: a writer that closes at once gives it EOF
            os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
            t.join(3)
        self.assertFalse(blocked, "open() blocked on a FIFO")
        self.assertEqual(swapped, [True])
        self.assertEqual(len(out), 1)
        self.assertIn("not a regular file", str(out[0]))

    def test_existing_fifo_is_rejected(self) -> None:
        path = Path(self.tmp.name, "f.json")
        os.mkfifo(path)
        self.assertIn("not a regular file", self.error(path))

    def test_api_version_message_is_capped(self) -> None:
        for data in ({"api_version": 2, "profile": "A" * 200000}, {"api_version": [0] * 80000}):
            with self.subTest(n=len(json.dumps(data))):
                self.assertLess(len(self.error(self.write(data))), 300)

    def test_extends_messages_are_capped(self) -> None:
        msg = self.error(self.write({"api_version": 1, "profile": "A" * 200000, "extends": ["x"]}))
        self.assertLess(len(msg), 300)

    def test_unknown_section_key_is_quoted_and_capped(self) -> None:
        msg = self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "fdb": {"a\nsnmp profile 'x': fake\u001b[2J": 1}}))
        self.assertNotIn("\n", msg)
        self.assertNotIn("\x1b", msg)
        self.assertLess(len(self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "fdb": {"k" * 200000: 1}}))), 300)
        self.assertLess(len(self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "k" * 200000: 1}))), 300)

    def test_short_unknown_key_message_unchanged(self) -> None:
        msg = self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "fdb": {"typo": 1}}))
        self.assertIn("unknown key fdb.typo", msg)

    def test_profile_name_in_validate_message_is_capped(self) -> None:
        msg = self.error(self.write({"api_version": 1, "extends": "standard", "profile": "x" * 200000, "fdb": {"strategy": "bad"}}))
        self.assertLess(len(msg), 300)
        self.assertIn("fdb.strategy 'bad'", msg)

    def test_short_map_applies_longest_key_first(self) -> None:
        p = snmp_profiles.load_file(self.write({"profile": "x", "api_version": 1, "extends": "standard",
                                                "port_name": {"short": {"GigabitEthernet": "GE", "Ten-GigabitEthernet": "XGE"}}}))
        self.assertEqual(short_ifname("Ten-GigabitEthernet1/0/49", p["port_name"]["short"]), "XGE1/0/49")
        self.assertEqual(short_ifname("GigabitEthernet1/0/1", p["port_name"]["short"]), "GE1/0/1")

    # a section key is shown as written, delimited when it is not a plain name, and a cut is marked
    def test_section_key_message_shows_non_ascii_as_written(self) -> None:
        msg = self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "fdb": {"l\u00e4nk": 1}}))
        self.assertIn("unknown key fdb.l\u00e4nk", msg)

    def test_cut_section_keys_are_marked_and_distinct(self) -> None:
        a = self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "fdb": {"x" * 41: 1}}))
        b = self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "fdb": {"x" * 40 + "y": 1}}))
        self.assertNotEqual(a, b)
        cut = self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "fdb": {"x" * 100: 1}}))
        self.assertIn("...", cut)
        top = self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "x" * 100: 1}))
        self.assertIn("...", top)
        self.assertNotEqual(a, b)

    def test_section_key_cannot_forge_a_second_problem(self) -> None:
        msg = self.error(self.write({"api_version": 1, "profile": "x", "extends": "standard", "fdb": {"x; missing key fdb.strategy": 1}}))
        self.assertIn("unknown key fdb.'x; missing key fdb.strategy'", msg)

    # a device node must not become the controlling terminal while it is being rejected
    def test_open_uses_noctty(self) -> None:
        path = self.write({"profile": "x", "api_version": 1, "extends": "standard"})
        with mock.patch.object(snmp_profiles.os, "open", wraps=os.open) as m:
            snmp_profiles.load_file(path)
        self.assertTrue(m.call_args.args[1] & os.O_NOCTTY)

    # MAX_DEPTH keeps resolving far from the recursion limit, so the deepest allowed file still validates
    def test_max_depth_file_reaches_validation(self) -> None:
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(200)
        try:
            msg = self.error(self.deep(snmp_profiles.MAX_DEPTH - 1, True))
        finally:
            sys.setrecursionlimit(old)
        self.assertIn("unknown key 'deep'", msg)

    # "_" comment keys are allowed in oids too
    def test_comment_key_in_oids_is_allowed(self) -> None:
        p = snmp_profiles.load_file(self.write({"profile": "x", "api_version": 1, "extends": "standard", "oids": {"_comment": "vendor MIB"}}))
        self.assertEqual(p["oids"]["_comment"], "vendor MIB")
        msg = self.error(self.write({"profile": "x", "api_version": 1, "extends": "standard", "oids": {"_comment": "vendor MIB"},
                                     "fdb": {"strategy": "cisco_per_vlan", "vlan_source": "_comment"}}))
        self.assertIn("fdb.vlan_source", msg)

    # the message does not grow with the number of unknown keys
    def test_many_unknown_keys_give_bounded_message(self) -> None:
        msg = self.error(self.write({"profile": "x", "api_version": 1, "extends": "standard", "fdb": {hex(i): 0 for i in range(20000)}}))
        self.assertLess(len(msg), 1000)
        self.assertIn("more", msg)

    # an empty short key is reported even when a value is also wrong
    def test_empty_short_key_and_bad_value_both_reported(self) -> None:
        msg = self.error(self.write({"profile": "x", "api_version": 1, "extends": "standard", "port_name": {"short": {"": 1}}}))
        self.assertIn("values must be strings", msg)
        self.assertIn("keys must not be empty", msg)



class SocketFileAndCommentKeyTest(unittest.TestCase):
    # the helpers only: subclassing would run every ProfileFileTest test twice
    setUp, write, error = ProfileFileTest.setUp, ProfileFileTest.write, ProfileFileTest.error

    def test_unix_socket_is_not_a_regular_file(self) -> None:
        import socket
        path = Path(self.tmp.name, "s.json")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(str(path))
        self.assertIn("not a regular file", self.error(path))

    def test_private_oids_cannot_name_a_comment_key(self) -> None:
        for val in ("see vendor doc", ["a"]):
            with self.subTest(val=val):
                msg = self.error(self.write({"profile": "x", "api_version": 1, "extends": "standard", "oids": {"_c": val},
                                             "fdb": {"strategy": "private", "private_oids": ["_c"]}}))
                self.assertIn("fdb.private_oids", msg)
        p = snmp_profiles.load_file(self.write({"profile": "x", "api_version": 1, "extends": "standard",
                                                "fdb": {"strategy": "private", "private_oids": ["1.3.6.1.4.1.32473.1"]}}))
        self.assertEqual(p["fdb"]["private_oids"], ["1.3.6.1.4.1.32473.1"])


if __name__ == "__main__":
    unittest.main()
