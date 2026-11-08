"""Edge cases of the switch client and build_snapshot (switch.py).

Synthetic data only; the switch is a FakeWalker behind the fake pysnmp module of test_switch_profiles.
"""
import asyncio, sys, unittest
from unittest import mock
from _env import clean_env, restore
from test_switch_profiles import CFG, VTP, FakePysnmp, FakeWalker, add_rows
from leasewatch import snmp_profiles
from leasewatch.config import Config
from leasewatch import switch as sw
from leasewatch.switch import SwitchClient, _fdb_key, build_snapshot, short_ifname

MAC = "02:00:00:00:00:01"


class EnvTest(unittest.TestCase):
    def setUp(self):
        self._saved = clean_env()
        self.cfg = Config()  # nothing below reads it beyond construction; the fake client config is CFG

    def tearDown(self):
        restore(self._saved)


class DottedWalker(FakeWalker):
    """An agent that, like pysnmp, accepts a request OID with a leading dot but answers without it."""

    def next(self, oid, context=""):
        return super().next(oid.lstrip("."), context)


class OctetString:
    """Stand-in for pyasn1's OctetString: asOctets() gives the bytes, str() decodes ISO-8859-1."""

    def __init__(self, raw: bytes):
        self.raw = raw

    def asOctets(self) -> bytes:
        return self.raw

    def __str__(self) -> str:
        return self.raw.decode("iso-8859-1")


def run(walker, client):
    with FakePysnmp(walker) as fake:
        snap = client.snapshot()
    return snap, fake


class OidFormTests(EnvTest):
    def test_r04_r86_r87_leading_dot_and_space_still_walk(self):
        for form in (".1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.31.1.1.1.1 ", "1.3.6.1.2.1.31.1.1.1.1."):
            with self.subTest(form=form):
                prof = snmp_profiles.load("standard")
                prof["oids"]["ifname"] = form
                snap, _ = run(DottedWalker("standard"), SwitchClient(CFG, prof))
                self.assertEqual(snap.ports[1].name, "ge-1")

    def test_r88_no_bulk_matches_dotted_and_parent_oids(self):
        for entry in (".1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.31.1.1.1"):
            with self.subTest(entry=entry):
                prof = snmp_profiles.load("standard")
                prof["snmp"]["bulk"], prof["snmp"]["no_bulk"] = True, [entry]
                _, fake = run(FakeWalker("standard"), SwitchClient(CFG, prof))
                self.assertFalse([c for c in fake.calls if c[0] == "bulk" and c[2].startswith("1.3.6.1.2.1.31.1.1.1.1")])


class PerVlanTests(EnvTest):
    def test_r05_empty_contexts_plus_a_failed_one_fail_the_poll(self):
        w = add_rows(FakeWalker("standard"), [(f"{VTP}.1.{v}", 1) for v in (1, 10, 30)])
        c = SwitchClient(CFG, snmp_profiles.load("cisco_ios"))
        with FakePysnmp(w):
            m = sys.modules["pysnmp.hlapi.v3arch.asyncio"]
            inner = m.next_cmd

            async def next_cmd(eng, user, tgt, ctx, oid):
                return ("requestTimedOut", 0, 0, []) if ctx == "vlan-10" else await inner(eng, user, tgt, ctx, oid)
            m.next_cmd = next_cmd
            with self.assertRaisesRegex(RuntimeError, "^snmp context vlan-10"):
                c.snapshot()


class ShortNameTests(unittest.TestCase):
    def test_r80_r81_empty_short_key_is_ignored(self):
        self.assertEqual(short_ifname("GE1/0/1", {"": "X"}), "GE1/0/1")
        prof = snmp_profiles.load("standard")
        prof["port_name"]["short"] = {"": "x"}
        s = build_snapshot([("1.2.0.0.0.0.1", 5)], [("5", 5)], [("5", "GE1/0/5")], [], profile=prof)
        self.assertEqual(s.describe(MAC), ("GE1/0/5", ""))


class BuildSnapshotTests(unittest.TestCase):
    def test_r82_warning_names_drop_and_can_be_silenced(self):
        prof = snmp_profiles.load("standard")
        prof["bridge_port_map"]["fallback"] = "drop"
        with self.assertLogs("leasewatch.switch", "WARNING") as logs:
            build_snapshot([("1.2.0.0.0.0.1", 5)], [], [], [], profile=prof)
        self.assertIn("dropped", logs.output[0])
        with self.assertNoLogs("leasewatch.switch", "WARNING"):
            build_snapshot([("1.2.0.0.0.0.1", 5)], [], [], [], profile=prof, warn=False)

    def test_r82_client_warns_once(self):
        w = FakeWalker("standard")
        w.tables[""] = [r for r in w.tables[""] if not r[1].startswith("1.3.6.1.2.1.17.1.4.1.2.")]
        c = SwitchClient(CFG, snmp_profiles.load("standard"))
        with self.assertLogs("leasewatch.switch", "WARNING") as logs:
            run(w, c)
            run(w, c)
        self.assertEqual(len([r for r in logs.output if "dot1dBasePortIfIndex" in r]), 1)

    def test_r83_fdb_only_port_keeps_its_lldp_neighbour(self):
        s = build_snapshot([("1.2.0.0.0.0.1", 5)], [("5", 5)], [], [("0.5.1", "ap-hall")])
        self.assertEqual((s.ports[5].neighbor, s.ports[5].uplink), ("ap-hall", True))
        self.assertEqual(s.describe(MAC), ("port 5", "ap-hall"))

    def test_r84_non_positive_ifindex_is_dropped(self):
        s = build_snapshot([("1.2.0.0.0.0.1", 3)], [("3", 0)], [], [])
        self.assertEqual((s.by_mac, s.ports), ({}, {}))
        prof = snmp_profiles.load("standard")
        prof["bridge_port_map"]["fallback"] = "identity"
        s = build_snapshot([("1.2.0.0.0.0.1", -2)], [("1", 1)], [], [], profile=prof)
        self.assertEqual((s.by_mac, s.ports), ({}, {}))

    def test_r85_edge_port_beats_the_uplink(self):
        names = [("9", "GigabitEthernet1/0/9"), ("14", "GigabitEthernet1/0/14")]
        for fdb in ([("10.2.0.0.0.0.1", 14), ("20.2.0.0.0.0.1", 9)], [("20.2.0.0.0.0.1", 9), ("10.2.0.0.0.0.1", 14)]):
            with self.subTest(fdb=fdb):
                s = build_snapshot(fdb, [("9", 9), ("14", 14)], names, [("0.9.1", "sw-core")])
                self.assertEqual(s.by_mac[MAC], (14, 10))
                self.assertEqual(s.describe(MAC), ("GE1/0/14", ""))

    def test_r144_mac_arcs_over_255_are_unusable(self):
        self.assertIsNone(_fdb_key("1.0.17.164.1.2.300", "none", {}))
        self.assertIsNone(_fdb_key("1.0.17.164.1.2.-1", "none", {}))
        self.assertEqual(_fdb_key("1.2.17.164.1.2.255", "none", {}), (1, "02:11:a4:01:02:ff"))

    def test_r145_default_profile_io_is_documented(self):
        import inspect
        from leasewatch import switch
        self.assertIn("Reads the built-in JSON files", inspect.getsource(switch._default_profile))


class ClientErrorTests(EnvTest):
    def test_r89_r146_non_runtime_detection_error_falls_back_and_names_the_instance(self):
        c = SwitchClient(CFG, name="sw-a")
        with FakePysnmp(FakeWalker("comware")), self.assertLogs("leasewatch.switch", "WARNING") as logs:
            async def get_cmd(*a):
                raise OSError("10.0.0.2 unreachable")
            sys.modules["pysnmp.hlapi.v3arch.asyncio"].get_cmd = get_cmd
            snap = c.snapshot()
        self.assertEqual((c.profile_name, len(snap.by_mac)), ("standard", 3))
        warned = [r for r in logs.output if "detection failed" in r]
        self.assertIn("sw-a:", warned[0])
        self.assertNotIn("10.0.0.2", warned[0])

    def test_r90_r149_raw_errors_become_runtimeerror(self):
        c = SwitchClient(CFG, snmp_profiles.load("standard"))
        with FakePysnmp(FakeWalker("standard")):
            class Target:
                @staticmethod
                async def create(addr, timeout, retries):
                    raise OSError("Bad IPv4/UDP transport address 10.0.0.2@161")
            sys.modules["pysnmp.hlapi.v3arch.asyncio"].UdpTransportTarget = Target
            for call in (c.probe, c.snapshot):
                with self.subTest(call=call.__name__), self.assertRaises(RuntimeError) as cm:
                    call()
                self.assertIsInstance(cm.exception.__cause__, OSError)

    def test_r96_timeout_is_the_clients(self):
        c = SwitchClient(CFG, snmp_profiles.load("standard"), timeout=1)

        async def slow():
            await asyncio.sleep(5)
        c._snapshot_async = slow
        with self.assertRaisesRegex(RuntimeError, "timeout after 1 s"):
            c.snapshot()
        self.assertEqual(SwitchClient(CFG).timeout, 60)

    def test_s21x_private_without_decoder_fails_the_probe(self):
        c = SwitchClient(CFG, snmp_profiles.load("edgeswitch"))
        with FakePysnmp(FakeWalker("standard")), self.assertRaisesRegex(RuntimeError, "needs a fdb_decoder"):
            c.probe()

    def test_s43x_profile_name_is_printable_and_capped(self):
        prof = snmp_profiles.load("standard")
        prof["profile"] = "mine\x1b[31m" + "a" * 5000
        c = SwitchClient(CFG, prof)
        self.assertTrue(c.profile_name.isprintable())
        self.assertLessEqual(len(c.profile_name), 64)


class PrivateTests(EnvTest):
    def test_s22x_decoder_ifindex_is_not_mapped_again(self):
        class Client(SwitchClient):
            def fdb_decoder(self, rows):
                return [(MAC, 1, 2)]
        prof = snmp_profiles.load("standard")
        prof["fdb"]["strategy"], prof["fdb"]["private_oids"] = "private", ["1.3.6.1.4.1.32473.9"]
        w = FakeWalker("standard")
        w.tables[""] = [r for r in w.tables[""] if not r[1].startswith("1.3.6.1.2.1.17.1.4.1.2.")]
        w = add_rows(w, [("1.3.6.1.2.1.17.1.4.1.2.2", 1)])  # bridge port 2 -> ifIndex 1: must not apply
        snap, fake = run(w, Client(CFG, prof))
        self.assertEqual(snap.by_mac, {MAC: (2, 1)})
        self.assertFalse([c for c in fake.calls if c[2] == "1.3.6.1.2.1.17.1.4.1.2"])
        s = build_snapshot([("1.2.0.0.0.0.1", 2)], [("2", 1)], [], [], profile=prof)
        self.assertEqual(s.by_mac, {MAC: (2, 1)})


class TextTests(EnvTest):
    def test_s24x_utf8_names_are_decoded(self):
        self.assertEqual(sw._text(OctetString("kök-ap".encode())), "kök-ap")
        self.assertEqual(sw._text(OctetString(b"\xe9t\xe9")), "\xe9t\xe9")  # not UTF-8: str() as before
        w = FakeWalker("standard")
        w.tables[""] = [(t, o, OctetString("kök-ap".encode()) if o.startswith("1.0.8802.1.1.2.1.4.1.1.9.") else v)
                        for t, o, v in w.tables[""]]
        snap, _ = run(w, SwitchClient(CFG, snmp_profiles.load("standard")))
        self.assertEqual(snap.ports[2].neighbor, "kök-ap")

    def test_s23x_detect_report_shows_binary_values_as_hex(self):
        self.assertEqual(sw._text(OctetString(b"\x02\x1b\x0a\x0d\x9e\x01"), mac=True), "02:1b:0a:0d:9e:01")
        prof = snmp_profiles.load("standard")
        prof["fdb"]["strategy"], prof["fdb"]["index_fix"] = "bridge", "row_number"
        addr = prof["oids"]["bridge_fdb_address"]
        w = add_rows(FakeWalker("standard"), [(f"{addr}.1", OctetString(b"\x02\x1b\x0a\x0d\x9e\x01"))])
        with FakePysnmp(w):
            r = SwitchClient(CFG, prof).detect_report()
        rows = dict(r["walks"])[f"bridge_fdb_address ({addr})"]
        self.assertEqual(rows, [("1", "02:1b:0a:0d:9e:01")])


class DetectReportTests(EnvTest):
    def test_r91_r92_r93_a_pysnmp_error_keeps_the_other_walks(self):
        prof = snmp_profiles.load("standard")
        prof["oids"]["lldp_rem_sysname"] = "LLDP-MIB::lldpRemSysName"
        with FakePysnmp(FakeWalker("standard")):
            r = SwitchClient(CFG, prof).detect_report()
        walks = dict(r["walks"])
        self.assertIsInstance(walks["lldp_rem_sysname (LLDP-MIB::lldpRemSysName)"], str)
        self.assertEqual(walks["ifname (1.3.6.1.2.1.31.1.1.1.1)"], [("1", "ge-1"), ("2", "ge-2")])

    def cisco(self, rows, limit, prof=None):
        w = add_rows(FakeWalker("standard"), rows)
        with FakePysnmp(w) as fake:
            r = SwitchClient(CFG, prof or snmp_profiles.load("cisco_ios")).detect_report(limit)
        return r, fake

    def test_r94_vlan_pick_reads_the_whole_vtp_table(self):
        prof = snmp_profiles.load("cisco_ios")
        prof["fdb"]["skip_vlans"] = [1, 1002, 1003, 1004, 1005]
        r, fake = self.cisco([(f"{VTP}.1.1", 1), (f"{VTP}.1.10", 1)], 1, prof)
        self.assertTrue(any(ctx == "vlan-10" for _, ctx, _ in fake.calls))
        shown = next(rows for label, rows in r["walks"] if VTP in label)
        self.assertEqual(len(shown), 1)  # the report still shows only `limit` rows

    def test_r95_report_mirrors_keep_status_and_bridge_port_map(self):
        prof = snmp_profiles.load("cisco_ios")
        prof["fdb"]["keep_status"], prof["bridge_port_map"]["strategy"] = [3], "identity"
        r, _ = self.cisco([(f"{VTP}.1.10", 1)], 5, prof)
        labels = [k for k, _ in r["walks"]]
        self.assertTrue(any(k.startswith("bridge_fdb_status") and "context vlan-10" in k for k in labels))
        self.assertTrue(any(k.startswith("fdb_status") for k in labels))
        self.assertFalse(any(k.startswith("baseport_ifindex") for k in labels))

    def test_r147_r148_detected_profile_is_cached(self):
        c = SwitchClient(CFG)
        with FakePysnmp(FakeWalker("comware")) as fake:
            c.detect_report()
            c.snapshot()
        self.assertEqual((c.profile_name, c._auto), ("comware", False))
        self.assertEqual(sum(1 for k, *_ in fake.calls if k == "get"), 1)

    def test_s02x_budget_out_keeps_the_finished_walks(self):
        real_wait_for, real_walk = asyncio.wait_for, SwitchClient._walk_key

        async def fast_budget(aw, timeout):  # the 120 s budget, scaled down to 0.12 s
            return await real_wait_for(aw, timeout=timeout / 1000)

        async def slow_lldp(self, eng, tgt, user, key, ctx, limit):
            if key == "lldp_rem_sysname":
                await asyncio.sleep(5)  # a walk that outlasts the budget
            return await real_walk(self, eng, tgt, user, key, ctx, limit)
        with FakePysnmp(FakeWalker("standard")), mock.patch.object(sw.asyncio, "wait_for", fast_budget), \
                mock.patch.object(SwitchClient, "_walk_key", slow_lldp):
            r = SwitchClient(CFG, snmp_profiles.load("standard")).detect_report()
        walks = dict(r["walks"])
        self.assertEqual(r["profile"], "standard")
        self.assertEqual(walks["ifname (1.3.6.1.2.1.31.1.1.1.1)"], [("1", "ge-1"), ("2", "ge-2")])
        self.assertEqual(r["walks"][-1], ("(remaining walks)", "snmp: timeout after 120 s"))


class DetectAndBaseportTests(EnvTest):
    def _detect(self, rows, prof=None):
        prof = prof or snmp_profiles.load("standard")
        w = add_rows(FakeWalker("standard"), rows)
        with FakePysnmp(w):
            return dict(SwitchClient(CFG, prof).detect_report()["walks"])

    def test_v22_detect_shows_names_as_the_poll_does(self):
        oid = snmp_profiles.load("standard")["oids"]["ifname"]
        w = FakeWalker("standard")
        w.tables[""] = [(t, o, OctetString(b"Port-\xf65") if o == f"{oid}.1" else
                         OctetString(b"GE1/0/1\x00") if o == f"{oid}.2" else v) for t, o, v in w.tables[""]]
        with FakePysnmp(w):
            rows = dict(SwitchClient(CFG, snmp_profiles.load("standard")).detect_report()["walks"])[f"ifname ({oid})"]
        self.assertEqual(rows, [("1", "Port-\xf65"), ("2", "GE1/0/1\x00")])

    def test_v64_v66_v67_v68_printable_mac_is_hex_in_detect(self):
        prof = snmp_profiles.load("standard")
        prof["fdb"]["strategy"], prof["fdb"]["index_fix"] = "bridge", "row_number"
        addr = prof["oids"]["bridge_fdb_address"]
        rows = self._detect([(f"{addr}.1", OctetString(b"\x2a\x41\x42\x43\x44\x45")),
                             (f"{addr}.2", OctetString(b"\x26\xc3\xa9\x51\x52\x53"))], prof)
        self.assertEqual(rows[f"bridge_fdb_address ({addr})"], [("1", "2a:41:42:43:44:45"), ("2", "26:c3:a9:51:52:53")])

    def test_v38_control_only_profile_name_is_not_empty(self):
        prof = snmp_profiles.load("standard")
        prof["profile"] = "\x1b\x07"
        name = SwitchClient(CFG, prof).profile_name
        self.assertTrue(name and name.isprintable(), repr(name))

    def test_v65_probe_uses_the_client_timeout(self):
        c = SwitchClient(CFG, snmp_profiles.load("standard"), timeout=7)
        budgets = []

        def fake_blocking(coro, timeout):
            coro.close()
            budgets.append(timeout)
            return ("", "")
        with mock.patch.object(sw, "_blocking", fake_blocking):
            c.probe()
        self.assertEqual(budgets, [7])

    def test_v94_no_bulk_key_name_is_trimmed(self):
        prof = snmp_profiles.load("standard")
        prof["snmp"]["bulk"], prof["snmp"]["no_bulk"] = True, [" ifname "]
        _, fake = run(FakeWalker("standard"), SwitchClient(CFG, prof))
        self.assertFalse([c for c in fake.calls if c[0] == "bulk" and c[2].startswith("1.3.6.1.2.1.31.1.1.1.1")])

    def test_v95_unparseable_baseport_rows_warn_once(self):
        # a compound index ("5.0") as from a mis-pointed baseport_ifindex OID: rows, but none build_snapshot can use
        oid = snmp_profiles.load("standard")["oids"]["baseport_ifindex"]
        w = FakeWalker("standard")
        w.tables[""] = [(t, f"{o}.0" if o.startswith(oid + ".") else o, v) for t, o, v in w.tables[""]]
        c = SwitchClient(CFG, snmp_profiles.load("standard"))
        with self.assertLogs("leasewatch.switch", "WARNING") as logs:
            run(w, c)
            run(w, c)
        self.assertEqual(len([r for r in logs.output if "dot1dBasePortIfIndex" in r]), 1)


class DecoderAndNoBulkTests(EnvTest):
    def test_w25_decoder_set_on_the_instance_passes_the_probe(self):
        c = SwitchClient(CFG, snmp_profiles.load("edgeswitch"))
        c.fdb_decoder = lambda rows: []
        with FakePysnmp(FakeWalker("standard")):
            c.probe()  # snapshot() would use this decoder, so the check must not refuse it

    def test_w32_no_bulk_key_name_covers_the_columns_under_its_oid(self):
        prof = snmp_profiles.load("standard")
        prof["oids"]["if_x_table"] = "1.3.6.1.2.1.31.1.1.1"
        prof["snmp"]["bulk"], prof["snmp"]["no_bulk"] = True, ["if_x_table"]
        _, fake = run(FakeWalker("standard"), SwitchClient(CFG, prof))
        self.assertFalse([c for c in fake.calls if c[0] == "bulk" and c[2].startswith("1.3.6.1.2.1.31.1.1.1.1")])

    def test_w33_baseport_warning_names_the_instance(self):
        oid = snmp_profiles.load("standard")["oids"]["baseport_ifindex"]
        w = FakeWalker("standard")
        w.tables[""] = [r for r in w.tables[""] if not r[1].startswith(oid + ".")]
        with self.assertLogs("leasewatch.switch", "WARNING") as logs:
            for name in ("sw-rack", "sw-office"):
                run(w, SwitchClient(CFG, snmp_profiles.load("standard"), name=name))
        lines = [r for r in logs.output if "dot1dBasePortIfIndex" in r]
        self.assertEqual(len(lines), 2)
        self.assertIn("sw-rack: ", lines[0])
        self.assertIn("sw-office: ", lines[1])


class NoBulkCommentKeyTests(EnvTest):
    def test_x04_no_bulk_naming_a_comment_key_with_a_list_still_walks(self):
        prof = snmp_profiles.load("standard")
        prof["oids"]["_tables"] = ["if_x is 1.3.6.1.2.1.31.1.1.1"]
        prof["snmp"]["bulk"], prof["snmp"]["no_bulk"] = True, ["_tables"]
        snap, fake = run(FakeWalker("standard"), SwitchClient(CFG, prof))
        self.assertTrue([c for c in fake.calls if c[0] == "bulk"])  # the entry covers nothing, so bulk stays on


if __name__ == "__main__":
    unittest.main()
