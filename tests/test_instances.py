"""Connector instances: LW_CONNECTORS parsing, validation, per-instance threads and timeouts, check() backoff,
log-on-change, status meta and /api/status. Fake connector types only; nothing here touches the network."""
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore, sources, swap_client  # noqa: E402
from leasewatch.collector import MAX_BACKOFF, SKIPPED, Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.connectors import (API_VERSION, Attachment, Batch, ConnectorError, ConnectorInfo, InstanceSpec,  # noqa: E402
                                   Setting, SettingsMixin, Sighting, registry)
from leasewatch import snmp_profiles  # noqa: E402
from leasewatch.db import Database  # noqa: E402
from leasewatch.fw1 import Fw1Error  # noqa: E402
from leasewatch.fw1 import Sighting as Fw1Sighting  # noqa: E402
from leasewatch.web import serve  # noqa: E402

MAC = "02:00:00:00:00:01"
FW1 = {"LW_CONNECTOR__FW1__TYPE": "opnsense", "LW_CONNECTOR__FW1__URL": "https://fw1.example.lan",
       "LW_CONNECTOR__FW1__KEY": "fw1-key", "LW_CONNECTOR__FW1__SECRET": "fw1-secret"}


class Fake(SettingsMixin):
    """An enricher whose check()/collect() behaviour the test sets per instance (on_check, on_collect)."""
    INFO = ConnectorInfo(type="fake", version="1.0", api_version=API_VERSION, produces=frozenset({"attachment"}),
                         settings=(Setting("token", secret=True), Setting("port", kind="int", min=1, max=65535),
                                   Setting("mode", default="a", choices=("a", "b"))))

    def __init__(self, name, settings, ctx=None, client=None):
        self._init_settings(name, settings, ctx)
        self.checks = self.collects = 0
        self.on_check = lambda: None
        self.on_collect = lambda: Batch()

    def validate(self):
        return self._generic_problems()

    def check(self):
        self.checks += 1
        self.on_check()

    def collect(self):
        self.collects += 1
        return self.on_collect()

    def close(self):
        pass


class FakeFw(Fake):
    INFO = replace(Fake.INFO, type="fakefw", produces=frozenset({"sighting"}))


class FakeClient:
    def __init__(self, rows):
        self.rows = rows
        self.fail = False

    def arp_raw(self):
        return []  # what the opnsense connector's check() calls; `fail` breaks collect() only

    def sightings(self, ignore=()):
        if self.fail:
            raise Fw1Error("boom")
        return list(self.rows), {"leases": 0, "arp": len(self.rows)}


def arp(mac, ip):
    return Fw1Sighting(mac=mac, ip=ip, hostname="", vendor="", vlan="LAN", iface="lan", source="arp", lease_type="", online=True)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = mock.patch.dict(registry(), {"fake": Fake, "fakefw": FakeFw})
        self.reg.start()
        self.dbs = []

    def tearDown(self):
        for db in self.dbs:
            db._conn.close()
        self.reg.stop()
        self.tmp.cleanup()

    def cfg(self, env):
        saved = clean_env({"DATA_DIR": self.tmp.name, "POLL_SECONDS": "15", **env})
        try:
            return Config()
        finally:
            restore(saved)

    def collector(self, env, rows=None):
        cfg = self.cfg(env)
        db = Database(cfg.db_path)
        self.dbs.append(db)
        self.client = FakeClient([arp(MAC, "10.0.0.5")] if rows is None else rows)
        return Collector(cfg, db, self.client), db


class ParseTests(Base):
    def test_names_order_and_delimiter(self):
        cfg = self.cfg({"LW_CONNECTORS": " fw1, swrack ,unifi", **FW1, "LW_CONNECTOR__SWRACK__TYPE": "SNMP_SWITCH",
                        "LW_CONNECTOR__SWRACK__HOST": " 10.0.0.2 ", "LW_CONNECTOR__SWRACK__AUTH_KEY": "a" * 8,
                        "LW_CONNECTOR__UNIFI__TYPE": "unifi", "LW_CONNECTOR__OTHER__TYPE": "unifi"})
        self.assertEqual([(s.name, s.type) for s in cfg.instances], [("fw1", "opnsense"), ("swrack", "snmp_switch"), ("unifi", "unifi")])
        self.assertEqual(cfg.instances[1].settings, {"host": "10.0.0.2", "auth_key": "a" * 8})
        self.assertEqual(cfg.instances[0].settings, {"url": "https://fw1.example.lan", "key": "fw1-key", "secret": "fw1-secret"})

    def test_secret_file(self):
        path = os.path.join(self.tmp.name, "fw1-secret")
        with open(path, "w") as f:
            f.write("  sekret-from-file\n")
        env = {**FW1, "LW_CONNECTORS": "fw1", "LW_CONNECTOR__FW1__SECRET_FILE": path}
        env.pop("LW_CONNECTOR__FW1__SECRET")
        cfg = self.cfg(env)
        self.assertEqual(cfg.instances[0].settings["secret"], "sekret-from-file")
        self.assertNotIn("secret_file", cfg.instances[0].settings)
        self.assertEqual(cfg.validate(), [])
        self.assertNotIn("sekret", repr(cfg) + repr(cfg.instances))
        # both forms at once, an unreadable file, and _FILE on a key that is not secret
        cfg = self.cfg({**env, "LW_CONNECTOR__FW1__SECRET": "x"})
        self.assertIn("connector fw1 (opnsense): set SECRET or SECRET_FILE, not both", cfg.validate())
        cfg = self.cfg({**env, "LW_CONNECTOR__FW1__SECRET_FILE": os.path.join(self.tmp.name, "missing")})
        self.assertIn("connector fw1 (opnsense): cannot read SECRET_FILE (No such file or directory)", cfg.validate())
        cfg = self.cfg({**FW1, "LW_CONNECTORS": "fw1", "LW_CONNECTOR__FW1__URL_FILE": path})
        self.assertIn("connector fw1 (opnsense): unknown setting URL_FILE", cfg.validate())
        # a FIFO or device would block the start, a huge file stall it: refused before reading, path contents not echoed
        fifo = os.path.join(self.tmp.name, "fifo")
        os.mkfifo(fifo)
        for bad in (fifo, "/dev/zero", self.tmp.name):
            cfg = self.cfg({**env, "LW_CONNECTOR__FW1__SECRET_FILE": bad})
            self.assertIn("connector fw1 (opnsense): cannot read SECRET_FILE (not a regular file)", cfg.validate())
        big = os.path.join(self.tmp.name, "big")
        with open(big, "w") as f:
            f.write("sekret" + "x" * 64 * 1024)
        p = self.cfg({**env, "LW_CONNECTOR__FW1__SECRET_FILE": big}).validate()
        self.assertIn("connector fw1 (opnsense): cannot read SECRET_FILE (larger than 64 KiB)", p)
        self.assertNotIn("sekret", "\n".join(p))

    def test_settings_for_unlisted_instance_or_case_twins(self):
        p = self.cfg({"LW_CONNECTORS": "fw1", **FW1, "LW_CONNECTOR__FW2__URL": "https://fw2.example.lan",
                      "LW_CONNECTOR__FW2__TYPE": "opnsense", "LW_CONNECTOR__SWA__HOST": "10.0.0.2"}).validate()
        self.assertEqual(p, ["LW_CONNECTOR__FW2__TYPE set but fw2 is not in LW_CONNECTORS",
                             "LW_CONNECTOR__SWA__HOST set but swa is not in LW_CONNECTORS"])
        p = self.cfg({"LW_CONNECTORS": "fw1", **FW1, "LW_CONNECTOR__fw1__key": "sekret-other"}).validate()
        self.assertEqual(p, ["LW_CONNECTOR__FW1__KEY and LW_CONNECTOR__fw1__key differ only in case"])


    def test_unknown_or_missing_type_and_bad_names(self):
        p = self.cfg({**FW1, "LW_CONNECTORS": "fw1,x,y,Bad_Name,fw1", "LW_CONNECTOR__X__TYPE": "dnsmasq"}).validate()
        self.assertIn("connector x: unknown type 'dnsmasq' (known: fake, fakefw, opnsense, snmp_switch, unifi)", p)
        self.assertIn("connector y: TYPE is required", p)
        self.assertIn("LW_CONNECTORS: 'Bad_Name' is not a valid instance name (only a-z and 0-9)", p)
        self.assertIn("LW_CONNECTORS: fw1 is listed twice", p)


class ValidateTests(Base):
    def test_messages(self):
        p = self.cfg({"LW_CONNECTORS": "fw1,swrack,x", **FW1, "LW_CONNECTOR__FW1__URL": "ftp://fw1.example.lan",
                      "LW_CONNECTOR__FW1__DHCP_BACKEND": "dhcpd", "LW_CONNECTOR__FW1__TIMEOUT": "0",
                      "LW_CONNECTOR__SWRACK__TYPE": "snmp_switch", "LW_CONNECTOR__SWRACK__AUTH_KEY": "sekret-a",
                      "LW_CONNECTOR__SWRACK__PRIV_KEY": "sekret-p",
                      "LW_CONNECTOR__X__TYPE": "fake", "LW_CONNECTOR__X__PORT": "70000", "LW_CONNECTOR__X__TIMEOUT": "abc",
                      "LW_CONNECTOR__X__TOKEN": "sekret-t"}).validate()
        for msg in ("connector fw1 (opnsense): TIMEOUT must be at least 1",
                    "connector fw1 (opnsense): DHCP_BACKEND must be one of isc, kea, dnsmasq",
                    "connector fw1 (opnsense): url must be a URL (https://<opnsense>)",
                    "connector swrack (snmp_switch): HOST is required",
                    "connector x (fake): TIMEOUT must be an integer",
                    "connector x (fake): PORT must be at most 65535"):
            self.assertIn(msg, p)
        self.assertEqual(len(p), len(set(p)), p)  # the generic check and validate() report a problem once
        self.assertNotIn("sekret", "\n".join(p))

    def test_one_sighting_producer_required(self):
        p = self.cfg({"LW_CONNECTORS": "x", "LW_CONNECTOR__X__TYPE": "fake"}).validate()
        self.assertEqual(p, ["LW_CONNECTORS: at least one connector must produce sightings (e.g. type opnsense)"])
        self.assertEqual(self.cfg({"LW_CONNECTORS": "x", "LW_CONNECTOR__X__TYPE": "fakefw"}).validate(), [])

    def test_invalid_instance_is_disabled_at_startup(self):
        with self.assertLogs("leasewatch.collector", "ERROR") as logs:
            col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake", "LW_CONNECTOR__X__PORT": "0"})
        # the "connector <name> (<type>)" prefix once, then the reason
        self.assertEqual(logs.output[0], "ERROR:leasewatch.collector:connector x (fake): PORT must be at least 1 (instance disabled)")
        self.assertNotIn("x", col._connectors)
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual((db.get_meta("conn.x.enabled"), db.get_meta("conn.x.ok")), ("0", "0"))
        self.assertTrue(db.get_meta("conn.x.error").startswith("disabled: "))


class ThreadTests(Base):
    def test_timeout_abandons_skips_and_drops_the_late_result(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,slow", **FW1, "LW_CONNECTOR__SLOW__TYPE": "fake", "LW_CONNECTOR__SLOW__TIMEOUT": "1"})
        slow = col._connectors["slow"]
        release = threading.Event()

        def late():
            release.wait(10)
            return Batch(attachments=[Attachment(mac=MAC, source="slow", observed_at=0, link="wired", device="sw", port="LATE")])
        slow.on_collect = late
        t0 = time.monotonic()
        self.assertTrue(col.run_once()["ok"])  # the poll completes without the slow instance
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual((db.get_meta("conn.slow.ok"), db.get_meta("conn.slow.error")), ("0", "timed out after 1 s"))
        self.assertEqual(db.get_meta("conn.fw1.ok"), "1")
        with self.assertLogs("leasewatch.collector", "WARNING") as logs:
            col.run_once()
            col.run_once()
        self.assertEqual([m for m in logs.output if SKIPPED in m], [f"WARNING:leasewatch.collector:connector slow (fake): {SKIPPED}"])
        self.assertEqual(slow.collects, 1)
        self.assertEqual(db.get_meta("conn.slow.error"), SKIPPED)
        release.set()
        col._runs["slow"].thread.join(5)
        self.assertIsNone(col._runs["slow"].result)  # the late result belonged to an abandoned generation
        slow.on_collect = Batch
        col.run_once()
        self.assertEqual((slow.collects, db.get_meta("conn.slow.ok")), (2, "1"))
        self.assertEqual(db.device(MAC)["sw_port"], "")

    def test_check_backoff(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake",
                                  "LW_CONNECTOR__X__TOKEN": "sekret-t"})
        x, run = col._connectors["x"], col._runs["x"]

        def down():
            raise ConnectorError("unreachable sekret-t")
        x.on_check = down
        waits = []
        for _ in range(7):
            col.run_once()
            waits.append(round(run.retry_at - time.monotonic()))
            col.run_once()  # inside the backoff: no new check
            run.retry_at = 0  # let the backoff pass
        self.assertEqual(waits, [15, 30, 60, 120, 240, 480, MAX_BACKOFF])
        self.assertEqual((x.checks, x.collects), (7, 0))
        self.assertEqual(db.get_meta("conn.x.error"), "check failed: unreachable ***")
        self.assertTrue(col.run_once()["ok"])  # backoff exhausted: collect() every poll, no more check()
        self.assertEqual((x.checks, x.collects, db.get_meta("conn.x.ok")), (7, 1, "1"))

    def test_check_once_then_collect(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake"})
        col.run_once()
        col.run_once()
        self.assertEqual((col._connectors["x"].checks, col._connectors["x"].collects), (1, 2))

    def test_log_on_change(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake"})
        x = col._connectors["x"]
        col.run_once()

        def down():
            raise ConnectorError("down")
        x.on_collect = down
        with self.assertLogs("leasewatch.collector", "WARNING") as logs:
            col.run_once()
        self.assertEqual(logs.output, ["WARNING:leasewatch.collector:connector x (fake) failed: down"])
        self.assertIsNone(logs.records[0].exc_info)
        with self.assertNoLogs("leasewatch.collector", "WARNING"):
            col.run_once()
        x.on_collect = Batch
        with self.assertLogs("leasewatch.collector", "INFO") as logs:
            col.run_once()
        self.assertIn("INFO:leasewatch.collector:connector x (fake) recovered", logs.output)

        def bug():
            raise ValueError("bad row")
        x.on_collect = bug
        with self.assertLogs("leasewatch.collector", "ERROR") as logs:
            col.run_once()
        # not a ConnectorError: the status shows the type name, the log the (redacted) traceback text
        self.assertTrue(logs.output[0].startswith("ERROR:leasewatch.collector:connector x (fake) failed: ValueError\nTraceback"))
        self.assertIn("ValueError: bad row", logs.output[0])
        self.assertIsNone(logs.records[0].exc_info)
        self.assertEqual(db.get_meta("conn.x.error"), "ValueError")

    def test_traceback_of_a_non_connectorerror_is_redacted(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake",
                                  "LW_CONNECTOR__X__TOKEN": "TOPSECRET-t"})

        def bug():
            raise RuntimeError("bad token TOPSECRET-t")
        col._connectors["x"].on_collect = bug
        with self.assertLogs("leasewatch.collector", "ERROR") as logs:
            col.run_once()
        out = "\n".join(logs.output)
        self.assertNotIn("TOPSECRET", out)
        self.assertIn("RuntimeError: bad token ***", out)
        self.assertIsNone(logs.records[0].exc_info)  # exc_info would print the raw text past the redactor
        self.assertEqual(db.get_meta("conn.x.error"), "RuntimeError")

    def test_escaped_secret_is_redacted(self):
        secret = "pa'ss\\word"
        col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake",
                                  "LW_CONNECTOR__X__TOKEN": secret})
        forms = (secret, repr(secret)[1:-1], json.dumps(secret)[1:-1], "ss\\")
        for exc in (KeyError(secret), RuntimeError(f"bad token {secret!r}")):
            def bug(exc=exc):
                raise exc
            col._connectors["x"].on_collect = bug
            col._runs["x"].failed = False  # log the failure again (logs only on a change)
            with self.assertLogs("leasewatch.collector", "ERROR") as logs:
                col.run_once()
            out = "\n".join(logs.output)
            self.assertIn("***", out)
            for f in forms:
                self.assertNotIn(f, out)

    def test_short_secret_is_not_masked(self):
        """A one-letter secret (LW_CONNECTOR__FW1__SECRET=s in tests) must not mangle unrelated text; a 4-character one is masked."""
        from leasewatch.connectors import make_redactor
        self.assertEqual(make_redactor(["s"])("snmp timeout"), "snmp timeout")
        self.assertEqual(make_redactor(["s", "abcd"])("snmp abcd timeout"), "snmp *** timeout")

    def test_passed_check_is_not_rerun_after_a_failed_collect(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake"})
        x = col._connectors["x"]

        def down():
            raise ConnectorError("down")
        x.on_collect = down
        col.run_once()
        col.run_once()
        self.assertEqual((x.checks, x.collects), (1, 2))

    def test_hanging_check_gets_the_check_backoff(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake", "LW_CONNECTOR__X__TIMEOUT": "1"})
        x, run = col._connectors["x"], col._runs["x"]
        release = threading.Event()
        x.on_check = lambda: release.wait(10)
        try:
            col.run_once()
            self.assertEqual(db.get_meta("conn.x.error"), "check failed: timed out after 1 s")
            self.assertEqual(round(run.retry_at - time.monotonic()), 15)
            self.assertFalse(run.checked)
        finally:
            release.set()
            run.thread.join(5)
        self.assertIsNone(run.result)  # the abandoned thread's late outcome belongs to no poll

    def test_alias_keys_need_name_and_type(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,switch", **FW1, "LW_CONNECTOR__SWITCH__TYPE": "fake"})
        col.run_once()
        self.assertEqual(db.get_meta("conn.switch.ok"), "1")
        self.assertEqual(db.get_meta("switch_ok", "unset"), "unset")  # a "switch" that is not an snmp_switch

    def test_sighting_producers(self):
        env = {"LW_CONNECTORS": "fw1,fw2", **FW1, "LW_CONNECTOR__FW2__TYPE": "fakefw"}
        col, db = self.collector(env, rows=[])
        fw2 = col._connectors["fw2"]
        fw2.on_collect = lambda: Batch(sightings=[Sighting(mac=MAC, source="fw2", kind="arp", presence=True, observed_at=0, ip="10.0.0.5")])
        self.client.fail = True
        self.assertTrue(col.run_once()["ok"])  # one producer is enough
        self.assertEqual((db.get_meta("conn.fw1.ok"), db.get_meta("conn.fw1.error"), db.device(MAC)["ip"]), ("0", "boom", "10.0.0.5"))

        def down():
            raise ConnectorError("down")
        fw2.on_collect = down
        r = col.run_once()
        self.assertFalse(r["ok"])
        self.assertEqual((db.get_meta("last_poll_ok"), db.get_meta("last_error")), ("0", "fw1: boom; fw2: down"))
        self.assertEqual(db.get_meta("conn.fw2.ok"), "0")


class StatusTests(Base):
    def test_meta_keys_and_legacy_aliases(self):
        col, db = self.collector(sources("unifi"))
        swap_client(col, "unifi", type("U", (), {"clients": lambda self: {}})())
        col.run_once()
        m = db.all_meta()
        for name, typ, count in (("fw1", "opnsense", "1"), ("unifi", "unifi", "0")):
            self.assertEqual((m[f"conn.{name}.type"], m[f"conn.{name}.ok"], m[f"conn.{name}.error"], m[f"conn.{name}.count"],
                              m[f"conn.{name}.enabled"]), (typ, "1", "", count, "1"))
            self.assertGreater(int(m[f"conn.{name}.ts"]), 0)
            self.assertGreaterEqual(int(m[f"conn.{name}.ms"]), 0)
        self.assertEqual((m["unifi_ok"], m["unifi_error"], m["unifi_clients"]), ("1", "", "0"))
        self.assertNotIn("switch_ok", m)

    def test_strategy_copied_to_meta(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,sw,x", **FW1, "LW_CONNECTOR__SW__TYPE": "fake", "LW_CONNECTOR__X__TYPE": "fake"})
        col._connectors["sw"].on_collect = lambda: Batch(stats={"macs": 0, "strategy": "qbridge"})
        col._connectors["x"].on_collect = lambda: Batch(stats={"strategy": 3})  # not a str: ignored
        col.run_once()
        self.assertEqual(db.get_meta("conn.sw.strategy"), "qbridge")
        self.assertEqual(db.get_meta("conn.x.strategy", "unset"), "unset")
        self.assertEqual(db.get_meta("conn.fw1.strategy", "unset"), "unset")

    def test_api_status(self):
        env = {"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake", "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0"}
        col, db = self.collector(env)
        col.run_once()
        srv = serve(col.cfg, db, "9.9.9-test")
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            conn.request("GET", "/api/status")
            resp = conn.getresponse()
            body = json.loads(resp.read())
            conn.close()
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(5)
        self.assertEqual(resp.status, 200)
        self.assertEqual(list(body), ["meta"])
        conns = body["meta"]["connectors"]
        self.assertEqual([(c["name"], c["type"], c["ok"], c["enabled"]) for c in conns], [("fw1", "opnsense", True, True), ("x", "fake", True, True)])
        self.assertEqual(set(conns[0]), {"name", "label", "type", "ok", "error", "ts", "ms", "count", "strategy", "enabled"})
        self.assertEqual(conns[0]["count"], 1)
        self.assertIn("switch", body["meta"])  # the 1.0 objects stay for one release
        self.assertNotIn("fw1-key", json.dumps(body))


if __name__ == "__main__":
    unittest.main()
