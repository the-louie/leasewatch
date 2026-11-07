"""Collector regressions from the 1.1 QA round: startup prune, log-on-change, thread start, history trim, event prune,
loop error logging, unknown types, status meta, mail retries, producer stats. Fake connectors only; no network."""
import ast
import logging
import os
import sqlite3
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_instances import FW1, MAC, Base, arp  # noqa: E402
from leasewatch import collector as collector_mod  # noqa: E402
from leasewatch import notify  # noqa: E402
from leasewatch.collector import EVENT_DAYS, HISTORY_PER_MAC, Collector  # noqa: E402
from leasewatch.connectors import Batch, ConnectorError, Sighting  # noqa: E402

DAY = 86400


class StartupTests(Base):
    def test_locked_db_at_startup_prune_does_not_crash(self):
        cfg = self.cfg({"LW_CONNECTORS": "fw1", **FW1})
        from leasewatch.db import Database
        db = Database(cfg.db_path)
        self.dbs.append(db)
        with mock.patch.object(db, "tx", side_effect=sqlite3.OperationalError("database is locked")):
            with self.assertLogs("leasewatch.collector", "WARNING") as cm:
                Collector(cfg, db)
        self.assertIn("database is locked", "\n".join(cm.output))

    def test_unknown_or_empty_type_gets_the_validate_message(self):
        col, _ = self.collector({"LW_CONNECTORS": "fw1,bad,empty", **FW1, "LW_CONNECTOR__BAD__TYPE": "bogus",
                                 "LW_CONNECTOR__EMPTY__TYPE": ""})
        self.assertIn("connector bad: unknown type 'bogus'", col._runs["bad"].error)
        self.assertIn("connector empty: TYPE is required", col._runs["empty"].error)
        self.assertNotIn("KeyError", col._runs["bad"].error + col._runs["empty"].error)

    def test_disabled_instance_is_marked_before_the_first_poll(self):  # S26x
        env = {"LW_CONNECTORS": "fw1,bad", **FW1, "LW_CONNECTOR__BAD__TYPE": "unifi",
               "LW_CONNECTOR__BAD__URL": "ftp://x.example.lan", "LW_CONNECTOR__BAD__USER": "u",
               "LW_CONNECTOR__BAD__PASSWORD": "pppppp"}
        col, db = self.collector(env)
        # no run_once: the web page reads these before any poll and must not draw a red dot for "bad"
        self.assertEqual(db.get_meta("conn.bad.enabled"), "0")
        self.assertIn("url must be a URL", db.get_meta("conn.bad.error"))
        self.assertEqual(db.get_meta("conn.fw1.enabled"), "1")
        # a later start with a fixed setting clears the stale "0"
        db.set_meta("conn.fw1.enabled", "0")
        Collector(col.cfg, db, self.client)
        self.assertEqual(db.get_meta("conn.fw1.enabled"), "1")

    def test_signatures_have_type_hints(self):
        with open(collector_mod.__file__) as f:
            tree = ast.parse(f.read())
        missing = [(n.name, a.arg) for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                   for a in n.args.args if a.annotation is None and a.arg not in ("self", "cls")]
        self.assertEqual(missing, [])


class OutcomeTests(Base):
    def test_unexpected_exception_after_a_connector_error_is_logged_with_traceback(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake"})
        x = col._connectors["x"]
        col.run_once()

        def down():
            raise ConnectorError("down")

        def bug():
            return {}["k"]
        x.on_collect = down
        col.run_once()
        x.on_collect = bug
        with self.assertLogs("leasewatch.collector", "ERROR") as cm:
            col.run_once()
        self.assertIn("Traceback", "\n".join(cm.output))
        # the same failure again is not logged every poll
        with self.assertNoLogs("leasewatch.collector", "WARNING"):
            col.run_once()
        self.assertEqual(db.get_meta("conn.x.error"), "KeyError")

    def test_thread_start_failure_fails_only_that_instance(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,a,b", **FW1, "LW_CONNECTOR__A__TYPE": "fake",
                                  "LW_CONNECTOR__B__TYPE": "fake"})
        orig = threading.Thread.start

        def start(t):
            if t.name == "connector-a":
                raise RuntimeError("can't start new thread")
            return orig(t)
        with mock.patch.object(threading.Thread, "start", start), self.assertLogs("leasewatch.collector", "WARNING"):
            r = col.run_once()
        self.assertTrue(r["ok"])
        self.assertEqual((db.get_meta("conn.b.ok"), db.get_meta("conn.a.ok")), ("1", "0"))
        self.assertNotEqual(db.get_meta("conn.a.error"), "")
        col.run_once()  # recovers on the next poll
        self.assertEqual((db.get_meta("conn.a.ok"), db.get_meta("conn.a.error")), ("1", ""))


class WriteTests(Base):
    def res(self, history=(), events=()):
        return SimpleNamespace(rows={}, history=list(history), events=list(events), seen=[], aliases=[], alias_seen=[])

    def test_history_trim_keeps_the_row_just_written_after_a_clock_step_back(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1})
        mac = "02:00:00:00:00:09"
        with db.tx() as c:
            for i in range(HISTORY_PER_MAC):
                c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                          (mac, 2_000_000_000, f"10.0.0.{i % 250}", "x", "LAN", "dynamic"))
        h = {"ip": "10.0.9.9", "hostname": "x", "vlan": "LAN", "lease_type": "dynamic"}
        with db.tx() as c:
            col._write(c, {}, self.res(history=[(mac, h)]), 1_900_000_000)
        rows = db.history(mac, 1000)
        self.assertEqual(len(rows), HISTORY_PER_MAC)
        self.assertIn("10.0.9.9", [r["ip"] for r in rows])

    def test_event_prune_survives_a_forward_clock_jump(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1})
        now = int(time.time())
        db.set_meta("last_poll_ts", str(now))
        with db.tx() as c:
            for i in range(5):
                c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now - i * DAY, f"02:00:00:00:00:0{i}", "new", ""))
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now - (EVENT_DAYS + 2) * DAY, MAC, "new", ""))
        with db.tx() as c:
            col._write(c, {}, self.res(), 2_147_483_647)
        # the year-old event still goes, the recent ones stay
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events")[0]["n"], 5)
        # a normal poll prunes as before
        with db.tx() as c:
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now - (EVENT_DAYS + 2) * DAY, MAC, "new", ""))
            col._write(c, {}, self.res(), now + 60)
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events")[0]["n"], 5)


class LoopTests(Base):
    def test_failure_of_fail_is_logged(self):
        col, _ = self.collector({"LW_CONNECTORS": "fw1", **FW1})
        stop = threading.Event()

        def run_once():
            stop.set()
            raise sqlite3.OperationalError("database is locked")

        def fail(msg, status=None):
            raise sqlite3.OperationalError("disk I/O error")
        col.run_once, col._fail = run_once, fail
        with self.assertLogs("leasewatch.collector", "WARNING") as cm:
            col.loop(stop)
        self.assertIn("cannot record the failed poll", "\n".join(cm.output))


class StatusTests(Base):
    def test_strategy_cleared_when_the_instance_fails(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,sw", **FW1, "LW_CONNECTOR__SW__TYPE": "fake"})
        sw = col._connectors["sw"]
        sw.on_collect = lambda: Batch(stats={"macs": 42, "strategy": "cisco_per_vlan"})
        col.run_once()
        self.assertEqual(db.get_meta("conn.sw.strategy"), "cisco_per_vlan")

        def down():
            raise ConnectorError("snmp timeout")
        sw.on_collect = down
        col.run_once()
        self.assertEqual((db.get_meta("conn.sw.ok"), db.get_meta("conn.sw.count"), db.get_meta("conn.sw.strategy")), ("0", "0", ""))
        self.assertEqual(db.get_meta("conn.fw1.strategy", "unset"), "unset")

    def test_disabled_switch_writes_its_status(self):
        cfg_env = {"LW_CONNECTORS": "fw1,switch", **FW1, "LW_CONNECTOR__SWITCH__TYPE": "snmp_switch"}  # no HOST: disabled
        col, db = self.collector(cfg_env)
        self.assertTrue(col._runs["switch"].disabled)
        db.set_meta("conn.switch.ok", "1")  # a good poll before the restart
        col.run_once()
        self.assertEqual((db.get_meta("conn.switch.ok"), db.get_meta("conn.switch.enabled")), ("0", "0"))
        self.assertTrue(db.get_meta("conn.switch.error").startswith("disabled: "))
        self.assertEqual(db.get_meta("switch_ok", "unset"), "unset")  # no 1.0 alias keys any more

    def test_string_stat_of_a_sighting_producer_does_not_break_the_poll(self):
        col, db = self.collector({"LW_CONNECTORS": "fw1,fx", **FW1, "LW_CONNECTOR__FX__TYPE": "fakefw"})
        col._connectors["fx"].on_collect = lambda: Batch(
            sightings=[Sighting(mac="02:00:00:00:00:02", source="", kind="arp", observed_at=0, presence=True)],
            stats={"arp": 1, "strategy": "per-vlan"})
        self.assertTrue(col.run_once()["ok"])
        self.assertEqual(db.get_meta("last_raw"), "0 leases, 2 arp")


class MailRetryTests(Base):
    def test_retry_drops_acked_devices_and_mails_current_values(self):
        env = {"LW_CONNECTORS": "fw1", **FW1, "MAILGUN_KEY": "k", "MAILGUN_DOMAIN": "mg.example.com",
               "MAIL_TO": "a@example.com"}
        col, db = self.collector(env, rows=[])
        self.client.rows = [arp(MAC, "10.0.0.12"), arp("02:00:00:00:00:02", "10.0.0.13")]
        col.run_once()
        db.update_user_fields(MAC, True, None, None)
        now = int(time.time())  # S4 T-09: the queue is devices.mail_queued
        db.q("UPDATE devices SET mail_queued=?", (now,))
        db.q("INSERT INTO devices(mac,first_seen,last_seen,ip,vlan,lease_type,mail_queued) VALUES(?,?,?,?,?,?,?)",
             ("02:00:00:00:00:03", now, now, "10.0.0.9", "LAN", "dynamic", now))
        sent = []
        with mock.patch.object(notify, "new_devices", lambda cfg, devs: sent.append(devs)):
            col._notify()
        self.assertEqual([(d["mac"], d["ip"]) for d in sent[0]],
                         [("02:00:00:00:00:02", "10.0.0.13"), ("02:00:00:00:00:03", "10.0.0.9")])


class Round2Tests(Base):
    """Fix round 2 (V01, V02, V27, V47, V48, V72, V73)."""
    MAIL = {"LW_CONNECTORS": "fw1", **FW1, "MAILGUN_KEY": "k", "MAILGUN_DOMAIN": "mg.example.com",
            "MAIL_TO": "a@example.com"}

    def test_flapping_failure_kinds_log_one_traceback(self):  # V01
        col, _ = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake"})
        run = col._runs["x"]
        with self.assertLogs("leasewatch.collector", "WARNING") as cm:
            for _ in range(3):
                col._outcome(run, "down", ConnectorError("down"))
                col._outcome(run, "ValueError", ValueError("bug"))
        self.assertEqual([r.levelname for r in cm.records], ["WARNING", "ERROR"])
        # a different unexpected exception still gets its traceback; after a recovery the cycle starts again
        with self.assertLogs("leasewatch.collector", "ERROR"):
            col._outcome(run, "KeyError", KeyError("k"))
        col._outcome(run, "", None)
        with self.assertLogs("leasewatch.collector", "ERROR"):
            col._outcome(run, "down", ConnectorError("down"))
            col._outcome(run, "ValueError", ValueError("bug"))

    def test_queue_read_error_skips_mail_and_retries_next_poll(self):  # V02, S4 T-09
        col, db = self.collector(self.MAIL)
        now = int(time.time())
        db.q("INSERT INTO devices(mac,first_seen,last_seen,mail_queued) VALUES(?,?,?,?)",
             ("02:00:00:00:00:03", now, now, now))
        sent = []
        with mock.patch.object(notify, "new_devices", lambda cfg, devs: sent.append([d["mac"] for d in devs])):
            with mock.patch.object(db, "tx", side_effect=sqlite3.OperationalError("database is locked")), \
                    self.assertLogs("leasewatch.collector", "WARNING"):
                col._notify()
            self.assertEqual(sent, [])
            col._notify()
        self.assertEqual(sent, [["02:00:00:00:00:03"]])

    def test_fixed_instance_drops_the_stale_disabled_error_at_start(self):  # V27
        env = {"LW_CONNECTORS": "fw1,wifi", **FW1, "LW_CONNECTOR__WIFI__TYPE": "unifi",
               "LW_CONNECTOR__WIFI__URL": "ftp://x.example.lan", "LW_CONNECTOR__WIFI__USER": "u",
               "LW_CONNECTOR__WIFI__PASSWORD": "pppppp"}
        col, db = self.collector(env)
        col.run_once()
        self.assertTrue(db.get_meta("conn.wifi.error").startswith("disabled: "))
        Collector(self.cfg({**env, "LW_CONNECTOR__WIFI__URL": "https://x.example.lan"}), db, self.client)
        self.assertEqual((db.get_meta("conn.wifi.enabled"), db.get_meta("conn.wifi.error")), ("1", ""))

    def test_disabled_status_is_written_at_start(self):  # V47
        db = self.collector({"LW_CONNECTORS": "fw1", **FW1})[1]
        col = Collector(self.cfg({"LW_CONNECTORS": "fw1,switch", **FW1, "LW_CONNECTOR__SWITCH__TYPE": "snmp_switch"}),
                        db, self.client)
        self.client.fail = True
        col.run_once()
        self.assertEqual(db.get_meta("conn.switch.enabled"), "0")
        self.assertTrue(db.get_meta("conn.switch.error").startswith("disabled: "))

    def test_event_prune_survives_a_clock_jump_that_lasts(self):  # V48
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1})
        now = int(time.time())
        db.set_meta("last_poll_ts", str(now))
        with db.tx() as c:
            for i in range(5):
                c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now - i * DAY, f"02:00:00:00:00:0{i}", "new", ""))
        jump = now + 10 * 365 * DAY
        res = SimpleNamespace(rows={}, history=[], events=[], seen=[], aliases=[], alias_seen=[])
        for k in range(3):  # as run_once: last_poll_ts follows the wrong clock
            with db.tx() as c:
                col._write(c, {}, res, jump + k * 120)
                db.set_meta("last_poll_ts", str(jump + k * 120), c)
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events")[0]["n"], 5)
        # a restart under the wrong clock does not wipe it either
        col2 = Collector(col.cfg, db, self.client)
        with db.tx() as c:
            col2._write(c, {}, res, jump + 600)
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events")[0]["n"], 5)

    def test_strategy_cleared_when_a_good_batch_has_none(self):  # V73
        col, db = self.collector({"LW_CONNECTORS": "fw1,sw", **FW1, "LW_CONNECTOR__SW__TYPE": "fake"})
        sw = col._connectors["sw"]
        sw.on_collect = lambda: Batch(stats={"macs": 1, "strategy": "cisco_per_vlan"})
        col.run_once()
        sw.on_collect = lambda: Batch(stats={"macs": 1})
        col.run_once()
        self.assertEqual((db.get_meta("conn.sw.ok"), db.get_meta("conn.sw.strategy")), ("1", ""))


    def test_failed_switch_does_not_hold_the_lease_type(self):  # V05
        env = {"LW_CONNECTORS": "fw1,fx,sw", **FW1, "LW_CONNECTOR__FX__TYPE": "fakefw", "LW_CONNECTOR__SW__TYPE": "fake",
               "LEASE_TYPE_MODE": "immediate"}
        col, db = self.collector(env)
        col.run_once()

        def poll(failing: str) -> str:
            with db.tx() as c:
                c.execute("UPDATE devices SET lease_type='static' WHERE mac=?", (MAC,))
            col._connectors[failing].on_collect = lambda: (_ for _ in ()).throw(ConnectorError("timeout"))
            col.run_once()
            col._connectors[failing].on_collect = lambda: Batch()
            return db.device(MAC)["lease_type"]
        # fw1 lists the MAC by ARP only, so its lease is gone. A switch never holds a lease: its failure says nothing
        self.assertEqual(poll("sw"), "")
        # a failed sighting producer may hold the lease: kept until it answers again
        self.assertEqual(poll("fx"), "static")

class Round3Tests(Base):
    """Fix round 3 (W01, W02, W03, W04, W29, W39)."""
    RES = SimpleNamespace(rows={}, history=[], events=[], seen=[], aliases=[], alias_seen=[])

    def test_fixed_switch_clears_its_disabled_error_at_start(self):  # W01
        env = {"LW_CONNECTORS": "fw1,switch", **FW1, "LW_CONNECTOR__SWITCH__TYPE": "snmp_switch"}  # no HOST
        col, db = self.collector(env)
        self.assertTrue(db.get_meta("conn.switch.error").startswith("disabled: "))
        col = Collector(self.cfg({**env, "LW_CONNECTOR__SWITCH__HOST": "10.0.0.2", "LW_CONNECTOR__SWITCH__USER": "u",
                                  "LW_CONNECTOR__SWITCH__AUTH_KEY": "aaaaaaaa", "LW_CONNECTOR__SWITCH__PRIV_KEY": "pppppppp"}),
                        db, self.client)
        self.assertFalse(col._runs["switch"].disabled)
        self.client.fail = True  # the firewall is down: _collect never reaches the enricher's status write
        col.run_once()
        self.assertEqual(db.get_meta("conn.switch.error"), "")

    def test_alternating_unexpected_failures_log_each_traceback_once(self):  # W02, W29
        col, _ = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake"})
        run = col._runs["x"]

        def raised(e: BaseException) -> BaseException:
            try:
                raise e
            except BaseException as caught:
                return caught

        def other_path() -> BaseException:
            try:
                raise ValueError("other bug")
            except ValueError as caught:
                return caught
        with self.assertLogs("leasewatch.collector", "ERROR") as cm:
            for _ in range(5):
                col._outcome(run, "KeyError", raised(KeyError("a")))
                col._outcome(run, "TypeError", raised(TypeError("b")))
                col._outcome(run, "check failed: ValueError", raised(ValueError("c")))
                col._outcome(run, "ValueError", raised(ValueError("c")))
            col._outcome(run, "ValueError", other_path())  # the same type from another place: a new bug
        self.assertEqual(len(cm.records), 5, [r.getMessage().splitlines()[0] for r in cm.records])

    def test_non_ascii_digit_prune_reference_falls_back(self):  # W03
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1})
        now = int(time.time())
        db.set_meta("events_prune_ts", "\u00b2")
        db.set_meta("last_poll_ts", str(now))
        with db.tx() as c:
            col._write(c, {}, self.RES, now)
        self.assertEqual(db.get_meta("events_prune_ts"), str(now))

    def test_clock_behind_does_not_pin_the_prune_reference(self):  # W04
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1})
        now = int(time.time())
        db.set_meta("events_prune_ts", str(now))
        with db.tx() as c:
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (3600, MAC, "new", ""))  # under the wrong clock
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now - 400 * DAY, MAC, "new", ""))
        with db.tx() as c:
            col._write(c, {}, self.RES, 3600)  # no RTC: a poll before NTP sync
        self.assertEqual(db.get_meta("events_prune_ts"), str(now))
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events")[0]["n"], 2)  # a wrong clock prunes nothing
        with db.tx() as c:
            col._write(c, {}, self.RES, now + 120)  # the clock is right again: the year-old event goes
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events WHERE ts>3600")[0]["n"], 0)

    def test_overlong_prune_reference_falls_back(self):  # X05
        col, db = self.collector({"LW_CONNECTORS": "fw1", **FW1})
        now = int(time.time())
        db.set_meta("events_prune_ts", "9" * 5000)  # past int()'s 4300-digit limit
        db.set_meta("last_poll_ts", str(now))
        with db.tx() as c:
            col._write(c, {}, self.RES, now)
        self.assertEqual(db.get_meta("events_prune_ts"), str(now))


class BaselineWaitTests(Base):
    """S05x: the baseline waits until every enabled sighting producer has answered at least once."""
    ENV = {"LW_CONNECTORS": "fw1,fx", **FW1, "LW_CONNECTOR__FX__TYPE": "fakefw", "MAILGUN_KEY": "k",
           "MAILGUN_DOMAIN": "mg.example.com", "MAIL_TO": "a@example.com"}
    FX_MACS = ("02:00:00:00:00:02", "02:00:00:00:00:03")

    def fx_batch(self) -> Batch:
        return Batch(sightings=[Sighting(mac=m, source="fx", kind="arp", presence=True, observed_at=0, ip=f"10.0.0.{i + 20}")
                                for i, m in enumerate(self.FX_MACS)])

    @staticmethod
    def down() -> Batch:
        raise ConnectorError("timeout")

    def poll(self, col: Collector, sent: list) -> dict:
        with mock.patch.object(notify, "new_devices", lambda cfg, devs: sent.append([d["mac"] for d in devs])):
            return col.run_once()

    def baselines(self, db) -> dict:
        return {r["mac"]: r["baseline"] for r in db.q("SELECT mac, baseline FROM devices")}

    def test_producer_failing_on_the_first_poll_holds_the_baseline_back(self):
        col, db = self.collector(self.ENV)
        sent = []
        col._connectors["fx"].on_collect = self.down
        with self.assertLogs("leasewatch.collector", "WARNING") as cm:
            self.poll(col, sent)
        self.assertIn("fx", "\n".join(cm.output))
        self.assertNotEqual(db.get_meta("first_run_done", ""), "1")
        col._connectors["fx"].on_collect = self.fx_batch
        self.poll(col, sent)
        self.assertEqual(sent, [])
        self.assertEqual(self.baselines(db), {MAC: 1, **{m: 1 for m in self.FX_MACS}})
        self.assertEqual(db.get_meta("first_run_done", ""), "1")
        self.assertTrue(db.get_meta("baseline_ts", ""))
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events WHERE kind='new'")[0]["n"], 0)

    # a producer counts as answered only once its poll is stored: a first poll whose write failed is not an answer
    def test_failed_first_write_does_not_count_as_an_answer(self):
        col, db = self.collector(self.ENV)
        sent = []
        col._connectors["fx"].on_collect = self.fx_batch
        with mock.patch.object(col, "_write", side_effect=sqlite3.OperationalError("database is locked")):
            with self.assertRaises(sqlite3.OperationalError):
                self.poll(col, sent)
        col._connectors["fx"].on_collect = self.down
        self.poll(col, sent)
        self.assertNotEqual(db.get_meta("first_run_done", ""), "1")  # "1" before the fix: baseline without fx
        col._connectors["fx"].on_collect = self.fx_batch
        self.poll(col, sent)
        self.assertEqual(sent, [])
        self.assertEqual(self.baselines(db), {MAC: 1, **{m: 1 for m in self.FX_MACS}})

    def test_single_producer_takes_the_baseline_at_once(self):
        env = {k: v for k, v in self.ENV.items() if not k.startswith("LW_CONNECTOR__FX")}
        col, db = self.collector({**env, "LW_CONNECTORS": "fw1"})
        sent = []
        res = self.poll(col, sent)
        self.assertTrue(res["first_run"])
        self.assertEqual(db.get_meta("first_run_done", ""), "1")
        self.client.rows = [arp(MAC, "10.0.0.5"), arp("00:00:5e:00:53:09", "10.0.0.9")]
        self.poll(col, sent)
        self.assertEqual(sent, [["00:00:5e:00:53:09"]])
        self.assertEqual(self.baselines(db), {MAC: 1, "00:00:5e:00:53:09": 0})

    def test_permanently_failing_producer_blocks_and_warns_once(self):
        col, db = self.collector(self.ENV)
        sent = []
        col._connectors["fx"].on_collect = self.down
        with self.assertLogs("leasewatch.collector", "WARNING") as cm:
            for i in range(3):
                self.client.rows = [arp(MAC, "10.0.0.5"), arp(f"02:00:00:00:01:0{i}", f"10.0.1.{i}")]
                self.poll(col, sent)
        self.assertEqual(sum("baseline" in line for line in cm.output), 1)
        self.assertEqual(sent, [])
        self.assertNotEqual(db.get_meta("first_run_done", ""), "1")
        self.assertFalse(db.get_meta("baseline_ts", ""))

    def test_restart_after_the_baseline_does_not_re_baseline(self):
        col, db = self.collector(self.ENV)
        sent = []
        col._connectors["fx"].on_collect = self.down
        self.poll(col, sent)
        col._connectors["fx"].on_collect = self.fx_batch
        self.poll(col, sent)
        self.assertEqual((sent, db.get_meta("first_run_done", "")), ([], "1"))
        # a new process whose fx fails at its first poll: the stored baseline stands, fw1's newcomer is mailed
        col2 = Collector(col.cfg, db, self.client)
        col2._connectors["fx"].on_collect = self.down
        self.client.rows = [arp(MAC, "10.0.0.5"), arp("00:00:5e:00:53:09", "10.0.0.9")]
        self.poll(col2, sent)
        self.assertEqual(sent, [["00:00:5e:00:53:09"]])
        self.assertEqual(self.baselines(db)["00:00:5e:00:53:09"], 0)

    # B-08.4: while the baseline waits for fx, its failed check() is retried at the next poll, not backed off
    def test_failed_check_is_retried_every_poll_while_the_baseline_waits(self):
        col, db = self.collector(self.ENV)
        sent, fx, run = [], col._connectors["fx"], col._runs["fx"]
        fx.on_check = self.down
        fx.on_collect = self.fx_batch
        for i in range(3):
            self.poll(col, sent)
            self.assertEqual((fx.checks, round(run.retry_at - time.monotonic())), (i + 1, 15))
            self.assertNotEqual(db.get_meta("first_run_done", ""), "1")
            run.retry_at -= 15  # one POLL_SECONDS passes
        fx.on_check = lambda: None
        self.poll(col, sent)
        self.assertEqual((fx.checks, fx.collects, db.get_meta("first_run_done", "")), (4, 1, "1"))
        self.assertEqual(sent, [])

    # B-08.4: once the baseline is stored (here by an earlier process) a failed check() backs off as before
    def test_failed_check_backs_off_after_the_baseline(self):
        col, db = self.collector(self.ENV)
        db.set_meta("first_run_done", "1")
        fx, run = col._connectors["fx"], col._runs["fx"]
        fx.on_check = self.down
        waits = []
        for _ in range(3):
            self.poll(col, [])
            waits.append(round(run.retry_at - time.monotonic()))
            run.retry_at = 0
        self.assertEqual(waits, [15, 30, 60])

    # Z02: an empty poll during the baseline wait, after devices are stored, is an ordinary poll, not "first poll empty"
    def test_empty_poll_during_the_wait_is_not_a_failed_first_poll(self):
        col, db = self.collector(self.ENV)
        sent = []
        col._connectors["fx"].on_collect = self.down
        with self.assertLogs("leasewatch.collector", "WARNING"):
            self.assertTrue(self.poll(col, sent)["ok"])
        self.client.rows = []
        res = self.poll(col, sent)
        self.assertTrue(res["ok"], res)
        self.assertEqual(db.get_meta("last_poll_ok", ""), "1")
        self.assertNotEqual(db.get_meta("first_run_done", ""), "1")
        self.assertEqual(sent, [])

    # B-09: while the baseline waits, a late producer's details are no change: no events, no history rows; the poll
    # that takes the baseline writes one history row per device with the complete picture
    def test_late_details_during_the_wait_write_no_events_or_history(self):
        col, db = self.collector(self.ENV)
        sent = []
        col._connectors["fx"].on_collect = self.down
        with self.assertLogs("leasewatch.collector", "WARNING"):
            self.poll(col, sent)
        self.assertEqual(db.q("SELECT COUNT(*) n FROM history")[0]["n"], 0)

        def late(hostname: str = "alex-laptop") -> Batch:
            return Batch(sightings=[Sighting(mac=MAC, source="fx", kind="dhcp", presence=False, observed_at=0,
                                             ip="10.0.0.5", hostname=hostname, network="LAN", lease_type="dynamic")])
        col._connectors["fx"].on_collect = late
        self.poll(col, sent)
        self.assertEqual(db.get_meta("first_run_done", ""), "1")
        self.assertEqual([dict(r) for r in db.q("SELECT kind, detail FROM events")], [])
        self.assertEqual([tuple(r) for r in db.q("SELECT mac, ip, hostname, vlan, lease_type FROM history")],
                         [(MAC, "10.0.0.5", "alex-laptop", "LAN", "dynamic")])
        dev = dict(db.q("SELECT hostname, lease_type, vlan, baseline FROM devices WHERE mac=?", (MAC,))[0])
        self.assertEqual(dev, {"hostname": "alex-laptop", "lease_type": "dynamic", "vlan": "LAN", "baseline": 1})
        # after the baseline a real change is an event and a history row again
        col._connectors["fx"].on_collect = lambda: late("alex-laptop-2")
        self.poll(col, sent)
        self.assertEqual([tuple(r) for r in db.q("SELECT kind, detail FROM events")],
                         [("hostname", "alex-laptop -> alex-laptop-2")])
        self.assertEqual(db.q("SELECT COUNT(*) n FROM history")[0]["n"], 2)
        self.assertEqual(sent, [])

    def test_single_producer_first_poll_writes_one_history_row_per_device(self):
        env = {k: v for k, v in self.ENV.items() if not k.startswith("LW_CONNECTOR__FX")}
        col, db = self.collector({**env, "LW_CONNECTORS": "fw1"}, rows=[arp(MAC, "10.0.0.5"), arp("02:00:00:00:00:09", "10.0.0.9")])
        self.poll(col, [])
        self.assertEqual(sorted(tuple(r) for r in db.q("SELECT mac, ip FROM history")),
                         [(MAC, "10.0.0.5"), ("02:00:00:00:00:09", "10.0.0.9")])
        self.client.rows = [arp(MAC, "10.0.0.7"), arp("02:00:00:00:00:09", "10.0.0.9")]
        self.poll(col, [])
        self.assertEqual([tuple(r) for r in db.q("SELECT kind, detail FROM events")], [("ip", "10.0.0.5 -> 10.0.0.7")])

    def test_empty_very_first_poll_still_fails(self):
        col, db = self.collector(self.ENV)
        col._connectors["fx"].on_collect = self.down
        self.client.rows = []
        with self.assertLogs("leasewatch.collector", "WARNING"):
            res = self.poll(col, [])
        self.assertEqual(res.get("error"), "first poll returned no devices")


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
