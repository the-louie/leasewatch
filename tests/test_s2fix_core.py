"""Sprint 2 review fixes in the collector and the merge: the check() fallback while the baseline waits, SystemExit from
a connector's constructor, device_names() while connectors are built, the 'changed' count during the wait. Fake
connectors only; no network."""
import logging
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_instances import FW1, MAC, Base, Fake, arp  # noqa: E402
import test_qa11_collector as qa11  # noqa: E402
from leasewatch import collector as collector_mod  # noqa: E402
from leasewatch.collector import MAX_BACKOFF  # noqa: E402
from leasewatch.connectors import Batch, HostContext, InstanceSpec, Sighting, registry  # noqa: E402


class _Exits(Fake):
    def __init__(self, name, settings, ctx=None, client=None):
        raise SystemExit(3)


class _ValidateExits(Fake):
    def validate(self):
        raise SystemExit(4)


class _Eager(Fake):
    def __init__(self, name, settings, ctx=None, client=None):
        super().__init__(name, settings, ctx, client)
        self.names = ctx.device_names()


class CheckFallbackWhileWaitingTests(Base):
    # the S05x setup of test_qa11_collector, not inherited: its tests would run twice
    ENV = qa11.BaselineWaitTests.ENV
    FX_MACS = qa11.BaselineWaitTests.FX_MACS
    fx_batch = qa11.BaselineWaitTests.fx_batch
    down = qa11.BaselineWaitTests.down
    poll = qa11.BaselineWaitTests.poll

    # S2R01/S2R15: a check() that keeps failing while collect() works must still reach the MAX_BACKOFF fallback
    # (collect() every poll) while the baseline waits, or the baseline is never taken
    def test_failing_check_falls_back_to_collect_while_the_baseline_waits(self):
        col, db = self.collector(self.ENV)
        fx, run = col._connectors["fx"], col._runs["fx"]
        fx.on_check = self.down
        fx.on_collect = self.fx_batch
        polls = MAX_BACKOFF // col.cfg.poll_seconds + 2
        for _ in range(polls):
            self.poll(col, [])
            run.retry_at = 0  # one POLL_SECONDS passes
        self.assertTrue(run.checked)
        self.assertGreater(fx.collects, 0)
        self.assertEqual(db.get_meta("first_run_done", ""), "1")
        self.assertLessEqual(fx.checks, MAX_BACKOFF // col.cfg.poll_seconds)

    def test_poll_seconds_of_max_backoff_collects_from_the_second_poll(self):
        col, db = self.collector({**self.ENV, "POLL_SECONDS": str(MAX_BACKOFF)})
        fx, run = col._connectors["fx"], col._runs["fx"]
        fx.on_check = self.down
        fx.on_collect = self.fx_batch
        for _ in range(2):
            self.poll(col, [])
            run.retry_at = 0
        self.assertEqual((fx.checks, fx.collects, db.get_meta("first_run_done", "")), (1, 1, "1"))

    # S2R32/S2R53: changes B-09 drops during the wait are not reported as 'changed'
    def test_changed_is_zero_while_the_baseline_waits(self):
        col, db = self.collector(self.ENV)
        col._connectors["fx"].on_collect = self.down
        with self.assertLogs("leasewatch.collector", "WARNING"):
            self.poll(col, [])
        self.client.rows = [arp(MAC, "10.0.0.9")]  # held back: fw1's own IP change
        self.assertEqual(self.poll(col, [])["changed"], 0)
        col._connectors["fx"].on_collect = lambda: Batch(sightings=[Sighting(
            mac=MAC, source="fx", kind="dhcp", presence=False, observed_at=0, ip="10.0.0.9", hostname="laptop")])
        res = self.poll(col, [])  # takes the baseline; fx's hostname is no change
        self.assertEqual((res["changed"], db.get_meta("first_run_done", "")), (0, "1"))
        self.assertEqual(db.q("SELECT COUNT(*) n FROM events")[0]["n"], 0)


class SetupTests(Base):
    # S2R13/S2R14: a plugin that calls sys.exit() while it is built only disables its instance
    def test_system_exit_in_the_constructor_disables_the_instance(self):
        with mock.patch.dict(registry(), {"exits": _Exits}):
            conn, problems = collector_mod.setup_instance(InstanceSpec("x", "exits", {}), HostContext())
            self.assertEqual((conn, problems), (None, ["connector x (exits): cannot be set up (SystemExit)"]))
            with self.assertLogs("leasewatch.collector", "ERROR"):
                col, _ = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "exits"})
        self.assertIn("cannot be set up (SystemExit)", col._runs["x"].error)

    # S2S25: a SystemExit from validate() keeps the built connector (so the caller can close() it) and the setting
    # problems found before validate(), as an ordinary exception does
    def test_system_exit_in_validate_keeps_the_connector_and_the_setting_problems(self):
        with mock.patch.dict(registry(), {"vexit": _ValidateExits}):
            conn, problems = collector_mod.setup_instance(InstanceSpec("y", "vexit", {"bogus": "1"}), HostContext())
        self.assertIsInstance(conn, _ValidateExits)
        self.assertEqual(problems, ["connector y (vexit): unknown setting BOGUS",
                                    "connector y (vexit): cannot be set up (SystemExit)"])

    # S2S09: the server and `check` with no names validate the config before the Collector is built; a plugin's
    # sys.exit() there must also only disable its instance, not end the process with the plugin's code
    def test_system_exit_in_the_constructor_is_a_config_problem(self):
        with mock.patch.dict(registry(), {"exits": _Exits}):
            cfg = self.cfg({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "exits"})
            self.assertIn("connector x (exits): cannot be set up (SystemExit)", cfg.validate())

    # S2R52: device_names() works while the connectors are built
    def test_device_names_callable_while_connectors_are_built(self):
        with mock.patch.dict(registry(), {"eager": _Eager}):
            col, _ = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "eager"})
        self.assertEqual(col._runs["x"].error, "")
        self.assertEqual(col._connectors["x"].names, {})


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
