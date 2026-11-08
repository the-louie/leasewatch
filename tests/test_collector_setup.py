"""Collector setup and the merge during the baseline wait: the check() fallback while the baseline waits, SystemExit from
a connector's constructor, device_names() while connectors are built, the 'changed' count during the wait. Fake
connectors only; no network."""
import logging
import unittest
from unittest import mock

from test_instances import FW1, MAC, Base, Fake, arp
import test_collector_edge_cases as cedge
from leasewatch import collector as collector_mod
from leasewatch.collector import MAX_BACKOFF
from leasewatch.connectors import Batch, HostContext, InstanceSpec, Sighting, registry


class _Exits(Fake):
    def __init__(self, name, settings, ctx=None, client=None):
        raise SystemExit(3)


class _ValidateExits(Fake):
    def validate(self):
        raise SystemExit(4)


class _GenExits(Fake):
    def validate(self):  # a generator: its body runs only when the result is read
        yield "x"
        raise SystemExit(5)


class _Eager(Fake):
    def __init__(self, name, settings, ctx=None, client=None):
        super().__init__(name, settings, ctx, client)
        self.names = ctx.device_names()


class CheckFallbackWhileWaitingTests(Base):
    # the setup of test_collector_edge_cases, not inherited: its tests would run twice
    ENV = cedge.BaselineWaitTests.ENV
    FX_MACS = cedge.BaselineWaitTests.FX_MACS
    fx_batch = cedge.BaselineWaitTests.fx_batch
    down = staticmethod(cedge.BaselineWaitTests.down)  # class access unwraps the staticmethod; re-wrap it
    poll = cedge.BaselineWaitTests.poll

    # a check() that keeps failing while collect() works must still reach the MAX_BACKOFF fallback
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

    # changes dropped during the baseline wait are not reported as 'changed'
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
    # a plugin that calls sys.exit() while it is built only disables its instance
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

    # S2T06: a generator validate() ran outside the try, so its SystemExit ended the host
    def test_system_exit_in_a_generator_validate_is_a_config_problem(self):
        with mock.patch.dict(registry(), {"genexit": _GenExits}):
            cfg = self.cfg({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "genexit"})
            self.assertIn("connector x (genexit): cannot be set up (SystemExit)", cfg.validate())

    # device_names() works while the connectors are built
    def test_device_names_callable_while_connectors_are_built(self):
        with mock.patch.dict(registry(), {"eager": _Eager}):
            col, _ = self.collector({"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "eager"})
        self.assertEqual(col._runs["x"].error, "")
        self.assertEqual(col._connectors["x"].names, {})


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
