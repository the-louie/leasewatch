"""Collector.close(): every connector closed once at shutdown, bounded by the instance TIMEOUT and a total cap."""
from __future__ import annotations

import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from test_instances import FW1, Base  # noqa: E402
from test_basic_auth import FW1_ENV, clean_env, restore  # noqa: E402
from test_unifi_session import USER, PASSWORD, Controller  # noqa: E402
from leasewatch import __main__ as cli  # noqa: E402
from leasewatch import collector as collector_mod  # noqa: E402

TWO = {"LW_CONNECTORS": "fw1,second", **FW1, "LW_CONNECTOR__SECOND__TYPE": "opnsense",
       "LW_CONNECTOR__SECOND__URL": "https://fw2.example.lan", "LW_CONNECTOR__SECOND__KEY": "k2",
       "LW_CONNECTOR__SECOND__SECRET": "s2"}


class Closer:
    def __init__(self, block: float = 0.0):
        self.calls = 0
        self.block = block
        self.release = threading.Event()

    def close(self) -> None:
        self.calls += 1
        if self.block:
            self.release.wait(self.block)


class CloseTests(Base):
    def test_closes_each_instance_once_and_twice_is_harmless(self):
        col, _ = self.collector(TWO)
        a, b = Closer(), Closer()
        col._connectors = {"fw1": a, "second": b}
        with self.assertLogs("leasewatch.collector", "INFO") as cm:
            col.close()
            col.close()
        self.assertEqual((a.calls, b.calls), (1, 1))
        self.assertEqual([r for r in cm.output if "connectors closed" in r].__len__(), 1, cm.output)

    def test_no_connector_built(self):
        col, _ = self.collector(TWO)
        col._connectors = {}
        col.close()
        col.close()

    def test_blocking_close_is_capped_by_the_instance_timeout(self):
        col, _ = self.collector(TWO)
        slow, fast = Closer(block=5), Closer()
        self.addCleanup(slow.release.set)
        col._connectors = {"fw1": slow, "second": fast}
        col._runs["fw1"].timeout = 0.2
        t0 = time.monotonic()
        with self.assertLogs("leasewatch", "WARNING") as cm:
            col.close()
        self.assertLess(time.monotonic() - t0, 2)
        self.assertEqual(fast.calls, 1)
        text = "\n".join(cm.output)
        self.assertIn("still closing: fw1", text)
        self.assertIn("close() did not return within 0.2 s", text)
        self.assertNotIn("second", text)

    def test_total_cap(self):
        col, _ = self.collector(TWO)
        a, b = Closer(block=5), Closer(block=5)
        self.addCleanup(a.release.set)
        self.addCleanup(b.release.set)
        col._connectors = {"fw1": a, "second": b}
        for r in col._runs.values():
            r.timeout = 30
        t0 = time.monotonic()
        with mock.patch.object(collector_mod, "CLOSE_SECONDS", 0.3), self.assertLogs("leasewatch", "INFO") as cm:
            col.close()
        self.assertLess(time.monotonic() - t0, 2)
        self.assertEqual((a.calls, b.calls), (1, 1))  # the second is still asked to close
        self.assertIn("fw1, second", "\n".join(cm.output))
        self.assertIn("still closing: fw1, second", "\n".join(cm.output))
        self.assertIn("close() started without waiting (shutdown budget used)", "\n".join(cm.output))

    def test_total_cap_is_five_seconds(self):
        self.assertEqual(collector_mod.CLOSE_SECONDS, 5)

    def test_busy_worker_is_not_waited_for_but_still_asked_to_close(self):
        col, _ = self.collector(TWO)
        busy, fast = Closer(block=5), Closer()
        self.addCleanup(busy.release.set)
        col._connectors = {"fw1": busy, "second": fast}
        worker_stop = threading.Event()
        worker = threading.Thread(target=worker_stop.wait, daemon=True)
        worker.start()
        self.addCleanup(worker_stop.set)
        col._runs["fw1"].thread = worker
        t0 = time.monotonic()
        with self.assertLogs("leasewatch", "INFO") as cm:
            col.close()
        self.assertLess(time.monotonic() - t0, 1)
        time.sleep(0.1)
        self.assertEqual((busy.calls, fast.calls), (1, 1))
        text = "\n".join(cm.output)
        self.assertIn("still busy: fw1", text)
        self.assertNotIn("still closing", text)
        self.assertNotIn("did not return", text)


class UnifiCollectorClose(Base):
    def test_collector_close_logs_out_of_the_controller(self):
        ctl = Controller("os")
        self.addCleanup(ctl.close)
        env = {"LW_CONNECTORS": "unifi", "LW_CONNECTOR__UNIFI__TYPE": "unifi", "LW_CONNECTOR__UNIFI__URL": ctl.url,
               "LW_CONNECTOR__UNIFI__USER": USER, "LW_CONNECTOR__UNIFI__PASSWORD": PASSWORD,
               "LW_CONNECTOR__UNIFI__VERIFY_TLS": "0"}
        col, _ = self.collector(env)
        conn = col._connectors["unifi"]
        conn.check()
        conn.collect()
        self.assertEqual(ctl.count("POST", "/api/auth/login"), 1)
        self.assertEqual(ctl.count("POST", "/api/auth/logout"), 0)
        col.close()
        self.assertEqual(ctl.count("POST", "/api/auth/logout"), 1)


class MainOrder(unittest.TestCase):
    def test_main_closes_connectors_then_database_after_the_poller_join(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        saved = clean_env({**FW1_ENV, "DATA_DIR": tmp.name})
        self.addCleanup(restore, saved)
        order: list[str] = []
        srv = mock.Mock()
        srv.RequestHandlerClass.verifier.flush.side_effect = lambda: order.append("flush")
        col = mock.Mock()
        col.close.side_effect = lambda: order.append("close")
        thread = mock.Mock()
        thread.join.side_effect = lambda *_: order.append("join")
        real = cli.Database

        def database(path: str) -> object:
            db = real(path)
            self.addCleanup(db._conn.close)
            real_close = db.close
            db.close = lambda *a, **k: (order.append("db"), real_close(*a, **k))[1]
            return db
        with mock.patch.object(cli, "Database", database), mock.patch.object(cli, "serve", return_value=srv), \
                mock.patch.object(cli, "Collector", return_value=col), \
                mock.patch.object(cli.threading, "Thread", return_value=thread), \
                mock.patch.object(cli.signal, "signal"), mock.patch.object(cli, "startup_line", return_value=""), \
                mock.patch.object(cli, "types_line", return_value=""), self.assertLogs("leasewatch", "INFO"):
            self.assertEqual(cli.main([]), 0)
        self.assertEqual(order, ["flush", "join", "close", "db"])


if __name__ == "__main__":
    unittest.main()
