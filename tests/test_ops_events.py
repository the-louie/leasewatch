"""source_down / source_up events per connector instance: counted polls, back-dated down event, restart memory in
conn.<name>.down_since, startup cleanup, the outcome transactions, and /api/events. Fake connector types only."""
from __future__ import annotations

import http.client
import json
import os
import sqlite3
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from test_instances import FW1, Base  # noqa: E402
from leasewatch.collector import SOURCE_DOWN_POLLS, Collector, outage_text  # noqa: E402
from leasewatch.connectors import Batch, ConnectorError  # noqa: E402
from leasewatch.web import serve  # noqa: E402

T0 = 1_800_000_000
ENV = {"LW_CONNECTORS": "fw1,x", **FW1, "LW_CONNECTOR__X__TYPE": "fake"}


def down():
    raise ConnectorError("down")


class Clock:
    """time.time() for the collector: moves on by `step` seconds per tick()."""

    def __init__(self, t=T0, step=120):
        self.t, self.step = t, step

    def __call__(self):
        return float(self.t)

    def tick(self):
        self.t += self.step


class SourceEventTests(Base):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        p = mock.patch("time.time", self.clock)
        p.start()
        self.addCleanup(p.stop)

    def src(self, db):
        return [(r["ts"], r["mac"], r["kind"], r["detail"]) for r in
                db.q("SELECT ts, mac, kind, detail FROM events WHERE kind LIKE 'source%' ORDER BY id")]

    def poll(self, col, n=1):
        for _ in range(n):
            col.run_once()
            self.clock.tick()

    def start(self, env=ENV):
        col, db = self.collector(env)
        self.poll(col)  # baseline taken, x answered
        self.assertEqual(db.get_meta("first_run_done"), "1")
        return col, db

    def test_down_after_three_polls_once_then_up(self):
        self.assertEqual(SOURCE_DOWN_POLLS, 3)
        col, db = self.start()
        x = col._connectors["x"]
        x.on_collect = down
        first = self.clock.t
        self.poll(col, 2)
        self.assertEqual(self.src(db), [])
        self.poll(col)
        self.assertEqual(self.src(db), [(first, "", "source_down", "x: down")])
        self.assertEqual(db.get_meta("conn.x.down_since"), str(first))
        self.poll(col, 3)
        self.assertEqual(len(self.src(db)), 1)
        x.on_collect = Batch
        up = self.clock.t  # 6 failed polls 120 s apart: 12 minutes
        self.poll(col, 2)
        self.assertEqual(self.src(db), [(first, "", "source_down", "x: down"), (up, "", "source_up", "x: up after 12m")])
        self.assertEqual(db.get_meta("conn.x.down_since", "unset"), "unset")
        self.assertFalse(db.q("SELECT 1 FROM events WHERE kind LIKE 'source%' AND mac != ''"))

    def test_two_failures_and_recovery_write_nothing(self):
        col, db = self.start()
        x = col._connectors["x"]
        x.on_collect = down
        self.poll(col, 2)
        x.on_collect = Batch
        self.poll(col)
        x.on_collect = down
        self.poll(col, 2)  # a new spell counts from one again
        self.assertEqual(self.src(db), [])

    def test_check_backoff_counts_as_failed(self):
        col, db = self.collector({**ENV, "LW_CONNECTOR__X__TOKEN": "sekret-t"})
        x = col._connectors["x"]
        x.on_check = lambda: (_ for _ in ()).throw(ConnectorError("unreachable sekret-t"))
        self.poll(col, 4)  # one check(), then held in its backoff; the first poll takes the baseline, uncounted
        self.assertEqual(x.checks, 1)
        self.assertEqual([d for _, _, _, d in self.src(db)], ["x: check failed: unreachable ***"])

    def test_long_error_is_cut(self):
        col, db = self.start()
        col._connectors["x"].on_collect = lambda: (_ for _ in ()).throw(ConnectorError("e" * 300))
        self.poll(col, 3)
        self.assertEqual(self.src(db)[0][3], "x: " + "e" * 200)

    def test_none_before_the_baseline(self):
        col, db = self.collector(ENV, rows=[])
        self.client.fail = True
        col._connectors["x"].on_collect = down
        self.poll(col, 4)
        self.client.fail = False
        self.client.rows = []
        self.poll(col)  # the producer answers but lists nothing: still no baseline
        self.assertNotEqual(db.get_meta("first_run_done"), "1")
        self.assertEqual(self.src(db), [])

    def test_disabled_instance_never(self):
        col, db = self.start({**ENV, "LW_CONNECTORS": "fw1,x,bad", "LW_CONNECTOR__BAD__TYPE": "fake",
                              "LW_CONNECTOR__BAD__PORT": "0"})
        self.assertTrue(col._runs["bad"].disabled)
        self.poll(col, 5)
        self.assertEqual(self.src(db), [])

    def test_all_producers_down_leaves_enricher_counts_and_uses_the_fail_transaction(self):
        col, db = self.start()
        x = col._connectors["x"]
        x.on_collect = down
        self.poll(col, 2)
        self.client.fail = True
        fw1_first = self.clock.t
        self.poll(col, 3)  # x is not collected: its count stays at 2
        self.assertEqual(col._runs["x"].fail_polls, 2)
        self.assertEqual(self.src(db), [(fw1_first, "", "source_down", "fw1: boom")])
        self.client.fail = False
        back = self.clock.t
        self.poll(col)  # x fails its third poll
        self.assertEqual(self.src(db)[1:], [(back, "", "source_up", "fw1: up after 6m"),
                                            (fw1_first - 240, "", "source_down", "x: down")])

    def test_restart_during_an_outage(self):
        col, db = self.start()
        col._connectors["x"].on_collect = down
        first = self.clock.t
        self.poll(col, 3)
        col.close()
        col2 = Collector(col.cfg, db, self.client)
        self.assertEqual(col2._runs["x"].down_since, first)
        col2._connectors["x"].on_collect = down
        self.poll(col2, 4)
        self.assertEqual(len(self.src(db)), 1)
        col2._connectors["x"].on_collect = Batch
        up = self.clock.t
        self.poll(col2)
        self.assertEqual(self.src(db)[1], (up, "", "source_up", f"x: up after {outage_text(up - first)}"))
        self.assertEqual(outage_text(up - first), "14m")
        col2.close()

    def test_startup_removes_down_since_of_unconfigured_instances(self):
        col, db = self.start()
        for name in ("x", "gone", "fw10"):
            db.set_meta(f"conn.{name}.down_since", str(T0))
        db.set_meta("conn.gone.ok", "0")
        col.close()
        Collector(col.cfg, db, self.client).close()
        self.assertEqual(db.get_meta("conn.x.down_since"), str(T0))
        self.assertEqual(db.get_meta("conn.gone.down_since", "unset"), "unset")
        self.assertEqual(db.get_meta("conn.fw10.down_since", "unset"), "unset")
        self.assertEqual(db.get_meta("conn.gone.ok"), "0")  # only the outage marker goes

    def test_failed_write_keeps_the_event_for_the_next_outcome(self):
        col, db = self.start()
        col._connectors["x"].on_collect = down
        first = self.clock.t
        self.poll(col, 2)
        with mock.patch.object(col, "_write", side_effect=sqlite3.OperationalError("locked")):
            with self.assertRaises(sqlite3.OperationalError):
                col.run_once()
        self.clock.tick()
        self.assertEqual(self.src(db), [])
        self.poll(col)
        self.assertEqual(self.src(db), [(first, "", "source_down", "x: down")])
        self.assertEqual(db.get_meta("conn.x.down_since"), str(first))

    def test_api_events_serves_them(self):
        col, db = self.start({**ENV, "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0"})
        col._connectors["x"].on_collect = down
        self.poll(col, 3)
        srv = serve(col.cfg, db, "9.9.9-test")
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            conn.request("GET", "/api/events")
            resp = conn.getresponse()
            body = json.loads(resp.read())
            conn.close()
        finally:
            srv.shutdown()
            srv.server_close()
            t.join(5)
        self.assertEqual(resp.status, 200)
        ev = [e for e in body["events"] if e["kind"] == "source_down"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["mac"], ev[0]["name"], ev[0]["detail"]), ("", None, "x: down"))


class OutageTextTests(unittest.TestCase):
    def test_formats(self):
        for secs, text in ((0, "0m"), (59, "0m"), (-5, "0m"), (60, "1m"), (3599, "59m"), (3600, "1h0m"),
                           (3 * 3600 + 12 * 60 + 30, "3h12m"), (86399, "23h59m"), (86400, "1d0h"),
                           (2 * 86400 + 5 * 3600 + 59 * 60, "2d5h")):
            self.assertEqual(outage_text(secs), text)


if __name__ == "__main__":
    unittest.main()
