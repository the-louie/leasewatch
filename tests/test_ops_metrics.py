"""metrics.render(): exposition format, escaping and the numbers of a seeded database."""
from __future__ import annotations

import os
import re
import tempfile
import time
import unittest

from _env import clean_env, restore, sources
from leasewatch import metrics
from leasewatch.config import Config
from leasewatch.db import Database

SAMPLE = re.compile(r'^([a-z_]+)(\{[^}]*\})? -?[0-9.e+-]+(inf|nan)?$')
LABEL = re.compile(r'([a-z_]+)="((?:[^"\\]|\\.)*)"')


def unescape(v: str) -> str:
    return re.sub(r"\\(.)", lambda m: "\n" if m.group(1) == "n" else m.group(1), v)


def parse(text: str) -> dict:
    """Strict parse: {metric: [(labels, value)]}. Fails on any line outside the format, or a sample before HELP/TYPE."""
    assert text.endswith("\n") and not text.endswith("\n\n")
    helped, typed, out = set(), set(), {}
    for ln in text.splitlines():
        if ln.startswith("# HELP "):
            name = ln.split(" ", 3)[2]
            assert name not in helped, f"HELP twice: {name}"
            helped.add(name)
        elif ln.startswith("# TYPE "):
            _, _, name, kind = ln.split(" ")
            assert name in helped and name not in typed and kind in ("gauge", "counter"), ln
            typed.add(name)
        else:
            m = SAMPLE.match(ln)
            assert m, f"bad line: {ln!r}"
            name = m.group(1)
            assert name in helped and name in typed, f"no HELP/TYPE before {name}"
            body = (m.group(2) or "")[1:-1]
            labels = {k: unescape(v) for k, v in LABEL.findall(body)}
            assert body == ",".join(m.group(0) for m in LABEL.finditer(body)), ln  # the body is only name="value" pairs
            out.setdefault(name, []).append((labels, float(ln.rsplit(" ", 1)[1])))
    return out


class MetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        env = dict(sources("switch"), DATA_DIR=self.tmp.name, NEW_DAYS="7")
        self._saved = clean_env(env)
        self.cfg = Config()
        self.db = Database(self.cfg.db_path)
        now = int(time.time())
        rows = [  # mac, vlan, online, first_seen, baseline, mail_queued
            ("02:00:00:00:00:01", 'a"b', 1, now - 60, 0, now),
            ("02:00:00:00:00:02", "lan", 1, now - 90 * 86400, 1, None),
            ("02:00:00:00:00:03", "lan", 0, now - 90 * 86400, 1, None),
        ]
        for mac, vlan, online, fs, base, mq in rows:
            self.db.q("INSERT INTO devices(mac,first_seen,last_seen,vlan,online,baseline,mail_queued) VALUES(?,?,?,?,?,?,?)",
                      (mac, fs, fs, vlan, online, base, mq))

    def tearDown(self) -> None:
        self.db._conn.close()
        self.tmp.cleanup()
        restore(self._saved)

    def m(self) -> dict:
        return parse(metrics.render(self.cfg, self.db, "1.2.3"))

    def one(self, parsed: dict, name: str) -> float:
        (labels, value), = parsed[name]
        self.assertEqual(labels, {})
        return value

    def test_numbers_match_seeded_db(self) -> None:
        p = self.m()
        self.assertEqual(sorted((l["network"], v) for l, v in p["leasewatch_devices"]), [("a\"b", 1), ("lan", 2)])
        self.assertEqual(sorted((l["network"], v) for l, v in p["leasewatch_devices_online"]), [("a\"b", 1), ("lan", 1)])
        self.assertEqual(sum(v for _, v in p["leasewatch_devices_online"]), 2)
        self.assertEqual(self.one(p, "leasewatch_devices_new"), 1)
        self.assertEqual(self.one(p, "leasewatch_mail_queued"), 1)
        self.assertEqual(self.one(p, "leasewatch_devices_archived"), 0)

    def test_network_label_round_trips_and_is_escaped(self) -> None:
        text = metrics.render(self.cfg, self.db, "1.2.3")
        self.assertIn('network="a\\"b"', text)
        self.db.q("UPDATE devices SET vlan=? WHERE mac='02:00:00:00:00:02'", ('x\\y\nz"',))
        text = metrics.render(self.cfg, self.db, "1.2.3")
        self.assertIn('network="x\\\\y\\nz\\""', text)
        nets = {l["network"] for l, _ in parse(text)["leasewatch_devices"]}
        self.assertEqual(nets, {'a"b', 'x\\y\nz"', "lan"})

    def test_build_info(self) -> None:
        (labels, value), = self.m()["leasewatch_build_info"]
        self.assertEqual((labels, value), ({"version": "1.2.3"}, 1))
        self.assertIn('version="a\\"b"', metrics.render(self.cfg, self.db, 'a"b'))

    def test_connectors_from_meta(self) -> None:
        for k, v in {"conn.fw1.ok": "1", "conn.fw1.ms": "1500", "conn.fw1.count": "7", "conn.fw1.failures": "2",
                     "conn.switch.ok": "0", "conn.switch.ms": "20", "conn.switch.count": "0"}.items():
            self.db.set_meta(k, v)
        p = self.m()
        lab = lambda name: {"name": name, "type": {"fw1": "opnsense", "switch": "snmp_switch"}[name]}
        self.assertEqual(p["leasewatch_connector_ok"], [(lab("fw1"), 1), (lab("switch"), 0)])
        self.assertEqual(p["leasewatch_connector_duration_seconds"], [(lab("fw1"), 1.5), (lab("switch"), 0.02)])
        self.assertEqual(p["leasewatch_connector_count"], [(lab("fw1"), 7), (lab("switch"), 0)])
        self.assertEqual(p["leasewatch_connector_failures_total"], [(lab("fw1"), 2), (lab("switch"), 0)])
        self.assertEqual([v for _, v in p["leasewatch_connector_enabled"]], [1, 1])

    def test_disabled_instance_has_no_ok(self) -> None:
        self.db.set_meta("conn.switch.enabled", "0")
        self.db.set_meta("conn.switch.ok", "0")
        p = self.m()
        self.assertEqual([l["name"] for l, _ in p.get("leasewatch_connector_ok", [])], [])
        self.assertIn(({"name": "switch", "type": "snmp_switch"}, 0), p["leasewatch_connector_enabled"])

    def test_poll_metrics_absent_before_first_poll_then_present(self) -> None:
        p = self.m()
        for name in ("leasewatch_poll_age_seconds", "leasewatch_poll_ok", "leasewatch_poll_duration_seconds"):
            self.assertNotIn(name, p)
        self.assertEqual({tuple(l.items()): v for l, v in p["leasewatch_polls_total"]}, {(("result", "ok"),): 0, (("result", "failed"),): 0})
        now = int(time.time())
        for k, v in {"last_poll_ts": str(now - 30), "last_attempt_ts": str(now - 5), "last_poll_ok": "1",
                     "last_poll_ms": "2500", "polls_ok": "4", "polls_failed": "1"}.items():
            self.db.set_meta(k, v)
        p = self.m()
        self.assertTrue(30 <= self.one(p, "leasewatch_poll_age_seconds") < 40)
        self.assertTrue(5 <= self.one(p, "leasewatch_poll_attempt_age_seconds") < 15)
        self.assertEqual(self.one(p, "leasewatch_poll_duration_seconds"), 2.5)
        self.assertEqual(self.one(p, "leasewatch_poll_ok"), 1)
        self.assertEqual({l["result"]: v for l, v in p["leasewatch_polls_total"]}, {"ok": 4, "failed": 1})

    def test_notify_ok_for_configured_channels_only(self) -> None:
        self.db.set_meta("notify.webhook.ok", "0")
        self.assertNotIn("leasewatch_notify_ok", self.m())  # webhook is not configured here
        restore(self._saved)
        self._saved = clean_env(dict(sources("switch"), DATA_DIR=self.tmp.name, WEBHOOK_URL="https://hook.example.lan/x"))
        self.cfg = Config()
        self.assertEqual(self.m()["leasewatch_notify_ok"], [({"channel": "webhook"}, 0)])

    def test_file_sizes(self) -> None:
        p = self.m()
        self.assertGreater(self.one(p, "leasewatch_db_bytes"), 0)
        self.assertGreaterEqual(self.one(p, "leasewatch_wal_bytes"), 0)
        self.db.path = os.path.join(self.tmp.name, "missing.sqlite3")
        p = self.m()
        self.assertEqual((self.one(p, "leasewatch_db_bytes"), self.one(p, "leasewatch_wal_bytes")), (0, 0))

    def test_collector_counters_add_up_in_meta(self) -> None:
        from leasewatch.collector import Collector
        bad = {"conn.fw1.ok": "0", "conn.fw1.enabled": "1", "conn.switch.ok": "0", "conn.switch.enabled": "0"}
        for ok, status in ((False, bad), (False, bad), (True, {"conn.fw1.ok": "1", "conn.fw1.enabled": "1"})):
            with self.db.tx() as c:
                Collector._count_poll(c, ok, status)
        m = self.db.all_meta()
        self.assertEqual((m["polls_ok"], m["polls_failed"], m["conn.fw1.failures"]), ("1", "2", "2"))
        self.assertNotIn("conn.switch.failures", m)

    def test_no_error_label(self) -> None:
        self.db.set_meta("conn.fw1.error", "host fw1.example.lan refused")
        text = metrics.render(self.cfg, self.db, "1.2.3")
        self.assertNotIn("refused", text)
        self.assertNotIn("error=", text)


if __name__ == "__main__":
    unittest.main()
