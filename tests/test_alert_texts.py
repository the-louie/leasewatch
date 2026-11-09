"""The alert subject and lines in MAIL_LANG: the keys of leasewatch/texts.py, the raw kind when a kind has no key, the
80-character cut after translation. The sv table is patched to a few made-up keys here."""
from __future__ import annotations

import unittest
from unittest import mock

from test_ops_events import ENV, Clock, down
from test_instances import Base
from leasewatch.collector import Collector
from leasewatch.connectors import Batch
from leasewatch.texts import TEXTS, t

SV = {
    "alert.source_down": "{name} är nere: {text}",
    "alert.source_up_after": "{name} är uppe efter {length}",
    "alert.source_up": "{name} är uppe {text}",
    "alert.count_source": {"one": "{n} källhändelse", "other": "{n} källhändelser"},
    "alert.count_watch": {"one": "{n} ändring", "other": "{n} ändringar"},
    "alert.count_mixed": {"one": "{n} larm", "other": "{n} larm totalt"},
    "kind.offline": "frånkopplad",
    "kind.source_down": "källa nere",
}
SRC = {"ts": 0, "mac": "", "kind": "source_down", "detail": "fw1: timeout"}
DEV = {"ts": 0, "mac": "m", "kind": "offline", "detail": ""}


class SwedishSubjectTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(TEXTS["sv"], SV)
        p.start()
        self.addCleanup(p.stop)

    def subject(self, rows):
        return Collector._alert_subject(rows, {"m": "printer"}, "sv")

    def test_source_down(self):
        self.assertEqual(self.subject([SRC]), "fw1 är nere: timeout")

    def test_source_up_with_the_length(self):
        self.assertEqual(self.subject([dict(SRC, kind="source_up", detail="fw1: up after 2h0m")]),
                         "fw1 är uppe efter 2h0m")

    def test_source_up_without_a_length_keeps_the_text(self):
        self.assertEqual(self.subject([dict(SRC, kind="source_up", detail="fw1: odd")]), "fw1 är uppe odd")

    def test_device_kind_is_translated(self):
        self.assertEqual(self.subject([DEV]), "printer: frånkopplad")

    def test_kind_without_a_key_is_the_raw_kind(self):
        self.assertEqual(self.subject([dict(DEV, kind="wobble")]), "printer: wobble")
        self.assertEqual(self.subject([dict(DEV, kind="ip")]), "printer: ip")  # en key, no sv key
        self.assertEqual(Collector._alert_subject([dict(SRC, kind="wobble", detail="fw1: x")], {}, "sv"), "fw1: wobble")

    def test_counts(self):
        self.assertEqual(self.subject([SRC, SRC]), "2 källhändelser")
        self.assertEqual(self.subject([DEV, DEV]), "2 ändringar")
        self.assertEqual(self.subject([SRC, DEV]), "2 larm totalt")
        # a count subject always has n >= 2; the one form is what the table gives for n=1
        self.assertEqual(t("sv", "alert.count_source", n=1), "1 källhändelse")

    def test_cut_to_80_after_translation(self):
        s = self.subject([dict(SRC, detail="fw1: " + "x" * 200)])
        self.assertEqual((len(s), s[:15]), (80, "fw1 är nere: xx"))

    def test_lines_translate_the_kind_only(self):
        lines = Collector._alert_lines([SRC, DEV, dict(DEV, kind="wobble", detail="d")], {"m": "printer"}, "sv")
        self.assertEqual([ln.split(" ", 2)[2] for ln in lines],
                         ["källa nere: fw1: timeout", "printer frånkopplad", "printer wobble: d"])

    def test_en_is_unchanged(self):
        self.assertEqual(Collector._alert_subject([DEV], {"m": "printer"}), "printer: offline")
        self.assertEqual(Collector._alert_subject([dict(DEV, kind="wobble")], {"m": "printer"}), "printer: wobble")
        self.assertEqual(Collector._alert_lines([SRC], {})[0].split(" ", 2)[2], "source_down: fw1: timeout")


class SwedishAlertTests(Base):
    """The alert pass with MAIL_LANG=sv: the subject in sv, and no exception when the table lacks the keys."""

    def setUp(self):
        super().setUp()
        self.clock = Clock()
        for p in (mock.patch("time.time", self.clock), mock.patch("leasewatch.notify.send", side_effect=self.sent)):
            p.start()
            self.addCleanup(p.stop)
        self.msgs = []

    def sent(self, cfg, msg, backoff=None, what="new devices"):
        if msg.event != "new_devices":
            self.msgs.append(msg)
        return ["webhook"]

    def run_down_up(self, table):
        env = {**ENV, "WEBHOOK_URL": "https://hook.example.com/t", "MAIL_ON_SOURCE": "1", "MAIL_LANG": "sv"}
        with mock.patch.dict(TEXTS["sv"], table, clear=True):
            col, _ = self.collector(env)
            self.addCleanup(col.close)
            self.assertEqual(col.cfg.mail_lang, "sv")
            for on_collect, polls in ((Batch, 1), (down, 3), (Batch, 1)):
                col._connectors["x"].on_collect = on_collect
                for _ in range(polls):
                    self.assertTrue(col.run_once()["ok"])
                    self.clock.tick()
        return [m.subject for m in self.msgs]

    def test_subjects_in_sv(self):
        self.assertEqual(self.run_down_up(SV), ["x är nere: down", "x är uppe efter 6m"])

    def test_no_sv_keys_falls_back_to_en(self):
        self.assertEqual(self.run_down_up({}), ["x is down: down", "x is back after 6m"])


if __name__ == "__main__":
    unittest.main()
