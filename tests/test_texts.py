"""leasewatch/texts.py: the en table equals the literals the builders produce, the fallback chain, plurals, params."""
from __future__ import annotations

import unittest

from _env import CONFIG_VARS
from leasewatch import collector, notify
from leasewatch.texts import TEXTS, t

DEV = {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": "", "vlan": "LAN", "lease_type": "dynamic"}


class EnglishTableTests(unittest.TestCase):
    def test_key_list(self):
        self.assertEqual(len(TEXTS["en"]), 21)
        self.assertEqual(TEXTS["sv"], {})

    def test_alert_subjects_equal_the_collector_templates(self):
        for kind, key in (("source_down", "alert.source_down"), ("source_up", "alert.source_up")):
            self.assertEqual(t("en", key, name="fw1", text="x"),
                             collector.ALERT_SUBJECTS[kind].format(name="fw1", text="x"))
        self.assertEqual(t("en", "alert.source_up_after", name="fw1", length="2h0m"),
                         collector.ALERT_SUBJECTS["source_up"].format(name="fw1", text="after 2h0m"))

    def test_alert_counts_equal_the_collector_subject(self):
        src = {"mac": "", "kind": "source_down", "detail": "fw1: x"}
        dev = {"mac": "m", "kind": "offline", "detail": ""}
        for rows, key in (([src, src], "alert.count_source"), ([dev, dev, dev], "alert.count_watch"),
                          ([src, dev], "alert.count_mixed")):
            self.assertEqual(t("en", key, n=len(rows)), collector.Collector._alert_subject(rows, {"m": "p"}))

    def test_kinds_are_the_identifiers(self):
        for kind in collector.WATCH_KINDS + collector.ALERT_KINDS:
            self.assertEqual(t("en", "kind." + kind), kind)

    def test_mail_texts_equal_build_message(self):
        cfg = notify.Config()
        cfg.public_url = "http://x"
        m1 = notify.build_message(cfg, [DEV])
        self.assertEqual(m1.subject, t("en", "mail.new_subject_where", who="aa:bb:cc:dd:ee:ff", where="10.0.0.5, LAN"))
        self.assertEqual(m1.text.splitlines()[0], t("en", "mail.head", n=1))
        self.assertEqual(m1.text.splitlines()[-1], t("en", "mail.review_link", url="http://x/?filter=unacked"))
        d2 = dict(DEV, ip="", vlan="", hostname="h")
        self.assertEqual(notify.build_message(cfg, [d2]).subject, t("en", "mail.new_subject", who="h"))
        m2 = notify.build_message(cfg, [DEV, DEV])
        self.assertEqual(m2.subject, t("en", "mail.new_subject_many", n=2))
        self.assertEqual(m2.text.splitlines()[0], t("en", "mail.head", n=2))
        self.assertIn(t("en", "mail.no_hostname"), notify._device_line(DEV))

    def test_more_line_equals_fit_lines(self):
        shown = notify._fit_lines(["a" * 10] * 5, 25, len)
        self.assertEqual(shown[-1], t("en", "mail.more", n=5 - len(shown) + 1))


class LookupTests(unittest.TestCase):
    def test_fallback_chain(self):
        self.assertEqual(t("sv", "mail.no_hostname"), "(no hostname)")
        self.assertEqual(t("xx", "mail.no_hostname"), "(no hostname)")
        self.assertEqual(t("en", "no.such.key", n=1), "no.such.key")
        self.assertEqual(t("sv", "no.such.key"), "no.such.key")

    def test_sv_value_wins_when_present(self):
        TEXTS["sv"]["mail.no_hostname"] = "(x)"
        try:
            self.assertEqual(t("sv", "mail.no_hostname"), "(x)")
        finally:
            del TEXTS["sv"]["mail.no_hostname"]

    def test_plurals(self):
        self.assertEqual(t("en", "mail.head", n=1), "1 new device on the network:")
        self.assertEqual(t("en", "mail.head", n=2), "2 new devices on the network:")
        self.assertEqual(t("en", "mail.head", n=0), "0 new devices on the network:")
        self.assertEqual(t("en", "mail.head"), "{n} new devices on the network:")

    def test_missing_param_stays_and_nothing_raises(self):
        self.assertEqual(t("en", "alert.source_down", name="fw1"), "fw1 is down: {text}")
        self.assertEqual(t("en", "alert.source_down"), "{name} is down: {text}")
        self.assertEqual(t("en", "mail.new_subject", who="{x} {0}"), "New device: {x} {0}")

    def test_mail_lang_is_a_known_config_var(self):
        self.assertIn("MAIL_LANG", CONFIG_VARS)


if __name__ == "__main__":
    unittest.main()
