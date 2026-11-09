"""The sv table of leasewatch/texts.py: the same keys, parameters and plural forms as en, every key in use, and the
mail, alert, webhook and MQTT texts in Swedish with MAIL_LANG=sv. The en texts stay as they were."""
from __future__ import annotations

import json
import os
import re
import string
import unittest
from pathlib import Path
from unittest import mock

from _env import CONFIG_VARS  # noqa: F401  (clears the configuration environment)
from leasewatch import collector, notify
from leasewatch.collector import ALERT_KINDS, WATCH_KINDS, Collector
from leasewatch.texts import TEXTS, t

SRC_DIR = Path(__file__).resolve().parent.parent / "leasewatch"
DEV = {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": "", "vlan": "LAN", "lease_type": "dynamic"}
SRC = {"ts": 0, "mac": "", "kind": "source_down", "detail": "fw1: timeout"}
WATCH = {"ts": 0, "mac": "m", "kind": "ip", "detail": "10.0.0.5 -> 10.0.0.6"}

# sv values that are the same words as en on purpose (loanwords used on the page too)
SAME_AS_EN = {"kind.offline", "kind.online"}

# the en texts as they were before the sv table: en output must not change
EN = {
    "mail.head": {"one": "{n} new device on the network:", "other": "{n} new devices on the network:"},
    "mail.new_subject": "New device: {who}",
    "mail.new_subject_where": "New device: {who} ({where})",
    "mail.new_subject_many": {"one": "{n} new device on the network", "other": "{n} new devices on the network"},
    "mail.no_hostname": "(no hostname)",
    "mail.review_link": "Review and acknowledge: {url}",
    "mail.more": "  … and {n} more",
    "alert.source_down": "{name} is down: {text}",
    "alert.source_up_after": "{name} is back after {length}",
    "alert.source_up": "{name} is back {text}",
    "alert.count_source": {"one": "{n} source event", "other": "{n} source events"},
    "alert.count_watch": {"one": "{n} change on a watched device", "other": "{n} changes on watched devices"},
    "alert.count_mixed": {"one": "{n} alert", "other": "{n} alerts"},
    "kind.offline": "offline",
    "kind.online": "online",
    "kind.ip": "ip",
    "kind.vlan": "vlan",
    "kind.port": "port",
    "kind.wifi": "wifi",
    "kind.source_down": "source_down",
    "kind.source_up": "source_up",
}


def _forms(value):
    return value if isinstance(value, dict) else {"": value}


def _params(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name is not None}


def _sv_cfg() -> notify.Config:
    with mock.patch.dict(os.environ, {"MAIL_LANG": "sv"}):
        cfg = notify.Config()
    cfg.public_url = "http://x"
    return cfg


class TableTests(unittest.TestCase):
    def test_same_keys(self):
        self.assertEqual(set(TEXTS["sv"]), set(TEXTS["en"]))
        self.assertEqual(len(TEXTS["sv"]), 21)

    def test_same_params_per_form(self):
        for key, en in TEXTS["en"].items():
            sv = TEXTS["sv"][key]
            with self.subTest(key=key):
                self.assertEqual(isinstance(sv, dict), isinstance(en, dict))
                self.assertEqual(set(_forms(sv)), set(_forms(en)))
                for form, text in _forms(en).items():
                    self.assertEqual(_params(_forms(sv)[form]), _params(text), form)

    def test_plurals_have_one_and_other(self):
        for lang in ("en", "sv"):
            for key, value in TEXTS[lang].items():
                if isinstance(value, dict):
                    with self.subTest(lang=lang, key=key):
                        self.assertEqual(set(value), {"one", "other"})

    def test_sv_differs_from_en(self):
        for key, en in TEXTS["en"].items():
            with self.subTest(key=key):
                if key in SAME_AS_EN:
                    self.assertEqual(TEXTS["sv"][key], en)
                else:
                    for form, text in _forms(en).items():
                        self.assertNotEqual(_forms(TEXTS["sv"][key])[form], text, form)

    def test_en_is_unchanged(self):
        self.assertEqual(TEXTS["en"], EN)


class UsageTests(unittest.TestCase):
    def setUp(self):
        src = "".join((SRC_DIR / f).read_text(encoding="utf-8") for f in ("notify.py", "collector.py"))
        # the keys in t(lang, "<key>") calls, and the keys a call picks from a conditional (the alert counts)
        self.literal = set(re.findall(r"""\bt\(\s*\w+(?:\.\w+)?\s*,\s*["'](\w+\.\w+)["']""", src))
        self.literal |= set(re.findall(r"""["']((?:mail|alert|kind)\.\w+)["']""", src))
        self.prefixed = set(re.findall(r"""["']((?:alert|kind)\.)["']\s*\+""", src))

    def test_literal_keys_exist_in_en(self):
        self.assertTrue(self.literal)
        self.assertEqual(self.literal - set(TEXTS["en"]), set())

    def test_every_en_key_is_used(self):
        self.assertEqual(self.prefixed, {"alert.", "kind."})
        used = self.literal | {"kind." + k for k in WATCH_KINDS + ALERT_KINDS} | {"alert." + k for k in ALERT_KINDS}
        self.assertEqual(set(TEXTS["en"]) - used, set())


class SwedishOutputTests(unittest.TestCase):
    def setUp(self):
        self.cfg = _sv_cfg()

    def test_mail_lang_is_sv(self):
        self.assertEqual(self.cfg.mail_lang, "sv")

    def test_one_device(self):
        m = notify.build_message(self.cfg, [DEV])
        self.assertEqual(m.subject, "Ny enhet: aa:bb:cc:dd:ee:ff (10.0.0.5, LAN)")
        lines = m.text.splitlines()
        self.assertEqual(lines[0], "1 ny enhet på nätverket:")
        self.assertIn("(inget värdnamn)", m.text)
        self.assertEqual(lines[-1], "Granska och markera som kända: http://x/?filter=unacked")
        d = dict(DEV, ip="", vlan="", hostname="skrivare")
        self.assertEqual(notify.build_message(self.cfg, [d]).subject, "Ny enhet: skrivare")

    def test_two_devices(self):
        m = notify.build_message(self.cfg, [DEV, dict(DEV, mac="aa:bb:cc:dd:ee:01")])
        self.assertEqual(m.subject, "2 nya enheter på nätverket")
        self.assertEqual(m.text.splitlines()[0], "2 nya enheter på nätverket:")

    def test_more_line(self):
        shown = notify._fit_lines(["a" * 10] * 5, 25, len, "sv")
        self.assertEqual(shown[-1], f"  … och {5 - len(shown) + 1} till")

    def test_source_down_alert(self):
        lang = self.cfg.mail_lang
        self.assertEqual(Collector._alert_subject([SRC], {}, lang), "fw1 är nere: timeout")
        self.assertEqual(Collector._alert_lines([SRC], {}, lang)[0].split(" ", 2)[2], "källa nere: fw1: timeout")
        up = dict(SRC, kind="source_up", detail="fw1: up after 2h0m")
        self.assertEqual(Collector._alert_subject([up], {}, lang), "fw1 är uppe igen efter 2h0m")
        self.assertEqual(Collector._alert_subject([SRC, SRC], {}, lang), "2 källhändelser")

    def test_watch_alert(self):
        lang, names = self.cfg.mail_lang, {"m": "skrivare"}
        self.assertEqual(Collector._alert_subject([WATCH], names, lang), "skrivare: ny IP")
        self.assertEqual(Collector._alert_lines([WATCH], names, lang)[0].split(" ", 2)[2],
                         "skrivare ny IP: 10.0.0.5 -> 10.0.0.6")
        self.assertEqual(Collector._alert_subject([WATCH, WATCH], names, lang), "2 ändringar på bevakade enheter")
        self.assertEqual(Collector._alert_subject([SRC, WATCH], names, lang), "2 larm")
        for kind in WATCH_KINDS:
            self.assertEqual(collector._kind_text(lang, kind), TEXTS["sv"]["kind." + kind])

    def test_webhook_and_mqtt_bodies(self):
        msg = notify.build_message(self.cfg, [DEV, DEV])
        body = notify.webhook_json_body(self.cfg, msg)
        payload = json.loads(body)
        self.assertEqual(set(payload), {"event", "site", "count", "title", "message", "url", "devices"})
        self.assertEqual(payload["title"], "2 nya enheter på nätverket")
        self.assertTrue(payload["message"].startswith("2 nya enheter på nätverket:\n"))
        self.assertIn("nätverket".encode(), body)  # UTF-8, not \u escapes

        client = mock.Mock(connected=True)
        alert = notify.build_alert(self.cfg, Collector._alert_subject([SRC], {}, "sv"),
                                   Collector._alert_lines([SRC], {}, "sv"), "source_down")
        notify.MqttChannel(self.cfg, lambda: client).send(alert)
        sent = client.publish.call_args.args[1]
        self.assertEqual(sent, notify.webhook_json_body(self.cfg, alert))
        self.assertEqual(json.loads(sent)["title"], "fw1 är nere: timeout")

    def test_en_output_unchanged(self):
        cfg = notify.Config()
        cfg.public_url = "http://x"
        self.assertEqual(cfg.mail_lang, "en")
        self.assertEqual(notify.build_message(cfg, [DEV, DEV]).subject, "2 new devices on the network")
        self.assertEqual(Collector._alert_subject([SRC], {}), "fw1 is down: timeout")
        self.assertEqual(Collector._alert_subject([WATCH], {"m": "p"}), "p: ip")
        self.assertEqual(t("en", "mail.more", n=3), "  … and 3 more")


if __name__ == "__main__":
    unittest.main()
