"""notify.py takes its words from the texts table in MAIL_LANG; the webhook JSON carries the mail's own texts."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from _env import CONFIG_VARS  # noqa: F401  (clears the configuration environment)
from leasewatch import notify
from leasewatch.texts import TEXTS

DEV = {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": "", "vlan": "LAN", "lease_type": "dynamic"}
# a small stand-in table; the real Swedish texts are not part of these tests
SV = {
    "mail.head": {"one": "{n} ny enhet i nätet:", "other": "{n} nya enheter i nätet:"},
    "mail.new_subject_where": "Ny enhet: {who} ({where})",
    "mail.new_subject_many": {"one": "{n} ny enhet i nätet", "other": "{n} nya enheter i nätet"},
}


def _cfg(lang: str) -> notify.Config:
    cfg = notify.Config()
    cfg.public_url = "http://x"
    cfg.mail_lang = lang
    return cfg


class SwedishTests(unittest.TestCase):
    def test_build_message_in_swedish(self):
        with mock.patch.dict(TEXTS, {"sv": SV}):
            one = notify.build_message(_cfg("sv"), [DEV])
            many = notify.build_message(_cfg("sv"), [DEV, DEV])
        self.assertEqual(one.subject, "Ny enhet: aa:bb:cc:dd:ee:ff (10.0.0.5, LAN)")
        self.assertEqual(one.text.splitlines()[0], "1 ny enhet i nätet:")
        self.assertEqual(many.subject, "2 nya enheter i nätet")
        self.assertEqual(many.text.splitlines()[0], "2 nya enheter i nätet:")
        # a key the language lacks falls back to en
        self.assertEqual(one.text.splitlines()[-1], "Review and acknowledge: http://x/?filter=unacked")
        self.assertIn("(no hostname)", one.text)

    def test_more_line_follows_the_language(self):
        with mock.patch.dict(TEXTS, {"sv": {"mail.more": "  … och {n} till"}}):
            self.assertEqual(notify._fit_lines(["a" * 10] * 5, 25, len, "sv")[-1], "  … och 3 till")
            self.assertEqual(notify._device_line(dict(DEV), "sv"), notify._device_line(dict(DEV)))
        self.assertEqual(notify._fit_lines(["a" * 10] * 5, 25, len)[-1], "  … and 3 more")

    def test_english_stays(self):
        msg = notify.build_message(_cfg("en"), [DEV, DEV])
        self.assertEqual(msg.subject, "2 new devices on the network")
        self.assertEqual(msg.text.splitlines()[0], "2 new devices on the network:")


class OneLanguageTests(unittest.TestCase):
    def test_json_body_carries_the_mail_texts(self):
        for lang in ("en", "sv"):
            with self.subTest(lang=lang), mock.patch.dict(TEXTS, {"sv": SV}):
                cfg = _cfg(lang)
                msg = notify.build_message(cfg, [DEV, DEV])
                body = json.loads(notify.webhook_json_body(cfg, msg))
                self.assertEqual(body["title"], msg.subject)
                self.assertEqual(body["message"], msg.text)
        self.assertEqual(body["title"], "2 nya enheter i nätet")


if __name__ == "__main__":
    unittest.main()
