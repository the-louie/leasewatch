import io
import json
import logging
import os
import subprocess
import sys
import unittest
from unittest import mock

from leasewatch.__main__ import _JsonFormatter


def run_service(**extra) -> str:
    """Start the module with an empty firewall URL (it stops at config validation) and return its stderr."""
    env = {k: v for k, v in os.environ.items() if k not in ("JOURNAL_STREAM", "LOG_FORMAT", "LOG_LEVEL")}
    env.update(extra, LW_CONNECTOR__FW1__URL="", PYTHONPATH=os.path.join(os.path.dirname(__file__), ".."))
    return subprocess.run([sys.executable, "-m", "leasewatch"], env=env, capture_output=True, text=True, timeout=30).stderr


def record(msg="hello", args=(), exc_info=None):
    return logging.LogRecord("leasewatch.x", logging.WARNING, __file__, 1, msg, args, exc_info)


class LogFormatTest(unittest.TestCase):
    def test_json_line_has_only_the_four_keys(self):
        first = run_service(LOG_FORMAT="json", LOG_LEVEL="verbose").splitlines()[0]
        d = json.loads(first)
        self.assertEqual(set(d), {"ts", "level", "logger", "msg"})
        self.assertRegex(d["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d$")

    def test_json_line_stays_json_when_stderr_is_not_utf8(self):
        first = run_service(LOG_FORMAT="json", LOG_LEVEL="DEB\u00dcG", PYTHONIOENCODING="ascii").splitlines()[0]
        self.assertIn("\\u00dc", first)
        self.assertIn("DEB\u00dcG", json.loads(first)["msg"])

    def test_plain_and_auto_differ_under_journald(self):
        plain = run_service(LOG_FORMAT="plain", LOG_LEVEL="verbose").splitlines()[0]
        self.assertRegex(plain, r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} WARNING leasewatch: ")
        auto = run_service(LOG_FORMAT="auto", LOG_LEVEL="verbose", JOURNAL_STREAM="1:2").splitlines()[0]
        self.assertTrue(auto.startswith("WARNING leasewatch: "), auto)

    def test_unknown_value_warns_and_uses_plain(self):
        lines = run_service(LOG_FORMAT="xml").splitlines()
        self.assertRegex(lines[0], r"^\d{4}-\d\d-\d\d .* WARNING leasewatch: LOG_FORMAT='xml' is not plain, json or auto; using plain$")

    def test_formatter_traceback_is_one_line(self):
        try:
            raise ZeroDivisionError("x")
        except ZeroDivisionError:
            line = _JsonFormatter().format(record("boom\nsecond", exc_info=sys.exc_info()))
        self.assertNotIn("\n", line)
        d = json.loads(line)
        self.assertIn("Traceback", d["exc"])
        self.assertEqual(d["msg"], "boom\nsecond")

    def test_formatter_without_exception_has_no_exc_and_keeps_unicode(self):
        line = _JsonFormatter().format(record("host %s åäö ✓", ("räv",)))
        self.assertNotIn("exc", json.loads(line))
        self.assertIn("host räv åäö ✓", line)

    def test_formatter_with_ascii_stderr_escapes(self):
        with mock.patch.object(sys, "stderr", io.TextIOWrapper(io.BytesIO(), encoding="ascii")):
            line = _JsonFormatter().format(record("ä"))
        self.assertIn("\\u00e4", line)
        self.assertEqual(json.loads(line)["msg"], "ä")

    def test_formatter_with_utf8_stderr_keeps_raw(self):
        with mock.patch.object(sys, "stderr", io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
            line = _JsonFormatter().format(record("ä"))
        self.assertIn("ä", line)


if __name__ == "__main__":
    unittest.main()
