"""The two control-character patterns differ on purpose: stored text keeps tab/newline, mail/webhook text does not."""
import unittest
import _env  # noqa: F401  # the repo root on the path and the network guard, also when this module runs on its own
from leasewatch.connectors.merge import _str
from leasewatch.db import CONTROL_CHARS
from leasewatch.notify import _LINE_UNSAFE

S = "a\tb\nc\x07d​e"  # tab, newline, BEL, zero-width space


class ControlCharSets(unittest.TestCase):
    def test_stored_text_keeps_tab_and_newline(self):
        self.assertEqual(CONTROL_CHARS.sub("", S), "a\tb\ncde")

    def test_mail_text_blanks_line_breaks_and_keeps_zero_width(self):
        self.assertEqual(_LINE_UNSAFE.sub(" ", S), "a b c d​e")

    def test_connector_text_blanks_tab_and_newline_and_drops_invisible(self):
        self.assertEqual(_str(S, False), "a b cde")
        self.assertNotEqual(CONTROL_CHARS.pattern, _LINE_UNSAFE.pattern)  # a "unification" must fail here


if __name__ == "__main__":
    unittest.main()
