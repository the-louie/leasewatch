"""Small loader and CLI-report cases: a LW_CONNECTORS_DIR entry name with a newline, and an int subclass's own
__int__ in the reported stats. Every plugin is synthetic, written into a temporary directory by the test."""
from __future__ import annotations

import os
import unittest

from _env import FW1_ENV
from test_loader import GROUP, LoaderBase, make_dir_dist

from leasewatch.__main__ import _report_stats
from leasewatch.connectors import broken_types

LOG = "leasewatch.connectors.loader"


class TestEntryNameOneLine(LoaderBase):
    def test_newline_in_a_dir_entry_forges_no_line(self):
        # an unreadable pyproject.toml (the raw newline in the name string), and one whose import fails
        make_dir_dist(self.dir, "a\nERROR forged entry", "lwt_nla", "nla")
        base = make_dir_dist(self.dir, "b\nERROR forged two", "lwt_nlb", "nlb", prelude="raise ImportError('no')")
        with open(os.path.join(base, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(f'[project]\nname = "x"\nversion = "1"\n\n[project.entry-points."{GROUP}"]\n'
                    'nlb = "lwt_nlb.connector:Conn"\n')
        self.use_dir()
        with self.assertLogs(LOG, "WARNING") as logs:
            problems = self.cfg(FW1_ENV).validate()
        # a logged import failure carries its traceback (with the file path) after the message
        texts = [t.split("\nTraceback ")[0] for t in logs.output] + problems + list(broken_types().values())
        self.assertFalse([t for t in texts if "\n" in t], texts)
        self.assertIn("LW_CONNECTORS_DIR a ERROR forged entry: pyproject.toml cannot be read (TOMLDecodeError)",
                      problems)
        self.assertIn("LW_CONNECTORS_DIR b ERROR forged two", broken_types()["nlb"])


class TestStatsOwnInt(unittest.TestCase):
    def test_int_subclass_own_int_is_not_called(self):
        class I(int):
            def __int__(self) -> int:
                return 99

        out = _report_stats({"x": I(4), "flag": True})
        self.assertEqual(out, {"x": 4, "flag": 1})
        self.assertIs(type(out["x"]), int)


if __name__ == "__main__":
    unittest.main()
