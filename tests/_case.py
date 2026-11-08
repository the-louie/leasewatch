"""Shared test base: a clean environment and a temporary DATA_DIR per test, restored and removed afterwards."""
import tempfile
import unittest

from _env import FW1_ENV, clean_env, restore


class EnvTmpCase(unittest.TestCase):
    """setUp: a TemporaryDirectory as DATA_DIR and a clean environment built from ENV; both undone by addCleanup
    (LIFO, after tearDown), so a tearDown that closes a Database still runs before the directory goes."""
    ENV: dict = FW1_ENV

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = clean_env({**self.ENV, "DATA_DIR": self.tmp.name})
        self.addCleanup(restore, self._saved)
        self.addCleanup(self.tmp.cleanup)
