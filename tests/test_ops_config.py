import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import FW1_ENV, clean_env, restore
from leasewatch.__main__ import startup_line
from leasewatch.config import Config

BASE = "leasewatch 1.1.0.dev0, connectors fw1 (opnsense); poll 120 s; mail off"


class WriteSettingsTests(unittest.TestCase):
    def setUp(self):
        self._saved = clean_env(FW1_ENV)

    def tearDown(self):
        restore(self._saved)

    def cfg(self, **env):
        os.environ.update(env)
        return Config()

    def test_defaults_allow_everyone(self):
        c = self.cfg()
        self.assertEqual(c.validate(), [])
        for a in ("10.0.1.7", "fd00::1", "not an address"):
            self.assertTrue(c.write_allowed(a))
        self.assertEqual(startup_line(c, "1.1.0.dev0"), BASE)

    def test_empty_settings_mean_the_defaults(self):
        c = self.cfg(READ_ONLY="", WRITE_ALLOW="")
        self.assertEqual(c.validate(), [])
        self.assertTrue(c.write_allowed("10.0.1.7"))

    def test_read_only_allows_nobody(self):
        c = self.cfg(READ_ONLY="1", WRITE_ALLOW="10.0.1.0/24")
        self.assertFalse(c.write_allowed("10.0.1.7"))
        self.assertFalse(self.cfg(READ_ONLY="yes", WRITE_ALLOW="").write_allowed("10.0.1.7"))

    def test_read_only_no_is_off(self):
        self.assertTrue(self.cfg(READ_ONLY="no").write_allowed("10.0.1.7"))

    def test_bad_read_only(self):
        self.assertEqual(self.cfg(READ_ONLY="maybe").validate(), ["READ_ONLY must be 1 or 0"])

    def test_list_of_networks_and_addresses(self):
        c = self.cfg(WRITE_ALLOW="10.0.1.0/24, 10.0.2.5")
        self.assertEqual(c.validate(), [])
        self.assertTrue(c.write_allowed("10.0.1.7"))
        self.assertTrue(c.write_allowed("10.0.2.5"))
        self.assertFalse(c.write_allowed("10.0.3.1"))
        self.assertFalse(c.write_allowed("10.0.2.6"))
        self.assertFalse(c.write_allowed("fd00::1"))

    def test_host_bits_are_tolerated(self):
        self.assertTrue(self.cfg(WRITE_ALLOW="10.0.1.9/24").write_allowed("10.0.1.200"))

    def test_ipv6(self):
        c = self.cfg(WRITE_ALLOW="fd00::/64")
        self.assertEqual(c.validate(), [])
        self.assertTrue(c.write_allowed("fd00::1"))
        self.assertFalse(c.write_allowed("fd00:0:0:1::1"))
        self.assertFalse(c.write_allowed("10.0.1.7"))

    def test_mapped_ipv6_is_compared_as_ipv4(self):
        c = self.cfg(WRITE_ALLOW="10.0.1.0/24")
        self.assertTrue(c.write_allowed("::ffff:10.0.1.7"))
        self.assertFalse(c.write_allowed("::ffff:10.0.3.1"))

    def test_unparsable_address_is_refused_when_a_list_is_set(self):
        c = self.cfg(WRITE_ALLOW="10.0.1.0/24")
        for a in ("", "garbage", "10.0.1", "10.0.1.7/24"):
            self.assertFalse(c.write_allowed(a), a)

    def test_empty_entries_and_trailing_comma(self):
        c = self.cfg(WRITE_ALLOW=" ,10.0.1.0/24,, ")
        self.assertEqual(c.validate(), [])
        self.assertTrue(c.write_allowed("10.0.1.7"))
        self.assertFalse(self.cfg(WRITE_ALLOW="10.0.1.0/24,").write_allowed("10.0.3.1"))
        self.assertTrue(self.cfg(WRITE_ALLOW=" , ,").write_allowed("10.0.3.1"))  # no entries = no limit

    def test_bad_entry_is_named_safely(self):
        p = self.cfg(WRITE_ALLOW="10.0.1.0/24, lan, 10.0.1.0/33").validate()
        self.assertEqual(p, ["WRITE_ALLOW: not an address or network: 'lan'",
                             "WRITE_ALLOW: not an address or network: '10.0.1.0/33'"])
        long = self.cfg(WRITE_ALLOW="x" * 500 + "\nINJECT").validate()
        self.assertEqual(len(long), 1)
        self.assertLess(len(long[0]), 120)
        self.assertNotIn("\n", long[0])

    def test_startup_line_variants(self):
        self.assertEqual(startup_line(self.cfg(READ_ONLY="1"), "1.1.0.dev0"), BASE + "; writes off")
        os.environ.pop("READ_ONLY")
        self.assertEqual(startup_line(self.cfg(WRITE_ALLOW="10.0.1.0/24"), "1.1.0.dev0"), BASE + "; writes from 1 network")
        self.assertEqual(startup_line(self.cfg(WRITE_ALLOW="10.0.1.0/24, 10.0.2.5,fd00::/8"), "1.1.0.dev0"),
                         BASE + "; writes from 3 networks")
        line = startup_line(self.cfg(READ_ONLY="1", WRITE_ALLOW="10.0.1.0/24"), "1.1.0.dev0")
        self.assertEqual(line, BASE + "; writes off")
        self.assertNotIn("10.0.1", line)


if __name__ == "__main__":
    unittest.main()
