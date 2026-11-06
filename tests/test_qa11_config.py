"""Regression tests for config.py: host normalisation, LW_CONNECTOR__ parsing, URL checks and env helpers."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _env import clean_env, restore
from leasewatch.config import Config, _env_int, _host_only, parse_instances

FW = {"LW_CONNECTORS": "fw1", "LW_CONNECTOR__FW1__TYPE": "opnsense", "LW_CONNECTOR__FW1__URL": "https://10.0.0.1",
      "LW_CONNECTOR__FW1__KEY": "k" * 8, "LW_CONNECTOR__FW1__SECRET": "s" * 8}
BASE = FW


class QaConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = clean_env(BASE)

    def tearDown(self) -> None:
        restore(self._saved)

    def cfg(self, **env: str) -> Config:
        os.environ.update(env)
        return Config()

    # R21: a non-ASCII entry must match the punycode Host a browser sends
    def test_idn_entry_matches_punycode_host(self) -> None:
        c = self.cfg(ALLOWED_HOSTS="BÜCHER.example")
        self.assertTrue(c.host_allowed("xn--bcher-kva.example"))
        self.assertFalse(c.host_allowed("other.example"))

    def test_idn_public_url_matches_punycode_host(self) -> None:
        c = self.cfg(PUBLIC_URL="https://bücher.example/")
        self.assertTrue(c.host_allowed("xn--bcher-kva.example:443"))

    # R22: only the literal "*" turns the Host check off
    def test_wildcard_lookalikes_do_not_disable_host_check(self) -> None:
        for v in ("*.", "*:80"):
            c = self.cfg(ALLOWED_HOSTS=v, PUBLIC_URL="http://lw.example.lan/")
            self.assertFalse(c.host_allowed("evil.example.com"), v)
            self.assertTrue(any("ALLOWED_HOSTS" in p for p in c.validate()), v)
        self.assertTrue(self.cfg(ALLOWED_HOSTS="*").host_allowed("evil.example.com"))

    # R120: an entry without a host must not replace the PUBLIC_URL default, and is reported
    def test_degenerate_entry_keeps_public_url_default(self) -> None:
        for v in (".", ":80", "[]"):
            c = self.cfg(ALLOWED_HOSTS=v, PUBLIC_URL="http://lw.example.lan/")
            self.assertTrue(c.host_allowed("lw.example.lan"), v)
            self.assertIn("ALLOWED_HOSTS: an entry has no host name", c.validate())

    # R122: a stray empty entry must not let an empty normalised Host through
    def test_empty_entry_does_not_match_empty_host(self) -> None:
        c = self.cfg(ALLOWED_HOSTS="leases.example.lan,:8443")
        for h in (":80", "[]", ".", "[]:1"):
            self.assertFalse(c.host_allowed(h), h)
        self.assertTrue(c.host_allowed("leases.example.lan"))

    # R23: LW_CONNECTOR__<NAME>_<KEY> (one underscore) or an empty key is reported, not dropped
    def test_malformed_connector_variable_reported(self) -> None:
        for var in ("LW_CONNECTOR__FW1_TIMEOUT", "LW_CONNECTOR__FW1__"):
            _, problems = parse_instances({**FW, var: "5"})
            self.assertTrue(any(var in p for p in problems), (var, problems))

    # Z01: an upper-case LW_CONNECTORS entry gets only the invalid-name problem, not a false "not in LW_CONNECTORS"
    def test_upper_case_list_entry_is_only_an_invalid_name(self) -> None:
        _, problems = parse_instances({"LW_CONNECTORS": "FW1", "LW_CONNECTOR__FW1__KEY": "x"})
        self.assertEqual(problems, ["LW_CONNECTORS: 'FW1' is not a valid instance name (only a-z and 0-9)"])

    # R24: an empty instance name is reported even with a trailing comma in LW_CONNECTORS
    def test_empty_instance_name_reported_with_trailing_comma(self) -> None:
        _, problems = parse_instances({**FW, "LW_CONNECTORS": "fw1,", "LW_CONNECTOR____URL": "https://10.0.0.9"})
        self.assertTrue(any("LW_CONNECTOR____URL" in p for p in problems), problems)

    # R25: LW_CONNECTOR__ variables without LW_CONNECTORS stop the start
    def test_connector_vars_without_list_reported(self) -> None:
        del os.environ["LW_CONNECTORS"]
        c = self.cfg(LW_CONNECTOR__SW1__TYPE="snmp_switch", LW_CONNECTOR__SW1__HOST="10.0.0.2")
        self.assertEqual(c.instances, [])
        p = c.validate()
        self.assertIn("LW_CONNECTOR__SW1__HOST set but sw1 is not in LW_CONNECTORS", p)
        self.assertIn("LW_CONNECTOR__FW1__KEY set but fw1 is not in LW_CONNECTORS", p)
        self.assertTrue(any(x.startswith("LW_CONNECTORS is not set") for x in p), p)

    # R27: the URL scheme is case-insensitive, as urllib treats it
    def test_uppercase_scheme_accepted(self) -> None:
        self.assertEqual(self.cfg(LW_CONNECTOR__FW1__URL="HTTPS://10.0.0.1", PUBLIC_URL="HTTP://lw.example.lan",
                                  MAILGUN_API_BASE="HTTPS://api.example.com").validate(), [])

    # R28: MAILGUN_API_BASE gets the same host check as the other URLs
    def test_mailgun_api_base_host_checked(self) -> None:
        for base in ("https://[api.example.com", "https://:443"):
            self.assertIn("MAILGUN_API_BASE is not a valid URL", self.cfg(MAILGUN_API_BASE=base).validate(), base)

    # R29: a non-numeric or out-of-range port is refused
    def test_bad_port_refused(self) -> None:
        for u in ("https://10.0.0.1:abc", "https://10.0.0.1:99999"):
            self.assertIn("connector fw1 (opnsense): url is not a valid URL", self.cfg(LW_CONNECTOR__FW1__URL=u).validate(), u)
        self.assertEqual(self.cfg(LW_CONNECTOR__FW1__URL="https://10.0.0.1:8443").validate(), [])

    # R30: credentials are refused even when '#', '/' or '?' cut the netloc short
    def test_credentials_with_delimiters_refused(self) -> None:
        for u in ("https://admin:pw#x@10.0.0.1", "https://admin:p/w@10.0.0.1", "https://admin:p?w@10.0.0.1",
                  "https://admin:1234/x@10.0.0.1"):
            self.assertIn("connector fw1 (opnsense): url must not contain credentials", self.cfg(LW_CONNECTOR__FW1__URL=u).validate(), u)
        self.assertIn("PUBLIC_URL must not contain credentials",
                      self.cfg(PUBLIC_URL="https://user:pa/ss@host.example.lan").validate())

    # R116: a set-but-empty integer variable uses the default without a warning
    def test_empty_int_no_warning(self) -> None:
        os.environ["NEW_DAYS"] = ""
        with self.assertNoLogs("leasewatch", "WARNING"):
            self.assertEqual(_env_int("NEW_DAYS", 7), 7)

    # R117 / R119: warnings go to the module's logger
    def test_warnings_on_module_logger(self) -> None:
        os.environ.update(POLL_SECONDS="abc")
        with self.assertLogs("leasewatch.config", "WARNING") as cm:
            self.assertEqual(_env_int("POLL_SECONDS", 120), 120)
        self.assertEqual(len(cm.records), 1)

    # R118: a long junk value is not echoed in full
    def test_long_value_truncated_in_log(self) -> None:
        os.environ["POLL_SECONDS"] = "9" * 5000
        with self.assertLogs("leasewatch", "WARNING") as cm:
            self.assertEqual(_env_int("POLL_SECONDS", 120), 120)
        self.assertLess(len(cm.output[0]), 200)

    # S06x: a UTF-8 BOM in a <KEY>_FILE is not part of the secret
    def test_secret_file_bom_stripped(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "key")
            with open(path, "wb") as f:
                f.write(b"\xef\xbb\xbfabcdefgh\r\n")
            env = {k: v for k, v in FW.items() if k != "LW_CONNECTOR__FW1__KEY"}
            specs, problems = parse_instances({**env, "LW_CONNECTOR__FW1__KEY_FILE": path})
        self.assertEqual(problems, [])
        self.assertEqual(specs[0].settings["key"], "abcdefgh")

    # V04: an "@" in the path or query is not a credential
    def test_at_sign_in_path_or_query_accepted(self) -> None:
        self.assertEqual(self.cfg(PUBLIC_URL="https://lw.example.lan/?x=a@b").validate(), [])
        self.assertEqual(self.cfg(LW_CONNECTOR__FW1__URL="https://fw1.example.lan/api@x").validate(), [])

    # V51: port 0 fails on every request, as url_problems says
    def test_port_zero_refused(self) -> None:
        self.assertIn("connector fw1 (opnsense): url is not a valid URL", self.cfg(LW_CONNECTOR__FW1__URL="https://10.0.0.1:0").validate())
        self.assertIn("PUBLIC_URL is not a valid URL", self.cfg(PUBLIC_URL="https://lw.example.lan:0").validate())

    # V77: spaces and control characters are refused at startup, as in connector mode
    def test_space_and_control_chars_refused(self) -> None:
        for u in ("https://fw 1.example.lan", "https://fw1.example.lan\x01", "https://fw1.example.lan/a b"):
            self.assertIn("connector fw1 (opnsense): url is not a valid URL", self.cfg(LW_CONNECTOR__FW1__URL=u).validate(), repr(u))

    # V50: deviation characters encode as browsers send them (UTS-46 nontransitional), not as IDNA2003 maps them
    def test_deviation_characters_match_browser_punycode(self) -> None:
        self.assertEqual(_host_only("straße.example"), "xn--strae-oqa.example")
        self.assertEqual(_host_only("ς.example"), "xn--3xa.example")
        self.assertTrue(self.cfg(ALLOWED_HOSTS="STRASSE.example,straße.example").host_allowed("xn--strae-oqa.example"))

    # V76: a trailing ideographic or fullwidth full stop is a trailing dot too
    def test_trailing_ideographic_full_stop_stripped(self) -> None:
        for e in ("bücher.example\u3002", "bücher.example\uff0e", "bücher.example\uff61"):
            self.assertEqual(_host_only(e), "xn--bcher-kva.example", repr(e))

    def test_host_only_plain_entries_unchanged(self) -> None:
        self.assertEqual(_host_only("Foo.example:8080"), "foo.example")
        self.assertEqual(_host_only("*"), "*")

    # W05: an upper-case final "Σ" is "σ" to a browser; str.lower() would make it "ς"
    def test_upper_final_sigma_matches_browser(self) -> None:
        self.assertEqual(_host_only("ΟΔΟΣ"), "xn--pxavbq")
        self.assertEqual(_host_only("ΟΔΟΣ:8080"), "xn--pxavbq")
        self.assertEqual(_host_only("οδος"), "xn--pxavbm")  # a literal "ς" is kept

    # W18, W40: characters mapped to nothing (soft hyphen) are removed next to a deviation character too
    def test_soft_hyphen_removed_with_deviation_character(self) -> None:
        self.assertEqual(_host_only("stra\u00adße.example"), "xn--strae-oqa.example")
        self.assertEqual(_host_only("straße\u00ad.example"), "xn--strae-oqa.example")
        self.assertEqual(_host_only("STRAßE.example"), "xn--strae-oqa.example")

    # W30, W31: ZWNJ and ZWJ are deviation characters as well; browsers keep them
    def test_joiners_kept_as_browsers_do(self) -> None:
        self.assertEqual(_host_only("\u0646\u0627\u0645\u0647\u200c\u0627\u06cc.example"), "xn--mgba3gch31f060k.example")
        self.assertEqual(_host_only("\u0928\u092e\u0938\u094d\u200d\u0924\u0947.example"), "xn--h2bhs4b8d8a2905a.example")

    # X13: the bidi rule applies to the whole label, not to the pieces between joiners
    def test_rtl_label_with_digit_before_joiner(self) -> None:
        self.assertEqual(_host_only("\u0646\u0627\u0645\u06471\u200c\u0627\u06cc.example"), "xn--1-ymcb2jdi74gp19l.example")

    # Y03: the text around a deviation character is mapped with Unicode 3.2 as nameprep does: a later NFKC turned
    # U+1D2C into an upper-case "A" that the lower-cased Host header can never match
    def test_post_unicode_3_2_compatibility_character_mapped_as_nameprep(self) -> None:
        entry = _host_only("\u1d2c\u00df.example")
        self.assertEqual(entry, entry.lower())

    # W19: the ":" of an IPv6 literal before an "@" in the path is not a password separator
    def test_at_sign_in_path_after_ipv6_literal_accepted(self) -> None:
        self.assertEqual(self.cfg(PUBLIC_URL="https://[::1]/a@b").validate(), [])
        self.assertIn("PUBLIC_URL must not contain credentials", self.cfg(PUBLIC_URL="https://u:p@[::1]/").validate())

    # an empty user info is refused, a ':' after the first '/', '?' or '#' is not a password (same rule as connector URLs)
    def test_url_credentials_rule_shared_with_connectors(self) -> None:
        self.assertIn("connector fw1 (opnsense): url must not contain credentials", self.cfg(LW_CONNECTOR__FW1__URL="https://@fw1.example.lan").validate())
        self.assertEqual(self.cfg(LW_CONNECTOR__FW1__URL=FW["LW_CONNECTOR__FW1__URL"],
                                  PUBLIC_URL="https://lw.example.lan/?t=10:00&m=a@b").validate(), [])


if __name__ == "__main__":
    unittest.main()
