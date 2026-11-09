"""Read-only API tokens (AUTH_TOKENS, Authorization: Bearer): config parsing and problems, the Verifier's token
branch, the HTTP answers (read, 403 on a write, 401, the ETag write bit), `make-token` and the start line."""
import base64
import hashlib
import io
import json
import os
import re
import secrets
import sys
import unittest
from unittest import mock

import test_web
from _case import EnvTmpCase
from test_basic_auth import FAST, GOOD, HASH, PASSWORD, USER
from test_readonly_login import CT, RO_GOOD, RO_HASH, RO_USER
from test_web import MAC2, WebTestCase
from leasewatch import __main__ as cli
from leasewatch import auth
from leasewatch.config import Config


def new_token() -> tuple[str, str]:
    """A fresh token and its SHA-256 hex, made in the test."""
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


TOKEN, TOKEN_HASH = new_token()
OTHER, OTHER_HASH = new_token()
MAIN = {"AUTH_USER": USER, "AUTH_PASSWORD_HASH": HASH}


class TokenConfigTests(EnvTmpCase):
    def cfg(self, **env):
        os.environ.update(env)  # EnvTmpCase restores the environment
        return Config()

    def problems(self, **env):
        return [p for p in self.cfg(**env).validate() if "AUTH" in p]

    def test_entries_parsed_blanks_skipped(self):
        c = self.cfg(**MAIN, AUTH_TOKENS=f" ha:{TOKEN_HASH} ,, mon-1 : {OTHER_HASH},")
        self.assertEqual(c.auth_token_entries, [("ha", TOKEN_HASH), ("mon-1", OTHER_HASH)])
        self.assertEqual(self.problems(**MAIN, AUTH_TOKENS=f"ha:{TOKEN_HASH},mon-1:{OTHER_HASH}"), [])
        self.assertEqual(self.cfg(AUTH_TOKENS=" , ").auth_token_entries, [])
        self.assertEqual(self.problems(AUTH_TOKENS=" , "), [])

    def test_repr_has_no_hash(self):
        self.assertNotIn(TOKEN_HASH, repr(self.cfg(**MAIN, AUTH_TOKENS=f"ha:{TOKEN_HASH}")))

    def test_needs_auth_user(self):
        self.assertEqual(self.problems(AUTH_TOKENS=f"ha:{TOKEN_HASH}"), ["AUTH_TOKENS needs AUTH_USER"])

    def test_no_colon(self):
        p = self.problems(**MAIN, AUTH_TOKENS=f"ha:{TOKEN_HASH},{OTHER_HASH}")
        self.assertEqual(p, ["AUTH_TOKENS entry 2 has no ':' (name:hash from python -m leasewatch make-token)"])

    def test_bad_names(self):
        msg = "AUTH_TOKENS entry 1: the name must be 1-32 characters of a-z, 0-9, _ and -"
        for name in ("", "Ha", "h a", "x" * 33, "hä"):
            with self.subTest(name=name):
                self.assertEqual(self.problems(**MAIN, AUTH_TOKENS=f"{name}:{TOKEN_HASH}"), [msg])

    def test_duplicate_name(self):
        self.assertEqual(self.problems(**MAIN, AUTH_TOKENS=f"ha:{TOKEN_HASH},ha:{OTHER_HASH}"),
                         ["AUTH_TOKENS: the name ha is used more than once"])

    def test_bad_hash_not_echoed(self):
        msg = ("AUTH_TOKENS entry ha is not a valid hash (64 lowercase hex characters; make one with "
               "python -m leasewatch make-token)")
        for digest in (TOKEN_HASH.upper(), TOKEN_HASH[:-1], TOKEN_HASH + "0", "", TOKEN):
            with self.subTest(digest=digest):
                p = self.problems(**MAIN, AUTH_TOKENS=f"ha:{digest}")
                self.assertEqual(p, [msg])
                if digest:
                    self.assertNotIn(digest, " ".join(p))


class VerifierTokenTests(unittest.TestCase):
    def setUp(self):
        self.v = auth.Verifier(USER, FAST, None, [("ha", TOKEN_HASH), ("mon", OTHER_HASH)])
        quiet = mock.patch.object(auth, "log")  # the failed-login line is tested in test_basic_auth
        quiet.start()
        self.addCleanup(quiet.stop)

    def test_token_is_ro(self):
        with mock.patch("hashlib.pbkdf2_hmac") as kdf:
            self.assertEqual(self.v.check("Bearer " + TOKEN), "ro")
            self.assertEqual(self.v.check("bEARER " + OTHER), "ro")
        kdf.assert_not_called()
        self.assertEqual(self.v._cache, {})

    def test_every_entry_compared(self):
        with mock.patch("hmac.compare_digest", wraps=auth.hmac.compare_digest) as cd:
            self.v.check("Bearer " + TOKEN)  # the first entry matches; the second is still compared
        self.assertEqual(cd.call_count, 2)

    def test_wrong_tokens_fail(self):
        pw = "Bearer " + PASSWORD
        bad = ("Bearer " + TOKEN[:-1], "Bearer " + TOKEN + "x", "Bearer ", "Bearer  " + TOKEN, "Bearer " + TOKEN_HASH,
               "Bearer tökén", pw, "Bearer " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode())
        for header in bad:
            with self.subTest(header=header), mock.patch.object(self.v, "_failed") as failed:
                self.assertIsNone(self.v.check(header, "10.0.0.9"))
                failed.assert_called_once_with("10.0.0.9")

    def test_no_tokens_configured(self):
        v = auth.Verifier(USER, FAST)
        with mock.patch.object(v, "_failed") as failed:
            self.assertIsNone(v.check("Bearer " + TOKEN, "10.0.0.9"))
        failed.assert_called_once_with("10.0.0.9")

    def test_basic_still_works(self):
        self.assertEqual(self.v.check(GOOD), "rw")


class TokenWebTests(WebTestCase):
    """The HTTP suite's server with the main login, the read-only login and one token."""

    def setUp(self):
        with mock.patch.dict(test_web.ENV, AUTH_USER=USER, AUTH_PASSWORD_HASH=HASH, AUTH_RO_USER=RO_USER,
                             AUTH_RO_PASSWORD_HASH=RO_HASH, AUTH_TOKENS=f"ha:{TOKEN_HASH}"):
            super().setUp()

    @staticmethod
    def creds(header, extra=None):
        return {**(extra or {}), "Authorization": header}

    def test_token_reads_but_may_not_write(self):
        st, _, body = self.req("GET", "/api/devices", headers=self.creds("Bearer " + TOKEN))
        self.assertEqual(st, 200)
        self.assertIs(json.loads(body)["meta"]["can_write"], False)
        self.assertEqual(json.loads(body)["meta"]["role"], "ro")
        st, _, body = self.req("POST", f"/api/devices/{MAC2}", body=json.dumps({"note": "x"}).encode(),
                               headers=self.creds("Bearer " + TOKEN, CT))
        self.assertEqual((st, json.loads(body)), (403, {"error": "read-only"}))
        self.assertEqual(self.db.device_detail(MAC2)["device"]["note"], "")

    def test_wrong_token_401_basic(self):
        for h in ("Bearer " + OTHER, "Bearer " + TOKEN_HASH):
            with self.subTest(h=h):
                st, hd, body = self.req("GET", "/api/devices", headers=self.creds(h))
                self.assertEqual((st, json.loads(body)), (401, {"error": "authentication required"}))
                self.assertTrue(hd["WWW-Authenticate"].startswith("Basic "))

    def test_etag_matches_the_ro_login(self):
        _, tok, _ = self.req("GET", "/api/devices", headers=self.creds("Bearer " + TOKEN))
        _, ro, _ = self.req("GET", "/api/devices", headers=self.creds(RO_GOOD))
        _, rw, _ = self.req("GET", "/api/devices", headers=self.creds(GOOD))
        self.assertEqual(tok["ETag"], ro["ETag"])
        self.assertNotEqual(tok["ETag"], rw["ETag"])
        st, _, _ = self.req("GET", "/api/devices", headers=self.creds("Bearer " + TOKEN, {"If-None-Match": ro["ETag"]}))
        self.assertEqual(st, 304)


class MakeTokenCliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            rc = cli.main(["make-token", *argv])
        return rc, out.getvalue(), err.getvalue()

    def test_prints_token_and_entry(self):
        rc, out, err = self.run_cli("home-assistant")
        self.assertEqual(rc, 0, err)
        self.assertIn("make-token", cli.SUBCOMMANDS)
        self.assertRegex(out, r"\A[A-Za-z0-9_-]{43}\n\Z")
        token = out.strip()
        m = re.search(r"^AUTH_TOKENS entry: home-assistant:([0-9a-f]{64})$", err, re.M)
        self.assertIsNotNone(m, err)
        self.assertNotIn(token, err)
        self.assertEqual(len(err.splitlines()), 2)
        v = auth.Verifier(USER, FAST, None, [("home-assistant", m.group(1))])
        self.assertEqual(v.check("Bearer " + token), "ro")

    def test_tokens_differ(self):
        self.assertNotEqual(self.run_cli("a")[1], self.run_cli("a")[1])

    def test_bad_name(self):
        for name in ("Big", "a b", "x" * 33, ""):
            with self.subTest(name=name):
                rc, out, err = self.run_cli(name)
                self.assertEqual((rc, out), (1, ""))
                self.assertIn("NAME must be 1-32 characters", err)


class StartupLineTests(EnvTmpCase):
    def test_token_count_no_names(self):
        os.environ.update(MAIN, AUTH_TOKENS=f"secret-name:{TOKEN_HASH}")
        line = cli.startup_line(Config(), "1.5.0")
        self.assertIn("; auth tokens: 1", line)
        self.assertNotIn("secret-name", line)
        self.assertNotIn(TOKEN_HASH, line)

    def test_no_tokens_no_mention(self):
        self.assertNotIn("auth tokens", cli.startup_line(Config(), "1.5.0"))


if __name__ == "__main__":
    unittest.main()
