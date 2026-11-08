"""The read-only second login (AUTH_RO_USER + AUTH_RO_PASSWORD_HASH): it reads, every write gets 403, the meta and
the ETag say it may not write, and it shares the Verifier's CPU cap and cache with the main login."""
import hashlib
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import test_web  # noqa: E402
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from test_basic_auth import FAST, GOOD, HASH, HASH_MSG, PASSWORD, USER, basic  # noqa: E402
from test_web import MAC2, WebTestCase  # noqa: E402
from leasewatch import auth  # noqa: E402
from leasewatch.config import Config  # noqa: E402

RO_USER = "family"
RO_PASSWORD = "look but do not touch"
RO_HASH = auth.make_hash(RO_PASSWORD, 100_000)
RO_FAST = (1000, b"r" * 16, hashlib.pbkdf2_hmac("sha256", RO_PASSWORD.encode(), b"r" * 16, 1000))
RO_GOOD = basic(RO_USER, RO_PASSWORD)
CT = {"Content-Type": "application/json"}


class VerifierRoleTests(unittest.TestCase):
    def setUp(self):
        self.v = auth.Verifier(USER, FAST, (RO_USER, RO_FAST))
        quiet = mock.patch.object(auth, "log")  # the failed-login line is tested in test_basic_auth
        quiet.start()
        self.addCleanup(quiet.stop)

    def test_roles(self):
        self.assertEqual(self.v.check(GOOD), "rw")
        self.assertEqual(self.v.check(RO_GOOD), "ro")
        self.assertIsNone(self.v.check(basic(RO_USER, PASSWORD)))  # the other login's password
        self.assertIsNone(self.v.check(basic(USER, RO_PASSWORD)))
        self.assertIsNone(self.v.check(basic("bob", RO_PASSWORD)))
        self.assertIsNone(self.v.check(None))
        self.assertEqual(auth.Verifier(USER, FAST).check(GOOD), "rw")  # one pair: as before, a truthy answer

    def test_cache_keeps_roles_apart(self):
        with mock.patch("hashlib.pbkdf2_hmac", wraps=hashlib.pbkdf2_hmac) as kdf:
            for _ in range(2):
                self.assertEqual(self.v.check(RO_GOOD), "ro")
                self.assertEqual(self.v.check(GOOD), "rw")
        self.assertEqual(kdf.call_count, 2)  # one per login, the second round from the cache
        self.assertEqual(len(self.v._cache), 2)
        self.assertEqual(sorted(role for _, role in self.v._cache.values()), ["ro", "rw"])

    def test_every_name_compared_one_pbkdf2(self):
        for header in (RO_GOOD, basic("bob", PASSWORD)):
            with self.subTest(header=header), mock.patch("hmac.compare_digest", wraps=auth.hmac.compare_digest) as cd, \
                    mock.patch("hashlib.pbkdf2_hmac", wraps=hashlib.pbkdf2_hmac) as kdf:
                self.v.check(header)
                names = [c for c in cd.call_args_list if c.args[1] in (USER.encode(), RO_USER.encode())]
                self.assertEqual(len(names), 2)  # both names, also after the first matched
                self.assertEqual(kdf.call_count, 1)

    def test_busy_bound_shared(self):
        self.v._sem.acquire()
        self.v._sem.acquire()
        try:
            with mock.patch.object(auth, "BUSY_TIMEOUT", 0.05):
                for header in (GOOD, RO_GOOD):
                    with self.subTest(header=header), self.assertRaises(auth.Busy):
                        self.v.check(header)
        finally:
            self.v._sem.release()
            self.v._sem.release()
        self.assertEqual(self.v.check(RO_GOOD), "ro")


class RoConfigTests(unittest.TestCase):
    MAIN = {"AUTH_USER": USER, "AUTH_PASSWORD_HASH": HASH}

    def cfg(self, **env):
        saved = clean_env({**FW1_ENV, **env})
        try:
            return Config()
        finally:
            restore(saved)

    def auth_problems(self, **env):
        return [p for p in self.cfg(**env).validate() if "AUTH" in p]

    def test_ro_on(self):
        c = self.cfg(**self.MAIN, AUTH_RO_USER=RO_USER, AUTH_RO_PASSWORD_HASH=RO_HASH)
        self.assertTrue(c.auth_ro_enabled)
        self.assertNotIn(RO_HASH, repr(c))
        self.assertEqual(self.auth_problems(**self.MAIN, AUTH_RO_USER=RO_USER, AUTH_RO_PASSWORD_HASH=RO_HASH), [])

    def test_ro_needs_main(self):
        self.assertEqual(self.auth_problems(AUTH_RO_USER=RO_USER, AUTH_RO_PASSWORD_HASH=RO_HASH),
                         ["AUTH_RO_USER needs AUTH_USER"])
        self.assertFalse(self.cfg(AUTH_RO_USER=RO_USER, AUTH_RO_PASSWORD_HASH=RO_HASH).auth_ro_enabled)

    def test_ro_hash_needs_the_same_iterations(self):
        other = auth.make_hash("pw", auth.MIN_ITERATIONS + 1)
        self.assertEqual(auth.parse_hash(HASH)[0], auth.parse_hash(RO_HASH)[0])
        self.assertEqual(self.auth_problems(**self.MAIN, AUTH_RO_USER=RO_USER, AUTH_RO_PASSWORD_HASH=other),
                         ["AUTH_RO_PASSWORD_HASH must use the same iteration count as AUTH_PASSWORD_HASH"])

    def test_ro_name_must_differ(self):
        self.assertEqual(self.auth_problems(**self.MAIN, AUTH_RO_USER=USER, AUTH_RO_PASSWORD_HASH=RO_HASH),
                         ["AUTH_RO_USER must differ from AUTH_USER"])

    def test_ro_both_or_neither_and_format(self):
        msg = ["AUTH_RO_USER and AUTH_RO_PASSWORD_HASH must be set together"]
        self.assertEqual(self.auth_problems(**self.MAIN, AUTH_RO_USER=RO_USER), msg)
        self.assertEqual(self.auth_problems(**self.MAIN, AUTH_RO_PASSWORD_HASH=RO_HASH), msg)
        bad = "pbkdf2_sha256:99999:" + RO_HASH.split(":", 2)[2]
        problems = self.auth_problems(**self.MAIN, AUTH_RO_USER=RO_USER, AUTH_RO_PASSWORD_HASH=bad)
        self.assertEqual(problems, [HASH_MSG.replace("AUTH_", "AUTH_RO_", 1)])
        self.assertEqual(self.auth_problems(**self.MAIN, AUTH_RO_USER="a:b", AUTH_RO_PASSWORD_HASH=RO_HASH),
                         ["AUTH_RO_USER must not contain ':' or control characters"])


class RoLoginWebTests(WebTestCase):
    """The HTTP suite's server with both logins on."""

    def setUp(self):
        with mock.patch.dict(test_web.ENV, AUTH_USER=USER, AUTH_PASSWORD_HASH=HASH, AUTH_RO_USER=RO_USER,
                             AUTH_RO_PASSWORD_HASH=RO_HASH):
            super().setUp()

    @staticmethod
    def creds(header, extra=None):
        return {**(extra or {}), "Authorization": header}

    def test_ro_reads_but_may_not_write(self):
        st, _, body = self.req("GET", "/api/devices", headers=self.creds(RO_GOOD))
        self.assertEqual(st, 200)
        self.assertIs(json.loads(body)["meta"]["can_write"], False)
        self.assertIs(json.loads(body)["meta"]["read_only"], False)
        st, _, body = self.req("POST", f"/api/devices/{MAC2}", body=json.dumps({"note": "x"}).encode(),
                               headers=self.creds(RO_GOOD, CT))
        self.assertEqual((st, json.loads(body)), (403, {"error": "read-only"}))
        self.assertEqual(self.db.device_detail(MAC2)["device"]["note"], "")

    def test_rw_still_writes(self):
        st, _, body = self.req("GET", "/api/devices", headers=self.creds(GOOD))
        self.assertIs(json.loads(body)["meta"]["can_write"], True)
        st, _, body = self.req("POST", f"/api/devices/{MAC2}", body=json.dumps({"note": "hi"}).encode(),
                               headers=self.creds(GOOD, CT))
        self.assertEqual(st, 200, body)
        self.assertEqual(json.loads(body)["device"]["note"], "hi")

    def test_wrong_or_missing_credentials(self):
        for h in ({}, self.creds(basic(RO_USER, "x")), self.creds(basic(RO_USER, PASSWORD))):
            with self.subTest(h=h):
                st, _, body = self.req("GET", "/api/stats", headers=h)
                self.assertEqual((st, json.loads(body)), (401, {"error": "authentication required"}))

    def test_etag_differs_per_role(self):
        st, rw, _ = self.req("GET", "/api/devices", headers=self.creds(GOOD))
        st2, ro, _ = self.req("GET", "/api/devices", headers=self.creds(RO_GOOD))
        self.assertEqual((st, st2), (200, 200))
        self.assertNotEqual(rw["ETag"], ro["ETag"])
        st, _, _ = self.req("GET", "/api/devices", headers=self.creds(RO_GOOD, {"If-None-Match": rw["ETag"]}))
        self.assertEqual(st, 200)  # no shared 304
        st, _, _ = self.req("GET", "/api/devices", headers=self.creds(RO_GOOD, {"If-None-Match": ro["ETag"]}))
        self.assertEqual(st, 304)

    def test_meta_carries_the_role_and_the_etag_the_role_bit(self):
        _, rw, body_rw = self.req("GET", "/api/devices", headers=self.creds(GOOD))
        _, ro, body_ro = self.req("GET", "/api/devices", headers=self.creds(RO_GOOD))
        self.assertEqual(json.loads(body_ro)["meta"]["role"], "ro")
        self.assertEqual(json.loads(body_rw)["meta"]["role"], "rw")
        self.assertFalse(json.loads(body_ro)["meta"]["can_write"])
        # a blocked rw client has can_write false too: the tag still differs from the ro login's
        w = self.srv.RequestHandlerClass
        with mock.patch.object(w, "_can_write", return_value=False):
            _, blocked, _ = self.req("GET", "/api/devices", headers=self.creds(GOOD))
        self.assertNotEqual(blocked["ETag"], ro["ETag"])

    def test_busy_gives_503_for_ro(self):
        v = self.srv.RequestHandlerClass.verifier
        v._sem.acquire()
        v._sem.acquire()
        try:
            with mock.patch.object(auth, "BUSY_TIMEOUT", 0.05):
                st, _, body = self.req("GET", "/api/devices", headers=self.creds(RO_GOOD))
        finally:
            v._sem.release()
            v._sem.release()
        self.assertEqual((st, json.loads(body)), (503, {"error": "busy"}))


if __name__ == "__main__":
    unittest.main()
