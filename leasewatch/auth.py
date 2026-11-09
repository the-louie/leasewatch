"""Optional HTTP basic auth (AUTH_USER + AUTH_PASSWORD_HASH, and a read-only AUTH_RO_USER), and read-only Bearer
tokens (AUTH_TOKENS): the PBKDF2 hash format and the per-request check."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import re
import secrets
import threading
import time
from collections import OrderedDict

log = logging.getLogger("leasewatch.auth")

SCHEME = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000
# floor: fewer is weak; cap: a typo must not make each login take minutes
MIN_ITERATIONS, MAX_ITERATIONS = 100_000, 10_000_000
MAX_HEADER = 4096
CACHE_TTL = 600.0
CACHE_MAX = 32
BUSY_TIMEOUT = 10.0  # seconds a request waits for a PBKDF2 slot before it gets 503
FAIL_LOG_EVERY = 60.0
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
# AUTH_TOKENS entries: name:<SHA-256 of the token, lowercase hex>
TOKEN_NAME_RE = re.compile(r"[a-z0-9_-]{1,32}")
TOKEN_HASH_RE = re.compile(r"[0-9a-f]{64}")


class Busy(Exception):
    """Every PBKDF2 slot stayed taken for BUSY_TIMEOUT seconds."""


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    if not _B64URL.fullmatch(s):  # urlsafe_b64decode itself would skip characters outside the alphabet
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_hash(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """An AUTH_PASSWORD_HASH value: pbkdf2_sha256:<iterations>:<salt>:<hash>, salt 16 random bytes, hash 32 bytes."""
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError("iterations out of range")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{SCHEME}:{iterations}:{_b64e(salt)}:{_b64e(dk)}"


def parse_hash(s: str) -> tuple[int, bytes, bytes] | None:
    """(iterations, salt, derived key) of a valid AUTH_PASSWORD_HASH, else None."""
    parts = (s or "").split(":")
    if len(parts) != 4 or parts[0] != SCHEME or not re.fullmatch(r"[0-9]{1,9}", parts[1]):  # ASCII digits only
        return None
    iterations = int(parts[1])
    try:
        salt, dk = _b64d(parts[2]), _b64d(parts[3])
    except (ValueError, binascii.Error):
        return None
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS or len(salt) < 8 or len(dk) != 32:
        return None
    # a non-canonical encoding (trailing bits set) would decode to the same bytes; only make_hash's form is valid
    if _b64e(salt) != parts[2] or _b64e(dk) != parts[3]:
        return None
    return iterations, salt, dk


def parse_basic(header: str | None) -> tuple[str, str] | None:
    """(user, password) from an `Authorization: Basic ...` header (RFC 7617), else None."""
    # ASCII only: str.strip() also drops non-ASCII blanks (0xA0, 0x85), and a header like that is a failed login
    if not header or len(header) > MAX_HEADER or not header.isascii():
        return None
    scheme, _, token = header.strip().partition(" ")
    if not scheme.isascii() or scheme.lower() != "basic":
        return None
    try:
        raw = base64.b64decode(token.strip(), validate=True)
        text = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):  # binascii.Error and a non-ASCII token are ValueErrors
        return None
    user, sep, password = text.partition(":")
    return (user, password) if sep else None


class Verifier:
    """Checks the Authorization header of a request against AUTH_USER and the parsed AUTH_PASSWORD_HASH, and the
    optional read-only pair AUTH_RO_USER and AUTH_RO_PASSWORD_HASH. Both pairs share one CPU cap and one cache.
    A Bearer token (AUTH_TOKENS, read-only) costs one SHA-256 and uses neither."""

    def __init__(self, user: str, parsed_hash: tuple[int, bytes, bytes],
                 ro: tuple[str, tuple[int, bytes, bytes]] | None = None,
                 tokens: list[tuple[str, str]] | tuple = ()) -> None:
        # (user, iterations, salt, derived key, role); the read-write pair first
        self._entries = [(user.encode("utf-8"), *parsed_hash, "rw")]
        if ro is not None:
            self._entries.append((ro[0].encode("utf-8"), *ro[1], "ro"))
        # (name, SHA-256 of the token); validate() checked the hex
        self._tokens = [(name, bytes.fromhex(digest)) for name, digest in tokens]
        # CPU cap: a password-guessing burst must not pin every core with PBKDF2
        self._sem = threading.BoundedSemaphore(2)
        # success cache, state of this verifier (one per server): HMAC of the header under a key of this process ->
        # (monotonic expiry, role). The key is the whole header, so the two logins never share an entry. Keyed by an HMAC so the memory never holds the header itself. No invalidation needed:
        # a new password means a new env var and a restart
        self._cache_key = secrets.token_bytes(32)
        self._cache: OrderedDict[bytes, tuple[float, str]] = OrderedDict()
        self._lock = threading.Lock()
        # failed attempts since the last log line (at most one line per FAIL_LOG_EVERY)
        self._fails = 0
        self._fail_client = ""
        self._fail_logged = float("-inf")
        self._fail_timer: threading.Timer | None = None

    def check(self, header: str | None, client: str = "") -> str | None:
        """The role of the login in the header ("rw" or "ro"), else None. Raises Busy when no PBKDF2 slot frees up."""
        if header and header[:7].lower() == "bearer ":
            return self._check_token(header[7:], client)
        creds = parse_basic(header)
        if creds is None:
            if header:
                self._failed(client)
            return None
        # parse_basic accepted it, so the header is ASCII (it refuses any other)
        key = hmac.new(self._cache_key, header.encode("ascii"), hashlib.sha256).digest()
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None and hit[0] > now:
                return hit[1]
        user, password = creds
        name = user.encode("utf-8")
        # every name is compared (no early exit); an unknown name is checked against the first pair, so the answer
        # time says nothing about which names exist (the hashes of hash-password share one iteration count)
        entry, user_ok = self._entries[0], False
        for e in self._entries:
            if hmac.compare_digest(name, e[0]) and not user_ok:
                entry, user_ok = e, True
        _, iterations, salt, want, role = entry
        if not self._sem.acquire(timeout=BUSY_TIMEOUT):
            raise Busy
        try:
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        finally:
            self._sem.release()
        ok = user_ok & hmac.compare_digest(dk, want)
        if not ok:
            self._failed(client)
            return None
        with self._lock:
            self._cache.pop(key, None)
            self._cache[key] = (time.monotonic() + CACHE_TTL, role)
            while len(self._cache) > CACHE_MAX:
                self._cache.popitem(last=False)
        return role

    def _check_token(self, token: str, client: str) -> str | None:
        # a random 32-byte token needs no slow hash: one SHA-256 per request, so no cache and no CPU cap
        if not token or len(token) > MAX_HEADER or not token.isascii():
            self._failed(client)
            return None
        digest = hashlib.sha256(token.encode("ascii")).digest()
        ok = False
        for _, want in self._tokens:  # every entry (no early exit): the answer time says nothing about which matched
            ok = hmac.compare_digest(digest, want) | ok
        if not ok:
            self._failed(client)
            return None
        return "ro"

    def _failed(self, client: str) -> None:
        # no lockout (anyone could lock the owner out); the address only, never the user name or password
        with self._lock:
            self._fails += 1
            self._fail_client = client
            wait = self._fail_logged + FAIL_LOG_EVERY - time.monotonic()
            if wait > 0:
                # the first one held back: a burst that ends inside the window must still reach the log
                if self._fails == 1:
                    t = threading.Timer(wait + 0.05, self._report_fails)
                    t.daemon = True
                    t.start()
                    self._fail_timer = t  # kept so flush() can stop it
                return
        self._report_fails()

    def flush(self) -> None:
        """Log the held-back failed attempts now. Called at shutdown: the daemon timer dies with the process.
        Idempotent: a second call finds nothing pending."""
        with self._lock:
            t, self._fail_timer = self._fail_timer, None
        if t is not None:
            t.cancel()
        self._report_fails(force=True)

    def _report_fails(self, force: bool = False) -> None:
        with self._lock:
            n, client, now = self._fails, self._fail_client, time.monotonic()
            # nothing pending, or a newer window has its own timer
            if not n or (not force and now - self._fail_logged < FAIL_LOG_EVERY):
                return
            self._fails, self._fail_logged = 0, now
        log.warning("auth: %d failed attempt%s since the last report, last from %s", n, "" if n == 1 else "s",
                    client or "?")
