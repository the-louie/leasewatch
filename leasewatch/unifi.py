"""Wi-Fi details per MAC from a UniFi Network controller (read-only user): a self-hosted classic controller or a
UniFi OS console (UDM, UCG, Cloud Key Gen2+ on UniFi OS, UniFi OS Server), where the same API sits under
/proxy/network.

GET /api/s/<site>/stat/sta gives every active client: ap_mac, essid, channel, radio, signal, is_wired,
and the operator-set alias ("name"). /stat/device maps ap_mac to the AP's name.

The login session is kept between polls; a 401 on a reused session logs in once more and retries once.
"""
from __future__ import annotations

import base64
import http.client
import http.cookiejar
import json
import logging
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .fw1 import MAX_BODY, _NoRedirect, norm_mac

if TYPE_CHECKING:  # only for the annotation: connectors.unifi imports this module
    from .connectors.unifi import _UnifiCfg

log = logging.getLogger("leasewatch.unifi")

TIMEOUT = 20            # seconds per request (module level so tests can shorten it)
LOGOUT_TIMEOUT = 5
RELOGIN_INTERVAL = 60   # at most one login per this many seconds after a successful one (as aiounifi)
_monotonic = time.monotonic  # module level so tests can drive the re-login pacing
# a classic controller's start page on newer standalone builds (older ones redirect / to /manage)
_MANAGE_RE = re.compile(rb"""<base\s+href=["']/manage/["']""", re.IGNORECASE)
# a csrfToken claim must be a plain visible-ASCII token: anything else (CR/LF, non-Latin-1) makes http.client refuse
# the header on every request of a session that is never dropped
_CSRF_RE = re.compile(r"[\x21-\x7e]{1,512}")


class _LoginRequired(Exception):
    """A read answered 401 (or LoginRequired): the session is gone."""


def _jwt_csrf(token: str) -> str:
    """The csrfToken claim of a UniFi OS TOKEN cookie, or "" for anything unexpected. Nothing else is kept."""
    try:
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        v = claims.get("csrfToken") if isinstance(claims, dict) else None
    except (IndexError, ValueError, UnicodeDecodeError, RecursionError):  # binascii.Error is a ValueError
        return ""
    return v if isinstance(v, str) and _CSRF_RE.fullmatch(v) else ""


@dataclass
class WifiInfo:
    ssid: str = ""
    ap: str = ""
    signal: int | None = None   # dBm
    radio: str = ""             # "2.4 GHz" / "5 GHz" / "6 GHz"
    channel: int | None = None
    wired: bool = False         # seen by UniFi as a wired client (behind a UniFi switch/AP port)
    alias: str = ""             # name set in the UniFi controller


RADIO_NAMES = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz", "ac": "5 GHz", "ax": "5 GHz"}


def parse_clients(sta: list[dict], devices: list[dict]) -> dict[str, WifiInfo]:
    """Pure function over the two API payloads (unit-testable)."""
    # a device without a usable MAC must not map "" -> name, or every client without ap_mac would get that AP
    ap_names = {norm_mac(d.get("mac", "")): (d.get("name") or d.get("hostname") or d.get("mac", "")) for d in devices
                if norm_mac(d.get("mac", ""))}
    out: dict[str, WifiInfo] = {}
    for c in sta:
        mac = norm_mac(c.get("mac", ""))
        if not mac:
            continue
        wired = bool(c.get("is_wired"))
        sig = c.get("signal")  # dBm; "rssi" is an SNR-like positive number, not a usable fallback
        # parsed as the merge's _int does ("-61.5", a Unicode minus), so the merge never sees a value it would read
        # differently; a bool is no signal (int(True) would be 1 dBm)
        try:
            sig = None if sig is None or isinstance(sig, bool) else int(float(str(sig).strip().replace("\u2212", "-")))
        except (TypeError, ValueError, OverflowError):
            sig = None
        radio = str(c.get("radio") or "")
        # isdigit() is also true for "²" and int() refuses over 4300 digits: an odd value drops this one field,
        # it must not fail the whole poll
        try:
            channel = int(c["channel"]) if str(c.get("channel", "")).isdigit() else None
        except ValueError:
            channel = None
        out[mac] = WifiInfo(
            ssid="" if wired else str(c.get("essid") or ""),
            ap="" if wired else ap_names.get(norm_mac(c.get("ap_mac", "")), ""),
            signal=None if wired else sig,
            radio="" if wired else RADIO_NAMES.get(radio, radio),
            channel=None if wired else channel,
            wired=wired, alias=str(c.get("name") or ""),
        )
    return out


def parse_integration_clients(clients: list, devices: list, stats: dict | None = None) -> dict[str, WifiInfo]:
    """Pure function over the Integration API client and device lists; it never raises. Only WIRED and WIRELESS rows
    are clients (VPN, TELEPORT and unknown types are skipped, not counted). A WIRED or WIRELESS row with a usable MAC is
    kept whatever its name: a name that is not a usable string gives alias "", since a dropped row would read as a
    device the controller no longer lists. A row that is not a dict, or a WIRED/WIRELESS row without a usable MAC, is
    dropped and counted in stats["dropped"] when stats is given. The API has no SSID, signal, radio or channel, so those
    stay empty. A wired client has no AP (as in parse_clients). A name equal to the client's own MAC is the
    controller's fallback, not an alias. A later row with the same MAC replaces an earlier one."""
    dev_names: dict[str, str] = {}
    for d in devices or []:
        if isinstance(d, dict) and isinstance(d.get("id"), str) and d["id"]:
            name = d.get("name")
            dev_names[d["id"]] = name if isinstance(name, str) else ""
    out: dict[str, WifiInfo] = {}
    dropped = 0
    for c in clients or []:
        if not isinstance(c, dict):
            dropped += 1
            continue
        if c.get("type") not in ("WIRED", "WIRELESS"):
            continue
        raw, name = c.get("macAddress"), c.get("name")
        mac = norm_mac(raw) if isinstance(raw, str) else ""
        if not mac:
            dropped += 1
            continue
        wired = c["type"] == "WIRED"
        up = c.get("uplinkDeviceId")
        name = name.strip() if isinstance(name, str) else ""
        out[mac] = WifiInfo(
            ap="" if wired or not isinstance(up, str) else dev_names.get(up, ""),
            wired=wired, alias="" if not name or norm_mac(name) == mac else name,
        )
    if stats is not None:
        stats["dropped"] = stats.get("dropped", 0) + dropped
    return out


class UnifiClient:
    """One controller session, kept across clients() calls. State (all guarded by _lock, since an abandoned poll
    thread may still run while check() or close() uses the same client):
    _op: the opener holding the session cookie jar, None = no session; _os: the session is a UniFi OS one;
    _csrf: the UniFi OS CSRF token (a secret: never logged); _last_login: monotonic time of the last successful
    login, for the re-login pacing."""

    def __init__(self, cfg: _UnifiCfg):
        self.cfg = cfg
        self._ctx = ssl.create_default_context()
        if not cfg.unifi_verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        self._op: urllib.request.OpenerDirector | None = None
        self._os = False
        self._csrf = ""
        self._last_login: float | None = None
        self._lock = threading.Lock()

    def _opener(self) -> urllib.request.OpenerDirector:
        cj = http.cookiejar.CookieJar()
        # no redirects: a 3xx on the login would carry the password to wherever it points
        handlers = [urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=self._ctx), _NoRedirect()]
        if not self.cfg.lan_proxy:  # the controller is on the LAN: ignore http(s)_proxy unless the instance's proxy setting is set
            handlers.append(urllib.request.ProxyHandler({}))
        op = urllib.request.build_opener(*handlers)
        op.cookiejar = cj  # type: ignore[attr-defined]  # kept on the opener: the UniFi OS CSRF fallback reads TOKEN
        return op

    def _open(self, op: urllib.request.OpenerDirector, path: str, data: bytes | None = None,
              headers: dict[str, str] | None = None, timeout: float | None = None, limit: int = MAX_BODY + 1) -> bytes:
        """One request; on UniFi OS it carries X-CSRF-Token and takes a rotated token from the reply."""
        h = dict(headers or {})
        if self._os and self._csrf:
            h["X-CSRF-Token"] = self._csrf
        req = urllib.request.Request(self.cfg.unifi_url + path, data=data, headers=h, method="POST" if data is not None else "GET")
        try:
            with op.open(req, timeout=TIMEOUT if timeout is None else timeout) as r:
                self._rotate(r.headers)
                return r.read(limit)
        except urllib.error.HTTPError as e:
            self._rotate(e.headers)
            raise

    def _rotate(self, headers: object) -> None:
        new = headers.get("X-Updated-CSRF-Token") if headers is not None else None  # type: ignore[attr-defined]
        if self._os and new:  # email.message headers: the lookup is case-insensitive
            self._csrf = new

    def _detect(self, op: urllib.request.OpenerDirector) -> bool:
        """True for a UniFi OS console: GET / answers 200 with a page that is not the classic /manage app."""
        try:
            with op.open(urllib.request.Request(self.cfg.unifi_url + "/", headers={"Accept": "text/html"}), timeout=TIMEOUT) as r:
                status, body = r.status, r.read(64 * 1024)
        except urllib.error.HTTPError as e:
            e.close()
            if 300 <= e.code < 400:  # the classic controller sends / to /manage
                return False
            raise RuntimeError(f"unifi: cannot detect the controller type (HTTP {e.code}); set PLATFORM") from e
        if status != 200:
            raise RuntimeError(f"unifi: cannot detect the controller type (HTTP {status}); set PLATFORM")
        return not _MANAGE_RE.search(body)

    def _login(self) -> None:
        """A fresh session on a fresh cookie jar; sets _op only when the login succeeded."""
        now = _monotonic()
        if self._last_login is not None and now - self._last_login < RELOGIN_INTERVAL:
            raise RuntimeError("unifi: session expired, re-login deferred")
        if self._last_login is not None:
            log.info("unifi: session expired, logging in again")
        op = self._opener()
        platform = self.cfg.platform
        self._os = self._detect(op) if platform == "auto" else platform == "unifi_os"
        self._csrf = ""
        path = "/api/auth/login" if self._os else "/api/login"
        creds = {"username": self.cfg.unifi_user, "password": self.cfg.unifi_password}
        creds["rememberMe" if self._os else "remember"] = True  # lifetime effect unverified; harmless
        try:
            with op.open(urllib.request.Request(self.cfg.unifi_url + path, data=json.dumps(creds).encode(),
                                                headers={"Content-Type": "application/json"}), timeout=TIMEOUT) as r:
                r.read(MAX_BODY + 1)
                csrf = r.headers.get("X-CSRF-Token") or ""
        except urllib.error.HTTPError as e:
            e.close()
            if 300 <= e.code < 400:
                raise RuntimeError(f"unifi: HTTP {e.code}") from e
            if e.code == 429:
                raise RuntimeError("unifi: login rate-limited (HTTP 429)") from e
            hint = "; check PLATFORM" if e.code == 404 else ""  # the other platform's login path does not exist
            raise RuntimeError(f"unifi: login failed (HTTP {e.code}){hint}") from e
        if self._os and not csrf:
            token = next((c.value for c in op.cookiejar if c.name == "TOKEN"), "")  # type: ignore[attr-defined]
            csrf = _jwt_csrf(token or "")
        self._csrf = csrf if self._os else ""
        self._op, self._last_login = op, now

    def _drop(self) -> None:
        self._op, self._csrf = None, ""

    def _get(self, op: urllib.request.OpenerDirector, path: str) -> list[dict]:
        prefix = "/proxy/network" if self._os else ""
        try:
            raw = self._open(op, prefix + path, headers={"Accept": "application/json"})
        except urllib.error.HTTPError as e:
            if e.code == 401:
                e.close()
                raise _LoginRequired from e
            if e.code == 403 and self._os:
                e.close()
                raise RuntimeError("unifi: HTTP 403 (user lacks Network access?)") from e
            raise
        if len(raw) > MAX_BODY:
            raise RuntimeError("unifi: response too large")
        body = json.loads(raw.decode())
        if not isinstance(body, dict):
            raise RuntimeError("unifi: unexpected response shape")
        meta = body.get("meta")
        if isinstance(meta, dict) and meta.get("rc") == "error" and meta.get("msg") == "api.err.LoginRequired":
            raise _LoginRequired
        if isinstance(meta, dict) and "rc" in meta and meta["rc"] != "ok":
            raise RuntimeError(f"unifi: {meta.get('msg') or 'api error'}")
        data = body.get("data", [])
        if not isinstance(data, list):
            raise RuntimeError("unifi: unexpected response shape")
        return data

    def _read(self) -> dict[str, WifiInfo]:
        op = self._op
        assert op is not None
        site = self.cfg.unifi_site
        sta = self._get(op, f"/api/s/{site}/stat/sta")
        devices = self._get(op, f"/api/s/{site}/stat/device")
        return parse_clients(sta, devices)

    def _clients(self) -> dict[str, WifiInfo]:
        fresh = self._op is None
        if fresh:
            self._login()
        try:
            return self._read()
        except _LoginRequired:
            self._drop()
            if fresh:  # a 401 right after a login is an error, not a reason to loop
                # and that session never worked: the next login is not a re-login, so it is neither paced nor
                # reported as an expired session
                self._last_login = None
                raise RuntimeError("unifi: HTTP 401") from None
        self._login()  # the reused session expired: once more, then one retry
        try:
            return self._read()
        except _LoginRequired:
            self._drop()
            raise RuntimeError("unifi: HTTP 401") from None

    def clients(self) -> dict[str, WifiInfo]:
        """Blocking. Raises RuntimeError on failure; any error but a 401 keeps the session."""
        with self._lock:
            try:
                return self._clients()
            except urllib.error.HTTPError as e:
                e.close()  # the error carries the open response; release its socket
                raise RuntimeError(f"unifi: HTTP {e.code}") from e
            except (urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError, OSError) as e:
                raise RuntimeError(f"unifi: {e}") from e
            except (TypeError, AttributeError, ValueError, OverflowError, RecursionError, http.client.HTTPException) as e:
                # no exception text: an InvalidURL/ValueError can echo the URL, credentials included
                raise RuntimeError("unifi: unexpected response") from e

    def close(self) -> None:
        """Log out (best effort, errors ignored) and forget the session; the next clients() logs in again."""
        with self._lock:
            op = self._op
            if op is not None:
                try:
                    self._open(op, "/api/auth/logout" if self._os else "/api/logout", data=b"", timeout=LOGOUT_TIMEOUT, limit=4096)
                except urllib.error.HTTPError as e:
                    e.close()
                except Exception:
                    pass
            self._drop()
            self._last_login = None  # a deliberate logout: the next login is not a re-login


INTEGRATION_PREFIX = "/proxy/network/integration"  # + /v1/...: the Integration API of a UniFi OS console
PAGE_LIMIT = 200   # the API's maximum page size
MAX_PAGES = 50     # per list read; past this the read stops with a warning (10 000 rows at PAGE_LIMIT)
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


class _NotFound(RuntimeError):
    """An Integration API read answered 404."""


def _count(v: object) -> int | None:
    """A non-negative int envelope field, or None (a bool is no count)."""
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


class UnifiKeyClient:
    """The Integration API of a UniFi OS console with an API key (AUTH=apikey). Stateless apart from the resolved site
    id: no session, no cookies, no login. The key is sent as X-API-KEY on every request and appears in no error text,
    log line or repr. The error body is never parsed or echoed: errors come from the HTTP status only."""

    def __init__(self, url: str, site: str, api_key: str, verify_tls: bool = True, proxy: bool = False,
                 timeout: float | None = None) -> None:
        self.url = url
        self.site = site
        self._key = api_key
        self.timeout = timeout  # None: the module TIMEOUT at call time
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        # no cookie jar and no redirects: a 3xx would carry the key to wherever it points
        handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=self._ctx), _NoRedirect()]
        if not proxy:  # the console is on the LAN: ignore http(s)_proxy unless the instance's proxy setting is set
            handlers.append(urllib.request.ProxyHandler({}))
        self._op = urllib.request.build_opener(*handlers)
        self._site_cache: str | None = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"UnifiKeyClient(site={self.site!r})"

    def _get(self, path: str) -> dict:
        """One GET of /v1/...; the body is capped at MAX_BODY and must be a JSON object."""
        req = urllib.request.Request(self.url + INTEGRATION_PREFIX + path,
                                     headers={"X-API-KEY": self._key, "Accept": "application/json"})
        where = path.split("?")[0]
        try:
            with self._op.open(req, timeout=TIMEOUT if self.timeout is None else self.timeout) as r:
                raw = r.read(MAX_BODY + 1)
        except urllib.error.HTTPError as e:
            e.close()  # the error carries the open response; release its socket (its body is never read)
            if e.code in (401, 403):
                raise RuntimeError(f"unifi: API key rejected (HTTP {e.code})") from None
            if e.code == 404:
                raise _NotFound(f"unifi: HTTP 404 on {where}") from None
            raise RuntimeError(f"unifi: HTTP {e.code} on {where}") from None
        if len(raw) > MAX_BODY:
            raise RuntimeError("unifi: response too large")
        body = json.loads(raw.decode())
        if not isinstance(body, dict):
            raise RuntimeError("unifi: unexpected response shape")
        return body

    def _page(self, path: str) -> list:
        """Every row of a paged list: offset += count until offset >= totalCount or count == 0, at most MAX_PAGES."""
        rows: list = []
        offset = 0
        for _ in range(MAX_PAGES):
            body = self._get(f"{path}?offset={offset}&limit={PAGE_LIMIT}")
            data = body.get("data")
            if not isinstance(data, list):
                raise RuntimeError("unifi: unexpected response shape")
            rows += data
            count = _count(body.get("count"))
            count = len(data) if count is None else count
            total = _count(body.get("totalCount"))
            offset += count
            if count == 0 or total is None or offset >= total:
                return rows
        log.warning("unifi: %s has more than %d pages; read stopped there", path.split("?")[0], MAX_PAGES)
        return rows

    def _resolve(self) -> str:
        """The site id for the SITE setting: an id as is; else the one site whose internalReference, then name
        (case-sensitive, then case-insensitive) equals it."""
        want = self.site
        if _UUID_RE.fullmatch(want):
            return want
        try:
            sites = self._page("/v1/sites")
        except _NotFound:
            raise RuntimeError("unifi: no Integration API at this URL (UniFi OS console needed)") from None
        rows = [s for s in sites if isinstance(s, dict) and isinstance(s.get("id"), str) and s["id"]]
        tests = (lambda s: s.get("internalReference") == want,
                 lambda s: s.get("name") == want,
                 lambda s: isinstance(s.get("name"), str) and s["name"].casefold() == want.casefold())
        for test in tests:
            hits = {s["id"] for s in rows if test(s)}
            if len(hits) == 1:
                return hits.pop()
            if hits:
                raise RuntimeError(f"unifi: site name {want} is ambiguous, use its id")
        raise RuntimeError(f"unifi: site {want} not found (use the site's internal reference, name or id)")

    def _read(self, site_id: str, stats: dict | None = None) -> dict[str, WifiInfo]:
        base = f"/v1/sites/{urllib.parse.quote(site_id, safe='')}"
        return parse_integration_clients(self._page(base + "/clients"), self._page(base + "/devices"), stats)

    def _clients(self, stats: dict | None = None) -> dict[str, WifiInfo]:
        fresh = self._site_cache is None
        if fresh:
            self._site_cache = self._resolve()
        try:
            return self._read(self._site_cache, stats)
        except _NotFound:
            if fresh or _UUID_RE.fullmatch(self.site):  # nothing to look up again: an error, not a loop
                raise
        self._site_cache = None  # the cached site is gone (removed or recreated): look it up once more
        self._site_cache = self._resolve()
        return self._read(self._site_cache, stats)

    def clients(self, stats: dict | None = None) -> dict[str, WifiInfo]:
        """Blocking. Raises RuntimeError on failure. stats["dropped"] counts the malformed client rows (see
        parse_integration_clients)."""
        with self._lock:
            try:
                return self._clients(stats)
            except _NotFound as e:
                raise RuntimeError(str(e)) from None
            except urllib.error.HTTPError as e:  # not expected (_get maps them), kept for parity
                e.close()
                raise RuntimeError(f"unifi: HTTP {e.code}") from None
            except (urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError, OSError) as e:
                raise RuntimeError(f"unifi: {e}") from e
            except (TypeError, AttributeError, ValueError, OverflowError, RecursionError, http.client.HTTPException):
                # no exception text and no chained cause: an invalid header value (a malformed key) or an InvalidURL echoes it
                raise RuntimeError("unifi: unexpected response") from None

    def close(self) -> None:
        """Nothing to release: there is no session."""
