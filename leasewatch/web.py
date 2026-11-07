"""Small HTTP server (stdlib only): static UI + JSON API."""
from __future__ import annotations

import csv
import gzip
import hashlib
import html
import io
import json
import logging
import mimetypes
import os
import re
import secrets
import socket
import threading
import time
from email.errors import FirstHeaderLineIsContinuationDefect, MissingHeaderBodySeparatorDefect
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import auth, metrics
from .config import Config
from .connectors import InstanceSpec
from .connectors.merge import is_private_mac
from .db import AlreadyADevice, Database, UnknownDevices
from .fw1 import MAC_RE

log = logging.getLogger("leasewatch.web")
STATIC_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "static"))
MAX_BODY = 16 * 1024
# devices per bulk POST: 200 MACs are about 4.2 KiB of JSON, well inside MAX_BODY
BULK_MAX = 200
INDEX = os.path.join(STATIC_DIR, "index.html")
# sent on every response: the page loads only its own script, style and images, and no inline script or style
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
# C0/C1 controls as \xNN and "\" as "\\", as the stdlib's own log_message does: a raw request line must not move the
# cursor or forge lines, and a typed "\x1b" must not read the same as a real ESC
_LOG_ESCAPE = str.maketrans({ord("\\"): "\\\\", **{c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0))}})
# a formula start after ';' or a line break: Excel with ';' as list separator (sv-SE) opens the unquoted rest as a cell
# (or row) of its own; quotes and blanks in between are dropped by its parser, so they do not hide the formula
# CRLF is one break: an apostrophe between "\r" and "\n" would change the note text in a restore
_CSV_SEMI_FORMULA = re.compile(r"(?:\r\n|[;\r\n])(?=[\s\"]*[=+\-@\t\r])")

_JSON = "application/json; charset=utf-8"
_ALLOW = {"Allow": "GET, HEAD, POST"}
# sent after Content-Type and Content-Length on every response; a route may override any of them (static: no-cache)
_SECURITY_HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                     "Cache-Control": "no-store", "Content-Security-Policy": CSP}
# the answer to a connection over the limit: built once, sent without reading the request, so the accept loop never
# waits on the client; the same security headers as every other response
_BUSY_BODY = b'{"error": "busy"}'
_BUSY_RESPONSE = ("HTTP/1.0 503 Service Unavailable\r\n" + "".join(
    f"{k}: {v}\r\n" for k, v in {"Content-Type": _JSON, "Content-Length": str(len(_BUSY_BODY)), **_SECURITY_HEADERS,
                                  "Retry-After": "5", "Connection": "close"}.items()) + "\r\n").encode("latin-1") + _BUSY_BODY
# one entry of If-None-Match: "*" or an entity tag, weak or strong; a tag may hold a comma, so no plain split
_ETAG_ITEM = re.compile(r'\*|(?:W/)?"[^"]*"')
_DEVICE_PATH = re.compile(r"^/api/devices/([0-9a-f:]{17})$")
_CSV_HEADER = ["mac", "ip", "name", "hostname", "vendor", "vlan", "lease_type", "sources", "online", "link", "switch_port", "via",
               "loc_source", "wifi_ssid", "wifi_ap", "wifi_signal", "first_seen", "last_online", "last_listed", "acked", "private",
               "archived", "note", "aliases"]
_WIFI_CSV_HEADER = ["mac", "name", "vendor", "last_ip", "private", "archived", "first_seen", "last_seen", "hours_seen", "polls_seen", "last_ap"]


def _dev(d: dict) -> dict:
    """A device row as the API sends it: plus `private`, a locally administered MAC (the page marks those)."""
    return {**d, "private": is_private_mac(d["mac"])}


def _wifi_row(w: dict) -> dict:
    """A wifi_presence row for the list: without the AP and the poll count, which only the detail route sends."""
    return {k: v for k, v in w.items() if k not in ("last_ap", "polls_seen")}


def _connector_label(s: InstanceSpec, instances: list[InstanceSpec]) -> str:
    """The dot text in the page: the switch's own NAME, "Wi-Fi"; the instance name stays the id."""
    if s.type == "snmp_switch":
        return s.settings.get("name") or s.name
    if s.type != "unifi":
        return s.name
    # with more than one controller the instance name tells the dots apart (a touch screen has no tooltip)
    return f"Wi-Fi {s.name}" if sum(i.type == "unifi" for i in instances) > 1 else "Wi-Fi"


def _csv_cell(v: object) -> str:
    """Neutralise spreadsheet formula injection (hostnames come from untrusted DHCP clients)."""
    s = str(v)
    s = _CSV_SEMI_FORMULA.sub(lambda m: m.group() + "'", s)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


_KIND = re.compile(r"[a-z_]{1,20}")
_DEFAULT_EVENT_LIMIT = 300
_EVENT_PARAMS = {"kind", "since", "until", "before", "limit"}


def _event_filters(query: str, default_limit: int, max_limit: int, paged: bool) -> dict:
    """The events API parameters, validated; raises ValueError with the short text of the 400. Unknown parameters
    are ignored. `paged` is False for the CSV, which has no `before`."""
    q = parse_qs(query, keep_blank_values=True)
    for k, v in q.items():
        if k in _EVENT_PARAMS and len(v) > 1:
            raise ValueError(f"repeated parameter: {k}")

    def num(name: str, lo: int) -> int | None:
        if name not in q:
            return None
        raw = q[name][0]
        if not (raw.isascii() and raw.isdigit()) or len(raw) > 15 or int(raw) < lo:
            raise ValueError(f"bad {name}")
        return int(raw)

    out: dict = {"kinds": None, "since": num("since", 0), "until": num("until", 0),
                 "before": num("before", 1) if paged else None}
    if "kind" in q:
        kinds = q["kind"][0].split(",")
        if not 1 <= len(kinds) <= 20 or not all(_KIND.fullmatch(k) for k in kinds):
            raise ValueError("bad kind")
        out["kinds"] = kinds
    if out["since"] is not None and out["until"] is not None and out["since"] > out["until"]:
        raise ValueError("since after until")
    limit = num("limit", 1)
    if limit is not None and limit > max_limit:
        raise ValueError("bad limit")
    out["limit"] = default_limit if limit is None else limit
    return out


def _query_hash(f: dict) -> str:
    """8 hex of the normalised filters (sorted key=value pairs), or "0" when there are none."""
    pairs = sorted(f"{k}={','.join(v) if k == 'kinds' else v}" for k, v in f.items() if v is not None and k != "limit")
    if f["limit"] != _DEFAULT_EVENT_LIMIT:
        pairs.append(f"limit={f['limit']}")
    return hashlib.sha256("&".join(sorted(pairs)).encode()).hexdigest()[:8] if pairs else "0"


_EVENTS_CSV_HEADER = ["id", "time", "mac", "kind", "detail", "name", "hostname", "vlan"]


def _csv_ts(t: int | None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M%z", time.localtime(t)) if t else ""  # ISO 8601 with the server's UTC offset


def _csv_row(d: dict) -> list:
    cell, ts = _csv_cell, _csv_ts
    return [d["mac"], d["ip"], cell(d["name"]), cell(d["hostname"]), cell(d["vendor"]), d["vlan"], d["lease_type"], d["sources"], d["online"],
            d["link"], cell(d["sw_port"]), cell(d["sw_via"]), cell(d["loc_source"]), cell(d["wifi_ssid"]), cell(d["wifi_ap"]),
            d["wifi_signal"] if d["wifi_signal"] is not None else "",
            ts(d["first_seen"]), ts(d["last_online"]), ts(d["last_seen"]), d["acked"], cell(int(is_private_mac(d["mac"]))),
            ts(d["archived_ts"]), cell(d["note"]),
            cell(" ".join(d["aliases"]))]  # last, so no earlier column moves; a space, as Excel with a ; separator splits on ;


class _DeadlineRaw(io.RawIOBase):
    """The socket's reader with one deadline for the whole request. Each recv gets only the time left, so a client
    that trickles a byte at a time cannot keep the thread by resetting a per-read timeout; past the deadline the
    read raises TimeoutError. Between reads the socket is back on the handler's write timeout."""

    def __init__(self, raw: io.RawIOBase, sock: socket.socket, deadline: float, write_timeout: float | None) -> None:
        super().__init__()
        self._raw, self._sock, self._deadline, self._write_timeout = raw, sock, deadline, write_timeout

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray | memoryview) -> int | None:  # type: ignore[override]
        left = self._deadline - time.monotonic()
        if left <= 0:
            # data that is already in the kernel buffer is read: the time may have gone on the server's own work.
            # Timeout 0, not MSG_DONTWAIT: with a timeout set, the socket layer polls for that long before the recv
            got: int | None = None
            try:
                self._sock.settimeout(0.0)
                got = self._sock.recv_into(b)
            except (BlockingIOError, InterruptedError):
                pass
            finally:
                try:
                    self._sock.settimeout(self._write_timeout)
                except OSError:  # the socket was closed under us
                    pass
            if got is None:
                raise TimeoutError("request not read in time")
            return got
        self._sock.settimeout(max(0.05, left))
        try:
            return self._raw.readinto(b)
        finally:
            try:
                self._sock.settimeout(self._write_timeout)
            except OSError:  # the socket was closed under us
                pass

    def allow_until(self, deadline: float) -> None:
        self._deadline = max(self._deadline, deadline)

    def close(self) -> None:
        if not self.closed:
            super().close()
            self._raw.close()


class _WriteRefusals:
    """Counts POSTs refused outside WRITE_ALLOW and logs them at most once a minute, as the verifier does for failed
    logins: a client that keeps retrying must not fill the log, and a burst that ends inside the window still gets
    its line (from a timer)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._n = 0
        self._client = ""
        self._logged = float("-inf")
        self._timer: threading.Timer | None = None

    def refused(self, client: str) -> None:
        with self._lock:
            self._n += 1
            self._client = client
            wait = self._logged + auth.FAIL_LOG_EVERY - time.monotonic()
            if wait > 0:
                if self._n == 1:
                    t = threading.Timer(wait + 0.05, self._report)
                    t.daemon = True
                    t.start()
                    self._timer = t
                return
        self._report()

    def _report(self) -> None:
        with self._lock:
            n, client, now = self._n, self._client, time.monotonic()
            if not n or now - self._logged < auth.FAIL_LOG_EVERY:
                return
            self._n, self._logged, self._timer = 0, now, None
        log.warning("refused %d write(s) outside WRITE_ALLOW (last from %s)", n, client or "?")


class Handler(BaseHTTPRequestHandler):
    """The UI and API. make_handler() binds it to one config, database and version through a subclass."""

    server_version = "leasewatch"
    sys_version = ""
    timeout = 30  # a client that stalls mid-response does not hold a thread forever
    # request line, headers and body must all arrive within this many seconds of the connection's start
    REQUEST_READ_SECONDS: float = 15
    # set per server by make_handler()
    cfg: Config
    db: Database
    app_version: str
    verifier: auth.Verifier | None = None  # None when auth is off
    started: float = 0.0  # process start, for the collector check before the first poll attempt
    boot: str = ""  # per make_handler(): the version counter starts again at 0 after a restart, an old ETag must not match
    write_refusals: _WriteRefusals  # per make_handler(): one log throttle per server

    def setup(self) -> None:
        deadline = time.monotonic() + self.REQUEST_READ_SECONDS
        super().setup()
        if isinstance(self.connection, socket.socket) and isinstance(self.rfile, io.BufferedReader):
            raw = self.rfile.detach()
            self.rfile = io.BufferedReader(_DeadlineRaw(raw, self.connection, deadline, self.timeout))

    def log_message(self, fmt: str, *args: object) -> None:  # quieter access log
        log.debug("%s %s", self.address_string(), (fmt % args).translate(_LOG_ESCAPE))

    # --- request entry points ----------------------------------------------
    def do_GET(self) -> None:
        p = self._checked_target()
        if p is None:
            return
        try:
            self._dispatch_get(p)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            log.exception("GET %s failed", p)
            self._error(500, "internal error")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        p = self._checked_target()
        if p is None:
            return
        # the password check may have used the request's read time; the body still gets 5 s
        raw = getattr(self.rfile, "raw", None)
        if isinstance(raw, _DeadlineRaw):
            raw.allow_until(time.monotonic() + 5)
        # after auth, so a client without credentials learns nothing about the write rules; before routing, so a
        # refused client learns nothing about which paths exist
        if not self._write_ok():
            return
        if p == "/api/devices":
            return self._api_devices_post()
        m = _DEVICE_PATH.match(p)
        if not m:
            return self._error(404, "not found")
        self._api_device_post(m.group(1), p)

    def _write_ok(self) -> bool:
        """True when this client may change data; else the 403 is sent. The socket peer only: X-Forwarded-For is
        set by the client and would let anyone on the LAN claim an allowed address."""
        addr = self.client_address[0]
        if self.cfg.read_only_on:
            log.debug("%s write refused: READ_ONLY", addr)
            self._error(403, "read-only")
            return False
        if self.cfg.write_allowed(addr):
            return True
        self.write_refusals.refused(addr)
        self._error(403, "writes are not allowed from this address")  # the address stays out of the body
        return False

    def _method_not_allowed(self) -> None:
        self._send(405, b'{"error": "method not allowed"}', _JSON, _ALLOW)

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _method_not_allowed

    def _dispatch_get(self, p: str) -> None:
        exact = {"/": self._route_index, "/healthz": self._healthz, "/api/devices": self._api_devices, "/api/devices.csv": self._csv,
                 "/api/status": self._api_status, "/api/stats": self._api_stats, "/api/events": self._api_events,
                 "/api/events.csv": self._events_csv, "/api/wifi/ssids": self._api_wifi_ssids, "/api/wifi": self._api_wifi,
                 "/api/wifi.csv": self._wifi_csv,
                 "/metrics": self._metrics}.get(p)
        if exact is not None:
            return exact()
        if p.startswith("/static/"):
            return self._static(p[len("/static/"):])
        m = _DEVICE_PATH.match(p)
        if m:
            return self._api_device_get(m.group(1))
        return self._error(404, "not found")

    # --- pre-checks, in this order: Host, auth, request target ---------------
    def _checked_target(self) -> str | None:
        """The request path once every pre-check passed, else None after the error response was sent."""
        # Host problems first (they say nothing about the data), then auth, then routing
        if not self._host_ok() or not self._auth_ok():
            return None
        return self._target()

    def _host_ok(self) -> bool:
        # RFC 9112 5.1: "Host : x" ends the parsed headers, so Host would read as absent; only header-line defects
        # count, as the email parser also records body defects (a multipart Content-Type with no body)
        if any(isinstance(d, (MissingHeaderBodySeparatorDefect, FirstHeaderLineIsContinuationDefect)) for d in self.headers.defects):
            self._error(400, "malformed header line")
            return False
        if len(self.headers.get_all("Host") or ()) > 1:  # RFC 9112 3.2: only the first one would be checked
            self._error(400, "more than one Host header")
            return False
        if self.cfg.host_allowed(self.headers.get("Host", "")):
            return True
        self._error(421, "unknown Host header; set ALLOWED_HOSTS or PUBLIC_URL")
        return False

    def _auth_ok(self) -> bool:
        """True when auth is off or the request carries the right credentials; else the 401 (or 503) is sent."""
        if self.verifier is None:
            return True
        try:
            if self.verifier.check(self.headers.get("Authorization"), self.client_address[0]):
                return True
        except auth.Busy:
            self._send(503, b'{"error": "busy"}', _JSON, {"Retry-After": "5"})
            return False
        # fixed realm, not SITE_NAME: operator text with quotes or CR must not reach a header
        self._send(401, b'{"error": "authentication required"}', _JSON,
                   {"WWW-Authenticate": 'Basic realm="leasewatch", charset="UTF-8"'})
        return False

    def _target(self) -> str | None:
        """The path of the request target, or None after a 400 (an absolute form like "http://[x/" does not parse)."""
        if self.path.startswith("/"):  # origin form (RFC 9112 3.2.1): "//x" is a path, not an authority
            return self.path.partition("?")[0]
        try:
            u = urlparse(self.path)
        except ValueError:
            self._error(400, "bad request target")
            return None
        # RFC 9110 4.2.3: an empty path means "/" only in absolute form; "?x", "*" and the like match no route
        return (u.path or "/") if u.scheme else ""

    # --- response writers ----------------------------------------------------
    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        headers = {"Content-Type": ctype, "Content-Length": str(len(body)), **_SECURITY_HEADERS}
        headers.update(extra or {})
        for k, v in headers.items():
            self.send_header(k, v)
        try:
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError as e:
            # the client reset, hung up or stalled past `timeout`: the status line may already be out, so nothing
            # more (no 500) may be written on this connection; it is closed instead of reaching handle_error
            self.close_connection = True
            log.debug("%s client gone during the response (%s)", self.address_string(), type(e).__name__)

    def _json(self, obj: object, status: int = 200) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode(), _JSON)

    def _accepts_gzip(self) -> bool:
        q: dict[str, float] = {}
        for part in (self.headers.get("Accept-Encoding") or "").split(","):
            name, _, params = part.partition(";")
            name, weight = name.strip().lower(), 1.0
            for param in params.split(";"):
                k, _, v = param.partition("=")
                if k.strip().lower() == "q":
                    try:
                        weight = float(v)
                    except ValueError:
                        weight = 0.0  # an unreadable weight is not an offer
            if name:
                q[name] = weight
        return q.get("gzip", q.get("*", 0.0)) > 0

    def _encode(self, body: bytes) -> tuple[bytes, dict]:
        """gzip for a client that accepts it; small bodies cost more to compress than they save. mtime=0 keeps the
        output the same for the same input."""
        if len(body) > 1024 and self._accepts_gzip():
            return gzip.compress(body, 6, mtime=0), {"Content-Encoding": "gzip"}
        return body, {}

    def _json_vary(self, obj: object, etag: str | None = None) -> None:
        """A JSON API answer that may be compressed; the cache must key on Accept-Encoding either way."""
        body = json.dumps(obj, ensure_ascii=False).encode()
        # the 304 decision was made before the body was built; the weak ETag is the same for gzip and identity
        tag = {"ETag": etag} if etag else {}
        body, extra = self._encode(body)
        self._send(200, body, _JSON, {"Vary": "Accept-Encoding", **extra, **tag})

    def _etag(self, version: int, meta: dict, query: str = "0") -> str:
        # the write bit: meta.can_write differs per client, so two clients must not share a tag (and a 304); the
        # stale and collector bits: the page shows a banner for each, so a flip must not be answered with a 304
        w = int(self.cfg.write_allowed(self.client_address[0]))
        return f'W/"{self.boot}.{version}.{w}{int(meta["stale"])}{int(meta["collector_stale"])}.{query}"'

    def _matches(self, etag: str) -> bool:
        """If-None-Match lists this ETag (weak compare: the W/ prefix is ignored on both sides) or is "*"."""
        own = etag.removeprefix("W/")
        for header in self.headers.get_all("If-None-Match") or ():
            for item in _ETAG_ITEM.findall(header):
                if item == "*" or item.removeprefix("W/") == own:
                    return True
        return False

    def _not_modified(self, etag: str) -> None:
        """304 (RFC 9110 15.4.5): the validator and the headers a 200 would carry, no Content-Type, Length or body."""
        self.send_response(304)
        for k, v in {"ETag": etag, "Vary": "Accept-Encoding", **_SECURITY_HEADERS}.items():
            self.send_header(k, v)
        try:
            self.end_headers()
        except OSError as e:
            self.close_connection = True
            log.debug("%s client gone during the response (%s)", self.address_string(), type(e).__name__)

    def _error(self, status: int, msg: str) -> None:
        self._json({"error": msg}, status)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # stdlib errors (501 TRACE, 414, 431) would otherwise bypass the JSON body and security headers; a bad request
        # line is still answered HTTP/0.9-style (body only), as the stdlib does
        self.log_error("code %d, message %s", code, message)
        self.close_connection = True
        self._send(code, json.dumps({"error": message or self.responses.get(code, ("error",))[0].lower()}).encode(),
                   _JSON, _ALLOW if code == 405 else None)

    # --- GET routes ----------------------------------------------------------
    def _route_index(self) -> None:
        self._static("index.html")

    def _static(self, name: str) -> None:
        path = os.path.normpath(os.path.join(STATIC_DIR, name))
        # the normalised path and the parsed target: "/static/./index.html" is the template, "http://host/" is "/"
        if (path == INDEX and self._target() != "/") or not path.startswith(STATIC_DIR + os.sep) or not os.path.isfile(path):
            return self._error(404, "not found")
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        with open(path, "rb") as f:
            body = f.read()
        if path == INDEX:  # VERSION first: a site name containing "{{VERSION}}" stays literal
            body = (body.replace(b"{{VERSION}}", html.escape(self.app_version).encode())
                    .replace(b"{{SITE_NAME}}", html.escape(self.cfg.site_name).encode()))
        self._send(200, body, ctype, {"Cache-Control": "no-cache"})

    def _healthz(self) -> None:
        m = self._meta()
        ok = m["last_poll_ok"] and not m["stale"]
        # collector: the poll loop is hung or dead (restart helps); source: polls run but fail or the data is old
        reason = "ok" if ok else "collector" if m["collector_stale"] else "source"
        self._json({"ok": ok, "reason": reason, **m}, 200 if ok else 503)

    def _metrics(self) -> None:
        # no ETag: every scrape wants the current numbers, and most change each poll anyway
        body, extra = self._encode(metrics.render(self.cfg, self.db, self.app_version).encode())
        self._send(200, body, metrics.CONTENT_TYPE, {"Vary": "Accept-Encoding", **extra})

    def _api_devices(self) -> None:
        # the version before the body: a write in between makes the body newer than its tag (one extra 200 later),
        # never an old body under a new tag
        version = self.db.version()
        meta = self._meta()
        etag = self._etag(version, meta)
        if self._matches(etag):
            return self._not_modified(etag)
        devices = self.db.devices_with_presence()  # devices and presence from one lock hold
        self._json_vary({"meta": meta, "devices": [_dev({**d, "wifi_presence": [_wifi_row(w) for w in d["wifi_presence"]]}) for d in devices]}, etag)

    def _api_status(self) -> None:
        self._json_vary({"meta": self._meta()})

    def _api_stats(self) -> None:
        self._json({"meta": self._meta(), "stats": self.db.stats(self.cfg.new_days)})

    def _api_events(self) -> None:
        query = urlparse(self.path).query
        try:
            f = _event_filters(query, _DEFAULT_EVENT_LIMIT, 500, True)
        except ValueError as e:
            return self._error(400, str(e))
        # the tag carries a hash of the accepted parameters: a 304 for one filter must never answer another
        version = self.db.version()  # before the body, as in _api_devices
        etag = self._etag(version, self._meta(), _query_hash(f))
        if self._matches(etag):
            return self._not_modified(etag)
        rows = self.db.events(None, f["limit"] + 1, f["kinds"], f["since"], f["until"], f["before"])
        more = len(rows) > f["limit"]
        rows = rows[:f["limit"]]
        self._json_vary({"events": rows, "next": rows[-1]["id"] if more else None}, etag)

    def _events_csv(self) -> None:
        try:
            f = _event_filters(urlparse(self.path).query, 10000, 50000, False)
        except ValueError as e:
            return self._error(400, str(e))
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(_EVENTS_CSV_HEADER)
        cell = _csv_cell
        for r in self.db.events(None, f["limit"], f["kinds"], f["since"], f["until"]):
            w.writerow([r["id"], _csv_ts(r["ts"]), r["mac"], r["kind"], cell(r["detail"]), cell(r["name"] or ""),
                        cell(r["hostname"] or ""), "" if r["vlan"] is None else r["vlan"]])
        self._send(200, buf.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="leasewatch-events.csv"'})

    def _wifi_query(self) -> str | None:
        """The ssid parameter, compared exactly (a space is part of the name); answers 400 and returns None when it is
        missing, repeated or longer than 64 characters."""
        vals = parse_qs(urlparse(self.path).query, keep_blank_values=True).get("ssid", [])
        if len(vals) != 1 or len(vals[0]) > 64:
            self._error(400, "ssid takes exactly one value of at most 64 characters")
            return None
        return vals[0]

    def _api_wifi_ssids(self) -> None:
        self._json_vary(self.db.wifi_ssids())

    def _api_wifi(self) -> None:
        ssid = self._wifi_query()
        if ssid is None:
            return
        res = self.db.wifi_devices(ssid)
        devs = [{"mac": r["mac"], "name": r["name"], "wifi_alias": r["wifi_alias"], "hostname": r["hostname"], "vendor": r["vendor"],
                 "ip": r["ip"], "private": is_private_mac(r["mac"]), "archived_ts": r["archived_ts"], "online": r["online"],
                 "on_now": bool(r["online"]) and r["wifi_ssid"] == ssid, "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                 "seconds_seen": r["seconds_seen"], "polls_seen": r["polls_seen"], "last_ap": r["last_ap"]} for r in res["devices"]]
        self._json_vary({"ssid": ssid, "since": res["since"], "devices": devs})

    def _wifi_csv(self) -> None:
        ssid = self._wifi_query()
        if ssid is None:
            return
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(_WIFI_CSV_HEADER)
        cell, ts = _csv_cell, _csv_ts
        for r in self.db.wifi_devices(ssid)["devices"]:
            w.writerow([r["mac"], cell(r["name"] or r["wifi_alias"] or r["hostname"] or r["label"]), cell(r["vendor"]), r["ip"], int(is_private_mac(r["mac"])), ts(r["archived_ts"]),
                        ts(r["first_seen"]), ts(r["last_seen"]), round(r["seconds_seen"] / 3600, 1), r["polls_seen"], cell(r["last_ap"])])
        self._send(200, buf.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="leasewatch-wifi.csv"'})

    def _api_device_get(self, mac: str) -> None:
        if not MAC_RE.match(mac):
            return self._error(400, "bad mac")
        out = self.db.device_detail(mac)
        if not out:
            return self._error(404, "unknown device")
        self._json({**out, "device": _dev(out["device"])})

    def _csv(self) -> None:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(_CSV_HEADER)
        for d in self.db.devices():
            w.writerow(_csv_row(d))
        self._send(200, buf.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="leasewatch-devices.csv"'})

    def _meta(self) -> dict:
        cfg = self.cfg
        m = self.db.all_meta()
        now = int(time.time())
        last = int(m.get("last_poll_ts") or 0)
        attempt = int(m.get("last_attempt_ts") or 0)
        # a poll lasts at most the producers' timeout plus the enrichers' timeout plus the mail; the loop then waits
        # POLL_SECONDS, and one missed round is allowed on top
        limit = (2 * cfg.poll_seconds + 2 * max([i.timeout for i in cfg.instances if m.get(f"conn.{i.name}.enabled", "1") == "1"] or [0]) + 120)
        # abs(): an attempt in the future (the clock stepped back) proves nothing; no attempt by this process yet (an
        # attempt from before its start counts as none): by process age
        collector_stale = abs(now - attempt) > limit if attempt and attempt >= self.started else now - self.started > limit
        # only the configured channels: a channel removed from the config keeps its meta row
        notify = {ch: m[f"notify.{ch}.ok"] == "1" for ch in cfg.mail_channels if f"notify.{ch}.ok" in m}
        return {
            "notify": notify,
            "last_attempt_ts": attempt or None, "last_attempt_age": abs(now - attempt) if attempt else None,
            "attempt_limit": limit, "collector_stale": collector_stale,
            "now": now, "last_poll_ts": last, "last_poll_age": abs(now - last) if last else None,  # abs(): as stale below
            "last_poll_ok": m.get("last_poll_ok") == "1", "last_error": m.get("last_error", ""),
            "last_error_ts": int(m.get("last_error_ts") or 0) or None, "last_raw": m.get("last_raw", ""),
            "baseline_ts": int(m.get("baseline_ts") or 0) or None, "poll_seconds": cfg.poll_seconds,
            "grace_minutes": cfg.online_grace_minutes,  # the drawer's "on the wire" per source uses the same window
            "wifi_presence_since": int(m.get("wifi_presence_since") or 0) or None,  # the SSID chips' "seen since"
            "new_days": cfg.new_days, "site_name": cfg.site_name, "version": self.app_version, "mail": cfg.mail_enabled,
            # abs(): a last poll in the future (the clock stepped back) proves nothing about the collector running
            "stale": abs(now - last) > cfg.poll_seconds * 3 if last else True,
            # one entry per configured instance, in LW_CONNECTORS order; name stays the instance id
            "connectors": [self._connector_meta(m, s) for s in cfg.instances],
            # read_only: for every client; can_write: for this one (the page leaves out its edit controls when false)
            "read_only": cfg.read_only_on, "can_write": cfg.write_allowed(self.client_address[0]),
        }

    def _connector_meta(self, m: dict, s: InstanceSpec) -> dict:
        return {"name": s.name, "label": _connector_label(s, self.cfg.instances), "type": s.type, "ok": m.get(f"conn.{s.name}.ok") == "1",
                "error": m.get(f"conn.{s.name}.error", ""), "ts": int(m.get(f"conn.{s.name}.ts") or 0) or None,
                "ms": int(m.get(f"conn.{s.name}.ms") or 0), "count": int(m.get(f"conn.{s.name}.count") or 0),
                "strategy": m.get(f"conn.{s.name}.strategy", ""),
                "enabled": m.get(f"conn.{s.name}.enabled", "1") == "1"}

    # --- POST route ----------------------------------------------------------
    def _api_device_post(self, mac: str, p: str) -> None:
        if not MAC_RE.match(mac):
            return self._error(400, "bad mac")
        body = self._read_json_body()
        if body is None:
            return
        if "split" in body:
            return self._api_device_split(mac, body, p)
        fields = self._user_fields(body)
        if fields is None:
            return
        try:
            d = self.db.update_user_fields(mac, *fields)
        except Exception:
            log.exception("POST %s failed", p)
            return self._error(500, "internal error")
        if not d:
            return self._error(404, "unknown device")
        self._json({"device": _dev(d)})

    def _api_device_split(self, mac: str, body: dict, p: str) -> None:
        """Turn a merged alias MAC back into a device of its own. The key stands alone: with other fields it would be
        unclear whether they apply before or after the split."""
        alias = body["split"]
        if not isinstance(alias, str) or not MAC_RE.fullmatch(alias.lower()):  # fullmatch: "$" lets a trailing "\n" in
            return self._error(400, "split must be a MAC")
        if len(body) > 1:
            return self._error(400, "split cannot be combined with other fields")
        try:
            res = self.db.split_alias(mac, alias.lower())
        except AlreadyADevice:
            return self._error(409, "MAC already has a device row")
        except Exception:
            log.exception("POST %s failed", p)
            return self._error(500, "internal error")
        if res is None:
            return self._error(404, "not an alias of this device")
        self._json({"device": _dev(res[0]), "split": _dev(res[1])})

    def _api_devices_post(self) -> None:
        """Mark known or archive/restore up to BULK_MAX devices at once: all or nothing, the same events as the same
        single POSTs. The UI reloads the list afterwards, so the answer holds only counts."""
        body = self._read_json_body()
        if body is None:
            return
        macs = body.get("macs")
        if not isinstance(macs, list) or not 1 <= len(macs) <= BULK_MAX:
            return self._error(400, f"macs must be a list of 1 to {BULK_MAX} MACs")
        for i, mac in enumerate(macs):
            if not isinstance(mac, str) or not MAC_RE.fullmatch(mac):  # fullmatch: "$" alone lets a trailing "\n" in
                return self._json({"error": "bad mac", "index": i}, 400)  # the value is not echoed back
        # exactly one of the two fields: a name or note for many devices at once is never meant
        if "name" in body or "note" in body or ("acked" in body) == ("archived" in body):
            return self._error(400, "bulk takes acked or archived")
        fields = self._user_fields(body)  # the same type checks and texts as the single POST
        if fields is None:
            return
        acked, _name, _note, archived = fields
        if acked is None and archived is None:  # {"acked": null}
            return self._error(400, "bulk takes acked or archived")
        try:
            changed, unchanged = self.db.update_many(macs, acked=acked, archived=archived)
        except UnknownDevices as e:
            return self._json({"error": "unknown device", "unknown": e.macs}, 404)
        except Exception:
            log.exception("POST /api/devices failed")
            return self._error(500, "internal error")
        self._json({"changed": len(changed), "unchanged": len(unchanged)})

    def _read_json_body(self) -> dict | None:
        """The request body as a JSON object, or None after the error response was sent (or the client left)."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_BODY:
            self._error(400, "bad body")
            return None
        ctype = self.headers.get("Content-Type", "")
        if ctype.split(";", 1)[0].strip().lower() != "application/json":  # exact media type: keeps POSTs out of CORS "simple requests"
            self._error(415, "json only")
            return None
        # browsers send Basic credentials cross-site too: this check and the JSON type above are what stop CSRF
        if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            self._error(403, "cross-site request")
            return None
        try:
            raw = self.rfile.read(length)
        except OSError:  # the client reset or hung up mid-body: no one is left to answer
            self.close_connection = True
            return None
        try:
            body = json.loads(raw.decode())
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError, RecursionError):  # RecursionError: deeply nested arrays like "[[[[..."
            self._error(400, "bad json")
            return None
        return body

    def _user_fields(self, body: dict) -> tuple | None:
        """(acked, name, note, archived) from the body, or None after the 400 for a wrong type."""
        acked = body.get("acked")
        name = body.get("name")
        note = body.get("note")
        archived = body.get("archived")
        if acked is not None and not isinstance(acked, bool):
            return self._error(400, "acked must be boolean")
        if name is not None and not isinstance(name, str):
            return self._error(400, "name must be a string")
        if note is not None and not isinstance(note, str):
            return self._error(400, "note must be a string")
        if archived is not None and not isinstance(archived, bool):
            return self._error(400, "archived must be boolean")
        for field, s in (("name", name), ("note", note)):
            try:
                if s is not None:
                    s.encode("utf-8")
            except UnicodeEncodeError:  # lone surrogate ("\ud800") from JSON escapes: SQLite and the response encoder would fail on it
                # the JSON itself is valid, so "bad json" would point the user at the wrong cause
                return self._error(400, f"{field} must be valid Unicode text")
        return acked, name, note, archived


def make_handler(cfg: Config, db: Database, version: str) -> type[BaseHTTPRequestHandler]:
    """A Handler subclass bound to this config, database and version; its `verifier` is None when auth is off."""
    verifier = None
    if cfg.auth_enabled:
        parsed = auth.parse_hash(cfg.auth_password_hash)
        if parsed is None:  # validate() reports it; a server started without validate() must not run open
            raise ValueError("AUTH_PASSWORD_HASH is not a valid hash")
        verifier = auth.Verifier(cfg.auth_user, parsed)
    # a subclass per call: two servers in one process (the tests) do not share settings
    return type("Handler", (Handler,), {"cfg": cfg, "db": db, "app_version": version, "verifier": verifier, "started": time.time(),
                                        "boot": secrets.token_hex(4), "write_refusals": _WriteRefusals()})


class Server(ThreadingHTTPServer):
    request_queue_size = 128  # socketserver's default backlog of 5 drops connections under a burst (3 per page load)
    daemon_threads = True
    # one thread per connection: without a cap, many idle connections would use up threads and memory
    MAX_CONNECTIONS = 64

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._slots = threading.BoundedSemaphore(self.MAX_CONNECTIONS)
        self._refused_lock = threading.Lock()
        self._refused = 0  # refused since the last accepted connection

    def process_request(self, request: socket.socket, client_address: object) -> None:  # type: ignore[override]
        if not self._slots.acquire(blocking=False):
            self._refuse(request)
            return
        with self._refused_lock:
            refused, self._refused = self._refused, 0
        if refused:
            log.info("connections accepted again (%d refused)", refused)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: object) -> None:  # type: ignore[override]
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def _refuse(self, request: socket.socket) -> None:
        with self._refused_lock:
            self._refused += 1
            first = self._refused == 1
        if first:
            log.warning("connection limit (%d) reached; refusing connections", self.MAX_CONNECTIONS)
        try:
            request.setblocking(False)  # a full send buffer must not stop the accept loop
            request.send(_BUSY_RESPONSE)
            # a request that has already arrived is dropped unread: closing with unread data would reset the
            # connection and the client could lose the 503
            request.recv(65536)
        except OSError:
            pass
        self.shutdown_request(request)


def serve(cfg: Config, db: Database, version: str) -> ThreadingHTTPServer:
    srv = Server((cfg.listen_host, cfg.listen_port), make_handler(cfg, db, version))
    log.info("listening on http://%s:%d", cfg.listen_host, cfg.listen_port)
    return srv
