"""Small HTTP server (stdlib only): static UI + JSON API."""
from __future__ import annotations

import csv
import html
import io
import json
import logging
import mimetypes
import os
import re
import time
from email.errors import FirstHeaderLineIsContinuationDefect, MissingHeaderBodySeparatorDefect
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import Config
from .connectors import InstanceSpec
from .db import Database
from .fw1 import MAC_RE

log = logging.getLogger("leasewatch.web")
STATIC_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "static"))
MAX_BODY = 16 * 1024
INDEX = os.path.join(STATIC_DIR, "index.html")
# C0/C1 controls as \xNN and "\" as "\\", as the stdlib's own log_message does: a raw request line must not move the
# cursor or forge lines, and a typed "\x1b" must not read the same as a real ESC
_LOG_ESCAPE = str.maketrans({ord("\\"): "\\\\", **{c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0))}})
# a formula start after ';' or a line break: Excel with ';' as list separator (sv-SE) opens the unquoted rest as a cell
# (or row) of its own; quotes and blanks in between are dropped by its parser, so they do not hide the formula
# CRLF is one break: an apostrophe between "\r" and "\n" would change the note text in a restore
_CSV_SEMI_FORMULA = re.compile(r"(?:\r\n|[;\r\n])(?=[\s\"]*[=+\-@\t\r])")


def make_handler(cfg: Config, db: Database, version: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "leasewatch"
        sys_version = ""
        timeout = 30  # a client that stalls mid-request does not hold a thread forever

        def log_message(self, fmt: str, *args: object) -> None:  # quieter access log
            log.debug("%s %s", self.address_string(), (fmt % args).translate(_LOG_ESCAPE))

        # --- helpers -------------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(status)
            headers = {"Content-Type": ctype, "Content-Length": str(len(body)), "X-Content-Type-Options": "nosniff",
                       "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}
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
            self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _error(self, status: int, msg: str) -> None:
            self._json({"error": msg}, status)

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            # stdlib errors (501 TRACE, 414, 431) would otherwise bypass the JSON body and security headers; a bad request
            # line is still answered HTTP/0.9-style (body only), as the stdlib does
            self.log_error("code %d, message %s", code, message)
            self.close_connection = True
            self._send(code, json.dumps({"error": message or self.responses.get(code, ("error",))[0].lower()}).encode(),
                       "application/json; charset=utf-8", {"Allow": "GET, HEAD, POST"} if code == 405 else None)

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
            if path == INDEX:
                body = body.replace(b"{{VERSION}}", html.escape(version).encode()).replace(b"{{SITE_NAME}}", html.escape(cfg.site_name).encode())  # VERSION first: a site name containing "{{VERSION}}" stays literal
            self._send(200, body, ctype, {"Cache-Control": "no-cache"})

        def _meta(self) -> dict:
            def _label(s: InstanceSpec) -> str:
                if s.type == "snmp_switch":
                    return s.settings.get("name") or s.name
                if s.type != "unifi":
                    return s.name
                # with more than one controller the instance name tells the dots apart (a touch screen has no tooltip)
                return f"Wi-Fi {s.name}" if sum(i.type == "unifi" for i in cfg.instances) > 1 else "Wi-Fi"

            m = db.all_meta()
            now = int(time.time())
            last = int(m.get("last_poll_ts") or 0)
            return {
                "now": now, "last_poll_ts": last, "last_poll_age": abs(now - last) if last else None,  # abs(): as stale below
                "last_poll_ok": m.get("last_poll_ok") == "1", "last_error": m.get("last_error", ""),
                "last_error_ts": int(m.get("last_error_ts") or 0) or None, "last_raw": m.get("last_raw", ""),
                "baseline_ts": int(m.get("baseline_ts") or 0) or None, "poll_seconds": cfg.poll_seconds,
                "grace_minutes": cfg.online_grace_minutes,  # the drawer's "on the wire" per source uses the same window
                "new_days": cfg.new_days, "site_name": cfg.site_name, "version": version, "mail": cfg.mail_enabled,
                # abs(): a last poll in the future (the clock stepped back) proves nothing about the collector running
                "stale": abs(now - last) > cfg.poll_seconds * 3 if last else True,
                # one entry per configured instance, in LW_CONNECTORS order
                # label: the dot text in the page (the switch's own NAME, "Wi-Fi"); name stays the instance id
                "connectors": [{"name": s.name, "label": _label(s), "type": s.type, "ok": m.get(f"conn.{s.name}.ok") == "1",
                                "error": m.get(f"conn.{s.name}.error", ""), "ts": int(m.get(f"conn.{s.name}.ts") or 0) or None,
                                "ms": int(m.get(f"conn.{s.name}.ms") or 0), "count": int(m.get(f"conn.{s.name}.count") or 0),
                                "strategy": m.get(f"conn.{s.name}.strategy", ""),
                                "enabled": m.get(f"conn.{s.name}.enabled", "1") == "1"} for s in cfg.instances],
            }

        # --- routes --------------------------------------------------------
        def do_HEAD(self) -> None:
            self.do_GET()

        def _method_not_allowed(self) -> None:
            self._send(405, b'{"error": "method not allowed"}', "application/json; charset=utf-8", {"Allow": "GET, HEAD, POST"})

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _method_not_allowed

        def _host_ok(self) -> bool:
            # RFC 9112 5.1: "Host : x" ends the parsed headers, so Host would read as absent; only header-line defects
            # count, as the email parser also records body defects (a multipart Content-Type with no body)
            if any(isinstance(d, (MissingHeaderBodySeparatorDefect, FirstHeaderLineIsContinuationDefect)) for d in self.headers.defects):
                self._error(400, "malformed header line")
                return False
            if len(self.headers.get_all("Host") or ()) > 1:  # RFC 9112 3.2: only the first one would be checked
                self._error(400, "more than one Host header")
                return False
            if cfg.host_allowed(self.headers.get("Host", "")):
                return True
            self._error(421, "unknown Host header; set ALLOWED_HOSTS or PUBLIC_URL")
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

        def do_GET(self) -> None:
            if not self._host_ok():
                return
            p = self._target()
            if p is None:
                return
            try:
                if p == "/":
                    return self._static("index.html")
                if p.startswith("/static/"):
                    return self._static(p[len("/static/"):])
                if p == "/healthz":
                    m = self._meta()
                    ok = m["last_poll_ok"] and not m["stale"]
                    return self._json({"ok": ok, **m}, 200 if ok else 503)
                if p == "/api/devices":
                    return self._json({"meta": self._meta(), "devices": db.devices()})
                if p == "/api/devices.csv":
                    return self._csv()
                if p == "/api/status":
                    return self._json({"meta": self._meta()})
                if p == "/api/stats":
                    return self._json({"meta": self._meta(), "stats": db.stats(cfg.new_days)})
                if p == "/api/events":
                    return self._json({"events": db.events(limit=300)})
                m = re.match(r"^/api/devices/([0-9a-f:]{17})$", p)
                if m:
                    if not MAC_RE.match(m.group(1)):
                        return self._error(400, "bad mac")
                    out = db.device_detail(m.group(1))
                    if not out:
                        return self._error(404, "unknown device")
                    return self._json(out)
                return self._error(404, "not found")
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception:
                log.exception("GET %s failed", p)
                return self._error(500, "internal error")

        def do_POST(self) -> None:
            if not self._host_ok():
                return
            p = self._target()
            if p is None:
                return
            m = re.match(r"^/api/devices/([0-9a-f:]{17})$", p)
            if not m:
                return self._error(404, "not found")
            mac = m.group(1)
            if not MAC_RE.match(mac):
                return self._error(400, "bad mac")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length <= 0 or length > MAX_BODY:
                return self._error(400, "bad body")
            ctype = self.headers.get("Content-Type", "")
            if ctype.split(";", 1)[0].strip().lower() != "application/json":  # exact media type: keeps POSTs out of CORS "simple requests"
                return self._error(415, "json only")
            if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
                return self._error(403, "cross-site request")
            try:
                raw = self.rfile.read(length)
            except OSError:  # the client reset or hung up mid-body: no one is left to answer
                self.close_connection = True
                return
            try:
                body = json.loads(raw.decode())
                if not isinstance(body, dict):
                    raise ValueError
            except (ValueError, UnicodeDecodeError, RecursionError):  # RecursionError: deeply nested arrays like "[[[[..."
                return self._error(400, "bad json")
            acked = body.get("acked")
            name = body.get("name")
            note = body.get("note")
            if acked is not None and not isinstance(acked, bool):
                return self._error(400, "acked must be boolean")
            if name is not None and not isinstance(name, str):
                return self._error(400, "name must be a string")
            if note is not None and not isinstance(note, str):
                return self._error(400, "note must be a string")
            for field, s in (("name", name), ("note", note)):
                try:
                    if s is not None:
                        s.encode("utf-8")
                except UnicodeEncodeError:  # lone surrogate ("\ud800") from JSON escapes: SQLite and the response encoder would fail on it
                    # the JSON itself is valid, so "bad json" would point the user at the wrong cause
                    return self._error(400, f"{field} must be valid Unicode text")
            try:
                d = db.update_user_fields(mac, acked, name, note)
            except Exception:
                log.exception("POST %s failed", p)
                return self._error(500, "internal error")
            if not d:
                return self._error(404, "unknown device")
            return self._json({"device": d})

        def _csv(self) -> None:
            buf = io.StringIO()
            w = csv.writer(buf)
            def cell(v: object) -> str:  # neutralise spreadsheet formula injection (hostnames come from untrusted DHCP clients)
                s = str(v)
                s = _CSV_SEMI_FORMULA.sub(lambda m: m.group() + "'", s)
                return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
            def ts(t: int | None) -> str:
                return time.strftime("%Y-%m-%dT%H:%M%z", time.localtime(t)) if t else ""  # ISO 8601 with the server's UTC offset
            w.writerow(["mac", "ip", "name", "hostname", "vendor", "vlan", "lease_type", "sources", "online", "link", "switch_port", "via", "loc_source", "wifi_ssid", "wifi_ap", "wifi_signal", "first_seen", "last_online", "last_listed", "acked", "note"])
            for d in db.devices():
                w.writerow([d["mac"], d["ip"], cell(d["name"]), cell(d["hostname"]), cell(d["vendor"]), d["vlan"], d["lease_type"], d["sources"], d["online"],
                            d["link"], cell(d["sw_port"]), cell(d["sw_via"]), cell(d["loc_source"]), cell(d["wifi_ssid"]), cell(d["wifi_ap"]), d["wifi_signal"] if d["wifi_signal"] is not None else "",
                            ts(d["first_seen"]), ts(d["last_online"]), ts(d["last_seen"]), d["acked"], cell(d["note"])])
            self._send(200, buf.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8", {"Content-Disposition": 'attachment; filename="leasewatch-devices.csv"'})

    return Handler


class Server(ThreadingHTTPServer):
    request_queue_size = 128  # socketserver's default backlog of 5 drops connections under a burst (3 per page load)
    daemon_threads = True


def serve(cfg: Config, db: Database, version: str) -> ThreadingHTTPServer:
    srv = Server((cfg.listen_host, cfg.listen_port), make_handler(cfg, db, version))
    log.info("listening on http://%s:%d", cfg.listen_host, cfg.listen_port)
    return srv
