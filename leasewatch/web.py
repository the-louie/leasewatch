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
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import Config
from .db import Database
from .fw1 import MAC_RE

log = logging.getLogger("leasewatch.web")
STATIC_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "static"))
MAX_BODY = 16 * 1024


def make_handler(cfg: Config, db: Database, version: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "leasewatch"
        sys_version = ""
        timeout = 30  # a client that stalls mid-request does not hold a thread forever

        def log_message(self, fmt, *args):  # quieter access log
            log.debug("%s %s", self.address_string(), fmt % args)

        # --- helpers -------------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(status)
            headers = {"Content-Type": ctype, "Content-Length": str(len(body)), "X-Content-Type-Options": "nosniff",
                       "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}
            headers.update(extra or {})
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, status: int = 200):
            self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _error(self, status: int, msg: str):
            self._json({"error": msg}, status)

        def _static(self, name: str):
            path = os.path.normpath(os.path.join(STATIC_DIR, name))
            if (name == "index.html" and self.path != "/" and not self.path.startswith("/?")) or not path.startswith(STATIC_DIR + os.sep) or not os.path.isfile(path):
                return self._error(404, "not found")
            ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
                ctype += "; charset=utf-8"
            with open(path, "rb") as f:
                body = f.read()
            if name == "index.html":
                body = body.replace(b"{{SITE_NAME}}", html.escape(cfg.site_name).encode()).replace(b"{{VERSION}}", html.escape(version).encode())
            self._send(200, body, ctype, {"Cache-Control": "no-cache"})

        def _meta(self) -> dict:
            m = db.all_meta()
            now = int(time.time())
            last = int(m.get("last_poll_ts") or 0)
            return {
                "now": now, "last_poll_ts": last, "last_poll_age": (now - last) if last else None,
                "last_poll_ok": m.get("last_poll_ok") == "1", "last_error": m.get("last_error", ""),
                "last_error_ts": int(m.get("last_error_ts") or 0) or None, "last_raw": m.get("last_raw", ""),
                "baseline_ts": int(m.get("baseline_ts") or 0) or None, "poll_seconds": cfg.poll_seconds,
                "new_days": cfg.new_days, "site_name": cfg.site_name, "version": version, "mail": cfg.mail_enabled,
                "stale": (now - last) > cfg.poll_seconds * 3 if last else True,
                "switch": {"enabled": cfg.snmp_enabled, "name": cfg.snmp_name, "ok": m.get("switch_ok") == "1", "error": m.get("switch_error", ""), "macs": int(m.get("switch_macs") or 0)},
                "unifi": {"enabled": cfg.unifi_enabled, "ok": m.get("unifi_ok") == "1", "error": m.get("unifi_error", ""), "clients": int(m.get("unifi_clients") or 0)},
            }

        # --- routes --------------------------------------------------------
        def do_HEAD(self):
            self.do_GET()

        def _method_not_allowed(self):
            self._send(405, b'{"error": "method not allowed"}', "application/json; charset=utf-8", {"Allow": "GET, HEAD, POST"})

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _method_not_allowed

        def do_GET(self):
            u = urlparse(self.path)
            p = u.path
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
                if p == "/api/stats":
                    return self._json({"meta": self._meta(), "stats": db.stats(cfg.new_days)})
                if p == "/api/events":
                    return self._json({"events": db.events(limit=300)})
                m = re.match(r"^/api/devices/([0-9a-f:]{17})$", p)
                if m:
                    if not MAC_RE.match(m.group(1)):
                        return self._error(400, "bad mac")
                    d = db.device(m.group(1))
                    if not d:
                        return self._error(404, "unknown device")
                    return self._json({"device": d, "history": db.history(d["mac"]), "events": db.events(d["mac"])})
                return self._error(404, "not found")
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception:
                log.exception("GET %s failed", p)
                return self._error(500, "internal error")

        def do_POST(self):
            p = urlparse(self.path).path
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
                body = json.loads(self.rfile.read(length).decode())
                if not isinstance(body, dict):
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
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
            try:
                d = db.update_user_fields(mac, acked, name, note)
            except Exception:
                log.exception("POST %s failed", p)
                return self._error(500, "internal error")
            if not d:
                return self._error(404, "unknown device")
            return self._json({"device": d})

        def _csv(self):
            buf = io.StringIO()
            w = csv.writer(buf)
            def cell(v):  # neutralise spreadsheet formula injection (hostnames come from untrusted DHCP clients)
                s = str(v)
                return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
            def ts(t):
                return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else ""
            w.writerow(["mac", "ip", "name", "hostname", "vendor", "vlan", "lease_type", "sources", "online", "link", "switch_port", "via", "wifi_ssid", "wifi_ap", "wifi_signal", "first_seen", "last_online", "last_listed", "acked", "note"])
            for d in db.devices():
                w.writerow([d["mac"], d["ip"], cell(d["name"]), cell(d["hostname"]), cell(d["vendor"]), d["vlan"], d["lease_type"], d["sources"], d["online"],
                            d["link"], d["sw_port"], cell(d["sw_via"]), cell(d["wifi_ssid"]), cell(d["wifi_ap"]), d["wifi_signal"] if d["wifi_signal"] is not None else "",
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
