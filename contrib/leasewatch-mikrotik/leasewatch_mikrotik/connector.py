"""MikroTik RouterOS 7 as a connector: DHCPv4 leases and the ARP table, read through the REST API.

Read-only: three GET requests per poll (`/rest/ip/dhcp-server`, `/rest/ip/dhcp-server/lease`, `/rest/ip/arp`),
plus one GET of `/rest/system/resource` as the probe. HTTP Basic auth, no redirects followed.

Built from the RouterOS 7 documentation, not against a real router. The lease keys `host-name`, `dynamic`,
`disabled`, `active-address`, `active-mac-address` and `active-client-id` are not in the documented lease table,
and RouterOS appears to leave out empty properties, so every key except the MAC is optional here: a missing key
reads as empty (or as the flag's documented default), never as an error.
"""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from leasewatch.connectors import (API_VERSION, Batch, ConnectorError, ConnectorInfo, HostContext, Setting,
                                   SettingsMixin, Sighting, make_redactor, parse_bool, url_problems)

log = logging.getLogger("leasewatch.contrib.mikrotik")

MAX_BODY = 32 * 1024 * 1024  # as fw1: a lease/ARP list is a few MB at most
MAX_ERROR_BODY = 64 * 1024  # an error answer is one small JSON object
MAX_ERROR_TEXT = 300  # characters of an error text kept, cut only after redaction and host masking
REQUEST_TIMEOUT = 30  # seconds per request; RouterOS itself cuts a command after 60 s

PATH_SERVERS = "/rest/ip/dhcp-server?.proplist=name,interface"
PATH_LEASES = ("/rest/ip/dhcp-server/lease?.proplist=address,mac-address,active-address,active-mac-address,"
               "client-id,active-client-id,host-name,server,status,dynamic,disabled")
PATH_ARP = "/rest/ip/arp?.proplist=address,mac-address,interface,complete,invalid,disabled,published,status"
PATH_PROBE = "/rest/system/resource?.proplist=version"

# ARP states in which RouterOS sets `complete` (MikroTik ARP docs); used only when `complete` itself is absent
COMPLETE_STATES = frozenset({"reachable", "stale", "delay", "probe", "permanent"})
# as db.py's _CTRL, plus tab and newline: also the Unicode line/paragraph separators and the bidi and zero-width
# controls, which split or reorder a line in a viewer as a newline would
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b\u200e\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\u061c\ufeff]+")


def _s(v: Any) -> str:
    """RouterOS sends every value as a string; anything else from a changed firmware must not crash the poll.
    Any non-string (null, number, boolean, list, object) is no value at all: "", so it never shadows the configured
    value. A number is not kept: 0 or NaN (json.loads accepts it) as an active-* value would hide the real MAC/IP."""
    return v.strip() if isinstance(v, str) else ""


def flag(row: Mapping[str, Any], key: str) -> bool | None:
    """A RouterOS yes/no property: "true" -> True, "false" -> False, absent or empty -> None. Any other value
    raises ValueError (the row is dropped): "yes", "1" or a typo are not what the REST API documents."""
    v = row.get(key)
    if v is None or v == "":
        return None
    if isinstance(v, bool):  # a JSON boolean is unambiguous even if RouterOS does not send one today
        return v
    if v == "true":
        return True
    if v == "false":
        return False
    raise ValueError(key)


def server_interfaces(servers: list) -> dict[str, str]:
    """DHCP server name -> its interface. Rows without a name are skipped. A relay server's interface is the
    one it listens on, not the clients' segment; it is used as it is."""
    out: dict[str, str] = {}
    for r in servers:
        if isinstance(r, dict) and _s(r.get("name")):
            out[_s(r.get("name"))] = _s(r.get("interface"))
    return out


def parse(servers: list, leases: list, arp: list, now: int,
          ignore: frozenset[str] = frozenset()) -> tuple[list[Sighting], int]:
    """The sightings in RouterOS's answers, and how many rows were dropped as malformed.

    Leases: only status "bound" and not disabled; the active-* values win over the configured ones (a static lease
    may be configured for one address and bound to another); lease type static when `dynamic` is "false", else
    dynamic (also when `dynamic` is absent). network and iface are the interface of the lease's server, or empty
    when the server is unknown. ARP: complete (or, without `complete`, a status that implies it), not invalid,
    not disabled, not published (a proxy-ARP entry is the router's own answer) and not "permanent" (a static entry
    says nothing about the wire) -> presence True. A row on an interface in `ignore` (lower-case names; for a lease
    also its server name) is skipped. Dropped and counted: a row that is not an object or has a flag that is not
    "true"/"false". Skipped without counting: other leases and ARP entries, and rows without a MAC. Never raises."""
    ifaces = server_interfaces(servers)
    out: list[Sighting] = []
    dropped = 0
    for r in leases:
        if not isinstance(r, dict):
            dropped += 1
            continue
        try:
            disabled, dynamic = flag(r, "disabled"), flag(r, "dynamic")
        except ValueError:
            dropped += 1
            continue
        if _s(r.get("status")).lower() != "bound" or disabled:
            continue
        mac = _s(r.get("active-mac-address")) or _s(r.get("mac-address"))
        if not mac:
            continue
        server = _s(r.get("server"))
        iface = ifaces.get(server, "")
        if iface.lower() in ignore or server.lower() in ignore:
            continue
        out.append(Sighting(mac=mac, source="", kind="dhcp", presence=False, observed_at=now,
                            ip=_s(r.get("active-address")) or _s(r.get("address")), hostname=_s(r.get("host-name")),
                            network=iface, iface=iface, lease_type="static" if dynamic is False else "dynamic",
                            client_id=_s(r.get("active-client-id")) or _s(r.get("client-id"))))
    for r in arp:
        if not isinstance(r, dict):
            dropped += 1
            continue
        try:
            complete, invalid = flag(r, "complete"), flag(r, "invalid")
            disabled, published = flag(r, "disabled"), flag(r, "published")
        except ValueError:
            dropped += 1
            continue
        status = _s(r.get("status")).lower()
        if complete is None:
            complete = status in COMPLETE_STATES
        if not complete or invalid or disabled or published or status == "permanent":
            continue
        mac = _s(r.get("mac-address"))
        iface = _s(r.get("interface"))
        if not mac or iface.lower() in ignore:
            continue
        out.append(Sighting(mac=mac, source="", kind="arp", presence=True, observed_at=now,
                            ip=_s(r.get("address")), network=iface, iface=iface))
    return out, dropped


def _host_forms(url: str) -> set[str]:
    """Spellings of the router's host in an error text: as given, lower-case, without a trailing dot, its IDNA
    form, and an IPv6 address compressed and exploded."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return set()
    forms = {host, host.rstrip(".")}
    try:
        forms.add(host.encode("idna").decode("ascii").lower().rstrip("."))
    except UnicodeError:  # a label idna cannot encode is never connected to
        pass
    try:
        ip = ipaddress.ip_address(host)
        forms |= {ip.compressed, ip.exploded}
    except ValueError:
        pass
    return {f for f in forms if len(f) >= 2}


def make_host_mask(url: str) -> Callable[[str], str]:
    """A function that replaces whole occurrences of the router's host by "<host>" ("10.0.0.1" is not "10.0.0.15").
    The router's address is internal infrastructure, not for the UI; ssl's hostname-mismatch text echoes it."""
    forms = _host_forms(url)
    if not forms:
        return lambda text: text
    rxs = []
    # not inside a name or number on either side; an IPv6 form must also not touch another ":" group
    # ("fe80::2" is not "fe80::2:5"), for the others a ":" is the port
    for group, colon in (([f for f in forms if ":" not in f], ""), ([f for f in forms if ":" in f], ":")):
        if group:
            alts = "|".join(re.escape(f) for f in sorted(group, key=len, reverse=True))
            ahead = r"(?![\w-]|\.\w|:(?::|[0-9a-f]{1,4}(?!\w)))" if colon else r"(?![\w-]|\.\w)"
            rxs.append(re.compile(rf"(?<![\w.{colon}-])(?:{alts}){ahead}", re.I))

    def mask(text: str) -> str:
        for rx in rxs:
            text = rx.sub("<host>", text)
        return text
    return mask


def _clean(text: str) -> str:
    """One line: control characters out, so a router answer cannot forge log lines. A text longer than
    MAX_ERROR_TEXT characters is cut to MAX_ERROR_TEXT characters plus "...". Only _error calls it, after redaction and masking: a cut first would leave a part of a secret or host
    that no longer matches."""
    text = _CTRL_RE.sub(" ", text).strip()
    return text if len(text) <= MAX_ERROR_TEXT else text[:MAX_ERROR_TEXT] + "..."


def _http_error_text(e: urllib.error.HTTPError) -> str:
    """ "HTTP <code>", a hint for 401/403, and RouterOS's `message`/`detail` when the body is its error object."""
    out = f"HTTP {e.code}"
    if e.code == 401:
        out += " (wrong USER or PASSWORD)"
    elif e.code == 403:
        out += " (the user's group needs the read and rest-api policies)"
    try:
        body = json.loads(e.read(MAX_ERROR_BODY + 1)[:MAX_ERROR_BODY].decode("utf-8"))
    except Exception:  # any: the body is a courtesy; a broken or non-JSON one changes nothing
        body = None
    if isinstance(body, dict):
        # raw: _error redacts, masks, then cleans and cuts the whole text. A message so long that it pushes the
        # detail past the cut loses the detail; cutting each part on its own first would cut before redaction and
        # masking, and a secret or host split by the cut would leak. RouterOS's message is a short reason phrase.
        parts = [_s(body.get(k)) for k in ("message", "detail") if isinstance(body.get(k), str)]
        parts = [p for p in parts if _CTRL_RE.sub("", p).strip()]
        if parts:
            out += ": " + "; ".join(parts)
    return out


def _os_error_text(e: BaseException) -> str:
    """What went wrong at the network or TLS level, without a stack of nested reprs. Raw: _error cleans and cuts."""
    if isinstance(e, ssl.SSLCertVerificationError):
        return f"TLS certificate not accepted ({getattr(e, 'verify_message', None) or 'verify failed'}); set VERIFY_TLS=0 for a self-signed certificate"
    if isinstance(e, ssl.SSLError):
        # .reason is set only on errors ssl itself raises; strerror carries the text of a hand-built one
        return f"TLS error ({getattr(e, 'reason', None) or e.strerror or type(e).__name__})"
    if isinstance(e, (TimeoutError, socket.timeout)):
        return "timed out"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused (is the www-ssl service enabled?)"
    if isinstance(e, socket.gaierror):
        return "host name not resolved"
    if isinstance(e, OSError) and e.strerror:
        return str(e.strerror)
    return type(e).__name__


class MikrotikConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="mikrotik", version="0.1", api_version=API_VERSION, produces=frozenset({"sighting"}),
        settings=(
            Setting("url", required=True, help="https://<router> (the www-ssl service)"),
            Setting("user", required=True, help="RouterOS user in a group with the read and rest-api policies"),
            Setting("password", required=True, secret=True, help="that user's password"),
            Setting("verify_tls", default="1", help="check the router's certificate"),
            Setting("ignore_interfaces", default="", help="comma-separated interface or DHCP server names to skip"),
            Setting("proxy", default="0", help="honour http(s)_proxy for this connection"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None) -> None:
        self._init_settings(name, settings, ctx)
        self.url = self.settings["url"].rstrip("/")
        self.ignore = frozenset(x.strip().lower() for x in self.settings["ignore_interfaces"].split(",") if x.strip())
        self._mask_host = make_host_mask(self.settings["url"])
        self._redact = make_redactor([self.settings["password"]])

    def validate(self) -> list[str]:
        problems = self._generic_problems()
        if self.settings["url"]:
            found = url_problems("url", self.settings["url"], "https://<router>")
            if not found and not self.settings["url"].lower().startswith("https://"):
                # Basic auth sends the password with every request; plain http (the www service) would expose it
                found.append("url must start with https:// (the www-ssl service)")
            if not found and ("?" in self.settings["url"] or "#" in self.settings["url"]):
                # every request path is appended to the URL; after a "?" or "#" it would become query or fragment
                # data and the router would answer with its web page. A path is allowed (a reverse proxy prefix)
                found.append("url must not contain a query (?) or fragment (#)")
            problems += found
        if ":" in self.settings["user"]:
            problems.append("user must not contain ':' (HTTP Basic auth cannot carry it)")
        for key in ("verify_tls", "proxy"):
            if parse_bool(self.settings[key]) is None:
                problems.append(f"{key} must be a boolean (1/0, true/false, yes/no, on/off)")
        return problems

    def _error(self, path: str, text: str) -> ConnectorError:
        """The one way out, in this order: the password (also when the router echoes it) and, through the host's
        redactor, the secrets of every instance redacted; then the host masked; then control characters out and
        the text cut. Redaction before masking: a secret that contains the host name would no longer match once
        the host is masked. Both before the cut: a secret or host cut in two would not match at all."""
        text = _clean(self._mask_host(self.ctx.redact(self._redact(text))))
        # only the text is masked: a host named "rest" must not mask the path, which is a constant of this module
        return ConnectorError(f"mikrotik {path.split('?', 1)[0]}: {text}")

    def _get(self, path: str) -> Any:
        """One GET, its body parsed as JSON. Raises ConnectorError."""
        verify, proxy = parse_bool(self.settings["verify_tls"]), parse_bool(self.settings["proxy"])
        try:
            req = urllib.request.Request(self.url + path, method="GET")
        except ValueError:  # e.g. an unclosed "[" in the URL; the message would only repeat it
            raise self._error(path, "bad URL") from None
        token = base64.b64encode(f"{self.settings['user']}:{self.settings['password']}".encode("utf-8")).decode("ascii")
        req.add_header("Authorization", f"Basic {token}")
        req.add_header("Accept", "application/json")
        timeout = max(1, min(self.ctx.timeout, REQUEST_TIMEOUT))
        try:
            # the opener never follows a redirect (it would resend the Authorization header) and ignores
            # http(s)_proxy unless PROXY is on (a proxy would see that header)
            opener = self.ctx.opener_factory(verify_tls=True if verify is None else verify, use_env_proxy=bool(proxy))
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_BODY + 1)
        except urllib.error.HTTPError as e:
            try:
                text = _http_error_text(e)
            finally:
                e.close()  # the error carries the open response; release its socket
            raise self._error(path, text) from None
        except urllib.error.URLError as e:
            reason = e.reason if isinstance(e.reason, BaseException) else None
            raise self._error(path, _os_error_text(reason) if reason else _s(e.reason)) from None
        except (http.client.HTTPException, OSError) as e:  # OSError covers ssl.SSLError and TimeoutError
            raise self._error(path, _os_error_text(e)) from None
        except UnicodeError:
            # the IDNA codec refuses the host ("label too long"), or http.client cannot encode a non-ASCII path
            # as ASCII; validate() catches neither, and which part failed is not known here, so neither is named
            raise self._error(path, "bad URL (not valid as ASCII/IDNA)") from None
        if len(raw) > MAX_BODY:
            raise self._error(path, f"response larger than {MAX_BODY // (1024 * 1024)} MiB")
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):  # ValueError covers UnicodeDecodeError and JSONDecodeError
            raise self._error(path, "response is not JSON (is URL the router's www-ssl service?)") from None

    def _get_list(self, path: str) -> list:
        r = self._get(path)
        if not isinstance(r, list):
            raise self._error(path, "unexpected response shape (not a list)")
        return r

    def check(self) -> None:
        self._get(PATH_PROBE)

    def collect(self) -> Batch:
        servers = self._get_list(PATH_SERVERS)
        leases = self._get_list(PATH_LEASES)
        arp = self._get_list(PATH_ARP)
        sightings, dropped = parse(servers, leases, arp, self.ctx.now(), self.ignore)
        if dropped:
            log.debug("connector %s: %d rows dropped", self.name, dropped)
        return Batch(sightings=sightings, stats={"leases": len(leases), "arp": len(arp), "dropped": dropped})

    def close(self) -> None:
        pass  # each request opens and closes its own connection
