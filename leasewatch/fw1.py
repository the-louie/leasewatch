"""Read DHCP leases and the ARP table from an OPNsense firewall through its REST API.

Only read-only endpoints are used: the DHCPv4 lease list (ISC, Kea or dnsmasq, the instance's dhcp_backend setting),
under Kea also the reservation search, and the ARP table. The API user needs the matching DHCP privilege and "Diagnostics: ARP Table".
"""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("leasewatch.fw1")
LEASE_ROWS = 5000
MAX_BODY = 32 * 1024 * 1024  # a lease/ARP list is a few MB at most; anything larger is not a sane answer
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class Fw1Error(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a 3xx: a redirect would resend the Basic auth header (and the POST) to wherever it points."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _s(v: Any) -> str:
    """API fields are meant to be strings, but a null or a number must not crash the poll."""
    return "" if v is None else str(v).strip()


@dataclass
class Sighting:
    """One observation of a device, from DHCP or ARP, normalised."""
    mac: str
    ip: str
    hostname: str
    vendor: str
    vlan: str          # human name of the interface (LAN, IOT, ...)
    iface: str         # OPNsense identifier (opt3, ...)
    source: str        # "dhcp" | "arp"
    lease_type: str    # "dynamic" | "static" | "" (arp only)
    online: bool


def _reserved(v: Any) -> bool:
    """is_reserved was a "1"/"0" string up to OPNsense 26.1.4 and is a list of matched keys (e.g. ["hwaddr"]) from
    26.1.5; str() of an empty list is "[]", which would read as reserved."""
    if isinstance(v, (list, tuple)):
        return len(v) > 0
    return _s(v).lower() not in ("", "0", "false", "no")


def norm_mac(mac: str) -> str:
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else ""


def isc_leases(rows: list[dict]) -> list[dict]:
    """ISC DHCPv4 rows (/api/dhcpv4/leases/searchLease), active leases only, in the common shape:
    mac, address, hostname, man, if, if_descr, type ("dynamic"/"static"), status ("online"/...)."""
    out = []
    for l in rows:
        if not isinstance(l, dict) or l.get("state") not in (None, "", "active"):
            continue
        out.append({**l, "hostname": _s(l.get("hostname")) or _s(l.get("client-hostname"))})
    return out


def kea_leases(rows: list[dict]) -> list[dict]:
    """Kea DHCPv4 rows (/api/kea/leases4/search) in the common shape. Kea names the MAC "hwaddr", the lease state is
    numeric (0 = default/active, 1 = declined, 2 = expired-reclaimed), hostnames may be FQDNs with a trailing dot,
    and reservations are flagged "is_reserved" (newer OPNsense also sends a precomputed "lease_type", preferred).
    Kea has no online status: ARP decides. "if" is the device (vlan0110), "if_name" the identifier (opt3): the
    identifier goes to "if" for parity with ISC, the device to "if_dev" so ignore_interfaces can still name it.
    Kea always sends "state" as an int; a row with "state": null is malformed and is treated as not active."""
    out = []
    for l in rows:
        if not isinstance(l, dict) or str(l.get("state", "0")).strip() not in ("", "0"):
            continue
        lease_type = _s(l.get("lease_type")).lower()
        if not lease_type:
            lease_type = "static" if _reserved(l.get("is_reserved")) else "dynamic"
        out.append({
            "mac": _s(l.get("hwaddr")) or _s(l.get("mac")), "address": _s(l.get("address")),
            "hostname": _s(l.get("hostname")).rstrip("."), "man": _s(l.get("mac_info")) or _s(l.get("man")),
            "if": _s(l.get("if_name")) or _s(l.get("if")), "if_descr": _s(l.get("if_descr")), "if_dev": _s(l.get("if")),
            "type": lease_type, "status": "",
        })
    return out


def dnsmasq_leases(rows: list[dict], now: float) -> list[dict]:
    """dnsmasq rows (/api/dnsmasq/leases/search) in the common shape. They use the Kea key names but have no "state"
    (every listed lease counts as active, kea_leases' default), write "*" for an empty hostname, and include IPv6 leases, which leasewatch does not track. Their client id
    ("*" when empty too) is not read: kea_leases keeps no client id, as Sighting.client_id is not used by this
    backend. As in the contrib dnsmasq_leases connector, skipped: a hardware address with a type prefix
    ("<type>-<bytes>": not Ethernet, or empty; norm_mac would turn a 5-byte one into a fake MAC) and a lease whose
    "expire" is not 0 (infinite) and not after `now` (dnsmasq prunes it only later)."""
    out = []
    for l in rows:
        if not isinstance(l, dict) or ":" in _s(l.get("address")) or "-" in _s(l.get("hwaddr")):
            continue
        try:
            expire = int(l.get("expire") or 0)
        except (TypeError, ValueError):  # a malformed expiry says nothing about the lease; keep it as before
            expire = 0
        if expire and expire <= now:
            continue
        out.append({**l, "hostname": ""} if _s(l.get("hostname")) == "*" else l)
    return kea_leases(out)


def kea_reservations(rows: list[dict], cidr_map: dict) -> list[dict]:
    """Kea reservation rows (/api/kea/dhcpv4/searchReservation) in the common lease shape. Unlike ISC static
    mappings, a Kea reservation without an active lease is not in the lease list, so it is read separately.
    Kea subnets carry no interface: cidr_map (CIDR text -> (if, if_descr, if_dev)) supplies it; unknown -> ""."""
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        ifc, descr, dev = cidr_map.get(_s(r.get("subnet")), ("", "", ""))
        out.append({
            "mac": _s(r.get("hw_address")), "address": _s(r.get("ip_address")),
            "hostname": _s(r.get("hostname")).rstrip("."), "man": "",
            "if": ifc, "if_descr": descr, "if_dev": dev, "type": "static", "status": "",
        })
    return out


def _net(text: str):
    """A reservation subnet as an ip_network, or None when it is not a valid CIDR."""
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _addr(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _cidr_map(reservations: list, lease_rows: list[dict], arp: list) -> dict:
    """Map each reservation subnet to the interface of a lease (first wins), else of an ARP entry, in that subnet."""
    nets = {}
    for r in reservations:
        if isinstance(r, dict):
            text = _s(r.get("subnet"))
            net = _net(text) if text else None
            if net is not None:
                nets[text] = net
    out: dict = {}
    for l in lease_rows:
        ip = _addr(_s(l.get("address"))) if _s(l.get("address")) else None
        for text, net in nets.items():
            if ip is not None and text not in out and ip in net:
                out[text] = (_s(l.get("if")), _s(l.get("if_descr")), _s(l.get("if_dev")))
    for a in arp:
        if not isinstance(a, dict):
            continue
        ip = _addr(_s(a.get("ip"))) if _s(a.get("ip")) else None
        for text, net in nets.items():
            if ip is not None and text not in out and ip in net:
                out[text] = ("", _s(a.get("intf_description")), _s(a.get("intf")))
    return out


class Fw1Client:
    def __init__(self, url: str, key: str, secret: str, verify_tls: bool = True, timeout: int = 20, dhcp_backend: str = "isc",
                 use_env_proxy: bool = False):
        self.url = url.rstrip("/")
        self.dhcp_backend = dhcp_backend
        self.timeout = timeout
        token = base64.b64encode(f"{key}:{secret}".encode()).decode()
        self._auth = f"Basic {token}"
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        # build_opener uses _NoRedirect in place of the default redirect handler. An empty ProxyHandler ignores
        # http(s)_proxy: the firewall is on the LAN, and a proxy would see the Basic auth header (the instance's proxy
        # setting turns it on).
        handlers = [_NoRedirect(), urllib.request.HTTPSHandler(context=self._ctx)]
        if not use_env_proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    def _call(self, path: str, body: dict | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        try:
            req = urllib.request.Request(self.url + path, data=data, method="POST" if data is not None else "GET")
        except ValueError as e:  # e.g. an unclosed "[" in the URL; the message would only repeat the URL
            raise Fw1Error(f"fw1 {path}: bad URL") from e
        req.add_header("Authorization", self._auth)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise Fw1Error(f"fw1 {path}: response too large")
            return json.loads(raw.decode())
        except urllib.error.HTTPError as e:
            e.close()  # the error carries the open response; release its socket
            raise Fw1Error(f"fw1 {path}: HTTP {e.code}") from e
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ssl.SSLError, OSError) as e:
            raise Fw1Error(f"fw1 {path}: {e}") from e
        except (ValueError, RecursionError) as e:  # ValueError covers UnicodeDecodeError and JSONDecodeError
            raise Fw1Error(f"fw1 {path}: invalid JSON ({type(e).__name__})") from e

    # --- raw ---------------------------------------------------------------
    def leases_raw(self) -> list[dict]:
        # dhcp_backend comes from the instance's dhcp_backend setting (default kea); this class's own "isc" default only applies when built directly
        path = {"kea": "/api/kea/leases4/search", "dnsmasq": "/api/dnsmasq/leases/search"}.get(
            self.dhcp_backend, "/api/dhcpv4/leases/searchLease")
        r = self._call(path, {"current": 1, "rowCount": LEASE_ROWS})
        if not isinstance(r, dict) or not isinstance(r.get("rows"), list):
            raise Fw1Error("fw1 leases: unexpected response shape")
        try:
            total = int(r.get("total") or 0)
        except (TypeError, ValueError, OverflowError):  # OverflowError: a JSON 1e999 or Infinity
            total = 0
        if total > len(r["rows"]):
            log.warning("lease list truncated: %d of %d rows (raise LEASE_ROWS)", len(r["rows"]), total)
        return r["rows"]

    def reservations_raw(self) -> list[dict]:
        """Kea reservations; a read-only search, POSTed like the lease search."""
        r = self._call("/api/kea/dhcpv4/searchReservation", {"current": 1, "rowCount": LEASE_ROWS})
        if not isinstance(r, dict) or not isinstance(r.get("rows"), list):
            raise Fw1Error("fw1 reservations: unexpected response shape")
        try:
            total = int(r.get("total") or 0)
        except (TypeError, ValueError, OverflowError):  # OverflowError: a JSON 1e999 or Infinity
            total = 0
        if total > len(r["rows"]):
            log.warning("reservation list truncated: %d of %d rows (raise LEASE_ROWS)", len(r["rows"]), total)
        return r["rows"]

    def arp_raw(self) -> list[dict]:
        r = self._call("/api/diagnostics/interface/get_arp")
        if isinstance(r, dict):
            r = r.get("rows", r.get("data"))
        if not isinstance(r, list):
            raise Fw1Error("fw1 arp: unexpected response shape")
        return r

    # --- normalised --------------------------------------------------------
    def sightings(self, ignore_interfaces: tuple = ()) -> tuple[list[Sighting], dict]:
        """Return (sightings, stats). Raises Fw1Error if the lease or ARP call fails; the Kea reservation search is best-effort.

        ignore_interfaces matches (case-insensitively) the OPNsense identifier (opt3), the device (vlan0110, igc4)
        or the description (Klienter, WAN), because leases and ARP rows name interfaces differently."""
        ign = {_s(x).lower() for x in ignore_interfaces if _s(x)}
        skip = lambda *names: any(_s(n).lower() in ign for n in names)
        leases = self.leases_raw()
        reservations = None
        if self.dhcp_backend == "kea":
            # reservations only add lease-less devices; an API key without that privilege must not stop the poll
            try:
                reservations = self.reservations_raw()
            except Fw1Error as e:
                log.warning("reservations unavailable, listing leases only: %s", e)
        arp = self.arp_raw()
        try:
            return self._sightings(leases, arp, skip, reservations)
        except (TypeError, AttributeError, KeyError) as e:
            raise Fw1Error("fw1: unexpected field type in leases/arp") from e

    def _sightings(self, leases: list, arp: list, skip, reservations: list | None = None) -> tuple[list[Sighting], dict]:
        out: list[Sighting] = []
        if self.dhcp_backend == "dnsmasq":
            lease_rows = dnsmasq_leases(leases, time.time())  # the clock read here keeps the parser pure
        else:
            lease_rows = {"kea": kea_leases}.get(self.dhcp_backend, isc_leases)(leases)
        if reservations:
            # an active lease already carries what its reservation says; only lease-less reservations are added
            leased = {norm_mac(_s(l.get("mac"))) for l in lease_rows}
            lease_rows = lease_rows + [r for r in kea_reservations(reservations, _cidr_map(reservations, lease_rows, arp))
                                       if norm_mac(_s(r.get("mac"))) not in leased]
        for l in lease_rows:
            mac = norm_mac(_s(l.get("mac")))
            if not mac or skip(l.get("if"), l.get("if_dev"), l.get("if_descr")):
                continue
            lease_type = _s(l.get("type")).lower() or "dynamic"
            if lease_type not in ("dynamic", "static"):
                lease_type = "dynamic"  # the UI filters know only those two
            out.append(Sighting(
                mac=mac, ip=_s(l.get("address")),
                hostname=_s(l.get("hostname")),
                vendor=_s(l.get("man")),
                vlan=_s(l.get("if_descr")) or _s(l.get("if")), iface=_s(l.get("if")),
                source="dhcp", lease_type=lease_type,
                online=l.get("status") == "online",
            ))
        for a in arp:
            if not isinstance(a, dict):
                continue
            mac = norm_mac(_s(a.get("mac")))
            if not mac or a.get("permanent") or a.get("expired"):
                continue
            iface = _s(a.get("intf"))
            if skip(iface, a.get("intf_description")):
                continue
            out.append(Sighting(
                mac=mac, ip=_s(a.get("ip")), hostname=_s(a.get("hostname")),
                vendor=_s(a.get("manufacturer")),
                vlan=_s(a.get("intf_description")) or iface, iface=iface,
                source="arp", lease_type="", online=True,
            ))
        stats = {"leases": len(leases), "arp": len(arp)}
        if reservations is not None:
            stats["reservations"] = len(reservations)
        return out, stats
