"""Read DHCP leases and the ARP table from an OPNsense firewall through its REST API.

Only two read-only endpoints are used: the DHCPv4 lease list (ISC or Kea, see DHCP_BACKEND) and the ARP table.
The API user needs just the matching leases privilege and "Diagnostics: ARP Table".
"""
from __future__ import annotations

import base64
import http.client
import json
import logging
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("leasewatch.fw1")
LEASE_ROWS = 5000
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class Fw1Error(Exception):
    pass


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


def norm_mac(mac: str) -> str:
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else ""


def isc_leases(rows: list[dict]) -> list[dict]:
    """ISC DHCPv4 rows (/api/dhcpv4/leases/searchLease), active leases only, in the common shape:
    mac, address, hostname, man, if, if_descr, type ("dynamic"/"static"), status ("online"/...)."""
    out = []
    for l in rows:
        if l.get("state") not in (None, "", "active"):
            continue
        out.append({**l, "hostname": l.get("hostname") or l.get("client-hostname") or ""})
    return out


def kea_leases(rows: list[dict]) -> list[dict]:
    """Kea DHCPv4 rows (/api/kea/leases4/search) in the common shape. Kea names the MAC "hwaddr", the lease state is
    numeric (0 = default/active, 1 = declined, 2 = expired-reclaimed), hostnames may be FQDNs with a trailing dot,
    and reservations are flagged "is_reserved". Kea has no online status: ARP decides."""
    out = []
    for l in rows:
        if str(l.get("state", "0")).strip() not in ("", "0"):
            continue
        reserved = str(l.get("is_reserved") or "").strip().lower() not in ("", "0", "false", "no")
        out.append({
            "mac": l.get("hwaddr") or l.get("mac") or "", "address": l.get("address") or "",
            "hostname": (l.get("hostname") or "").strip().rstrip("."), "man": l.get("man") or l.get("mac_info") or "",
            "if": l.get("if") or "", "if_descr": l.get("if_descr") or "",
            "type": "static" if reserved else "dynamic", "status": "",
        })
    return out


class Fw1Client:
    def __init__(self, url: str, key: str, secret: str, verify_tls: bool = True, timeout: int = 20, dhcp_backend: str = "isc"):
        self.url = url.rstrip("/")
        self.dhcp_backend = dhcp_backend
        self.timeout = timeout
        token = base64.b64encode(f"{key}:{secret}".encode()).decode()
        self._auth = f"Basic {token}"
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _call(self, path: str, body: dict | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method="POST" if data is not None else "GET")
        req.add_header("Authorization", self._auth)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise Fw1Error(f"fw1 {path}: HTTP {e.code}") from e
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ssl.SSLError, json.JSONDecodeError, OSError) as e:
            raise Fw1Error(f"fw1 {path}: {e}") from e

    # --- raw ---------------------------------------------------------------
    def leases_raw(self) -> list[dict]:
        path = "/api/kea/leases4/search" if self.dhcp_backend == "kea" else "/api/dhcpv4/leases/searchLease"
        r = self._call(path, {"current": 1, "rowCount": LEASE_ROWS})
        if not isinstance(r, dict) or not isinstance(r.get("rows"), list):
            raise Fw1Error("fw1 leases: unexpected response shape")
        try:
            total = int(r.get("total") or 0)
        except (TypeError, ValueError):
            total = 0
        if total > len(r["rows"]):
            log.warning("lease list truncated: %d of %d rows (raise LEASE_ROWS)", len(r["rows"]), total)
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
        """Return (sightings, stats). Raises Fw1Error if either call fails.

        ignore_interfaces matches (case-insensitively) the OPNsense identifier (opt3), the device (vlan0110, igc4)
        or the description (Klienter, WAN), because leases and ARP rows name interfaces differently."""
        ign = {x.strip().lower() for x in ignore_interfaces if x.strip()}
        skip = lambda *names: any((n or "").lower() in ign for n in names)
        leases = self.leases_raw()
        arp = self.arp_raw()
        out: list[Sighting] = []
        lease_rows = kea_leases(leases) if self.dhcp_backend == "kea" else isc_leases(leases)
        for l in lease_rows:
            mac = norm_mac(l.get("mac", ""))
            if not mac or skip(l.get("if"), l.get("if_descr")):
                continue
            out.append(Sighting(
                mac=mac, ip=l.get("address") or "",
                hostname=(l.get("hostname") or "").strip(),
                vendor=(l.get("man") or "").strip(),
                vlan=(l.get("if_descr") or l.get("if") or "").strip(), iface=l.get("if") or "",
                source="dhcp", lease_type=l.get("type") or "dynamic",
                online=l.get("status") == "online",
            ))
        for a in arp:
            mac = norm_mac(a.get("mac", ""))
            if not mac or a.get("permanent") or a.get("expired"):
                continue
            iface = a.get("intf") or ""
            if skip(iface, a.get("intf_description")):
                continue
            out.append(Sighting(
                mac=mac, ip=a.get("ip") or "", hostname=(a.get("hostname") or "").strip(),
                vendor=(a.get("manufacturer") or "").strip(),
                vlan=(a.get("intf_description") or iface).strip(), iface=iface,
                source="arp", lease_type="", online=True,
            ))
        return out, {"leases": len(leases), "arp": len(arp)}
