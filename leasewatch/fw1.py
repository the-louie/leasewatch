"""Read DHCP leases and the ARP table from an OPNsense firewall through its REST API.

Only read-only endpoints are used: the DHCPv4 lease list (ISC, Kea or dnsmasq, the instance's dhcp_backend setting),
under Kea also the reservation search, under dnsmasq the static host search, and the ARP table. The API user needs the matching DHCP privilege and "Diagnostics: ARP Table".
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
    source: str        # "dhcp" | "arp" | "ndp"
    lease_type: str    # "dynamic" | "static" | "" (arp only)
    online: bool
    client_id: str = ""  # as the server sends it (ISC: already hex); connectors.merge.norm_client_id normalises it
    label: str = ""  # a Kea reservation's description (an operator-written name), at most LABEL_MAX characters
    ip6: str = ""  # the device's IPv6 address when the source gives one; the host normalises it


LABEL_MAX = 128  # a description is free text; a longer one would only crowd the display name


def _reserved(v: Any) -> bool:
    """is_reserved was a "1"/"0" string up to OPNsense 26.1.4 and is a list of matched keys (e.g. ["hwaddr"]) from
    26.1.5; str() of an empty list is "[]", which would read as reserved."""
    if isinstance(v, (list, tuple)):
        return len(v) > 0
    return _s(v).lower() not in ("", "0", "false", "no")


def norm_mac(mac: str) -> str:
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else ""


def isc_uid(text: str) -> str:
    """dhcpd's lease-file uid (the text between the quotes, with C escapes: \\001 octal, \\" and \\\\) as lowercase hex;
    "" when it is malformed or shorter than 2 bytes. OPNsense's parser splits on whitespace, so a uid with a space
    or \\" may arrive cut short; it is taken as it comes."""
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            octal = re.match(r"[0-7]{3}", text[i + 1:i + 4])
            if octal and int(octal.group(), 8) <= 0xFF:
                out.append(int(octal.group(), 8))
                i += 4
                continue
            if i + 1 >= len(text) or text[i + 1] not in "\\\"":
                return ""
            ch = text[i + 1]
            i += 1
        if ord(ch) > 0x7E or ord(ch) < 0x20:  # dhcpd escapes every non-printable byte
            return ""
        out.append(ord(ch))
        i += 1
    return out.hex() if len(out) >= 2 else ""


def isc_leases(rows: list[dict]) -> list[dict]:
    """ISC DHCPv4 rows (/api/dhcpv4/leases/searchLease), active leases only, in the common shape:
    mac, address, hostname, man, if, if_descr, type ("dynamic"/"static"), status ("online"/...), client_id (hex)."""
    out = []
    for l in rows:
        if not isinstance(l, dict) or l.get("state") not in (None, "", "active"):
            continue
        out.append({**l, "hostname": _s(l.get("hostname")) or _s(l.get("client-hostname")),
                    "client_id": isc_uid(_s(l.get("uid")))})
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
            "type": lease_type, "status": "", "client_id": _s(l.get("client_id")),
        })
    return out


def dnsmasq_leases(rows: list[dict], now: float) -> list[dict]:
    """dnsmasq rows (/api/dnsmasq/leases/search) in the common shape. They use the Kea key names but have no "state"
    (every listed lease counts as active, kea_leases' default), write "*" for an empty hostname and client id, and include IPv6 leases, which leasewatch does not track. As in the contrib dnsmasq_leases connector, skipped: a hardware address with a type prefix
    ("<type>-<bytes>": not Ethernet, or empty; norm_mac would turn a 5-byte one into a fake MAC) and a lease whose
    "expire" is not 0 (infinite) and not after `now` (dnsmasq prunes it only later)."""
    out = []
    for l in rows:
        if not isinstance(l, dict) or ":" in _s(l.get("address")) or "-" in _s(l.get("hwaddr")):
            continue
        try:
            expire = int(l.get("expire") or 0)
        except (TypeError, ValueError, OverflowError):  # a malformed or non-finite expiry says nothing about the lease; keep it as before
            expire = 0
        if expire and expire <= now:
            continue
        out.append({**l, **{k: "" for k in ("hostname", "client_id") if _s(l.get(k)) == "*"}})
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
            # "description" is the field name in the OPNsense Kea reservation model; a row without it gives ""
            "label": _s(r.get("description"))[:LABEL_MAX].strip(),
            "subnet": _s(r.get("subnet")),  # picks the reservation of a leased MAC reserved in several subnets
        })
    return out


def _items(v: Any) -> list[str]:
    """A model list field (ip, hwaddr) as its items: the API may send a list or a comma-joined string."""
    if isinstance(v, (list, tuple)):
        return [x for x in (_s(i) for i in v) if x]
    return [x.strip() for x in _s(v).split(",") if x.strip()]


def _host_ip(row: dict) -> str:
    """The first IPv4 address of a dnsmasq host row's "ip" list; "" when it has none (empty or IPv6 only)."""
    return next((t for t in _items(row.get("ip")) if (a := _addr(t)) is not None and a.version == 4), "")


def _host_net(ip: str) -> str:
    """The /24 around a dnsmasq host's address, its fallback cidr_map key ("" for no address). The hosts model has
    no subnet, so a lease-less host without an exact match (_exact_ifaces) takes the interface of a lease or ARP
    entry in the same /24, which is wrong on a subnet smaller than /24."""
    return str(ipaddress.ip_network(f"{ip}/24", strict=False)) if ip else ""


def _exact_ifaces(lease_rows: list[dict], arp: list) -> dict:
    """Address text -> (if, if_descr, if_dev) of the lease (first wins), else the ARP entry, with that address: the
    interface of a dnsmasq host for sure, so dnsmasq_hosts looks it up before the /24 guess."""
    out: dict = {}
    for l in lease_rows:
        if (a := _s(l.get("address"))) and a not in out:
            out[a] = (_s(l.get("if")), _s(l.get("if_descr")), _s(l.get("if_dev")))
    for e in arp:
        if isinstance(e, dict) and (a := _s(e.get("ip"))) and a not in out:
            out[a] = ("", _s(e.get("intf_description")), _s(e.get("intf")))
    return out


def dnsmasq_hosts(rows: list[dict], cidr_map: dict) -> list[dict]:
    """dnsmasq static host rows (/api/dnsmasq/settings/search_host) in the kea_reservations shape, one row per MAC in
    "hwaddr". Skipped: a row with no valid MAC (a DNS-only record), a row with "ignore" set (dnsmasq ignores that
    client) and a row whose "ip" holds only IPv6 addresses (leasewatch tracks IPv4). An empty "ip" (a MAC-only
    reservation with a dynamic address) gives address "": the MAC is still a configured device. The hostname is the
    short "host" name, the label "descr", subnet "" (the model has none). cidr_map is keyed by the address itself
    (_exact_ifaces), looked up first, and by _host_net."""
    out = []
    for r in rows:
        if not isinstance(r, dict) or _s(r.get("ignore")).lower() in ("1", "true", "yes"):
            continue
        ip = _host_ip(r)
        if not ip and _items(r.get("ip")):
            continue
        ifc, descr, dev = cidr_map.get(ip) or cidr_map.get(_host_net(ip), ("", "", ""))
        label = _s(r.get("descr"))[:LABEL_MAX].strip()
        for mac in dict.fromkeys(m for m in (norm_mac(t) for t in _items(r.get("hwaddr"))) if m):
            out.append({"mac": mac, "address": ip, "hostname": _s(r.get("host")).rstrip("."), "man": "",
                        "if": ifc, "if_descr": descr, "if_dev": dev, "type": "static", "status": "",
                        "label": label, "subnet": ""})
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


def _res_label(rows: list[dict] | None, lease: dict) -> str:
    """The label of a leased MAC's reservation: the one whose subnet holds the lease's IP, else the first labelled
    row in API order (so a MAC reserved in two subnets does not get whichever row the API returns last)."""
    if not rows:
        return ""
    ip = _addr(_s(lease.get("address"))) if _s(lease.get("address")) else None
    if ip is not None:
        for r in rows:
            net = _net(r["subnet"]) if r.get("subnet") else None
            if net is not None and ip.version == net.version and ip in net:
                return r["label"]
    return next((r["label"] for r in rows if r["label"]), "")


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
        return self._search_rows("/api/kea/dhcpv4/searchReservation", "reservation")

    def hosts_raw(self) -> list[dict]:
        """dnsmasq static hosts (Services > Dnsmasq DNS & DHCP > Hosts); a read-only search, POSTed like the lease search."""
        return self._search_rows("/api/dnsmasq/settings/search_host", "host")

    def _search_rows(self, path: str, what: str) -> list[dict]:
        r = self._call(path, {"current": 1, "rowCount": LEASE_ROWS})
        if not isinstance(r, dict) or not isinstance(r.get("rows"), list):
            raise Fw1Error(f"fw1 {what}s: unexpected response shape")
        try:
            total = int(r.get("total") or 0)
        except (TypeError, ValueError, OverflowError):  # OverflowError: a JSON 1e999 or Infinity
            total = 0
        if total > len(r["rows"]):
            log.warning("%s list truncated: %d of %d rows (raise LEASE_ROWS)", what, len(r["rows"]), total)
        return r["rows"]

    def arp_raw(self) -> list[dict]:
        r = self._call("/api/diagnostics/interface/get_arp")
        if isinstance(r, dict):
            r = r.get("rows", r.get("data"))
        if not isinstance(r, list):
            raise Fw1Error("fw1 arp: unexpected response shape")
        return r

    def ndp_raw(self) -> list[dict]:
        """The NDP table (IPv6 neighbours); needs "Diagnostics: NDP Table"."""
        r = self._call("/api/diagnostics/interface/get_ndp")
        if isinstance(r, dict):
            r = r.get("rows", r.get("data"))
        if not isinstance(r, list):
            raise Fw1Error("fw1 ndp: unexpected response shape")
        return r

    # --- normalised --------------------------------------------------------
    def sightings(self, ignore_interfaces: tuple = (), ipv6: bool = False) -> tuple[list[Sighting], dict]:
        """Return (sightings, stats). Raises Fw1Error if the lease or ARP call fails; the Kea reservation
        and dnsmasq host searches are best-effort.

        With ipv6, the NDP table is also read (best-effort) into "ndp" sightings with ip6 set and online False;
        skipped are rows without a MAC, on an ignored interface, with a link-local or unparsable address, and
        rows whose MAC is in a permanent ARP entry of this poll (the firewall's own interfaces).

        ignore_interfaces matches (case-insensitively) the OPNsense identifier (opt3), the device (vlan0110, igc4)
        or the description (Klienter, WAN), because leases and ARP rows name interfaces differently."""
        ign = {_s(x).lower() for x in ignore_interfaces if _s(x)}
        skip = lambda *names: any(_s(n).lower() in ign for n in names)
        leases = self.leases_raw()
        reservations = None
        labels_unavailable = False
        if self.dhcp_backend in ("kea", "dnsmasq"):
            # reservations only add lease-less devices; an API key without that privilege must not stop the poll
            try:
                reservations = self.reservations_raw() if self.dhcp_backend == "kea" else self.hosts_raw()
            except Fw1Error as e:
                log.warning("reservations unavailable, listing leases only: %s", e)
                labels_unavailable = True
        arp = self.arp_raw()
        ndp = None
        ndp_unavailable = False
        if ipv6:
            # the NDP table only adds IPv6 addresses; an API key without that privilege must not stop the poll
            try:
                ndp = self.ndp_raw()
                self._ndp_warned = False
            except Fw1Error as e:
                if not getattr(self, "_ndp_warned", False):  # one WARNING per spell, not one per poll
                    log.warning("NDP table unavailable, listing IPv4 only: %s", e)
                    self._ndp_warned = True
                ndp_unavailable = True
        try:
            out, stats = self._sightings(leases, arp, skip, reservations, ndp)
        except (TypeError, AttributeError, KeyError) as e:
            raise Fw1Error("fw1: unexpected field type in leases/arp") from e
        if labels_unavailable:
            # the labels come from the reservations: an empty one this poll is no evidence, so the merge keeps the stored labels
            stats["labels_unavailable"] = 1
        if ndp_unavailable:
            stats["ndp_unavailable"] = 1
        return out, stats

    def _sightings(self, leases: list, arp: list, skip, reservations: list | None = None,
                   ndp: list | None = None) -> tuple[list[Sighting], dict]:
        out: list[Sighting] = []
        if self.dhcp_backend == "dnsmasq":
            lease_rows = dnsmasq_leases(leases, time.time())  # the clock read here keeps the parser pure
        else:
            lease_rows = {"kea": kea_leases}.get(self.dhcp_backend, isc_leases)(leases)
        if reservations:
            # an active lease already carries what its reservation says, except the description (label);
            # only lease-less reservations are added as rows
            leased = {norm_mac(_s(l.get("mac"))) for l in lease_rows}
            if self.dhcp_backend == "dnsmasq":
                nets = [{"subnet": _host_net(_host_ip(r))} for r in reservations if isinstance(r, dict)]
                res_rows = dnsmasq_hosts(reservations, {**_cidr_map(nets, lease_rows, arp), **_exact_ifaces(lease_rows, arp)})
            else:
                res_rows = kea_reservations(reservations, _cidr_map(reservations, lease_rows, arp))
            by_mac: dict[str, list[dict]] = {}
            for r in res_rows:
                if (m := norm_mac(_s(r.get("mac")))) in leased:
                    by_mac.setdefault(m, []).append(r)
            lease_rows = [{**l, "label": lab} if not l.get("label") and (lab := _res_label(by_mac.get(norm_mac(_s(l.get("mac")))), l))
                          else l for l in lease_rows]
            lease_rows = lease_rows + [r for r in res_rows if norm_mac(_s(r.get("mac"))) not in leased]
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
                online=l.get("status") == "online", client_id=_s(l.get("client_id")),
                label=_s(l.get("label"))[:LABEL_MAX],
            ))
        own: set[str] = set()  # MACs of permanent ARP entries: the firewall's own interfaces
        for a in arp:
            if not isinstance(a, dict):
                continue
            mac = norm_mac(_s(a.get("mac")))
            if mac and a.get("permanent"):
                own.add(mac)
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
        kept = 0
        for n in ndp or ():
            if not isinstance(n, dict):
                continue
            mac = norm_mac(_s(n.get("mac")))
            if not mac:  # "(incomplete)"
                continue
            iface = _s(n.get("intf"))
            if skip(iface, n.get("intf_description")):
                continue
            ip6 = _s(n.get("ip")).split("%", 1)[0]  # a link-local row may carry its %scope
            addr = _addr(ip6)
            if addr is not None and addr.version == 6 and addr.is_link_local:
                continue
            if mac in own or addr is None or addr.version != 6:
                continue
            kept += 1
            out.append(Sighting(
                mac=mac, ip="", hostname="", vendor=_s(n.get("manufacturer")),
                vlan=_s(n.get("intf_description")) or iface, iface=iface,
                source="ndp", lease_type="", online=False, ip6=ip6,
            ))
        stats = {"leases": len(leases), "arp": len(arp)}
        if reservations is not None:
            stats["reservations"] = len(reservations)
        if ndp is not None:
            stats["ndp"] = kept
        return out, stats
