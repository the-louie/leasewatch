"""One pure merge of a poll's batches into the device rows.

Identity (ip, network, hostname, lease type, presence) comes from the sightings, the switch-port and Wi-Fi columns
from the attachments, and events and history from the diff against the previous rows. No database and no clock:
the caller passes the previous rows and `now`, and writes MergeResult.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Config
from ..fw1 import Sighting as Fw1Sighting
from . import Attachment, Batch, Sighting

# device columns the merge owns; user fields (name, note, acked, acked_at) and baseline/first_seen of an existing
# row are never written
UPDATE_COLUMNS = ("last_seen", "last_online", "ip", "hostname", "vendor", "vlan", "iface", "lease_type", "sources", "online",
                  "sw_port", "sw_via", "wifi_ssid", "wifi_ap", "wifi_signal", "wifi_radio", "wifi_alias", "link")
INSERT_COLUMNS = ("mac", "first_seen", "baseline") + UPDATE_COLUMNS
# the database defaults of the columns added after 1.0.0, for a new row and for a prev row given without them
ROW_DEFAULTS = {"sw_port": "", "sw_via": "", "wifi_ssid": "", "wifi_ap": "", "wifi_signal": None, "wifi_radio": "",
                "wifi_alias": "", "link": ""}


@dataclass
class Merged:
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    vlan: str = ""
    iface: str = ""
    lease_type: str = ""
    sources: set = field(default_factory=set)
    online: bool = False


@dataclass(frozen=True)
class ConnectorFailure:
    """An enabled instance whose collect() failed this poll: it claims nothing and forces nobody offline."""
    name: str
    error: str
    ts: int


@dataclass
class MergeState:
    """What the merge needs beyond the rows. no_lease_since (mac -> first poll listed without a lease) is updated in
    place, so LEASE_TYPE_MODE=grace keeps its clock across polls. controllers: instance names whose batch is a Wi-Fi
    controller's complete client list (a MAC missing from an answered batch has left Wi-Fi)."""
    no_lease_since: dict[str, int] = field(default_factory=dict)
    first_run: bool = False
    prev_ok: bool = True
    controllers: frozenset[str] = frozenset()


@dataclass
class MergeResult:
    rows: dict[str, dict] = field(default_factory=dict)       # mac -> full row, every merged or changed device
    new: list[str] = field(default_factory=list)              # new devices to announce (none on the first run)
    events: list[tuple[str, str, str]] = field(default_factory=list)  # (mac, kind, detail)
    history: list[tuple[str, dict]] = field(default_factory=list)     # (mac, {ip, hostname, vlan, lease_type})
    stats: dict[str, int] = field(default_factory=dict)       # devices, new, changed


def to_fw1(s: Sighting) -> Fw1Sighting:
    """The connector record back in the shape merge_sightings sorts on (kind -> source, presence -> online)."""
    return Fw1Sighting(mac=s.mac, ip=s.ip, hostname=s.hostname, vendor=s.vendor, vlan=s.network, iface=s.iface,
                       source=s.kind, lease_type=s.lease_type, online=s.presence)


def merge_sightings(sightings: list[Fw1Sighting]) -> dict[str, Merged]:
    """One record per MAC, independent of the order fw1 returns rows in.

    The lease whose IP is actually in the ARP table wins; ip/vlan/iface always come from one and the same
    sighting (what is on the wire), so a device that moved VLAN while its old lease is still listed is shown
    where it really is. DHCP gives hostname and lease type; ARP decides 'online'."""
    by_mac: dict[str, list[Fw1Sighting]] = {}
    for s in sightings:
        by_mac.setdefault(s.mac, []).append(s)
    out: dict[str, Merged] = {}
    for mac, ss in by_mac.items():
        # a total order over the rows, so ties (same vlan/ip, several hostnames) never depend on fw1's row order
        ss = sorted(ss, key=lambda s: (s.source != "dhcp", s.vlan == "", s.vlan, s.ip == "", s.ip, s.lease_type != "static", s.hostname))
        # an empty IP sorts last (it cannot be where the device is), a static lease before a dynamic one
        pick = lambda s: (s.ip == "", s.vlan, s.ip, s.lease_type != "static", s.hostname)
        dhcp = sorted((s for s in ss if s.source == "dhcp"), key=pick)
        arp = sorted((s for s in ss if s.source == "arp"), key=pick)
        arp_ips = {s.ip for s in arp if s.ip}
        lease = next((s for s in dhcp if s.ip in arp_ips), dhcp[0] if dhcp else None)
        wire = next((s for s in arp if lease and s.ip == lease.ip), arp[0] if arp else None)
        loc = wire or lease
        m = Merged(mac=mac, ip=loc.ip or "", vlan=loc.vlan or "", iface=loc.iface or "",
                   sources={s.source for s in ss}, online=bool(arp) or any(s.online for s in dhcp))
        if lease:
            m.hostname, m.lease_type = lease.hostname, lease.lease_type
        m.hostname = m.hostname or next((s.hostname for s in ss if s.hostname), "")
        m.vendor = next((s.vendor for s in ss if s.vendor), "")
        out[mac] = m
    return out


def merge(prev: dict[str, dict], batches: dict[str, Batch | ConnectorFailure], cfg: Config, now: int,
          state: MergeState) -> MergeResult:
    """prev: every device row (mac -> column dict). batches: this poll's result per connector instance."""
    ok = {n: b for n, b in batches.items() if isinstance(b, Batch)}
    merged = merge_sightings([to_fw1(s) for b in ok.values() for s in b.sightings])
    grace_s = cfg.online_grace_minutes * 60
    grace = now - grace_s
    res = MergeResult()
    rows = {mac: {**ROW_DEFAULTS, **r} for mac, r in prev.items()}
    before = {mac: dict(r) for mac, r in rows.items()}
    changes = 0
    for mac, m in merged.items():
        sources = ",".join(sorted(m.sources))
        cur = rows.get(mac)
        if cur is None:
            rows[mac] = {**ROW_DEFAULTS, "mac": mac, "first_seen": now, "baseline": int(state.first_run), "last_seen": now,
                         "last_online": now if m.online else None, "ip": m.ip, "hostname": m.hostname, "vendor": m.vendor,
                         "vlan": m.vlan, "iface": m.iface, "lease_type": m.lease_type, "sources": sources, "online": int(m.online)}
            res.history.append((mac, {"ip": m.ip, "hostname": m.hostname, "vlan": m.vlan, "lease_type": m.lease_type}))
            if not state.first_run:
                res.events.append((mac, "new", " ".join(filter(None, [m.ip, m.hostname, m.vendor])) + (f" ({m.vlan})" if m.vlan else "")))
                res.new.append(mac)
            continue
        ev = []
        if m.ip and m.ip != cur["ip"]:
            ev.append(("ip", f"{cur['ip'] or '-'} -> {m.ip}"))
        if m.hostname and m.hostname != cur["hostname"]:
            ev.append(("hostname", f"{cur['hostname'] or '-'} -> {m.hostname}"))
        if m.vlan and m.vlan != cur["vlan"]:
            ev.append(("vlan", f"{cur['vlan'] or '-'} -> {m.vlan}"))
        if m.lease_type and m.lease_type != cur["lease_type"]:
            ev.append(("lease_type", f"{cur['lease_type'] or 'no DHCP'} -> {m.lease_type}"))
        lease_type = m.lease_type or cur["lease_type"]
        if m.lease_type:
            state.no_lease_since.pop(mac, None)
        elif cur["lease_type"] and cfg.lease_type_mode != "keep":
            since = state.no_lease_since.setdefault(mac, now)
            if cfg.lease_type_mode == "immediate" or now - since >= grace_s:
                lease_type = ""
                state.no_lease_since.pop(mac, None)
                ev.append(("lease_type", f"{cur['lease_type']} -> no DHCP"))
        # prev_ok: after a failed poll every device looks "away" for the outage, so "back" would be a false positive
        if m.online and not cur["online"] and cur["last_online"] and now - cur["last_online"] > 86400 and state.prev_ok:
            days = (now - cur["last_online"]) // 86400
            ev.append(("back", f"back after {days} day{'' if days == 1 else 's'}"))
        res.events += [(mac, kind, detail) for kind, detail in ev]
        if any(k in ("ip", "hostname", "vlan", "lease_type") for k, _ in ev):
            res.history.append((mac, {"ip": m.ip or cur["ip"], "hostname": m.hostname or cur["hostname"],
                                      "vlan": m.vlan or cur["vlan"], "lease_type": lease_type}))
            changes += 1
        # not on the wire right now: stays online until the grace period after its last sighting has passed
        online = m.online or bool(cur["online"] and (cur["last_online"] or 0) >= grace)
        cur.update(last_seen=now, last_online=now if m.online else cur["last_online"], ip=m.ip or cur["ip"],
                   hostname=m.hostname or cur["hostname"], vendor=m.vendor or cur["vendor"], vlan=m.vlan or cur["vlan"],
                   iface=m.iface or cur["iface"], lease_type=lease_type, sources=sources, online=int(online))
    _apply_attachments(rows, merged, batches, ok, state, res)
    for row in rows.values():
        # devices not seen on the wire for longer than the grace period go offline
        if row["online"] and (row["last_online"] or 0) < grace:
            row["online"] = 0
    res.rows = {mac: row for mac, row in rows.items()
                if mac in merged or any(row[k] != before[mac][k] for k in UPDATE_COLUMNS)}
    res.stats = {"devices": len(merged), "new": len(res.new), "changed": changes}
    return res


def _apply_attachments(rows: dict[str, dict], merged: dict[str, Merged], batches: dict[str, Batch | ConnectorFailure],
                       ok: dict[str, Batch], state: MergeState, res: MergeResult) -> None:
    """Switch-port and Wi-Fi columns from the attachments, on the rows after the identity merge (in place)."""
    controllers = [n for n in batches if n in state.controllers]
    # C6: one controller and one switch today; with several, the first instance listing a MAC wins here instead of
    # the report's "edge port beats Wi-Fi beats uplink, newest observation breaks ties"
    wifi: dict[str, Attachment] = {}
    for n in controllers:
        if n in ok:
            for a in ok[n].attachments:
                wifi.setdefault(a.mac, a)
    wired: dict[str, Attachment] = {}
    for n, b in ok.items():
        if n not in state.controllers:
            for a in b.attachments:
                if a.link == "wired":
                    wired.setdefault(a.mac, a)
    ctrl_ok = any(n in ok for n in controllers)
    ctrl_failed = bool(controllers) and not ctrl_ok
    for mac, row in rows.items():
        cur = dict(row)
        upd: dict = {}  # later keys win, as the rightmost assignment of a repeated column in an SQL UPDATE does
        w = wifi.get(mac)
        on_wifi = w is not None and w.link == "wifi"
        on_wire = mac in merged and merged[mac].online
        # controller down this poll: a Wi-Fi device would get the AP's uplink port from the FDB; keep its last values
        blind = ctrl_failed and cur["link"] == "wifi"
        sw = wired.get(mac)
        # on the wire this poll, not in grace: the FDB ages out slower than ARP, so a departed device would get a stale port
        # C6: Wi-Fi beats any switch port here, also an edge port (today's rule); the report ranks the edge port first
        if sw and on_wire and not on_wifi and not blind:
            if sw.port and (sw.port != cur["sw_port"] or sw.via != cur["sw_via"]):
                if cur["sw_port"] and sw.port != cur["sw_port"]:
                    res.events.append((mac, "port", f"{cur['sw_port']} -> {sw.port}{' via ' + sw.via if sw.via else ''}"))
                upd.update(sw_port=sw.port, sw_via=sw.via)
        if on_wifi:
            if w.ssid and (w.ssid != cur["wifi_ssid"] or w.ap != cur["wifi_ap"]):
                if cur["wifi_ssid"]:
                    res.events.append((mac, "wifi", f"{cur['wifi_ssid']} @ {cur['wifi_ap'] or '?'} -> {w.ssid} @ {w.ap or '?'}"))
            upd.update(wifi_ssid=w.ssid, wifi_ap=w.ap, wifi_signal=w.signal, wifi_radio=w.radio, wifi_alias=w.alias, link="wifi")
            if cur["sw_port"] and "sw_port" not in upd:  # on Wi-Fi now: the switch port it had on a cable is stale
                upd.update(sw_port="", sw_via="")
        elif w is not None:  # the controller says wired now: drop the old Wi-Fi details
            upd.update(wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", wifi_alias=w.alias, link="wired")
        # on the wire this poll, not just in grace: a phone walking out drops off ARP and the controller together, and
        # its last SSID must stay (the FDB may still hold it on the AP uplink, which is not a cable)
        if ctrl_ok and on_wire and cur["wifi_ssid"] and mac not in wifi:
            # the controller answered but no longer lists it: it left Wi-Fi, so the SSID/AP are stale. The switch
            # branch above already recorded its port, so a cable is shown in this same poll.
            upd.update(wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", link="wired" if sw else "")
        if cur["online"] and sw and not on_wifi and cur["link"] != "wifi":
            upd["link"] = "wired"
        row.update(upd)
