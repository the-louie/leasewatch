"""One pure merge of a poll's batches into the device rows.

Identity (ip, network, hostname, lease type, presence) comes from the sightings, the switch-port and Wi-Fi columns
from the attachments, and events and history from the diff against the previous rows. No database and no clock:
the caller passes the previous rows and `now`, and writes MergeResult.

RANKING (rule 4 of the connector design), by Sighting.kind; a kind not listed ranks after all listed ones:

    field                 order                         rule
    online, last_online   any kind                      a sighting with presence=True this poll (rule 1)
    ip, network, iface    arp, dhcp, then client, scan  taken together from one sighting. The lease is the first DHCP
                                                        sighting whose IP is in an ARP sighting, else the first DHCP
                                                        one; shown where ARP saw that IP, else at the first ARP
                                                        sighting, else at the lease. A lease flagged online by the
                                                        DHCP server does not override an ARP row (1.0 behaviour).
                                                        Only with neither DHCP nor ARP: the first client, then scan,
                                                        then any other kind (presence first within a kind)
    hostname              dhcp, client, arp, scan       the lease's hostname first, then the first non-empty value
    vendor                dhcp, arp, client, scan       the first non-empty value
    lease_type            dhcp                          the chosen lease only

"First" is by the sort keys (empty IP last, network, IP, static before dynamic, hostname, vendor, interface), so
the result never depends on the order the sources return rows in.

Attachments: link must be "wired" or "wifi" (anything else is ignored, logged once per instance and value). A
controller (ConnectorInfo.roles has "controller") sends its whole client list: "wifi" places a device on Wi-Fi,
"wired" means the controller sees it on a cable, so its Wi-Fi details are cleared. Several switches: each instance's
first wired attachment for a MAC is its candidate; across instances an edge (non-uplink) port beats an uplink port,
then the instance that already holds the device (its loc_source, if it still lists the MAC), then the instance order
(batch order = LW_CONNECTORS); the same between two uplinks. observed_at is not used: a walk stamps every row with
one time, so it would flap. Wi-Fi from a controller still beats any switch port. loc_source is the instance whose
attachment placed the device. A wired device whose loc_source switch failed this poll keeps its port (no event),
whatever the other switches offer, as a Wi-Fi device is "blind" while its controller is down.

Per-source freshness (MergeResult.seen): one (mac, instance, now, now if present else None) per instance that listed
a known MAC this poll, in a sighting or an attachment; present when a sighting has presence or an attachment has
present (a controller's active client).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace

from ..config import Config
from ..fw1 import Sighting as Fw1Sighting
from ..fw1 import norm_mac
from . import Attachment, Batch, Sighting

log = logging.getLogger("leasewatch.merge")

FALLBACK_KINDS = ("client", "scan")              # ip/network/iface when there is neither a dhcp nor an arp sighting
NAME_KINDS = ("dhcp", "client", "arp", "scan")    # hostname fallback
VENDOR_KINDS = ("dhcp", "arp", "client", "scan")  # vendor (rule 4)
LINKS = ("wired", "wifi")
# module globals, written by the merge: each warning below is logged once per process, not at every poll
_mac_warned: set[str] = set()                # instance names that sent a malformed record (invalid MAC, wrong type)
_link_warned: set[tuple[str, str]] = set()   # (instance name, link value) outside LINKS


def _rank(order: tuple[str, ...], kind: str) -> int:
    return order.index(kind) if kind in order else len(order)

# device columns the merge owns; user fields (name, note, acked, acked_at) and baseline/first_seen of an existing
# row are never written
UPDATE_COLUMNS = ("last_seen", "last_online", "ip", "hostname", "vendor", "vlan", "iface", "lease_type", "sources", "online",
                  "sw_port", "sw_via", "wifi_ssid", "wifi_ap", "wifi_signal", "wifi_radio", "wifi_alias", "link", "loc_source")
INSERT_COLUMNS = ("mac", "first_seen", "baseline") + UPDATE_COLUMNS
# the database defaults of the columns added after 1.0.0, for a new row and for a prev row given without them
ROW_DEFAULTS = {"sw_port": "", "sw_via": "", "wifi_ssid": "", "wifi_ap": "", "wifi_signal": None, "wifi_radio": "",
                "wifi_alias": "", "link": "", "loc_source": ""}


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
    # (mac, instance, last_seen, last_present or None): the instance listed the MAC this poll; last_present only when
    # one of its sightings asserted presence or one of its attachments is present (the writer keeps the stored
    # last_present on None)
    seen: list[tuple[str, str, int, int | None]] = field(default_factory=list)


def to_fw1(s: Sighting) -> Fw1Sighting:
    """The connector record back in the shape merge_sightings sorts on (kind -> source, presence -> online)."""
    return Fw1Sighting(mac=s.mac, ip=s.ip, hostname=s.hostname, vendor=s.vendor, vlan=s.network, iface=s.iface,
                       source=s.kind, lease_type=s.lease_type, online=s.presence)


def merge_sightings(sightings: list[Fw1Sighting]) -> dict[str, Merged]:
    """One record per MAC, independent of the order the sources return rows in (see RANKING above).

    s.source is the sighting's kind here and s.online its presence claim (to_fw1). The lease whose IP is in the ARP
    table wins; ip/vlan/iface always come from one and the same sighting (what is on the wire), so a device that
    moved VLAN while its old lease is still listed is shown where it really is."""
    by_mac: dict[str, list[Fw1Sighting]] = {}
    for s in sightings:
        by_mac.setdefault(s.mac, []).append(s)
    out: dict[str, Merged] = {}
    # an empty IP sorts last (it cannot be where the device is), a static lease before a dynamic one
    # vendor and iface too: every field the merge takes from a sighting is a key, so ties never depend on row order
    pick = lambda s: (s.ip == "", s.vlan, s.ip, s.lease_type != "static", s.hostname, s.vendor, s.iface)
    for mac, ss in by_mac.items():
        ss = sorted(ss, key=lambda s: (s.source,) + pick(s))
        dhcp = [s for s in ss if s.source == "dhcp"]
        arp = [s for s in ss if s.source == "arp"]
        arp_ips = {s.ip for s in arp if s.ip}
        lease = next((s for s in dhcp if s.ip in arp_ips), dhcp[0] if dhcp else None)
        wire = next((s for s in arp if lease and s.ip == lease.ip), arp[0] if arp else None)
        # no firewall sighting at all (a controller or scanner only): the best of the other kinds, so they still merge
        loc = wire or lease or min(ss, key=lambda s: (_rank(FALLBACK_KINDS, s.source), s.source, not s.online) + pick(s))
        m = Merged(mac=mac, ip=loc.ip or "", vlan=loc.vlan or "", iface=loc.iface or "",
                   sources={s.source for s in ss}, online=any(s.online for s in ss))
        if lease:
            m.hostname, m.lease_type = lease.hostname, lease.lease_type
        named = sorted(ss, key=lambda s: (_rank(NAME_KINDS, s.source), s.source) + pick(s))
        m.hostname = m.hostname or next((s.hostname for s in named if s.hostname), "")
        vendors = sorted(ss, key=lambda s: (_rank(VENDOR_KINDS, s.source), s.source) + pick(s))
        m.vendor = next((s.vendor for s in vendors if s.vendor), "")
        out[mac] = m
    return out


def normalise_batch(name: str, b: Batch) -> Batch:
    """The host's part of the record contract, for one instance's batch: `source` set to the instance name, `mac`
    normalised, records whose MAC fails norm_mac dropped (stats["dropped"], one WARNING per instance per process).
    Never raises: one connector's malformed batch must not fail the poll for the others, so a record of the wrong
    type, a MAC that is not a str, and a sightings/attachments field that is not a list (counted as one) are
    dropped the same way. Returns a new Batch; the given one is left as it is. Applying it twice drops nothing more."""
    dropped = 0

    def fix(records: object, kind: type) -> list:
        nonlocal dropped
        if not isinstance(records, (list, tuple)):
            dropped += 1
            return []
        out = []
        for r in records:
            mac = norm_mac(r.mac) if isinstance(r, kind) and isinstance(r.mac, str) else ""
            if mac:
                out.append(r if (mac, name) == (r.mac, r.source) else replace(r, mac=mac, source=name))
            else:
                dropped += 1
        return out
    sightings, attachments = fix(b.sightings, Sighting), fix(b.attachments, Attachment)
    stats = b.stats if isinstance(b.stats, dict) else {}
    before = stats.get("dropped", 0)
    if dropped and name not in _mac_warned:
        _mac_warned.add(name)
        log.warning("connector %s: %d malformed records dropped (invalid MAC or wrong type)", name, dropped)
    return Batch(sightings=sightings, attachments=attachments,
                 stats={**stats, "dropped": (before if isinstance(before, int) else 0) + dropped})


def merge(prev: dict[str, dict], batches: dict[str, Batch | ConnectorFailure], cfg: Config, now: int,
          state: MergeState) -> MergeResult:
    """prev: every device row (mac -> column dict). batches: this poll's result per connector instance."""
    ok = {n: normalise_batch(n, b) for n, b in batches.items() if isinstance(b, Batch)}
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
    # only MACs with a device row: a switch FDB lists MACs no sighting ever named, which would leave orphan rows
    for n, b in ok.items():
        listed: dict[str, bool] = {}
        for s in b.sightings:
            listed[s.mac] = listed.get(s.mac, False) or s.presence
        for a in b.attachments:
            listed[a.mac] = listed.get(a.mac, False) or a.present is True
        res.seen += [(mac, n, now, now if present else None) for mac, present in listed.items() if mac in rows]
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
    """Switch-port and Wi-Fi columns from the attachments, on the rows after the identity merge (in place).

    Several controllers: a device has left Wi-Fi only when every controller answered and none lists it; while any
    controller failed this poll and none that answered lists it, a Wi-Fi device is "blind" (keeps its last values,
    gets no switch port). A "wifi"
    attachment from an instance without the controller role is ignored (its list is not complete)."""
    controllers = [n for n in batches if n in state.controllers]
    wifi: dict[str, Attachment] = {}
    wired: dict[str, Attachment] = {}
    rank: dict[str, tuple] = {}  # mac -> sort key of the wired candidate kept so far (lower wins)
    for i, (n, b) in enumerate(ok.items()):
        mine: set[str] = set()  # MACs this instance already put up: its first wired attachment is its candidate
        for a in b.attachments:
            if a.link not in LINKS:
                value = str(a.link)[:40]  # whatever the connector put there; capped so a log line stays one line
                if (n, value) not in _link_warned:
                    _link_warned.add((n, value))
                    log.warning("connector %s: attachments with link %r ignored (allowed: wired, wifi)", n, value)
                continue
            if n in state.controllers:
                wifi.setdefault(a.mac, a)
            elif a.link == "wired" and a.mac not in mine:
                mine.add(a.mac)
                # the edge port is where the device is; an uplink only says which way it lies. Two edge ports (the
                # FDBs age at different speeds): the switch that already holds the device (sticky, so a walk order
                # or an FDB timing never makes it flap), then the instance order
                sticky = n == rows.get(a.mac, {}).get("loc_source")
                key = (bool(a.uplink), not sticky, i)
                if a.mac not in rank or key < rank[a.mac]:
                    wired[a.mac], rank[a.mac] = a, key
    ctrl_ok = any(n in ok for n in controllers)
    ctrl_failed = any(n not in ok for n in controllers)
    for mac, row in rows.items():
        cur = dict(row)
        upd: dict = {}  # later keys win, as the rightmost assignment of a repeated column in an SQL UPDATE does
        w = wifi.get(mac)
        on_wifi = w is not None and w.link == "wifi"
        on_wire = mac in merged and merged[mac].online
        # controller down this poll: a Wi-Fi device would get the AP's uplink port from the FDB; keep its last values
        # a controller that answered and lists the device (wired or Wi-Fi) is first-hand evidence, so not blind
        blind = ctrl_failed and cur["link"] == "wifi" and w is None
        sw = wired.get(mac)
        # the switch that placed this wired device failed this poll: another switch can only offer a worse view (an
        # uplink towards it, an aged FDB entry), so the port stays as it is, as a Wi-Fi device does while blind
        held = (cur["link"] == "wired" and cur["loc_source"] in batches and cur["loc_source"] not in ok
                and cur["loc_source"] not in state.controllers)
        # on the wire this poll, not in grace: the FDB ages out slower than ARP, so a departed device would get a stale port
        # Wi-Fi beats any switch port, also an edge port: a controller's client list is first-hand, an FDB entry for a
        # Wi-Fi client can be an AP port that is not marked as an uplink
        if sw and on_wire and not on_wifi and not blind and not held and sw.port:
            # only the winner is compared with the row, so a losing candidate that moves writes no event
            if sw.port != cur["sw_port"] or sw.via != cur["sw_via"]:
                if cur["sw_port"] and sw.port != cur["sw_port"]:
                    res.events.append((mac, "port", f"{cur['sw_port']} -> {sw.port}{' via ' + sw.via if sw.via else ''}"))
                upd.update(sw_port=sw.port, sw_via=sw.via)
            upd["loc_source"] = sw.source
        if on_wifi:
            if w.ssid and (w.ssid != cur["wifi_ssid"] or w.ap != cur["wifi_ap"]):
                if cur["wifi_ssid"]:
                    res.events.append((mac, "wifi", f"{cur['wifi_ssid']} @ {cur['wifi_ap'] or '?'} -> {w.ssid} @ {w.ap or '?'}"))
            upd.update(wifi_ssid=w.ssid, wifi_ap=w.ap, wifi_signal=w.signal, wifi_radio=w.radio, wifi_alias=w.alias, link="wifi",
                       loc_source=w.source)
            if cur["sw_port"] and "sw_port" not in upd:  # on Wi-Fi now: the switch port it had on a cable is stale
                upd.update(sw_port="", sw_via="")
        elif w is not None:  # the controller says wired now: drop the old Wi-Fi details
            upd.update(wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", wifi_alias=w.alias, link="wired")
            upd.setdefault("loc_source", w.source)  # a switch port found above names the device's place more exactly
        # on the wire this poll, not just in grace: a phone walking out drops off ARP and the controller together, and
        # its last SSID must stay (the FDB may still hold it on the AP uplink, which is not a cable)
        if ctrl_ok and not ctrl_failed and on_wire and cur["wifi_ssid"] and mac not in wifi:
            # every controller answered and none lists it: it left Wi-Fi, so the SSID/AP are stale. The switch
            # branch above already recorded its port, so a cable is shown in this same poll.
            upd.update(wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", link="wired" if sw else "")
            upd.setdefault("loc_source", "")  # the controller no longer places it; a switch port above may
        if cur["online"] and sw and not on_wifi and cur["link"] != "wifi":
            upd["link"] = "wired"
        row.update(upd)
