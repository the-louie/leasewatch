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
                                                        sighting, else at the lease if it has an IP. A lease flagged
                                                        online by the DHCP server does not override an ARP row (1.0
                                                        behaviour). Only with neither ARP nor a lease with an IP: a
                                                        sighting with an IP first, then the (empty-IP) lease, then
                                                        client, scan, any other kind (presence first within a kind)
    hostname              dhcp, arp, client, scan,      the lease's hostname first, then the first non-empty value (the
                          dhcp6                         firewall stays the authority; a controller fills gaps)
    vendor                dhcp, arp, client, scan, ndp  the first non-empty value
    lease_type            dhcp                          the chosen lease only
    ip6                   any kind                      GUA, ULA, other; one a dhcp6 sighting carries; the MAC's EUI-64
                                                        address; the lowest value. Sticky: the stored one stays while
                                                        listed in the best class (prefix, DHCPv6, EUI-64) or while
                                                        none is listed

ndp and dhcp6 sightings only enrich: a MAC listed by them alone gets no row, and they never assert presence. The
same holds for a MAC listed this poll only by secondary instances (MergeState.secondary: a controller or a name
source): without a row it gets none (not new, not present); once a primary instance lists it, their values are the
fallbacks above.

"First" is by the sort keys (empty IP last, then empty network last, network, IP, static before dynamic, hostname,
vendor, interface), so the result never depends on the order the sources return rows in.

Attachments: link must be "wired" or "wifi" (anything else is ignored, logged once per instance and value). A
controller (ConnectorInfo.roles has "controller") sends its whole client list: "wifi" places a device on Wi-Fi,
"wired" means the controller sees it on a cable, so its Wi-Fi details are cleared. Several switches: each instance's
first wired attachment for a MAC is its candidate; across instances an edge (non-uplink) port beats an uplink port,
then the instance that already holds the device (its loc_source, if it still lists the MAC), then the instance order
(batch order = LW_CONNECTORS); the same between two uplinks. observed_at is not used: a walk stamps every row with
one time, so it would flap. Wi-Fi from a controller still beats any switch port. loc_source is the instance whose
attachment placed the device. A wired device whose loc_source switch failed this poll keeps its port (no event),
whatever the other switches offer, as a Wi-Fi device is "blind" while its controller is down.

Private MACs (decide_aliases): before all of the above, each MAC gets its device key: a known alias (MergeState.aliases)
its device, a new private MAC the one device it matches (README Semantics), else itself. Every record is rewritten to
that key, so the rules above run on devices, not MACs; new aliases come back in MergeResult.aliases.

Per-source freshness (MergeResult.seen): one (mac, instance, now, now if present else None) per instance that listed
a known MAC this poll, in a sighting or an attachment; present when a sighting has presence or an attachment has
present (a controller's active client).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field, replace

from ..config import Config
from ..db import CONTROL_CHARS
from ..fw1 import Sighting as Fw1Sighting
from ..fw1 import norm_mac
from . import Attachment, Batch, Sighting, parse_bool

log = logging.getLogger("leasewatch.merge")

# ndp and dhcp6 are not in FALLBACK_KINDS: unlisted, so they rank after every listed kind for ip/network/iface
FALLBACK_KINDS = ("client", "scan")              # ip/network/iface when there is neither a dhcp nor an arp sighting
# hostname fallback: the firewall's names (lease, ARP/DNS) first; a controller's client name only fills a gap
NAME_KINDS = ("dhcp", "arp", "client", "scan", "dhcp6")
VENDOR_KINDS = ("dhcp", "arp", "client", "scan", "ndp")    # vendor (rule 4)
# IPv6-only kinds: they enrich a known device (ip6, a last-resort name or vendor) but never create a row or assert
# presence, and do not place the device (network/iface)
V6_KINDS = frozenset({"ndp", "dhcp6"})
_GUA = ipaddress.ip_network("2000::/3")  # by prefix: is_global is False for the documentation range 2001:db8::/32
_ULA = ipaddress.ip_network("fc00::/7")
LINKS = ("wired", "wifi")
# module globals, written by the merge: each warning below is logged once per process, not at every poll
_mac_warned: set[str] = set()                # instance names that sent a malformed record (invalid MAC, wrong type)
_link_warned: set[tuple[str, str]] = set()   # (instance name, link value) outside LINKS


# a hostname merge needs a target seen within this many days (the private-MAC rotations found are 14 days or less)
MERGE_RECENT_DAYS = 30
# DHCP hostnames many devices send alike: never evidence of one particular device
GENERIC_HOSTNAMES = frozenset(
    "iphone ipad ipod mac macbook macbook-air macbook-pro imac apple-watch watch android localhost unknown none host "
    "client device phone tablet laptop desktop pc galaxy pixel chromecast espressif esp32 esp8266 linux raspberrypi "
    "ubuntu debian dhcp".split())
_GENERIC_RE = re.compile(r"(android|galaxy|iphone|ipad|esp|wlan|eth)[-_ ]?[0-9a-f]*|[0-9a-f:_-]+")
# brand/model stems: a name that starts with one is a default model name ("galaxy-s21", "pixel-7"), shared by every
# device of that model, so it is generic whatever follows
GENERIC_PREFIXES = ("iphone", "ipad", "ipod", "imac", "macbook", "apple-watch", "android", "galaxy", "pixel",
                    "chromecast", "espressif", "esp32", "esp8266", "raspberrypi")
# a private row that nobody touched may be folded into an older device (deferred hostname merge) for this many days
# after its first sighting
MERGE_FOLD_DAYS = 1
# a fold needs the target off the wire within this long after the candidate first appeared: an old MAC lingering in
# the firewall's ARP table after a rotation (FreeBSD keeps an entry 1200 s); a second interface overlaps for longer
FOLD_OVERLAP_SECONDS = 1800
# a new private MAC is held back (no row) at most this long while a lease producer fails: longer than the collector's
# MAX_BACKOFF (600 s) between retries of a failed instance, so a passing outage gets at least one more answer
MERGE_HOLD_SECONDS = 1800


def is_private_mac(mac: str) -> bool:
    """A locally administered unicast MAC (first octet: bit 0x02 set, bit 0x01 clear), e.g. a private Wi-Fi address."""
    try:
        b = int(mac[:2], 16)
    except (TypeError, ValueError):
        return False
    return b & 0x03 == 0x02


def norm_hostname(v: str) -> str:
    """A hostname as the merge compares it: lower case, the trailing dot and the domain dropped, trimmed."""
    return v.lower().rstrip(".").split(".", 1)[0].strip()


def _merge_host(v: str) -> str:
    """The normalised DHCP hostname if it may identify a device (3+ characters, not generic), else ""."""
    h = norm_hostname(v)
    return "" if len(h) < 3 or h in GENERIC_HOSTNAMES or h.startswith(GENERIC_PREFIXES) or _GENERIC_RE.fullmatch(h) else h


def decide_aliases(raw: dict[str, Merged], present: set[str], prev: dict[str, dict], aliases: dict[str, str],
                   first_run: bool, now: int, limits: dict | None = None
                   ) -> tuple[dict[str, str], list[tuple[str, str, str, str]]]:
    """(raw MAC -> device key, new (alias, device, reason, detail)) for this poll's sighting MACs. A known alias maps to
    its device, a MAC with a row to itself; a new private MAC to the one device it matches, else to
    itself. present: raw MACs with a sighting or attachment that asserts presence this poll. A hostname merge needs
    the device off the wire this poll (else the new MAC is a second interface); a client-id merge does not, since two
    devices cannot share a client-id and the old MAC often lingers in the firewall's ARP table after a rotation.
    limits, when given, receives "hosts" (hostname -> new MACs carrying it) and "taken" (device -> new MACs that picked
    it), so decide_folds keeps the same limits."""
    keys: dict[str, str] = {}
    fresh: list[str] = []
    for mac in raw:
        if mac in aliases:
            keys[mac] = aliases[mac]
        else:
            keys[mac] = mac
            if mac not in prev:
                fresh.append(mac)
    if first_run:  # the baseline (and its wait) never merges
        return keys, []
    # devices on the wire this poll, under their own MAC or an alias: a second MAC with the same hostname is then a
    # second interface (a client-id match is the same device even while the old MAC still shows)
    busy = {keys.get(m, aliases.get(m, m)) for m in present}
    cids, hosts = {}, {}  # signal value -> how many new MACs carry it (two new MACs with one value do not merge)
    for mac in fresh:
        for counts, v in ((cids, raw[mac].client_id), (hosts, _merge_host(raw[mac].lease_hostname))):
            if v:
                counts[v] = counts.get(v, 0) + 1
    picks: dict[str, tuple[str, str, str]] = {}  # new MAC -> (device, reason, detail)
    for mac in fresh:
        if not is_private_mac(mac):
            continue
        m = raw[mac]
        cid, host = m.client_id, _merge_host(m.lease_hostname)
        # the first signal with exactly one candidate decides; archived devices count as candidates
        by_cid = [d for d, r in prev.items() if cid and r.get("client_id") == cid]
        by_host = [d for d, r in prev.items() if host and norm_hostname(r.get("hostname") or "") == host]
        if len(by_cid) == 1:
            dev, reason, value, counts = by_cid[0], "client-id", cid, cids
        elif len(by_host) == 1:
            dev, reason, value, counts = by_host[0], "hostname", host, hosts
            r = prev[dev]
            if (r.get("last_online") or r.get("last_seen") or 0) < now - MERGE_RECENT_DAYS * 86400:
                continue
        else:
            continue
        if counts[value] == 1 and (reason == "client-id" or dev not in busy):
            picks[mac] = (dev, reason, value)
    # two new MACs that pick one device in one poll are two interfaces, as above: neither merges
    taken: dict[str, int] = {}
    for dev, _, _ in picks.values():
        taken[dev] = taken.get(dev, 0) + 1
    if limits is not None:
        limits.update(hosts=hosts, taken=taken)
    out = []
    for mac, (dev, reason, value) in picks.items():
        if taken[dev] == 1:
            keys[mac] = dev
            out.append((mac, dev, reason, value))
    return keys, out


def decide_folds(raw: dict[str, Merged], present: set[str], prev: dict[str, dict], aliases: dict[str, str],
                 fresh_hosts: dict[str, int], keys: dict[str, str], now: int,
                 fresh_targets: frozenset[str] = frozenset()) -> list[tuple[str, str, str, str]]:
    """(candidate, device, "hostname", hostname) for each existing private row that becomes an alias of an older
    device (deferred hostname merge): rule 4 kept the new MAC apart while the old one was still listed, and the old
    one stopped soon after. The candidate is a row nobody touched (no name or note, not acked, archived or baseline),
    at most MERGE_FOLD_DAYS old, without aliases of its own (a fold never re-points a chain). Its hostname is this
    poll's DHCP lease hostname with the rule (3) tests (an ARP or controller name is no evidence). The target is the
    one other device with that hostname: recent, older than the candidate, not the row it was split from, off the wire
    this poll, and last online no later than FOLD_OVERLAP_SECONDS after the candidate first appeared (a longer
    overlap is a second interface, e.g. a docked laptop on cable and Wi-Fi). A hostname a new MAC also carries, two
    candidates with one hostname, two candidates for one device and a candidate a new MAC merges into this poll
    (fresh_targets) decide nothing. The caller applies the gate (first
    run, lease-blind hold) and the limit shared with fresh merges."""
    busy = {keys.get(m, aliases.get(m, m)) for m in present}
    owners = set(aliases.values()) | fresh_targets
    picks: dict[str, tuple[str, str]] = {}  # candidate -> (device, hostname)
    for mac, m in raw.items():
        r = prev.get(mac)
        if (r is None or not is_private_mac(mac) or mac in aliases or mac in owners or keys.get(mac, mac) != mac
                or r.get("name") or r.get("note") or r.get("tags") or r.get("acked") or r.get("archived_ts") is not None
                or r.get("baseline") or (r.get("first_seen") or 0) < now - MERGE_FOLD_DAYS * 86400):
            continue
        host = _merge_host(m.lease_hostname)
        if not host or fresh_hosts.get(host):
            continue
        by_host = [d for d, o in prev.items() if d != mac and norm_hostname(o.get("hostname") or "") == host]
        if len(by_host) != 1:
            continue
        dev, t = by_host[0], prev[by_host[0]]
        if ((t.get("last_online") or t.get("last_seen") or 0) < now - MERGE_RECENT_DAYS * 86400
                or (t.get("first_seen") or 0) >= r["first_seen"] or dev == (r.get("split_from") or "")
                or dev in busy or (t.get("last_online") or 0) >= r["first_seen"] + FOLD_OVERLAP_SECONDS):
            continue
        picks[mac] = (dev, host)
    hosts: dict[str, int] = {}
    taken: dict[str, int] = {}
    for dev, host in picks.values():
        hosts[host] = hosts.get(host, 0) + 1
        taken[dev] = taken.get(dev, 0) + 1
    # a device that is itself folded this poll would leave its new alias pointing at a removed row
    return [(mac, dev, "hostname", host) for mac, (dev, host) in picks.items()
            if hosts[host] == 1 and taken[dev] == 1 and dev not in picks]


def _rekey(b: Batch, keys: dict[str, str]) -> Batch:
    """The batch with every record's MAC replaced by its device key (records of other MACs unchanged)."""
    return Batch(sightings=[replace(s, mac=keys[s.mac]) if keys.get(s.mac, s.mac) != s.mac else s for s in b.sightings],
                 attachments=[replace(a, mac=keys[a.mac]) if keys.get(a.mac, a.mac) != a.mac else a
                              for a in b.attachments], stats=b.stats)


def _rank(order: tuple[str, ...], kind: str) -> int:
    return order.index(kind) if kind in order else len(order)

# device columns the merge owns; user fields (name, note, acked, acked_at) and baseline/first_seen of an existing
# row are never written
UPDATE_COLUMNS = ("last_seen", "last_online", "ip", "hostname", "vendor", "vlan", "iface", "lease_type", "sources", "online",
                  "sw_port", "sw_via", "wifi_ssid", "wifi_ap", "wifi_signal", "wifi_radio", "wifi_alias", "link", "loc_source",
                  "client_id", "archived_ts", "label", "watch_online", "ip6", "ip6_stable")
INSERT_COLUMNS = ("mac", "first_seen", "baseline") + UPDATE_COLUMNS
# the database defaults of the columns added after 1.0.0, for a new row and for a prev row given without them
ROW_DEFAULTS = {"sw_port": "", "sw_via": "", "wifi_ssid": "", "wifi_ap": "", "wifi_signal": None, "wifi_radio": "",
                "wifi_alias": "", "link": "", "loc_source": "", "client_id": "",
                "archived_ts": None, "label": "", "watch_online": None, "ip6": "", "ip6_stable": ""}


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
    client_id: str = ""  # from the chosen lease only
    lease_hostname: str = ""  # the chosen lease's own hostname (option 12), not a fallback from another kind
    label: str = ""  # see merge_sightings
    ip6: str = ""  # the best IPv6 candidate this poll (_ip6_key)
    ip6s: tuple[str, ...] = ()  # candidates in ip6's class (prefix, DHCPv6, EUI-64), best first: a stored one kept if listed
    ip6_stable: str = ""  # the best stable IPv6 candidate this poll (EUI-64 of the MAC or a DHCPv6 lease's address)
    # every stable candidate this poll -> its class (prefix, DHCPv6, EUI-64), best first (_settle_ip6_stable)
    ip6_stables: dict[str, tuple[int, int, int]] = field(default_factory=dict)


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
    controller's complete client list (a MAC missing from an answered batch has left Wi-Fi). producers: instance
    names that produce sightings (only they can hold a lease); None when unknown, then every failed instance but a
    controller counts."""
    no_lease_since: dict[str, int] = field(default_factory=dict)
    first_run: bool = False
    prev_ok: bool = True
    controllers: frozenset[str] = frozenset()
    producers: frozenset[str] | None = None
    # instance names that listed a dhcp sighting when they last answered (only they can hold a lease); None when
    # unknown (first poll), then the producers decide
    lease_holders: frozenset[str] | None = None
    # instance names that answered at least once while holders were tracked: a failed producer missing from it (added
    # or renamed since) may hold a lease too. None: not tracked, only lease_holders decides
    answered: frozenset[str] | None = None
    # secondary sighting producers (role "controller" or "names"): their sightings count, but their failure is no
    # lease blindness and they never hold a lease
    secondary: frozenset[str] = frozenset()
    held_back: bool = False  # first_run, and the baseline is not taken this poll (a producer has not answered yet)
    aliases: dict[str, str] = field(default_factory=dict)  # alias MAC -> device key (devices.mac), from the aliases table
    # new private MAC -> first poll it was held back undecided while a lease producer failed (updated in place)
    undecided_since: dict[str, int] = field(default_factory=dict)
    restored: dict[str, int] = field(default_factory=dict)  # mac -> last "restored" event ts (PRUNE_DAYS spares it)
    # the clamped prune clock (never ahead of the wall clock, moves slowly after a clock step); None: the wall clock
    prune_now: int | None = None


@dataclass
class MergeResult:
    rows: dict[str, dict] = field(default_factory=dict)       # mac -> full row, every merged or changed device
    new: list[str] = field(default_factory=list)              # new devices to announce (none on the first run)
    events: list[tuple[str, str, str]] = field(default_factory=list)  # (mac, kind, detail)
    history: list[tuple[str, dict]] = field(default_factory=list)     # (mac, {ip, hostname, vlan, lease_type, ip6})
    stats: dict[str, int] = field(default_factory=dict)       # devices, new, changed
    # (mac, instance, last_seen, last_present or None): the instance listed the MAC this poll; last_present only when
    # one of its sightings asserted presence or one of its attachments is present (the writer keeps the stored
    # last_present on None)
    seen: list[tuple[str, str, int, int | None]] = field(default_factory=list)
    aliases: list[tuple[str, str, str, str]] = field(default_factory=list)  # new (alias, device, reason, detail)
    # (candidate, device, "hostname", hostname): an existing row folded into the device this poll (also in aliases).
    # The writer moves the candidate's history, events (its `new` event deleted) and seen rows to the device and
    # deletes its row; this poll's records are already on the device
    folds: list[tuple[str, str, str, str]] = field(default_factory=list)
    alias_seen: list[str] = field(default_factory=list)       # alias MACs (known or new) listed this poll
    # (device key, ssid, ap): a controller that answered this poll lists the device on that SSID. One entry per device;
    # a device kept on its stored SSID while its controller is blind, or listed without an SSID, has none
    wifi: list[tuple[str, str, str]] = field(default_factory=list)
    # the lease holders after this poll (the input for the next one): an answering instance is one when its batch has
    # a dhcp sighting or none at all; a failed one keeps its last state
    lease_holders: frozenset[str] = frozenset()
    answered: frozenset[str] = frozenset()  # the primary producers that answered at least once, this poll included


def to_fw1(s: Sighting) -> Fw1Sighting:
    """The connector record back in the shape merge_sightings sorts on (kind -> source, presence -> online)."""
    return Fw1Sighting(mac=s.mac, ip=s.ip, hostname=s.hostname, vendor=s.vendor, vlan=s.network, iface=s.iface,
                       source=s.kind, lease_type=s.lease_type, online=s.presence, client_id=s.client_id,
                       label=s.label, ip6=s.ip6)


def _ip6_key(mac: str, addr: str, dhcp6: bool) -> tuple[int, int, int, int]:
    """The rank of an IPv6 candidate (lower wins): GUA, ULA, other; one a DHCPv6 lease carries; the EUI-64 address of
    the MAC (stable) before others (temporary); the lowest numeric value."""
    a = ipaddress.IPv6Address(addr)
    cls = 0 if a in _GUA else 1 if a in _ULA else 2
    b = bytes.fromhex(mac.replace(":", "")) if len(mac) == 17 else b""
    eui = len(b) == 6 and a.packed[8:] == bytes((b[0] ^ 0x02, b[1], b[2], 0xff, 0xfe, b[3], b[4], b[5]))
    return cls, 0 if dhcp6 else 1, 0 if eui else 1, int(a)


def _pick_ip6(mac: str, ss: list[Fw1Sighting]) -> tuple[str, ...]:
    """The IPv6 candidates of one MAC in the best class ((prefix, DHCPv6, EUI-64) equal to the best), best first: a
    stored temporary address gives way to the EUI-64 one once that is listed, two temporaries stay sticky."""
    found: dict[str, bool] = {}  # address -> carried by a dhcp6 sighting
    for s in ss:
        if s.ip6:
            try:
                ipaddress.IPv6Address(s.ip6)
            except ValueError:
                continue
            found[s.ip6] = found.get(s.ip6, False) or s.source == "dhcp6"
    keys = sorted((_ip6_key(mac, a, d), a) for a, d in found.items())
    if not keys:
        return ()
    return tuple(a for k, a in keys if k[:3] == keys[0][0][:3])


def _stable_key(macs: tuple[str, ...], addr: str, dhcp6: bool) -> tuple[int, int, int, int]:
    """_ip6_key of a stable candidate for a device with these MACs: EUI-64 when it is the address of any of them."""
    return min(_ip6_key(mac, addr, dhcp6) for mac in macs)


def _pick_ip6_stable(macs: tuple[str, ...], ss: list[Fw1Sighting]) -> dict[str, tuple[int, int, int]]:
    """The stable IPv6 candidates of a device (the EUI-64 address of one of its MACs, or one a DHCPv6 lease carries)
    -> their class (prefix, DHCPv6, EUI-64), best first by _ip6_key. A temporary address is never one."""
    found: dict[str, bool] = {}  # address -> carried by a dhcp6 sighting
    for s in ss:
        if s.ip6:
            try:
                ipaddress.IPv6Address(s.ip6)
            except ValueError:
                continue
            found[s.ip6] = found.get(s.ip6, False) or s.source == "dhcp6"
    keys = sorted((_stable_key(macs, a, d), a) for a, d in found.items())
    return {a: k[:3] for k, a in keys if k[1] == 0 or k[2] == 0}


def _settle_ip6_stable(macs: tuple[str, ...], stored: str, m: Merged) -> str:
    """The device's stable IPv6 address after this poll. A worse class never replaces the stored one; nothing listed
    keeps it (NDP aged it out); within its class it stays while still listed, so a renumbering that lists the old
    and the new address side by side changes it only once the old one has left."""
    if not m.ip6_stable or not stored:
        return stored or m.ip6_stable
    best = m.ip6_stables[m.ip6_stable]
    if stored in m.ip6_stables:
        cls = m.ip6_stables[stored]
    else:  # not listed: a stored address that is no EUI-64 one came from a DHCPv6 lease
        k = _stable_key(macs, stored, False)
        cls = k[:3] if k[2] == 0 else (k[0], 0, 1)
    if stored in m.ip6_stables and cls == best:
        return stored
    return m.ip6_stable if best <= cls else stored


def merge_sightings(sightings: list[Fw1Sighting]) -> dict[str, Merged]:
    """One record per MAC, independent of the order the sources return rows in (see RANKING above).

    s.source is the sighting's kind here and s.online its presence claim (to_fw1). The lease whose IP is in the ARP
    table wins; ip/vlan/iface always come from one and the same sighting (what is on the wire), so a device that
    moved VLAN while its old lease is still listed is shown where it really is."""
    by_mac: dict[str, list[Fw1Sighting]] = {}
    for s in sightings:
        by_mac.setdefault(s.mac, []).append(s)
    out: dict[str, Merged] = {}
    # an empty IP or network sorts last (it cannot be where the device is), a static lease before a dynamic one
    # vendor and iface too: every field the merge takes from a sighting is a key, so ties never depend on row order
    # client_id too: two leases that differ only in it would otherwise give the client-id of the first row
    # lease type: static, then dynamic, then none, so a "" lease never ties with a dynamic one
    pick = lambda s: (s.ip == "", s.vlan == "", s.vlan, s.ip, _rank(("static", "dynamic", ""), s.lease_type), s.lease_type,
                      s.hostname, s.vendor, s.iface,
                      s.client_id == "", s.client_id)
    for mac, ss in by_mac.items():
        ss = sorted(ss, key=lambda s: (s.source,) + pick(s))
        dhcp = [s for s in ss if s.source == "dhcp"]
        arp = [s for s in ss if s.source == "arp"]
        arp_ips = {s.ip for s in arp if s.ip}
        lease = next((s for s in dhcp if s.ip in arp_ips), dhcp[0] if dhcp else None)
        wire = next((s for s in arp if lease and lease.ip and s.ip == lease.ip), arp[0] if arp else None)
        # no firewall sighting at all (a controller or scanner only): the best of the other kinds, so they still merge
        # an empty-IP lease (a Kea reservation without ip_address) cannot be where the device is, as for `wire`, but
        # it still names the network better than another kind's sighting that has no IP either
        loc = wire or (lease if lease and lease.ip else None) or min(ss, key=lambda s: (
            s.ip == "", s.source != "dhcp", _rank(FALLBACK_KINDS, s.source), s.source, not s.online) + pick(s))
        m = Merged(mac=mac, ip=loc.ip or "", vlan=loc.vlan or "", iface=loc.iface or "",
                   sources={s.source for s in ss}, online=any(s.online for s in ss))
        if m.sources <= V6_KINDS:  # an NDP/DHCPv6 listing alone does not say where the device is
            m.vlan = m.iface = ""
        m.ip6s = _pick_ip6(mac, ss)
        m.ip6 = m.ip6s[0] if m.ip6s else ""
        m.ip6_stables = _pick_ip6_stable((mac,), ss)
        m.ip6_stable = next(iter(m.ip6_stables), "")
        if lease:
            m.hostname, m.lease_type, m.client_id = lease.hostname, lease.lease_type, lease.client_id
            m.lease_hostname = lease.hostname
        named = sorted(ss, key=lambda s: (_rank(NAME_KINDS, s.source), s.source) + pick(s))
        m.hostname = m.hostname or next((s.hostname for s in named if s.hostname), "")
        vendors = sorted(ss, key=lambda s: (_rank(VENDOR_KINDS, s.source), s.source) + pick(s))
        m.vendor = next((s.vendor for s in vendors if s.vendor), "")
        # label: a DHCP sighting's label first (a reservation's description belongs to the lease the device is
        # served), else any non-empty one in the same stable order as the name
        m.label = next((s.label for s in dhcp + [s for s in named if s.source != "dhcp"] if s.label), "")
        out[mac] = m
    return out


_HEX_RE = re.compile(r"[0-9a-f]*")
_GROUP_RE = re.compile(r"[0-9a-f]{1,2}")


def norm_client_id(v: object) -> str:
    """A DHCP client-id in its normal form: lowercase hex, two digits per byte, no separators. Groups split by ":" or
    "-" are padded to two digits (MikroTik writes 1:2:0); input without separators must be even-length hex. Anything
    else, and a value shorter than 2 bytes, is "" (too short to tell devices apart)."""
    t = ("" if v is None else str(v)).strip().lower()
    if ":" in t or "-" in t:
        groups = re.split(r"[:-]", t)
        if not all(_GROUP_RE.fullmatch(g) for g in groups):
            return ""
        t = "".join(g.zfill(2) for g in groups)
    elif not _HEX_RE.fullmatch(t) or len(t) % 2:
        return ""
    return t if len(t) >= 4 else ""


_STR_FIELDS = {Sighting: ("ip", "hostname", "vendor", "network", "iface", "lease_type", "client_id", "kind", "label", "ip6"),
               Attachment: ("link", "device", "port", "via", "ssid", "ap", "radio", "alias")}
_BOOL_FIELDS = {Sighting: ("presence",), Attachment: ("uplink", "present")}
_OPT_INT_FIELDS = {Sighting: (), Attachment: ("vlan", "signal")}
# names the controller shows as given: an SSID may begin or end with a space, and two such SSIDs are different networks
_UNSTRIPPED = ("ssid", "ap", "alias")
# every line break (CR, VT, FF, NEL, LS, PS too, not only LF) separates words: CONTROL_CHARS would delete it and glue them
_SPACES = dict.fromkeys(map(ord, "\n\t\r\x0b\x0c\x85\u2028\u2029"), " ")
_INT64 = 2 ** 63  # SQLite INTEGER is signed 64-bit; a larger int raises OverflowError at the write and fails the poll


def _int(v: object) -> int | None:
    """int(v) for a number or a numeric string ("-61", "\u221261" with a Unicode minus), else None."""
    if isinstance(v, bool) or v is None:
        return None
    try:
        s = str(v).strip().replace("\u2212", "-")
        try:
            n = int(s)  # first: a float round trip loses precision above 2**53 and turns 2**63-1 into 2**63
        except ValueError:
            n = int(float(s))
    except (TypeError, ValueError, OverflowError):
        return None
    return n if -_INT64 <= n < _INT64 else None


def _str(v: object, strip: bool) -> str:
    """str(v) safe to store and show: a lone surrogate (a name cut inside an emoji pair) would make the SQLite write
    raise UnicodeEncodeError for the whole poll, so it becomes "?"; control and bidi characters are removed and tab
    and newline become spaces, as db.py does for a name, so a hostname cannot reverse or split the "old -> new" text
    of an event."""
    s = ("" if v is None else str(v)).encode("utf-8", "replace").decode("utf-8")
    s = CONTROL_CHARS.sub("", s.replace("\r\n", "\n").translate(_SPACES))  # CONTROL_CHARS keeps tab/newline (for notes)
    return s.strip() if strip else s


def _ipv4(s: str) -> str:
    """The dotted-quad form of s, or "" for anything else (IPv6, junk, leading zeros): the page sorts and shows `ip`
    as a dotted quad."""
    try:
        return str(ipaddress.IPv4Address(s)) if s else ""
    except ValueError:
        return ""


def _ipv6(s: str) -> str:
    """The compressed lower-case form of an IPv6 address (a trailing %scope dropped), or "" for what names no device
    on the network: link-local, loopback, unspecified, multicast, site-local (fec0::/10), IPv4-mapped or
    IPv4-compatible (below 2**32), an IPv4 value, and anything that does not parse."""
    try:
        a = ipaddress.IPv6Address(s.split("%", 1)[0]) if s else None
    except ValueError:
        return ""
    if a is None or a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local or a.is_site_local:
        return ""
    return "" if a.ipv4_mapped or int(a) < 2**32 else str(a)


def _flag(v: object) -> bool:
    """A flag from a bool or a number, or from text by the words config.py accepts ("false", "0", "no" are False;
    bool("false") would be True); text that is none of them is False, as it asserts nothing. Bytes are read as text:
    bool(b"false") would be True too."""
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("utf-8", "replace")
    return parse_bool(v) is True if isinstance(v, str) else bool(v)


def _coerce(r: Sighting | Attachment, mac: str, name: str) -> Sighting | Attachment:
    """A copy with every field of its declared type: a third-party connector's None or number in a str field would
    otherwise raise deep in the merge (sort keys, .strip(), the SQL write) and fail the whole poll. `link` keeps its
    value after the str conversion: anything but "wired"/"wifi" is ignored and logged later, as before."""
    t = Sighting if isinstance(r, Sighting) else Attachment  # a subclass has the same fields; type(r) is no table key
    ch: dict = {"mac": mac, "source": name, "observed_at": _int(r.observed_at) or 0}
    ch.update({f: _str(getattr(r, f), f not in _UNSTRIPPED) for f in _STR_FIELDS[t]})
    if t is Sighting:
        ch["ip"] = _ipv4(ch["ip"])
        ch["ip6"] = _ipv6(ch["ip6"])
    if t is Sighting:  # the merge compares kinds exactly: "DHCP" would silently lose its lease
        ch["kind"] = ch["kind"].lower()
        ch["client_id"] = norm_client_id(ch["client_id"])
    ch.update({f: _flag(getattr(r, f)) for f in _BOOL_FIELDS[t]})
    if t is Sighting and ch["kind"] in V6_KINDS:  # a neighbour entry or a v6 lease never says the device is here now
        ch["presence"] = False
    ch.update({f: _int(getattr(r, f)) for f in _OPT_INT_FIELDS[t]})
    return r if all(getattr(r, f) == v and type(getattr(r, f)) is type(v) for f, v in ch.items()) else replace(r, **ch)


def normalise_batch(name: str, b: Batch) -> Batch:
    """The host's part of the record contract, for one instance's batch: `source` set to the instance name, `mac`
    normalised, records whose MAC fails norm_mac dropped (stats["dropped"], one WARNING per instance per process).
    Never raises: one connector's malformed batch must not fail the poll for the others, so a record of the wrong
    type, a MAC that is not a str, and a sightings/attachments field that is not a list or cannot be iterated
    (counted as one) are dropped the same way, as is a record whose MAC or field cannot be converted (its str(),
    bool() or str method raises). A record with a
    valid MAC but a wrong-typed field is kept with its fields coerced (str fields: None -> "", else str() with lone
    surrogates replaced, tab/line breaks as spaces and control/bidi characters removed, then .strip() except ssid/ap/alias; kind lower-cased;
    client_id in its normal form (norm_client_id); ip "" unless a dotted IPv4 (rewritten by str(IPv4Address));
    ip6 "" unless an IPv6 address that names a device (_ipv6; rewritten compressed, %scope dropped);
    flags -> bool, text by the config words; observed_at -> int or 0; vlan/signal -> int in int64 range or None).
    Returns a new Batch; the given one is left as it is. Applying it twice drops nothing more."""
    dropped = bad_ip = bad_ip6 = 0

    def fix(records: object, kind: type) -> list:
        nonlocal dropped, bad_ip, bad_ip6
        try:  # a list subclass may raise in __iter__
            items = list(records) if isinstance(records, (list, tuple)) else None
        except Exception:
            items = None
        if items is None:
            dropped += 1
            return []
        out = []
        for r in items:
            try:  # the MAC too: a str subclass's strip() or a `mac` property may raise
                mac = norm_mac(r.mac) if isinstance(r, kind) and isinstance(r.mac, str) else ""
                if mac:
                    c = _coerce(r, mac, name)
                    if kind is Sighting and c.ip == "" and _str(r.ip, True):
                        bad_ip += 1
                    if kind is Sighting and c.ip6 == "" and _str(r.ip6, True):
                        bad_ip6 += 1
                    out.append(c)
                    continue
            except Exception:  # any: a MAC or field whose conversion raises is as malformed as a bad MAC
                pass
            dropped += 1
        return out
    sightings, attachments = fix(b.sightings, Sighting), fix(b.attachments, Attachment)
    try:  # a plain copy: a dict subclass's get() or items may raise
        stats = dict(b.stats) if isinstance(b.stats, dict) else {}
    except Exception:
        stats = {}
    before = stats.get("dropped", 0)
    # only a count: a negative value (or a bool) from the connector would cancel this poll's drops, and the partial
    # check in _apply_attachments (dropped > 0) would take the batch as complete
    before = before if type(before) is int and before > 0 else 0
    if dropped and name not in _mac_warned:
        _mac_warned.add(name)
        log.warning("connector %s: %d malformed records dropped (invalid MAC, wrong type or unconvertible field)",
                    name, dropped)
    if bad_ip:
        log.debug("connector %s: %d sightings with an ip that is not IPv4, ip emptied", name, bad_ip)
    if bad_ip6:
        log.debug("connector %s: %d sightings with an ip6 that names no device or is not IPv6, ip6 emptied", name, bad_ip6)
    return Batch(sightings=sightings, attachments=attachments,
                 stats={**stats, "dropped": before + dropped})


def merge(prev: dict[str, dict], batches: dict[str, Batch | ConnectorFailure], cfg: Config, now: int,
          state: MergeState) -> MergeResult:
    """prev: every device row (mac -> column dict). batches: this poll's result per connector instance."""
    ok = {n: normalise_batch(n, b) for n, b in batches.items() if isinstance(b, Batch)}
    # an instance that failed may be the one holding the lease: its absence is no evidence that the lease is gone
    # (a switch, a controller or a name source lists no leases, so its failure does not count)
    # holder: judged by what it listed when it last answered (a firewall lists leases, a controller never does); with
    # no such record yet (first poll) every failed primary producer counts
    holders, answered = state.lease_holders, state.answered
    failed = [n for n, b in batches.items() if isinstance(b, ConnectorFailure)]
    # failed sighting producers but a controller (any instance but a controller when the producers are unknown)
    sighting_src = [n for n in failed if n not in state.controllers and (state.producers is None or n in state.producers)]

    def primary(n: str) -> bool:  # a sighting producer that is not secondary (controller, name source)
        return n not in state.controllers and n not in state.secondary and (state.producers is None or n in state.producers)
    # a failed primary producer that has never answered (added or renamed since) may hold a lease too
    lease_blind = any(primary(n) and (holders is None or n in holders or (answered is not None and n not in answered))
                      for n in failed)
    # source-blind: any failed primary producer, lease holder or not, may be the only one listing a device, so no
    # watch event is written (offline / online) on this poll (a secondary one asserts no presence of its own)
    src_blind = any(primary(n) for n in failed)
    now_holders = {n for n in holders or () if n not in state.controllers and n not in state.secondary}
    for n, b in ok.items():
        if not primary(n):
            continue
        # an empty answer proves nothing, so the instance stays a suspect
        (now_holders.discard if b.sightings and not any(s.kind == "dhcp" for s in b.sightings) else now_holders.add)(n)
    if holders is None:  # unknown: a failed producer stays a suspect until it has answered
        now_holders |= {n for n in failed if primary(n)}
    now_answered = set(answered or ()) | {n for n in ok if primary(n)}
    # lease-blind: a new private MAC may lack the client-id or hostname the failed instance holds. No alias is
    # decided; the MAC is held back (no row) so a later poll can still merge it, up to MERGE_HOLD_SECONDS. Only with
    # the producers known: otherwise a failed switch would count and hide new devices for nothing
    hold = lease_blind and state.producers is not None
    # label-blind: any failed sighting producer (a name source too), or a producer whose reservation search failed
    # (stats labels_unavailable), may hold a device's label, so an empty label this poll is no evidence that it was
    # removed
    label_blind = bool(sighting_src) or any(type(v := b.stats.get("labels_unavailable")) is int and v > 0 for b in ok.values())
    raw, keys, new_aliases, folds, folded, prev = _decide_keys(ok, prev, state, hold, now)
    held = _held_back(raw, keys, prev, state, hold, now)
    ok, att_macs = _rekey_batches(ok, keys, state.aliases, held)
    merged = merge_sightings([to_fw1(s) for b in ok.values() for s in b.sightings])
    # enrichment only: a MAC listed by NDP/DHCPv6 alone, or by secondary instances alone (a controller, a name
    # source), gets no row of its own (not new, not present)
    listed = {s.mac for n, b in ok.items() if n not in state.secondary for s in b.sightings if s.kind not in V6_KINDS}
    merged = {mac: m for mac, m in merged.items() if mac in prev or mac in listed}
    grace_s = cfg.online_grace_minutes * 60
    grace = now - grace_s
    res = MergeResult(aliases=new_aliases + folds, folds=folds,
                      alias_seen=sorted(m for m, k in keys.items() if k != m), lease_holders=frozenset(now_holders),
                      answered=frozenset(now_answered))
    res.events += _merge_events(new_aliases, folds, folded, now)
    rows = {mac: {**ROW_DEFAULTS, **r} for mac, r in prev.items()}
    before = {mac: dict(r) for mac, r in rows.items()}
    changes = _update_rows(rows, merged, cfg, state, now, lease_blind, grace_s, res, label_blind)
    _apply_attachments(rows, merged, batches, ok, state, res, att_macs)
    res.seen += _seen_rows(ok, rows, now)
    for row in rows.values():
        # devices not seen on the wire for longer than the grace period go offline
        if row["online"] and (row["last_online"] or 0) < grace:
            row["online"] = 0
    res.events += _watch_events(rows, before, res, state, now, src_blind)
    res.events += _auto_archive(rows, cfg, state, now)
    _assemble(res, rows, before, merged, state, changes)
    return res


def _decide_keys(ok: dict[str, Batch], prev: dict[str, dict], state: MergeState, hold: bool, now: int
                 ) -> tuple[dict[str, Merged], dict[str, str], list[tuple[str, str, str, str]],
                            list[tuple[str, str, str, str]], dict[str, dict], dict[str, dict]]:
    """(raw MAC -> record, raw MAC -> device key, new aliases, folds, folded rows, prev without the folded rows)."""
    # private MACs: decide each raw MAC's device key, then rewrite every record to it, so an alias's history,
    # events, seen rows and port land on its device and the ranking below chooses between both MACs' records
    raw = merge_sightings([to_fw1(s) for b in ok.values() for s in b.sightings])
    present = {s.mac for b in ok.values() for s in b.sightings if s.presence}
    present |= {a.mac for b in ok.values() for a in b.attachments if a.present is True}
    limits: dict = {}
    keys, new_aliases = decide_aliases(raw, present, prev, state.aliases, state.first_run or hold, now, limits)
    folds = [] if state.first_run or hold else decide_folds(raw, present, prev, state.aliases, limits["hosts"], keys, now,
                                                            frozenset(d for _, d, _, _ in new_aliases))
    # one device takes at most one new alias per poll: a fresh merge and a fold into one device are two interfaces,
    # so neither happens
    clash = {dev for _, dev, _, _ in folds} & set(limits.get("taken", ()))
    if clash:
        folds = [f for f in folds if f[1] not in clash]
        for alias, dev, _, _ in new_aliases:
            if dev in clash:
                keys[alias] = alias
        new_aliases = [a for a in new_aliases if a[1] not in clash]
    folded = {cand: prev[cand] for cand, _, _, _ in folds}
    for cand, dev, _, _ in folds:  # this poll's records land on the device; the candidate's row is gone
        keys[cand] = dev
        state.no_lease_since.pop(cand, None)
        state.undecided_since.pop(cand, None)
    if folded:  # no offline pass, prune or result row for a folded row
        prev = {mac: r for mac, r in prev.items() if mac not in folded}
    return raw, keys, new_aliases, folds, folded, prev


def _held_back(raw: dict[str, Merged], keys: dict[str, str], prev: dict[str, dict], state: MergeState, hold: bool,
               now: int) -> set[str]:
    """New private MACs held back undecided (no row) this poll; updates state.undecided_since in place."""
    held: set[str] = set()
    if hold and not state.first_run:
        for mac in raw:
            if keys[mac] == mac and mac not in prev and is_private_mac(mac):
                if now - state.undecided_since.setdefault(mac, now) < MERGE_HOLD_SECONDS:
                    held.add(mac)
                    continue
            state.undecided_since.pop(mac, None)
    else:  # every lease producer answered: what was held is decided now (or no longer listed)
        state.undecided_since.clear()
    return held


def _rekey_batches(ok: dict[str, Batch], keys: dict[str, str], aliases: dict[str, str], held: set[str]
                   ) -> tuple[dict[str, Batch], dict[str, list[str]]]:
    """(the batches on device keys without the held MACs' sightings, the MAC each attachment was listed under).
    Adds each attachment-only MAC to keys in place."""
    for b in ok.values():  # an attachment-only MAC (a switch FDB) follows a known alias too
        for a in b.attachments:
            keys.setdefault(a.mac, aliases.get(a.mac, a.mac))
    # the MAC each attachment was listed under, so an alias's record and its device's compete by rank
    att_macs = {n: [a.mac for a in b.attachments] for n, b in ok.items()}
    ok = {n: _rekey(b, keys) for n, b in ok.items()}
    if held:
        ok = {n: Batch(sightings=[s for s in b.sightings if s.mac not in held], attachments=b.attachments,
                       stats=b.stats) for n, b in ok.items()}
    return ok, att_macs


def _merge_events(new_aliases: list[tuple[str, str, str, str]], folds: list[tuple[str, str, str, str]],
                  folded: dict[str, dict], now: int) -> list[tuple[str, str, str]]:
    """The `merged` event on the device for each new alias and each fold, in that order."""
    # a merge is no new device: no `new` event and no mail, only this event on the device
    events = [(dev, "merged", f"{alias} (client-id)" if reason == "client-id" else f"{alias} (hostname {value})")
              for alias, dev, reason, value in new_aliases]
    # a fold: the same event, saying how long the MAC had its own row
    events += [(dev, "merged", f"{cand} (hostname {value}, own row for "
                               f"{max(0, now - folded[cand]['first_seen']) // 60} min)")
               for cand, dev, _, value in folds]
    return events


def _update_rows(rows: dict[str, dict], merged: dict[str, Merged], cfg: Config, state: MergeState, now: int,
                 lease_blind: bool, grace_s: int, res: MergeResult, label_blind: bool = False) -> int:
    """Each merged device's row added or updated in place, with its events and history; returns the changed count."""
    changes = 0
    for mac, m in merged.items():
        sources = ",".join(sorted(m.sources))
        cur = rows.get(mac)
        if cur is None:
            rows[mac] = {**ROW_DEFAULTS, "mac": mac, "first_seen": now, "baseline": int(state.first_run), "last_seen": now,
                         "last_online": now if m.online else None, "ip": m.ip, "hostname": m.hostname, "vendor": m.vendor,
                         "vlan": m.vlan, "iface": m.iface, "lease_type": m.lease_type, "sources": sources, "online": int(m.online),
                         "client_id": m.client_id, "label": m.label, "ip6": m.ip6, "ip6_stable": m.ip6_stable}
            res.history.append((mac, {"ip": m.ip, "hostname": m.hostname, "vlan": m.vlan, "lease_type": m.lease_type,
                                      "ip6": m.ip6_stable}))
            if not state.first_run:
                res.events.append((mac, "new", " ".join(filter(None, [m.ip, m.hostname, m.vendor])) + (f" ({m.vlan})" if m.vlan else "")))
                res.new.append(mac)
            continue
        changes += _update_row(mac, cur, m, sources, cfg, state, now, lease_blind, grace_s, res, label_blind)
    return changes


def _change_events(cur: dict, m: Merged) -> list[tuple[str, str]]:
    """(kind, detail) for each of ip, hostname, vlan and lease type that this poll's record changes."""
    ev = []
    if m.ip and m.ip != cur["ip"]:
        ev.append(("ip", f"{cur['ip'] or '-'} -> {m.ip}"))
    if m.hostname and m.hostname != cur["hostname"]:
        ev.append(("hostname", f"{cur['hostname'] or '-'} -> {m.hostname}"))
    if m.vlan and m.vlan != cur["vlan"]:
        ev.append(("vlan", f"{cur['vlan'] or '-'} -> {m.vlan}"))
    if m.lease_type and m.lease_type != cur["lease_type"]:
        ev.append(("lease_type", f"{cur['lease_type'] or 'no DHCP'} -> {m.lease_type}"))
    return ev


def _settle_lease_type(mac: str, cur: dict, m: Merged, cfg: Config, state: MergeState, now: int, lease_blind: bool,
                       grace_s: int, ev: list[tuple[str, str]]) -> str:
    """The row's lease type after this poll by LEASE_TYPE_MODE; appends a `-> no DHCP` event to ev when it is dropped."""
    lease_type = m.lease_type or cur["lease_type"]
    if m.lease_type:
        state.no_lease_since.pop(mac, None)
    elif cur["lease_type"] and cfg.lease_type_mode != "keep" and not lease_blind:
        since = state.no_lease_since.setdefault(mac, now)
        if cfg.lease_type_mode == "immediate" or now - since >= grace_s:
            lease_type = ""
            state.no_lease_since.pop(mac, None)
            ev.append(("lease_type", f"{cur['lease_type']} -> no DHCP"))
    return lease_type


def _back_event(cur: dict, m: Merged, now: int, prev_ok: bool) -> tuple[str, str] | None:
    """The `back` event of a device online again after the archive or a day away; clears cur's archived_ts."""
    # archive: online again (on the wire, not merely listed: a static lease is listed every poll) brings an
    # archived device back to the list; this `back` replaces the ordinary one. One archived while still online
    # stays archived until it has been offline
    if cur["archived_ts"] is not None and m.online and not cur["online"]:
        days = max(0, now - cur["archived_ts"]) // 86400
        cur["archived_ts"] = None
        return ("back", f"back from the archive (archived {days} day{'' if days == 1 else 's'} ago)")
    # prev_ok: after a failed poll every device looks "away" for the outage, so "back" would be a false positive
    if m.online and not cur["online"] and cur["last_online"] and now - cur["last_online"] > 86400 and prev_ok:
        days = (now - cur["last_online"]) // 86400
        return ("back", f"back after {days} day{'' if days == 1 else 's'}")
    return None


def _watch_events(rows: dict[str, dict], before: dict[str, dict], res: MergeResult, state: MergeState,
                  now: int, lease_blind: bool = False) -> list[tuple[str, str, str]]:
    """`offline` / `online` for each watched row (watch=1) whose online flag differs from the one its last event
    reported (watch_online, set in place); other rows get none and their watch_online is cleared, so watching again
    starts clean. offline: after the grace (in _update_row for a device still listed, or by the grace rule in merge),
    so the grace is the debounce. online: back on the wire, unless this poll writes its `back` event (a day away or the
    archive). Only on a poll every source can be trusted for: the previous poll was ok (after a failed one every
    device looks "away" for the outage, and _fail turned online off silently) and no sighting producer failed this
    poll (lease_blind: a device only the failed one lists goes offline by the grace rule). A change on another poll is
    written at the first trusted poll after it, if it still holds."""
    if not state.prev_ok or lease_blind:
        for row in rows.values():  # unwatched rows need no evidence to forget what was reported
            if not row.get("watch"):
                row["watch_online"] = None
        return []
    back = {mac for mac, kind, _ in res.events if kind == "back"}
    events = []
    for mac, row in rows.items():
        if not row.get("watch"):
            row["watch_online"] = None
            continue
        online = int(bool(row["online"]))
        reported = row.get("watch_online")
        if reported is None:  # just watched: the state before this poll is what was known when the watch began
            was = before.get(mac)
            reported = online if was is None else int(bool(was["online"]))
        row["watch_online"] = online
        if online == bool(reported):
            continue
        if not online:
            ago = max(0, now - (row["last_online"] or now)) // 60
            events.append((mac, "offline", f"last seen {ago} min ago"))
        elif mac not in back:
            events.append((mac, "online", ""))
    return events


def _update_row(mac: str, cur: dict, m: Merged, sources: str, cfg: Config, state: MergeState, now: int,
                lease_blind: bool, grace_s: int, res: MergeResult, label_blind: bool = False) -> int:
    """A known device's row updated in place from this poll's record; returns 1 when it writes a history row."""
    # sticky, no event or history: the stored address stays while still listed in the best class (a temporary
    # address rotating beside it changes nothing) or while nothing is listed (NDP aged it out)
    ip6 = cur["ip6"] if cur["ip6"] in m.ip6s else m.ip6 or cur["ip6"]
    old_stable = cur.get("ip6_stable") or ""
    stable = _settle_ip6_stable((mac,), old_stable, m)
    # a stable address replaced by another one is a renumbering; the first one ('' before) is no event
    renumbered = [("ip6", f"{old_stable} -> {stable}")] if old_stable and stable != old_stable else []
    if m.sources <= V6_KINDS:
        # listed by NDP/DHCPv6 alone: enrichment only. ip6, ip6_stable and last_seen move, nothing else: no lease-type
        # clock (the record has no lease), and online is left to the grace rule in merge(). A renumbering writes
        # its event and history row; the first stable address is filled silently. sources records what listed it
        # this poll, except on a split row waiting for its first poll, whose '' must stay so that first full
        # listing still fills it silently
        keep = not cur["sources"] and cur.get("split_from")
        changed = 0
        if renumbered:
            res.events += [(mac, kind, detail) for kind, detail in renumbered]
            res.history.append((mac, {"ip": cur["ip"], "hostname": cur["hostname"], "vlan": cur["vlan"],
                                      "lease_type": cur["lease_type"], "ip6": stable}))
            changed = 1
        cur.update(ip6=ip6, ip6_stable=stable, last_seen=now, sources=cur["sources"] if keep else sources)
        return changed
    ev = _change_events(cur, m)
    lease_type = _settle_lease_type(mac, cur, m, cfg, state, now, lease_blind, grace_s, ev)
    ev += renumbered
    # a row made by a split has sources '' and split_from set until a poll lists it: its first listing fills the
    # empty fields and writes the history row, but the fill is no change worth an event. Sources '' alone is no
    # marker: a connector that emits kind "" is stored that way for good
    fields_changed = bool(ev)
    if not cur["sources"] and cur.get("split_from"):
        ev = []
    back = _back_event(cur, m, now, state.prev_ok)
    if back is not None:
        ev.append(back)
    res.events += [(mac, kind, detail) for kind, detail in ev]
    # ip/vlan/iface come from one sighting (merge_sightings): when the device moved, an empty ip, vlan or iface is
    # unknown at the new place, and the stored one would name the old place
    # an unknown stored network becoming known is no move: the stored IP is still right
    moved = (m.ip and m.ip != cur["ip"]) or (m.vlan and cur["vlan"] and m.vlan != cur["vlan"])
    ip = m.ip if moved else m.ip or cur["ip"]
    vlan, iface = (m.vlan, m.iface) if moved else (m.vlan or cur["vlan"], m.iface or cur["iface"])
    changed = 0
    if fields_changed or stable != old_stable or any(k in ("ip", "hostname", "vlan", "lease_type") for k, _ in ev):
        res.history.append((mac, {"ip": ip, "hostname": m.hostname or cur["hostname"],
                                  "vlan": vlan, "lease_type": lease_type, "ip6": stable}))
        changed = 1
    # not on the wire right now: stays online until the grace period after its last sighting has passed
    online = m.online or bool(cur["online"] and (cur["last_online"] or 0) >= now - grace_s)
    cur.update(ip6=ip6, ip6_stable=stable, last_seen=now, last_online=now if m.online else cur["last_online"], ip=ip,
               hostname=m.hostname or cur["hostname"], vendor=m.vendor or cur["vendor"], vlan=vlan,
               iface=iface, lease_type=lease_type, sources=sources, online=int(online),
               client_id=m.client_id or cur["client_id"],
               # label-blind: a label read this poll still wins, an empty one keeps the stored label
               label=m.label or cur["label"] if label_blind else m.label)
    return changed


def _seen_rows(ok: dict[str, Batch], rows: dict[str, dict], now: int) -> list[tuple[str, str, int, int | None]]:
    """(mac, instance, last_seen, last_present or None) for each MAC with a device row that an instance listed."""
    seen: list[tuple[str, str, int, int | None]] = []
    # only MACs with a device row: a switch FDB lists MACs no sighting ever named, which would leave orphan rows
    for n, b in ok.items():
        listed: dict[str, bool] = {}
        for s in b.sightings:
            listed[s.mac] = listed.get(s.mac, False) or s.presence
        for a in b.attachments:
            listed[a.mac] = listed.get(a.mac, False) or a.present is True
        seen += [(mac, n, now, now if present else None) for mac, present in listed.items() if mac in rows]
    return seen


def _auto_archive(rows: dict[str, dict], cfg: Config, state: MergeState, now: int) -> list[tuple[str, str, str]]:
    """Archives (in place) each row PRUNE_DAYS prunes this poll; returns their `archived` events."""
    events: list[tuple[str, str, str]] = []
    # PRUNE_DAYS: archive what has been offline that long and was never named, tagged, marked known or watched; the
    # baseline is not spared. last_online, not last_seen: a static lease is listed for ever. Never on the first run
    # PRUNE_PRIVATE_DAYS: a shorter threshold for a private MAC that never merged (no name, note, tags, ack, watch,
    # split origin or alias pointing at it), never longer than PRUNE_DAYS
    if (cfg.prune_days > 0 or cfg.prune_private_days > 0) and not state.first_run:
        ref = now if state.prune_now is None else state.prune_now
        targets = set(state.aliases.values())
        for mac, row in rows.items():
            private = (cfg.prune_private_days > 0 and is_private_mac(mac) and not row["name"] and not row.get("note")
                       and not row.get("tags") and not row.get("split_from") and not row.get("watch") and mac not in targets)
            if private:
                days = min(cfg.prune_private_days, cfg.prune_days) if cfg.prune_days > 0 else cfg.prune_private_days
            else:
                days = cfg.prune_days
            if days <= 0:
                continue
            since = row["last_online"] or row["first_seen"]
            # a restore by hand since it was last online holds until it has been online again
            if (row["archived_ts"] is None and not row["online"] and since < ref - days * 86400 and not row["name"]
                    and not row.get("tags") and not row["acked"] and not row.get("watch") and state.restored.get(mac, 0) < since):
                row["archived_ts"] = now
                label = "auto (private)" if private else "auto"
                events.append((mac, "archived", f"{label}: not online for {(ref - since) // 86400} days"))
    return events


def _assemble(res: MergeResult, rows: dict[str, dict], before: dict[str, dict], merged: dict[str, Merged],
              state: MergeState, changes: int) -> None:
    """The result's first-run events and history, its rows (every merged or changed device) and its stats."""
    if state.first_run:
        # until the baseline is taken, a producer answering late only completes the
        # first picture (e.g. "hostname - -> laptop"), so it is no change: no events, and no history until the poll
        # that takes the baseline writes one row per device with its complete values
        res.events = []
        res.history = [] if state.held_back else [
            (mac, {**{k: row[k] for k in ("ip", "hostname", "vlan", "lease_type")}, "ip6": row.get("ip6_stable") or ""})
            for mac, row in rows.items()]
    res.rows = {mac: row for mac, row in rows.items()
                if mac in merged or any(row[k] != before[mac][k] for k in UPDATE_COLUMNS)}
    # what the first run counted is no change (no event, no history row of its own), so it is not reported as one
    res.stats = {"devices": len(merged), "new": len(res.new), "changed": 0 if state.first_run else changes}


def _apply_attachments(rows: dict[str, dict], merged: dict[str, Merged], batches: dict[str, Batch | ConnectorFailure],
                       ok: dict[str, Batch], state: MergeState, res: MergeResult,
                       att_macs: dict[str, list[str]] | None = None) -> None:
    """Switch-port and Wi-Fi columns from the attachments, on the rows after the identity merge (in place).

    Several controllers: a device has left Wi-Fi only when every controller answered and none lists it; while any
    controller failed this poll and none that answered lists it, a Wi-Fi device is "blind" (keeps its last values,
    gets no switch port). A "wifi"
    attachment from an instance without the controller role is ignored (its list is not complete)."""
    controllers = [n for n in batches if n in state.controllers]
    wifi, wired = _pick_attachments(rows, ok, state.controllers, att_macs)
    # a batch normalise_batch dropped records from (here or in the collector) is not a complete list: what it leaves
    # out is no evidence, so it counts as failed for "left Wi-Fi" and for releasing a held port
    partial = {n for n, b in ok.items() if b.stats.get("dropped", 0) > 0}
    ctrl_ok = any(n in ok and n not in partial for n in controllers)
    ctrl_failed = any(n not in ok or n in partial for n in controllers)
    new = set(res.new)  # a device new this poll already has its "new" event: joining Wi-Fi is no change of its own
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
        # a cable shown: an edge port this poll. An uplink entry (a Wi-Fi client on its AP's uplink) is no cable
        edge = bool(sw and sw.port and not sw.uplink)
        # the switch that placed this wired device failed this poll: another switch can only offer a worse view (an
        # uplink towards it, an aged FDB entry), so the port stays as it is, as a Wi-Fi device does while blind
        held = (cur["link"] == "wired" and cur["loc_source"] in batches
                and (cur["loc_source"] not in ok or cur["loc_source"] in partial) and cur["loc_source"] not in state.controllers)
        # on the wire this poll, not in grace: the FDB ages out slower than ARP, so a departed device would get a stale port
        # Wi-Fi beats any switch port, also an edge port: a controller's client list is first-hand, an FDB entry for a
        # Wi-Fi client can be an AP port that is not marked as an uplink
        if sw and on_wire and not on_wifi and not blind and not held and sw.port:
            _place_on_port(mac, cur, sw, state.controllers, res, upd)
        if on_wifi:
            # the instance that listed it cannot report SSIDs (stats ssid_unavailable): a stored SSID is stale, not kept
            no_ssid = type(v := (ok[w.source].stats if w.source in ok else {}).get("ssid_unavailable")) is int and v > 0
            _place_on_wifi(mac, cur, w, mac in new, res, upd, no_ssid)
        elif w is not None:  # the controller says wired now: drop the old Wi-Fi details
            _place_off_wifi(mac, cur, w, held, res, upd)
        # on the wire this poll, not just in grace: a phone walking out drops off ARP and the controller together, and
        # its last SSID must stay (the FDB may still hold it on the AP uplink, which is not a cable)
        # a client listed without an SSID has link "wifi" but no SSID: it left Wi-Fi too
        if ctrl_ok and not ctrl_failed and on_wire and (cur["wifi_ssid"] or cur["link"] == "wifi") and mac not in wifi:
            _leave_wifi(mac, cur, edge, res, upd)
        # on the wire, as for the port above: a device only in grace would be called wired on a stale FDB entry
        if on_wire and sw and not on_wifi and cur["link"] != "wifi":
            upd["link"] = "wired"
        row.update(upd)


def _pick_attachments(rows: dict[str, dict], ok: dict[str, Batch], controllers: frozenset[str],
                      att_macs: dict[str, list[str]] | None) -> tuple[dict[str, Attachment], dict[str, Attachment]]:
    """(device -> its controller attachment, device -> its winning switch attachment) from this poll's batches."""
    wifi: dict[str, Attachment] = {}
    wired: dict[str, Attachment] = {}
    rank: dict[str, tuple] = {}  # mac -> sort key of the wired candidate kept so far (lower wins)
    for i, (n, b) in enumerate(ok.items()):
        mine: set[str] = set()  # MACs this instance already put up: its first wired attachment is its candidate
        listed = (att_macs or {}).get(n) or [a.mac for a in b.attachments]  # as listed, before the alias rewrite
        for a, lmac in zip(b.attachments, listed):
            if a.link not in LINKS:
                value = str(a.link)[:40]  # whatever the connector put there; capped so a log line stays one line
                if (n, value) not in _link_warned:
                    _link_warned.add((n, value))
                    log.warning("connector %s: attachments with link %r ignored (allowed: wired, wifi)", n, value)
                continue
            if n in controllers:
                # an alias and its device in one client list: the active client is where the device is
                old = wifi.get(a.mac)
                if old is None or (old.source == n and a.present is True and old.present is not True):
                    wifi[a.mac] = a
            # per MAC as listed: an alias and its device on one switch are two candidates, ranked below
            elif a.link == "wired" and lmac not in mine:
                mine.add(lmac)
                # the edge port is where the device is; an uplink only says which way it lies. Two edge ports (the
                # FDBs age at different speeds): the switch that already holds the device (sticky, so a walk order
                # or an FDB timing never makes it flap), then the instance order
                sticky = n == rows.get(a.mac, {}).get("loc_source")
                # an empty label ranks last: the row would drop it below, losing a labelled candidate of another switch
                key = (not a.port, bool(a.uplink), not sticky, i)
                if a.mac not in rank or key < rank[a.mac]:
                    wired[a.mac], rank[a.mac] = a, key
    return wifi, wired


def _place_on_port(mac: str, cur: dict, sw: Attachment, controllers: frozenset[str], res: MergeResult,
                   upd: dict) -> None:
    """The winning switch port into upd, with a `port` event when the device moved."""
    # only the winner is compared with the row, so a losing candidate that moves writes no event
    # another switch with the same port label (switches of one model share GE1/0/N): a move all the same, named
    # by instance as the label alone would read "GE1/0/14 -> GE1/0/14"
    other = (cur["sw_port"] == sw.port and cur["loc_source"] not in ("", sw.source)
             and cur["loc_source"] not in controllers)
    if other:
        res.events.append((mac, "port", f"{cur['sw_port']} ({cur['loc_source']}) -> {sw.port} ({sw.source})"
                                        f"{' via ' + sw.via if sw.via else ''}"))
    if sw.port != cur["sw_port"] or sw.via != cur["sw_via"]:
        if cur["sw_port"] and sw.port != cur["sw_port"]:
            res.events.append((mac, "port", f"{cur['sw_port']} -> {sw.port}{' via ' + sw.via if sw.via else ''}"))
        upd.update(sw_port=sw.port, sw_via=sw.via)
    upd["loc_source"] = sw.source


def _place_on_wifi(mac: str, cur: dict, w: Attachment, is_new: bool, res: MergeResult, upd: dict,
                   no_ssid: bool = False) -> None:
    """A controller's Wi-Fi listing into upd and res.wifi, with a `wifi` event for an SSID change or a join.
    no_ssid: the controller reports no SSID, signal or radio at all: the stored ones are cleared, with one event."""
    # this poll's listing is the evidence of presence: only here, never from the stored SSID
    if w.ssid:
        res.wifi.append((mac, w.ssid, w.ap))
    # only an SSID change or joining Wi-Fi is an event; a roam between APs updates the row silently
    if w.ssid and w.ssid != cur["wifi_ssid"]:
        if cur["wifi_ssid"]:
            res.events.append((mac, "wifi", f"{cur['wifi_ssid']} -> {w.ssid}"))
        # joined from a cable only: on Wi-Fi without an SSID, or placed nowhere (a walk-out
        # cleared silently below), it never left Wi-Fi as far as the record shows
        # a row wired through an uplink (sw_via names what is behind it: the AP a walked-out phone was
        # last learned on) showed no cable either
        elif not is_new and cur["link"] == "wired" and not cur["sw_via"]:
            res.events.append((mac, "wifi", f"- -> {w.ssid}"))
    # an empty SSID (a client listed without its essid) says nothing: the stored one stays, so the next change is logged
    if no_ssid and not w.ssid:
        if cur["wifi_ssid"]:
            res.events.append((mac, "wifi", "SSID unknown (controller reports none)"))
        upd.update(wifi_ssid="", wifi_ap=w.ap, wifi_signal=None, wifi_radio="", wifi_alias=w.alias, link="wifi",
                   loc_source=w.source)
        if cur["sw_port"] and "sw_port" not in upd:
            upd.update(sw_port="", sw_via="")
        return
    upd.update(wifi_ssid=w.ssid or cur["wifi_ssid"], wifi_ap=w.ap, wifi_signal=w.signal, wifi_radio=w.radio, wifi_alias=w.alias, link="wifi",
               loc_source=w.source)
    if cur["sw_port"] and "sw_port" not in upd:  # on Wi-Fi now: the switch port it had on a cable is stale
        upd.update(sw_port="", sw_via="")


def _place_off_wifi(mac: str, cur: dict, w: Attachment, held: bool, res: MergeResult, upd: dict) -> None:
    """A controller listing the device as wired: the old Wi-Fi details dropped in upd, with a `wifi` event."""
    if cur["wifi_ssid"]:
        res.events.append((mac, "wifi", f"{cur['wifi_ssid']} -> wired"))
    upd.update(wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", wifi_alias=w.alias, link="wired")
    if not held:  # the failed holder switch keeps the device: taking loc_source would unlock a port move next poll
        upd.setdefault("loc_source", w.source)  # a switch port found above names the device's place more exactly


def _leave_wifi(mac: str, cur: dict, edge: bool, res: MergeResult, upd: dict) -> None:
    """No answering controller lists the device: its Wi-Fi details cleared in upd, with an event if a cable shows."""
    # every controller answered and none lists it: it left Wi-Fi, so the SSID/AP are stale. The switch
    # branch above already recorded its port, so a cable is shown in this same poll.
    # an event only with a cable shown: ARP alone keeps a walked-out phone ~20 min after the
    # controller dropped it, so without a switch port this cannot be told from a walk-out
    if cur["wifi_ssid"] and edge:
        res.events.append((mac, "wifi", f"{cur['wifi_ssid']} -> off Wi-Fi"))
    upd.update(wifi_ssid="", wifi_ap="", wifi_signal=None, wifi_radio="", link="wired" if edge else "")
    upd.setdefault("loc_source", "")  # the controller no longer places it; a switch port above may
