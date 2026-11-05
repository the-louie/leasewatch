"""Switch port per MAC over SNMPv3 (Q-BRIDGE-MIB forwarding table + IF-MIB names + LLDP neighbours).

Tested on HP/H3C Comware 7. What is walked and which vendor quirks apply comes from an SNMP profile
(leasewatch/snmp_profiles/*.json), chosen by name or detected from sysObjectID/sysDescr at the first snapshot.
pysnmp (7.x) is imported lazily so the rest of leasewatch works without it.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from . import snmp_profiles
from .config import Config

log = logging.getLogger("leasewatch.switch")

# 1.0 names, kept for importers; the walks now use the profile's "oids" (same values in standard.json)
OID_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"      # dot1qTpFdbPort: index vlan.mac6 -> bridge port
OID_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex: bridge port -> ifIndex
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"            # ifName: ifIndex -> name
OID_LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"  # lldpRemSysName: timeMark.localPort.index -> neighbour name
OID_LLDP_LOC_PORTID = "1.0.8802.1.1.2.1.3.7.1.3"    # lldpLocPortId: lldpLocPortNum -> port id (usually the ifName)
OID_LLDP_LOC_PORTDESC = "1.0.8802.1.1.2.1.3.7.1.4"  # lldpLocPortDesc: lldpLocPortNum -> description
UPLINK_MACS = 6  # 1.0 default of the profiles' uplink.min_macs: this many MACs on a port without LLDP = uplink/AP port
# 1.0's hard-coded Comware abbreviations, used when no profile map is given; the profiles carry their own map
# (comware.json has these). Order matters: the longer name first, so "Ten-GigabitEthernet" is not turned into "Ten-GE".
DEFAULT_SHORT = {"Ten-GigabitEthernet": "XGE", "GigabitEthernet": "GE", "FortyGigE": "FGE", "Bridge-Aggregation": "BAGG"}


def short_ifname(name: str, short: dict | None = None) -> str:
    for long, abbr in (DEFAULT_SHORT if short is None else short).items():
        name = name.replace(long, abbr)
    return name


def _default_profile() -> dict:
    # profile=None is 1.0's behaviour: the standard walks plus the Comware short names, i.e. the comware profile
    return snmp_profiles.load("comware")


@dataclass
class PortInfo:
    ifindex: int
    name: str
    neighbor: str = ""      # LLDP system name of what is plugged in (switch/AP), if any
    macs: int = 0
    uplink: bool = False


@dataclass
class SwitchSnapshot:
    ports: dict = field(default_factory=dict)      # ifindex -> PortInfo
    by_mac: dict = field(default_factory=dict)     # mac -> (ifindex, vlan)
    short: dict | None = None                      # port_name.short of the profile; None = DEFAULT_SHORT

    def describe(self, mac: str) -> tuple[str, str]:
        """(port label, via) for the UI, e.g. ("GE1/0/14", "") or ("GE1/0/3", "ap-hall")."""
        hit = self.by_mac.get(mac)
        if not hit:
            return "", ""
        p = self.ports.get(hit[0])
        if not p:
            return f"port {hit[0]}", ""
        return short_ifname(p.name, self.short), (p.neighbor or f"{p.macs} devices") if p.uplink else ""


def _fdb_key(idx: str, fix: str, addresses: dict[str, str]) -> tuple[int, str] | None:
    """(vlan, mac) from a forwarding-table index "vlan.<mac part>", after the profile's index_fix; None = unusable row.

    none: vlan.m1..m6. length_byte (ArubaOS-CX style): vlan.6.m1..m6, a 7-part index is accepted as is. zynos: first
    arc is the VLAN, the last six the MAC, whatever sits between. row_number (Netonix style): vlan.row, the MAC comes
    from dot1dTpFdbAddress at the same row (`addresses`)."""
    parts = idx.split(".")
    try:
        if fix == "row_number":
            mac = addresses.get(".".join(parts[1:]), "")
            return (int(parts[0]), mac) if len(parts) >= 2 and mac else None
        if fix == "zynos" and len(parts) >= 7:
            parts = [parts[0]] + parts[-6:]
        elif fix == "length_byte" and len(parts) == 8 and parts[1] == "6":
            parts = [parts[0]] + parts[2:]
        if len(parts) != 7:
            return None
        return int(parts[0]), ":".join(f"{int(x):02x}" for x in parts[1:])
    except ValueError:
        return None


def build_snapshot(fdb: list[tuple[str, int]], baseport: list[tuple[str, int]], ifname: list[tuple[str, str]],
                   lldp: list[tuple[str, str]], locports: list[tuple[str, str]] | None = None, profile: dict | None = None,
                   fdb_status: list[tuple[str, int]] | None = None, fdb_address: list[tuple[str, str]] | None = None) -> SwitchSnapshot:
    """Pure function over raw (index, value) walks, so it can be unit-tested without a switch.

    `fdb` rows are (vlan.<mac part>, bridge port); the client prefixes VLAN 0 (bridge) or the context's VLAN
    (cisco_per_vlan) so every strategy arrives in the Q-BRIDGE index form. `profile` (None = 1.0 behaviour) sets
    fdb.index_fix and fdb.keep_status (applied when `fdb_status` rows, same index as `fdb`, are given; a row the status
    walk does not list is kept), bridge_port_map, lldp.local_port, port_name.short and uplink. `fdb_address` is
    dot1dTpFdbAddress as (vlan.row, "aa:bb:..") for index_fix row_number.

    lldpRemSysName is indexed by lldpLocPortNum, which is only the ifIndex on some vendors (Comware). With
    lldp.local_port "auto", `locports` (lldpLocPortId / lldpLocPortDesc rows: lldpLocPortNum -> text) maps a port number
    to the interface whose ifName matches; a number without a match is taken as an ifIndex. "ifindex" skips the
    name step (RouterOS)."""
    prof = profile if profile is not None else _default_profile()
    fdb_p, bpm, short = prof["fdb"], prof["bridge_port_map"], prof["port_name"]["short"]
    bp2if: dict[int, int] = {}
    for k, v in baseport:
        try:
            bp2if[int(k)] = int(v)
        except ValueError:  # one odd row must not lose the whole snapshot
            continue
    names: dict[int, str] = {}
    for k, v in ifname:
        try:
            names[int(k)] = str(v).strip()
        except ValueError:
            continue
    use_bp_map = bpm["strategy"] == "dot1dBasePortIfIndex"
    if fdb and use_bp_map and not bp2if:
        log.warning("no dot1dBasePortIfIndex rows: bridge ports used as ifIndex")
    by_name = {v: k for k, v in names.items()}
    by_name.update({short_ifname(v, short): k for k, v in names.items()})
    loc2if: dict[int, int] = {}
    for num, text in (locports or []) if prof["lldp"]["local_port"] == "auto" else []:
        try:
            n, t = int(num), str(text).strip()
        except ValueError:
            continue
        if t in by_name:
            loc2if.setdefault(n, by_name[t])
    neighbors: dict[int, str] = {}
    for idx, name in lldp:
        parts = idx.split(".")
        if len(parts) >= 2:
            try:
                n = int(parts[1])
                neighbors[loc2if.get(n, n)] = str(name)
            except ValueError:
                pass
    snap = SwitchSnapshot(short=short)
    for ifindex, name in names.items():
        snap.ports[ifindex] = PortInfo(ifindex=ifindex, name=name, neighbor=neighbors.get(ifindex, ""))

    def to_ifindex(port: int) -> int | None:
        if use_bp_map and port in bp2if:
            return bp2if[port]
        cand = port + bpm["offset"]
        if names and cand not in names:
            for tmpl in bpm["name_match"] or []:  # JetStream: the offset missed, try the interface name
                hit = by_name.get(tmpl.format(port=port))
                if hit is not None:
                    return hit
        return cand if bpm["fallback"] == "identity" else None

    keep = set(fdb_p["keep_status"])
    status: dict[str, int] = {}
    for k, v in fdb_status or []:
        try:
            status[str(k)] = int(v)
        except ValueError:
            continue
    addresses = {str(k).split(".", 1)[1] if "." in str(k) else str(k): str(v) for k, v in fdb_address or []}
    macs_on: dict[int, set] = {}  # distinct MACs: one MAC learned in several VLANs is still one device
    for idx, port in fdb:
        if keep and idx in status and status[idx] not in keep:  # e.g. self(4)/mgmt(5) when only learned(3) is kept
            continue
        key = _fdb_key(idx, fdb_p["index_fix"], addresses)
        if key is None:
            continue
        vlan, mac = key
        try:
            if int(port) == 0:  # the switch's own / management MACs: no real port
                continue
            ifindex = to_ifindex(int(port))
        except ValueError:
            continue
        if ifindex is None:
            continue
        snap.by_mac[mac] = (ifindex, vlan)
        macs_on.setdefault(ifindex, set()).add(mac)
    for ifindex, macs in macs_on.items():
        p = snap.ports.setdefault(ifindex, PortInfo(ifindex=ifindex, name=f"port {ifindex}"))
        p.macs = len(macs)
    min_macs, lldp_uplink = prof["uplink"]["min_macs"], prof["uplink"]["lldp_neighbor"]
    for p in snap.ports.values():
        if p.neighbor and lldp_uplink:
            p.uplink = True
        elif p.macs >= min_macs:  # many MACs on one port without LLDP: an unmanaged switch or AP hangs there
            p.uplink = True
    return snap


_END = ("EndOfMibView", "NoSuchObject", "NoSuchInstance")


def _oid_tuple(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in s.split("."))


class SwitchClient:
    def __init__(self, cfg: Config, profile: dict | None = None):
        self.cfg = cfg
        # None: detected from sysObjectID/sysDescr at the first snapshot and cached here (see _snapshot_async)
        self.profile = profile
        self.profile_name = profile["profile"] if profile else ""

    @staticmethod
    def _context(name: str) -> object:
        from pysnmp.hlapi.v3arch.asyncio import ContextData
        # SNMPv3 context (cisco_per_vlan: "vlan-<N>"); the v1/v2c community@vlan form is out of scope, leasewatch is v3-only
        return ContextData(contextName=name) if name else ContextData()

    @staticmethod
    def _accept(base: str, prev: str, oid: object, val: object) -> str | None:
        """The OID as text if the row belongs to the walk, None if the walk has ended."""
        s = str(oid)
        if not s.startswith(base + ".") or type(val).__name__ in _END:
            return None
        # an agent that does not advance (same or lower OID) would make the walk loop forever
        if _oid_tuple(s) <= _oid_tuple(prev):
            return None
        return s

    async def _walk(self, eng, tgt, user, base: str, context: str = "") -> list[tuple[str, object]]:
        from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, next_cmd
        out = []
        cur_oid = base
        while True:
            err_ind, err_stat, _, vbs = await next_cmd(eng, user, tgt, self._context(context), ObjectType(ObjectIdentity(cur_oid)))
            if err_ind:
                raise RuntimeError(f"snmp walk {base}: {err_ind}")
            if err_stat:  # a partial table would silently drop ports; fail the poll instead
                raise RuntimeError(f"snmp walk {base}: status {err_stat}")
            if not vbs:
                break
            s = self._accept(base, cur_oid, vbs[0][0], vbs[0][1])
            if s is None:
                break
            out.append((s[len(base) + 1:], vbs[0][1]))
            cur_oid = s
        return out

    async def _bulk_walk(self, eng, tgt, user, base: str, context: str = "") -> list[tuple[str, object]]:
        """GETBULK walk with the same end rules as _walk; pysnmp 7's bulk_cmd returns a flat list of var-binds."""
        from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, bulk_cmd
        reps = int(self.profile["snmp"]["max_repetitions"]) if self.profile else 10
        out = []
        cur_oid = base
        while True:
            err_ind, err_stat, _, vbs = await bulk_cmd(eng, user, tgt, self._context(context), 0, reps, ObjectType(ObjectIdentity(cur_oid)))
            if err_ind:
                raise RuntimeError(f"snmp walk {base}: {err_ind}")
            if err_stat:
                raise RuntimeError(f"snmp walk {base}: status {err_stat}")
            if not vbs:
                break
            for vb in vbs:
                s = self._accept(base, cur_oid, vb[0], vb[1])
                if s is None:
                    return out
                out.append((s[len(base) + 1:], vb[1]))
                cur_oid = s
        return out

    async def _walk_key(self, eng, tgt, user, key: str, context: str = "") -> list[tuple[str, object]]:
        """Walk the profile's oids[key] (or a numeric OID) with GETBULK when snmp.bulk is on and the OID is not in no_bulk."""
        oid = self.profile["oids"].get(key, key)
        snmp = self.profile["snmp"]
        if snmp["bulk"] and key not in snmp["no_bulk"] and oid not in snmp["no_bulk"]:
            return await self._bulk_walk(eng, tgt, user, oid, context)
        return await self._walk(eng, tgt, user, oid, context)

    async def _detect_profile(self, eng, tgt, user) -> str:
        """Built-in profile name for this agent from a GET of sysObjectID and sysDescr."""
        from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, get_cmd
        oids = snmp_profiles.load("standard")["oids"]
        err_ind, err_stat, _, vbs = await get_cmd(eng, user, tgt, self._context(""), ObjectType(ObjectIdentity(oids["sysobjectid"])),
                                                  ObjectType(ObjectIdentity(oids["sysdescr"])))
        if err_ind:
            raise RuntimeError(f"snmp get sysObjectID: {err_ind}")
        if err_stat:
            raise RuntimeError(f"snmp get sysObjectID: status {err_stat}")
        vals = ["" if type(vb[1]).__name__ in _END else str(vb[1]) for vb in vbs or []] + ["", ""]
        name = snmp_profiles.detect(vals[0], vals[1])
        log.info("snmp profile %s detected (sysObjectID %s)", name, vals[0] or "-")
        return name

    def fdb_decoder(self, rows: dict[str, list[tuple[str, object]]]) -> list[tuple[str, int, int]]:
        """fdb.strategy "private": turn the walks of fdb.private_oids ({oid: rows}) into (mac, vlan, ifindex).

        A subclass supplies this for a vendor table (EdgeSwitch, VRP style); the base class has no decoder."""
        raise NotImplementedError(f"snmp profile {self.profile_name}: fdb strategy 'private' needs a fdb_decoder")

    async def _fdb_async(self, eng, tgt, user) -> tuple[list, list, list, list]:
        """(fdb, baseport, fdb_status, fdb_address) rows for build_snapshot, in Q-BRIDGE index form (vlan.<mac part>)."""
        f, use_bp = self.profile["fdb"], self.profile["bridge_port_map"]["strategy"] == "dot1dBasePortIfIndex"
        fdb: list = []
        bp: list = []
        status: list = []
        addr: list = []

        async def rows(key: str, prefix: str, context: str = "") -> list:
            return [(prefix + k, v) for k, v in await self._walk_key(eng, tgt, user, key, context)]

        if f["strategy"] == "qbridge":
            fdb = await rows("fdb_port", "")
            if f["keep_status"]:
                status = await rows("fdb_status", "")
        elif f["strategy"] == "bridge":  # BRIDGE-MIB has no VLAN: stored under VLAN 0
            fdb = await rows("bridge_fdb_port", "0.")
            if f["keep_status"]:
                status = await rows("bridge_fdb_status", "0.")
            if f["index_fix"] == "row_number":
                addr = await rows("bridge_fdb_address", "0.")
        elif f["strategy"] == "cisco_per_vlan":
            vlans = []
            for k, v in await self._walk_key(eng, tgt, user, f["vlan_source"]):
                try:
                    vlan, state = int(k.split(".")[-1]), int(v)
                except (ValueError, TypeError):
                    continue
                if state == 1 and vlan not in f["skip_vlans"]:  # vtpVlanState operational(1)
                    vlans.append(vlan)
            for vlan in vlans:
                ctx = f"{f['context_prefix']}{vlan}"
                fdb += await rows("bridge_fdb_port", f"{vlan}.", ctx)
                if f["keep_status"]:
                    status += await rows("bridge_fdb_status", f"{vlan}.", ctx)
                if use_bp:  # a bridge port maps to the same ifIndex in every VLAN, so the per-VLAN maps are merged
                    bp += await rows("baseport_ifindex", "", ctx)
            return fdb, bp, status, addr
        else:  # private
            walked = {oid: await self._walk_key(eng, tgt, user, oid) for oid in f["private_oids"]}
            for mac, vlan, ifindex in self.fdb_decoder(walked):
                fdb.append((f"{int(vlan)}." + ".".join(str(int(x, 16)) for x in mac.split(":")), int(ifindex)))
        if use_bp:
            bp = await rows("baseport_ifindex", "")
        return fdb, bp, status, addr

    async def _snapshot_async(self) -> SwitchSnapshot:
        from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, UdpTransportTarget, UsmUserData, usmAesCfb128Protocol,
                                                 usmHMAC192SHA256AuthProtocol, usmHMACSHAAuthProtocol)
        auth = {"SHA": usmHMACSHAAuthProtocol, "SHA256": usmHMAC192SHA256AuthProtocol}[self.cfg.snmp_auth]
        eng = SnmpEngine()
        try:
            snmp = (self.profile or snmp_profiles.load("standard"))["snmp"]
            tgt = await UdpTransportTarget.create((self.cfg.snmp_host, 161), timeout=snmp["timeout"], retries=snmp["retries"])
            user = UsmUserData(self.cfg.snmp_user, self.cfg.snmp_auth_key, self.cfg.snmp_priv_key, authProtocol=auth, privProtocol=usmAesCfb128Protocol)
            if self.profile is None:
                # cached for this client's lifetime; a failed detection raises and is retried at the next snapshot
                self.profile = snmp_profiles.load(await self._detect_profile(eng, tgt, user))
                self.profile_name = self.profile["profile"]
                if (self.profile["snmp"]["timeout"], self.profile["snmp"]["retries"]) != (snmp["timeout"], snmp["retries"]):
                    snmp = self.profile["snmp"]
                    tgt = await UdpTransportTarget.create((self.cfg.snmp_host, 161), timeout=snmp["timeout"], retries=snmp["retries"])
            p = self.profile
            fdb_raw, bp_raw, status_raw, addr_raw = await self._fdb_async(eng, tgt, user)
            fdb = [(k, int(v)) for k, v in fdb_raw]
            bp = [(k, int(v)) for k, v in bp_raw]
            status = [(k, int(v)) for k, v in status_raw]
            addr = [(k, ":".join(f"{b:02x}" for b in bytes(v))) for k, v in addr_raw]
            names = [(k, str(v)) for k, v in await self._walk_key(eng, tgt, user, "ifname")]
            lldp = [(k, str(v)) for k, v in await self._walk_key(eng, tgt, user, "lldp_rem_sysname")]
            locports = []
            if p["lldp"]["local_port"] == "auto":  # "ifindex" never reads the local port table
                locports = [(k, str(v)) for key in ("lldp_loc_portid", "lldp_loc_portdesc") for k, v in await self._walk_key(eng, tgt, user, key)]
            return build_snapshot(fdb, bp, names, lldp, locports, profile=p, fdb_status=status or None, fdb_address=addr or None)
        finally:
            eng.close_dispatcher()

    def snapshot(self) -> SwitchSnapshot:
        """Blocking; runs its own event loop (called from the collector thread). Raises on failure."""
        try:
            return asyncio.run(asyncio.wait_for(self._snapshot_async(), timeout=60))
        except (asyncio.TimeoutError, TimeoutError) as e:  # str() of these is empty
            raise RuntimeError("snmp: timeout after 60 s") from e
