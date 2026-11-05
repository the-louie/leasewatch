"""Switch port per MAC over SNMPv3 (Q-BRIDGE-MIB forwarding table + IF-MIB names + LLDP neighbours).

Tested on HP/H3C Comware 7; the MIBs are standard, so any managed switch with Q-BRIDGE and LLDP should do.
pysnmp (7.x) is imported lazily so the rest of leasewatch works without it.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from .config import Config

log = logging.getLogger("leasewatch.switch")

OID_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"      # dot1qTpFdbPort: index vlan.mac6 -> bridge port
OID_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex: bridge port -> ifIndex
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"            # ifName: ifIndex -> name
OID_LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"  # lldpRemSysName: timeMark.localPort.index -> neighbour name
OID_LLDP_LOC_PORTID = "1.0.8802.1.1.2.1.3.7.1.3"    # lldpLocPortId: lldpLocPortNum -> port id (usually the ifName)
OID_LLDP_LOC_PORTDESC = "1.0.8802.1.1.2.1.3.7.1.4"  # lldpLocPortDesc: lldpLocPortNum -> description
UPLINK_MACS = 6  # a port with this many MACs (and no LLDP neighbour) is treated as an uplink/AP port anyway


def short_ifname(name: str) -> str:
    return (name.replace("Ten-GigabitEthernet", "XGE").replace("GigabitEthernet", "GE")
                .replace("FortyGigE", "FGE").replace("Bridge-Aggregation", "BAGG"))


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

    def describe(self, mac: str) -> tuple[str, str]:
        """(port label, via) for the UI, e.g. ("GE1/0/14", "") or ("GE1/0/3", "ap-hall")."""
        hit = self.by_mac.get(mac)
        if not hit:
            return "", ""
        p = self.ports.get(hit[0])
        if not p:
            return f"port {hit[0]}", ""
        return short_ifname(p.name), (p.neighbor or f"{p.macs} devices") if p.uplink else ""


def build_snapshot(fdb: list[tuple[str, int]], baseport: list[tuple[str, int]], ifname: list[tuple[str, str]],
                   lldp: list[tuple[str, str]], locports: list[tuple[str, str]] | None = None) -> SwitchSnapshot:
    """Pure function over raw (index, value) walks, so it can be unit-tested without a switch.

    lldpRemSysName is indexed by lldpLocPortNum, which is only the ifIndex on some vendors (Comware). `locports`
    (lldpLocPortId / lldpLocPortDesc rows: lldpLocPortNum -> text) maps a port number to the interface whose ifName
    matches; a number without a match is taken as an ifIndex."""
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
    if fdb and not bp2if:
        log.warning("no dot1dBasePortIfIndex rows: bridge ports used as ifIndex")
    by_name = {v: k for k, v in names.items()}
    by_name.update({short_ifname(v): k for k, v in names.items()})
    loc2if: dict[int, int] = {}
    for num, text in locports or []:
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
    snap = SwitchSnapshot()
    for ifindex, name in names.items():
        snap.ports[ifindex] = PortInfo(ifindex=ifindex, name=name, neighbor=neighbors.get(ifindex, ""))
    macs_on: dict[int, set] = {}  # distinct MACs: one MAC learned in several VLANs is still one device
    for idx, port in fdb:
        parts = idx.split(".")
        if len(parts) != 7:
            continue
        try:
            vlan = int(parts[0])
            mac = ":".join(f"{int(x):02x}" for x in parts[1:])
            if int(port) == 0:  # the switch's own / management MACs: no real port
                continue
            ifindex = bp2if.get(int(port), int(port))
        except ValueError:
            continue
        snap.by_mac[mac] = (ifindex, vlan)
        macs_on.setdefault(ifindex, set()).add(mac)
    for ifindex, macs in macs_on.items():
        p = snap.ports.setdefault(ifindex, PortInfo(ifindex=ifindex, name=f"port {ifindex}"))
        p.macs = len(macs)
    for p in snap.ports.values():
        if p.neighbor:
            p.uplink = True
        elif p.macs >= UPLINK_MACS:  # many MACs on one port without LLDP: an unmanaged switch or AP hangs there
            p.uplink = True
    return snap


class SwitchClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    async def _walk(self, eng, tgt, user, base: str) -> list[tuple[str, object]]:
        from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, next_cmd
        out = []
        cur_oid = base
        while True:
            err_ind, err_stat, _, vbs = await next_cmd(eng, user, tgt, ContextData(), ObjectType(ObjectIdentity(cur_oid)))
            if err_ind:
                raise RuntimeError(f"snmp walk {base}: {err_ind}")
            if err_stat:  # a partial table would silently drop ports; fail the poll instead
                raise RuntimeError(f"snmp walk {base}: status {err_stat}")
            if not vbs:
                break
            oid, val = vbs[0][0], vbs[0][1]
            s = str(oid)
            if not s.startswith(base + ".") or type(val).__name__ in ("EndOfMibView", "NoSuchObject", "NoSuchInstance"):
                break
            # an agent that does not advance (same or lower OID) would make this loop forever
            if tuple(int(x) for x in s.split(".")) <= tuple(int(x) for x in cur_oid.split(".")):
                break
            out.append((s[len(base) + 1:], val))
            cur_oid = s
        return out

    async def _snapshot_async(self) -> SwitchSnapshot:
        from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, UdpTransportTarget, UsmUserData, usmAesCfb128Protocol,
                                                 usmHMAC192SHA256AuthProtocol, usmHMACSHAAuthProtocol)
        auth = {"SHA": usmHMACSHAAuthProtocol, "SHA256": usmHMAC192SHA256AuthProtocol}[self.cfg.snmp_auth]
        eng = SnmpEngine()
        try:
            tgt = await UdpTransportTarget.create((self.cfg.snmp_host, 161), timeout=4, retries=1)
            user = UsmUserData(self.cfg.snmp_user, self.cfg.snmp_auth_key, self.cfg.snmp_priv_key, authProtocol=auth, privProtocol=usmAesCfb128Protocol)
            fdb = [(k, int(v)) for k, v in await self._walk(eng, tgt, user, OID_FDB_PORT)]
            bp = [(k, int(v)) for k, v in await self._walk(eng, tgt, user, OID_BASEPORT_IFINDEX)]
            names = [(k, str(v)) for k, v in await self._walk(eng, tgt, user, OID_IFNAME)]
            lldp = [(k, str(v)) for k, v in await self._walk(eng, tgt, user, OID_LLDP_REM_SYSNAME)]
            locports = [(k, str(v)) for oid in (OID_LLDP_LOC_PORTID, OID_LLDP_LOC_PORTDESC) for k, v in await self._walk(eng, tgt, user, oid)]
            return build_snapshot(fdb, bp, names, lldp, locports)
        finally:
            eng.close_dispatcher()

    def snapshot(self) -> SwitchSnapshot:
        """Blocking; runs its own event loop (called from the collector thread). Raises on failure."""
        try:
            return asyncio.run(asyncio.wait_for(self._snapshot_async(), timeout=60))
        except (asyncio.TimeoutError, TimeoutError) as e:  # str() of these is empty
            raise RuntimeError("snmp: timeout after 60 s") from e
