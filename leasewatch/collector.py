"""Poll fw1, merge DHCP + ARP sightings per MAC, write devices/history/events, notify on new devices.

LEASE_TYPE_MODE=grace times "listed without a lease" in memory (Collector._no_lease_since), not in the database:
a restart starts the grace clock again, which only delays clearing a lease type by one grace period.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from .config import Config
from .db import Database
from .fw1 import Fw1Client, Fw1Error, Sighting
from . import notify

log = logging.getLogger("leasewatch.collector")
INFRA_RE = re.compile(r"^(ap|apu|sw|switch|xgs|gs|usw|uap)[-_0-9]", re.I)  # hostnames that mean "another AP/switch hangs on this port"
HISTORY_PER_MAC = 200
EVENT_DAYS = 365


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


def merge(sightings: list[Sighting]) -> dict[str, Merged]:
    """One record per MAC, independent of the order fw1 returns rows in.

    The lease whose IP is actually in the ARP table wins; ip/vlan/iface always come from one and the same
    sighting (what is on the wire), so a device that moved VLAN while its old lease is still listed is shown
    where it really is. DHCP gives hostname and lease type; ARP decides 'online'."""
    by_mac: dict[str, list[Sighting]] = {}
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


class Collector:
    def __init__(self, cfg: Config, db: Database, client: Fw1Client | None = None):
        self.cfg = cfg
        self.db = db
        self.client = client or Fw1Client(cfg.fw1_url, cfg.fw1_key, cfg.fw1_secret, cfg.fw1_verify_tls, dhcp_backend=cfg.dhcp_backend,
                                            use_env_proxy=cfg.lan_proxy)
        self._no_lease_since: dict[str, int] = {}  # mac -> first poll that listed it without a lease (grace/immediate)
        self._unmailed: list[dict] = []  # new devices whose mail failed; retried with the next batch
        self._switch = None
        self._unifi = None
        if cfg.snmp_enabled:
            from .switch import SwitchClient
            self._switch = SwitchClient(cfg)
        if cfg.unifi_enabled:
            from .unifi import UnifiClient
            self._unifi = UnifiClient(cfg)

    def _enrich(self) -> tuple[object, dict, dict]:
        """Fetch the optional sources; a failure is recorded in meta and the device fields are left as they were."""
        snap, wifi, status = None, {}, {}
        if self._switch:
            try:
                snap = self._switch.snapshot()
                status["switch_ok"] = "1"; status["switch_error"] = ""; status["switch_macs"] = str(len(snap.by_mac))
            except Exception as e:
                log.warning("switch poll failed: %s", e)
                status["switch_ok"] = "0"; status["switch_error"] = (str(e) or type(e).__name__)[:200]  # a bare TimeoutError has no text
        if self._unifi:
            try:
                wifi = self._unifi.clients()
                status["unifi_ok"] = "1"; status["unifi_error"] = ""; status["unifi_clients"] = str(len(wifi))
            except Exception as e:
                log.warning("unifi poll failed: %s", e)
                status["unifi_ok"] = "0"; status["unifi_error"] = (str(e) or type(e).__name__)[:200]
        return snap, wifi, status

    def _fail(self, msg: str) -> dict:
        now = int(time.time())
        with self.db.tx() as c:
            self.db.set_meta("last_error", msg, c)
            self.db.set_meta("last_error_ts", str(now), c)
            self.db.set_meta("last_poll_ok", "0", c)
            # the grace rule still applies while fw1 is unreachable: nothing stays "online" forever
            c.execute("UPDATE devices SET online=0 WHERE online=1 AND COALESCE(last_online,0)<?", (now - self.cfg.online_grace_minutes * 60,))
        return {"ok": False, "error": msg}

    def run_once(self) -> dict:
        t0 = time.time()
        try:
            sightings, raw_stats = self.client.sightings(self.cfg.ignore_interfaces)
        except Exception as e:  # Fw1Error, or anything unexpected fw1 throws at us
            log.warning("poll failed: %s", e, exc_info=not isinstance(e, Fw1Error))
            return self._fail(str(e))
        merged = merge(sightings)
        snap, wifi, enrich_status = self._enrich()
        now = int(time.time())
        first_run = self.db.get_meta("first_run_done", "") != "1"
        prev_ok = self.db.get_meta("last_poll_ok", "1") == "1"
        if first_run and not merged:
            log.warning("first poll returned no devices (%s); not taking a baseline", raw_stats)
            return self._fail("first poll returned no devices")
        new_devices: list[dict] = []
        changes = 0
        grace = now - self.cfg.online_grace_minutes * 60
        with self.db.tx() as c:
            existing = {r["mac"]: dict(r) for r in c.execute("SELECT * FROM devices").fetchall()}
            touched_history: list[str] = []
            for mac, m in merged.items():
                sources = ",".join(sorted(m.sources))
                cur = existing.get(mac)
                if cur is None:
                    c.execute(
                        "INSERT INTO devices(mac,first_seen,last_seen,last_online,ip,hostname,vendor,vlan,iface,lease_type,sources,online,baseline) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (mac, now, now, now if m.online else None, m.ip, m.hostname, m.vendor, m.vlan, m.iface, m.lease_type, sources, int(m.online), int(first_run)))
                    c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)", (mac, now, m.ip, m.hostname, m.vlan, m.lease_type))
                    if not first_run:
                        c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now, mac, "new", " ".join(filter(None, [m.ip, m.hostname, m.vendor])) + (f" ({m.vlan})" if m.vlan else "")))
                        new_devices.append({"mac": mac, "ip": m.ip, "hostname": m.hostname, "vendor": m.vendor, "vlan": m.vlan, "lease_type": m.lease_type})
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
                    self._no_lease_since.pop(mac, None)
                elif cur["lease_type"] and self.cfg.lease_type_mode != "keep":
                    since = self._no_lease_since.setdefault(mac, now)
                    if self.cfg.lease_type_mode == "immediate" or now - since >= self.cfg.online_grace_minutes * 60:
                        lease_type = ""
                        self._no_lease_since.pop(mac, None)
                        ev.append(("lease_type", f"{cur['lease_type']} -> no DHCP"))
                # prev_ok: after a failed poll every device looks "away" for the outage, so "back" would be a false positive
                if m.online and not cur["online"] and cur["last_online"] and now - cur["last_online"] > 86400 and prev_ok:
                    days = (now - cur["last_online"]) // 86400
                    ev.append(("back", f"back after {days} day{'' if days == 1 else 's'}"))
                for kind, detail in ev:
                    c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now, mac, kind, detail))
                if any(k in ("ip", "hostname", "vlan", "lease_type") for k, _ in ev):
                    c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)",
                              (mac, now, m.ip or cur["ip"], m.hostname or cur["hostname"], m.vlan or cur["vlan"], lease_type))
                    touched_history.append(mac)
                    changes += 1
                # not on the wire right now: stays online until the grace period after its last sighting has passed
                online = m.online or bool(cur["online"] and (cur["last_online"] or 0) >= grace)
                c.execute(
                    "UPDATE devices SET last_seen=?, last_online=COALESCE(?, last_online), ip=?, hostname=?, vendor=?, vlan=?, iface=?, lease_type=?, sources=?, online=? WHERE mac=?",
                    (now, now if m.online else None, m.ip or cur["ip"], m.hostname or cur["hostname"], m.vendor or cur["vendor"],
                     m.vlan or cur["vlan"], m.iface or cur["iface"], lease_type, sources, int(online), mac))
            # --- optional enrichers: switch port and Wi-Fi ---
            unifi_ok = enrich_status.get("unifi_ok") == "1"
            if snap is not None or wifi or unifi_ok:
                rows = {r["mac"]: dict(r) for r in c.execute("SELECT mac, sw_port, sw_via, wifi_ssid, wifi_ap, link, online, hostname, name FROM devices").fetchall()}
                if snap is not None:
                    # an uplink port without an LLDP name: if an infrastructure device (AP, switch) sits on it, name the port after it
                    for p in snap.ports.values():
                        if p.uplink and not p.neighbor:
                            infra = sorted(r2["name"] or r2["hostname"] for mac2, (ifi, _vlan) in snap.by_mac.items()
                                           for r2 in (rows.get(mac2),) if ifi == p.ifindex and r2 and INFRA_RE.match(r2["name"] or r2["hostname"] or ""))
                            if infra:
                                p.neighbor = infra[0]
                for mac, cur in rows.items():
                    sets, params = [], []
                    w0 = wifi.get(mac) if wifi else None
                    # UniFi down this poll: a Wi-Fi device would get the AP's uplink port from the FDB; keep its last values
                    unifi_blind = self._unifi is not None and not unifi_ok and cur["link"] == "wifi"
                    # on the wire this poll, not in grace: the FDB ages out slower than ARP, so a departed device would get a stale port
                    if snap is not None and merged.get(mac) and merged[mac].online and not (w0 and not w0.wired) and not unifi_blind:
                        port, via = snap.describe(mac)
                        if port and (port != cur["sw_port"] or via != cur["sw_via"]):
                            if cur["sw_port"] and port != cur["sw_port"]:
                                c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now, mac, "port", f"{cur['sw_port']} -> {port}{' via ' + via if via else ''}"))
                            sets += ["sw_port=?", "sw_via=?"]; params += [port, via]
                    if wifi:
                        w = wifi.get(mac)
                        if w and not w.wired:
                            if w.ssid and (w.ssid != cur["wifi_ssid"] or w.ap != cur["wifi_ap"]):
                                if cur["wifi_ssid"]:
                                    c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now, mac, "wifi", f"{cur['wifi_ssid']} @ {cur['wifi_ap'] or '?'} -> {w.ssid} @ {w.ap or '?'}"))
                            sets += ["wifi_ssid=?", "wifi_ap=?", "wifi_signal=?", "wifi_radio=?", "wifi_alias=?", "link=?"]
                            params += [w.ssid, w.ap, w.signal, w.radio, w.alias, "wifi"]
                            if cur["sw_port"] and "sw_port=?" not in sets:  # on Wi-Fi now: the switch port it had on a cable is stale
                                sets += ["sw_port=?", "sw_via=?"]; params += ["", ""]
                        elif w and w.wired:  # UniFi says wired now: drop the old Wi-Fi details
                            sets += ["wifi_ssid=?", "wifi_ap=?", "wifi_signal=?", "wifi_radio=?", "wifi_alias=?", "link=?"]
                            params += ["", "", None, "", w.alias, "wired"]
                    # on the wire this poll, not just in grace: a phone walking out drops off ARP and UniFi together, and its
                    # last SSID must stay (the FDB may still hold it on the AP uplink, which is not a cable)
                    if unifi_ok and merged.get(mac) and merged[mac].online and cur["wifi_ssid"] and mac not in wifi:
                        # UniFi answered but no longer lists it: it left Wi-Fi, so the SSID/AP are stale. The switch
                        # branch above already recorded its port (w0 is None), so a cable is shown in this same poll.
                        sets += ["wifi_ssid=?", "wifi_ap=?", "wifi_signal=?", "wifi_radio=?", "link=?"]
                        params += ["", "", None, "", "wired" if snap is not None and mac in snap.by_mac else ""]
                    if snap is not None and cur["online"] and mac in snap.by_mac and not (wifi.get(mac) and not wifi[mac].wired) and cur["link"] != "wifi":
                        sets += ["link=?"]; params += ["wired"]
                    if sets:
                        params.append(mac)
                        c.execute(f"UPDATE devices SET {', '.join(sets)} WHERE mac=?", tuple(params))
            for k, v in enrich_status.items():
                self.db.set_meta(k, v, c)
            # devices not seen on the wire for longer than the grace period go offline
            c.execute("UPDATE devices SET online=0 WHERE online=1 AND COALESCE(last_online,0)<?", (grace,))
            for mac in touched_history:
                c.execute("DELETE FROM history WHERE mac=? AND id NOT IN (SELECT id FROM history WHERE mac=? ORDER BY ts DESC, id DESC LIMIT ?)", (mac, mac, HISTORY_PER_MAC))
            c.execute("DELETE FROM events WHERE ts<?", (now - EVENT_DAYS * 86400,))
            self.db.set_meta("first_run_done", "1", c)
            self.db.set_meta("last_poll_ts", str(now), c)
            self.db.set_meta("last_poll_ok", "1", c)
            self.db.set_meta("last_error", "", c)
            self.db.set_meta("last_poll_ms", str(int((time.time() - t0) * 1000)), c)
            self.db.set_meta("last_raw", f"{raw_stats['leases']} leases, {raw_stats['arp']} arp", c)
            if first_run:
                self.db.set_meta("baseline_ts", str(now), c)
        if self.cfg.mail_enabled:
            pending = self._unmailed + new_devices
            if pending:
                try:
                    notify.new_devices(self.cfg, pending)
                    self._unmailed = []
                except Exception as e:  # never let mail break the collector; keep the batch for the next poll
                    self._unmailed = pending[-50:]
                    log.warning("mail failed (%d device(s) queued): %s", len(self._unmailed), e)
                    if len(pending) > len(self._unmailed):
                        log.warning("mail retry queue full: %d device(s) dropped without a mail", len(pending) - len(self._unmailed))
        log.info("poll ok: %d devices, %d new, %d changed, %d ms", len(merged), len(new_devices), changes, int((time.time() - t0) * 1000))
        return {"ok": True, "devices": len(merged), "new": len(new_devices), "changed": changes, "first_run": first_run}

    def loop(self, stop_event) -> None:
        while not stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("collector crashed in run_once; continuing")
                try:
                    self._fail("internal error in collector (see logs)")
                except Exception:
                    pass
            stop_event.wait(self.cfg.poll_seconds)
