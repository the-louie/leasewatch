"""Poll fw1, merge DHCP + ARP sightings per MAC, write devices/history/events, notify on new devices.

LEASE_TYPE_MODE=grace times "listed without a lease" in memory (Collector._no_lease_since), not in the database:
a restart starts the grace clock again, which only delays clearing a lease type by one grace period.
"""
from __future__ import annotations

import logging
import time
from typing import Callable

from .config import Config
from .db import Database
from .connectors import ConnectorError
from .connectors.legacy import legacy_instances, switch_settings, unifi_settings
from .connectors.merge import (INSERT_COLUMNS, UPDATE_COLUMNS, ConnectorFailure, MergeResult, MergeState, to_fw1,
                               merge as merge_batches)
from .connectors.merge import merge_sightings as merge  # noqa: F401  (the per-MAC identity merge, kept importable here)
from .connectors.snmp_switch import SnmpSwitchConnector
from .connectors.unifi import UnifiConnector
from .fw1 import Fw1Client
from . import notify

log = logging.getLogger("leasewatch.collector")
HISTORY_PER_MAC = 200
EVENT_DAYS = 365


class Collector:
    def __init__(self, cfg: Config, db: Database, client: Fw1Client | None = None):
        self.cfg = cfg
        self.db = db
        # the sources as connector instances (fw1, switch, unifi) built from today's variables; client/_switch/_unifi
        # below read and replace the client object each one wraps
        self._connectors: dict = legacy_instances(cfg, fw1_client=client)
        self._no_lease_since: dict[str, int] = {}  # mac -> first poll that listed it without a lease (grace/immediate)
        self._poll_hosts: dict[str, str] = {}  # mac -> hostname from this poll's firewall data, for _device_names()
        # the connectors share one context: lend them the device names (the switch names unnamed uplinks with them)
        self._connectors["fw1"].ctx.device_names = self._device_names
        self._unmailed: list[dict] = []  # new devices whose mail failed; retried with the next batch

    @property
    def client(self) -> object:
        return self._connectors["fw1"].client

    @client.setter
    def client(self, obj: object) -> None:
        self._connectors["fw1"].client = obj

    def _get_client(self, name: str) -> object | None:
        conn = self._connectors.get(name)
        return conn.client if conn else None

    def _set_client(self, name: str, factory: Callable[[str, object], object], obj: object | None) -> None:
        """Swap the client a connector wraps; None removes the connector, a client without one gets a new wrapper."""
        if obj is None:
            self._connectors.pop(name, None)
        elif name in self._connectors:
            self._connectors[name].client = obj
        else:
            self._connectors[name] = factory(name, obj)

    @property
    def _switch(self) -> object | None:
        return self._get_client("switch")

    @_switch.setter
    def _switch(self, obj: object | None) -> None:
        self._set_client("switch", lambda n, o: SnmpSwitchConnector(n, switch_settings(self.cfg), self._connectors["fw1"].ctx, client=o), obj)

    @property
    def _unifi(self) -> object | None:
        return self._get_client("unifi")

    @_unifi.setter
    def _unifi(self, obj: object | None) -> None:
        self._set_client("unifi", lambda n, o: UnifiConnector(n, unifi_settings(self.cfg), self._connectors["fw1"].ctx, client=o), obj)

    def _device_names(self) -> dict[str, str]:
        """mac -> name, else hostname, as the rows will read once this poll's firewall data is merged in."""
        hosts = self._poll_hosts
        out = dict(hosts)
        for r in self.db.q("SELECT mac, name, hostname FROM devices"):
            out[r["mac"]] = r["name"] or hosts.get(r["mac"]) or r["hostname"]
        return out

    def _enrich(self) -> tuple[object, object, dict]:
        """Collect the optional sources: (switch result, UniFi result, meta status). A result is None when the source
        is off, a ConnectorFailure when it failed; then the merge leaves the device fields as they were."""
        sw = un = None
        status: dict[str, str] = {}
        if self._switch:
            try:
                sw = self._connectors["switch"].collect()
                status["switch_ok"] = "1"; status["switch_error"] = ""; status["switch_macs"] = str(sw.stats["macs"])
            except Exception as e:
                log.warning("switch poll failed: %s", e)
                status["switch_ok"] = "0"; status["switch_error"] = (str(e) or type(e).__name__)[:200]  # a bare TimeoutError has no text
                sw = ConnectorFailure("switch", status["switch_error"], int(time.time()))
        if self._unifi:
            try:
                un = self._connectors["unifi"].collect()
                status["unifi_ok"] = "1"; status["unifi_error"] = ""; status["unifi_clients"] = str(un.stats["clients"])
            except Exception as e:
                log.warning("unifi poll failed: %s", e)
                status["unifi_ok"] = "0"; status["unifi_error"] = (str(e) or type(e).__name__)[:200]
                un = ConnectorFailure("unifi", status["unifi_error"], int(time.time()))
        return sw, un, status

    def _fail(self, msg: str) -> dict:
        now = int(time.time())
        with self.db.tx() as c:
            self.db.set_meta("last_error", msg, c)
            self.db.set_meta("last_error_ts", str(now), c)
            self.db.set_meta("last_poll_ok", "0", c)
            # the grace rule still applies while fw1 is unreachable: nothing stays "online" forever
            c.execute("UPDATE devices SET online=0 WHERE online=1 AND COALESCE(last_online,0)<?", (now - self.cfg.online_grace_minutes * 60,))
        return {"ok": False, "error": msg}

    def _write(self, c, prev: dict[str, dict], res: MergeResult, now: int) -> None:
        for mac, row in res.rows.items():
            if mac in prev:
                c.execute(f"UPDATE devices SET {', '.join(k + '=?' for k in UPDATE_COLUMNS)} WHERE mac=?",
                          tuple(row[k] for k in UPDATE_COLUMNS) + (mac,))
            else:
                c.execute(f"INSERT INTO devices({','.join(INSERT_COLUMNS)}) VALUES({','.join('?' * len(INSERT_COLUMNS))})",
                          tuple(row[k] for k in INSERT_COLUMNS))
        for mac, h in res.history:
            c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)", (mac, now, h["ip"], h["hostname"], h["vlan"], h["lease_type"]))
        for mac, kind, detail in res.events:
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now, mac, kind, detail))
        for mac in dict.fromkeys(mac for mac, _ in res.history):
            c.execute("DELETE FROM history WHERE mac=? AND id NOT IN (SELECT id FROM history WHERE mac=? ORDER BY ts DESC, id DESC LIMIT ?)", (mac, mac, HISTORY_PER_MAC))
        c.execute("DELETE FROM events WHERE ts<?", (now - EVENT_DAYS * 86400,))

    def _notify(self, new_devices: list[dict]) -> None:
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

    def run_once(self) -> dict:
        t0 = time.time()
        try:
            fw1 = self._connectors["fw1"].collect()
        except Exception as e:  # ConnectorError, or anything unexpected fw1 throws at us
            log.warning("poll failed: %s", e, exc_info=not isinstance(e, ConnectorError))
            return self._fail(str(e))
        raw_stats = fw1.stats
        # this poll's hostnames, read by _device_names() while the switch names its uplink ports
        self._poll_hosts = {mac: m.hostname for mac, m in merge([to_fw1(s) for s in fw1.sightings]).items()}
        sw, un, enrich_status = self._enrich()
        now = int(time.time())
        first_run = self.db.get_meta("first_run_done", "") != "1"
        prev_ok = self.db.get_meta("last_poll_ok", "1") == "1"
        if first_run and not fw1.sightings:
            log.warning("first poll returned no devices (%s); not taking a baseline", raw_stats)
            return self._fail("first poll returned no devices")
        batches = {"fw1": fw1, **{n: r for n, r in (("switch", sw), ("unifi", un)) if r is not None}}
        state = MergeState(self._no_lease_since, first_run, prev_ok,
                           frozenset(n for n, conn in self._connectors.items() if conn.describe().type == "unifi"))
        with self.db.tx() as c:
            prev = {r["mac"]: dict(r) for r in c.execute("SELECT * FROM devices").fetchall()}
            res = merge_batches(prev, batches, self.cfg, now, state)
            self._write(c, prev, res, now)
            for k, v in enrich_status.items():
                self.db.set_meta(k, v, c)
            self.db.set_meta("first_run_done", "1", c)
            self.db.set_meta("last_poll_ts", str(now), c)
            self.db.set_meta("last_poll_ok", "1", c)
            self.db.set_meta("last_error", "", c)
            self.db.set_meta("last_poll_ms", str(int((time.time() - t0) * 1000)), c)
            last_raw = f"{raw_stats['leases']} leases, {raw_stats['arp']} arp"
            if self.cfg.dhcp_backend == "kea" and "reservations" in raw_stats:
                last_raw += f", {raw_stats['reservations']} reservations"
            self.db.set_meta("last_raw", last_raw, c)
            if first_run:
                self.db.set_meta("baseline_ts", str(now), c)
        self._notify([{k: res.rows[mac][k] for k in ("mac", "ip", "hostname", "vendor", "vlan", "lease_type")} for mac in res.new])
        st = res.stats
        log.info("poll ok: %d devices, %d new, %d changed, %d ms", st["devices"], st["new"], st["changed"], int((time.time() - t0) * 1000))
        return {"ok": True, "devices": st["devices"], "new": st["new"], "changed": st["changed"], "first_run": first_run}

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
