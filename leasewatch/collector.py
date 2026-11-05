"""Poll the connector instances, merge their batches per MAC, write devices/history/events, notify on new devices.

LEASE_TYPE_MODE=grace times "listed without a lease" in memory (Collector._no_lease_since), not in the database:
a restart starts the grace clock again, which only delays clearing a lease type by one grace period.

Each instance collects in its own thread with its own TIMEOUT. The sighting producers (the firewall) run first, so
the switch can name uplinks after this poll's hostnames; then the others. A thread still running at its deadline is
abandoned: its result is dropped (generation counter) and the instance is skipped until the thread ends.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Callable

from .config import Config
from .db import Database
from .connectors import (Batch, ConnectorError, InstanceSpec, build_instance, instance_problems, instances_context,
                         registry)
from .connectors.legacy import switch_settings, unifi_settings
from .connectors.merge import (INSERT_COLUMNS, UPDATE_COLUMNS, ConnectorFailure, MergeResult, MergeState,
                               normalise_batch, to_fw1, merge as merge_batches)
from .connectors.merge import merge_sightings as merge  # noqa: F401  (the per-MAC identity merge, kept importable here)
from .connectors.snmp_switch import SnmpSwitchConnector
from .connectors.unifi import UnifiConnector
from .fw1 import Fw1Client
from . import notify

log = logging.getLogger("leasewatch.collector")
HISTORY_PER_MAC = 200
EVENT_DAYS = 365
MAX_BACKOFF = 600  # check() retries back off from POLL_SECONDS up to this, then collect() is tried every poll
SKIPPED = "previous collection has not completed; skipped"
# meta aliases the 1.0 UI reads, for the instances the legacy mapping names (name and type must both match):
# (type, ok, error, count key, Batch.stats key)
ALIASES = {"switch": ("snmp_switch", "switch_ok", "switch_error", "switch_macs", "macs"),
           "unifi": ("unifi", "unifi_ok", "unifi_error", "unifi_clients", "clients")}


@dataclass
class _Run:
    """Collection state of one instance. Only the collector thread changes it, except `result`, which a worker
    thread sets under Collector._lock and only while `gen` is still the generation it was started with."""
    name: str
    type: str
    timeout: int
    produces: frozenset
    backoff: int
    disabled: str = ""          # validate() problems: never collected, never retried
    checked: bool = False       # check() passed (or was given up on): collect() directly
    retry_at: float = 0.0       # monotonic time before which a failed check() is not retried
    failed: bool = False        # last outcome, so a change is logged once and not every poll
    error: str = ""
    thread: threading.Thread | None = None
    started: float = 0.0
    gen: int = 0
    phase: str = ""             # the worker's phase ("check"/"collect"), so a timeout knows which call hung
    result: tuple | None = None
    skip_logged: bool = False


class Collector:
    def __init__(self, cfg: Config, db: Database, client: Fw1Client | None = None):
        self.cfg = cfg
        self.db = db
        self._lock = threading.Lock()  # guards _Run.result/_Run.gen between the worker threads and run_once
        specs = cfg.instances
        # one context for all instances: it lends them the device names (the switch names unnamed uplinks with them)
        self._ctx = instances_context(specs)
        self._ctx.device_names = self._device_names
        self._connectors: dict = {}
        self._runs: dict[str, _Run] = {}  # in LW_CONNECTORS order: the merge's tie-break order
        for spec in specs:
            self._add(spec, client if spec.name == "fw1" else None, validate=cfg.connector_specs is not None)
        # an instance removed from the configuration (or renamed) would keep its "Seen by" line forever: its rows never
        # update again. Disabled instances are still configured, so theirs stay (writes to the seen table)
        names = [spec.name for spec in specs]
        with db.tx() as c:
            pruned = c.execute(f"DELETE FROM seen WHERE source NOT IN ({','.join('?' * len(names))})", names).rowcount
        if pruned:
            log.info("removed %d seen rows of instances that are no longer configured", pruned)
        self._no_lease_since: dict[str, int] = {}  # mac -> first poll that listed it without a lease (grace/immediate)
        self._poll_hosts: dict[str, str] = {}  # mac -> hostname from this poll's firewall data, for _device_names()
        self._unmailed: list[dict] = []  # new devices whose mail failed; retried with the next batch

    def _add(self, spec: InstanceSpec, client: object | None, validate: bool) -> None:
        """Build one instance. validate: run validate() and disable the instance on problems (LW_CONNECTORS only;
        the legacy variables are checked by Config.validate() under their own names)."""
        cls = registry().get(spec.type)
        run = _Run(spec.name, spec.type, spec.timeout, cls.describe().produces if cls else frozenset(),
                   self.cfg.poll_seconds, checked=client is not None)  # C5: remove (an injected client is a test double without check())
        self._runs[spec.name] = run
        try:
            conn = build_instance(spec, self._ctx, client=client)
            problems = instance_problems(spec, conn) if validate else []
        except Exception as e:
            conn, problems = None, [f"connector {spec.name} ({spec.type or '?'}): cannot be set up ({type(e).__name__})"]
        if problems:
            run.disabled = run.error = "disabled: " + "; ".join(problems)
            # each problem already starts with "connector <name> (<type>)"
            log.error("%s (instance disabled)", "; ".join(problems))
            return
        self._connectors[spec.name] = conn

    # C5: remove the client/_switch/_unifi shims (tests swap the wrapped client objects through them)
    @property
    def client(self) -> object:
        return self._connectors["fw1"].client

    @client.setter
    def client(self, obj: object) -> None:
        self._connectors["fw1"].client = obj
        self._runs["fw1"].checked = True

    def _get_client(self, name: str) -> object | None:
        conn = self._connectors.get(name)
        return conn.client if conn else None

    def _set_client(self, name: str, factory: Callable[[str, object], object], obj: object | None) -> None:
        """Swap the client a connector wraps; None removes the connector, a client without one gets a new wrapper."""
        if obj is None:
            self._connectors.pop(name, None)
            self._runs.pop(name, None)
            return
        if name in self._connectors:
            self._connectors[name].client = obj
        else:
            self._connectors[name] = conn = factory(name, obj)
            self._runs[name] = _Run(name, conn.describe().type, 60, conn.describe().produces, self.cfg.poll_seconds)
        self._runs[name].checked = True  # a test double: no check()

    @property
    def _switch(self) -> object | None:
        return self._get_client("switch")

    @_switch.setter
    def _switch(self, obj: object | None) -> None:
        self._set_client("switch", lambda n, o: SnmpSwitchConnector(n, switch_settings(self.cfg), self._ctx, client=o), obj)

    @property
    def _unifi(self) -> object | None:
        return self._get_client("unifi")

    @_unifi.setter
    def _unifi(self, obj: object | None) -> None:
        self._set_client("unifi", lambda n, o: UnifiConnector(n, unifi_settings(self.cfg), self._ctx, client=o), obj)

    def _device_names(self) -> dict[str, str]:
        """mac -> name, else hostname, as the rows will read once this poll's firewall data is merged in."""
        hosts = self._poll_hosts
        out = dict(hosts)
        for r in self.db.q("SELECT mac, name, hostname FROM devices"):
            out[r["mac"]] = r["name"] or hosts.get(r["mac"]) or r["hostname"]
        return out

    def _work(self, run: _Run, gen: int, conn: object, check: bool) -> None:
        """Worker thread: check() if due, then collect(). Stores (phase, Batch or exception, ms) unless abandoned."""
        t0 = time.monotonic()
        phase = "check"
        try:
            if check:
                self._phase(run, gen, phase)
                conn.check()
            phase = "collect"
            self._phase(run, gen, phase)
            out: object = conn.collect()
        except BaseException as e:  # everything is reported through the result; a worker never dies silently
            out = e
        with self._lock:
            if run.gen == gen:
                run.result = (phase, out, int((time.monotonic() - t0) * 1000))

    def _phase(self, run: _Run, gen: int, phase: str) -> None:
        with self._lock:
            if run.gen == gen:
                run.phase = phase

    def _outcome(self, run: _Run, error: str, exc: BaseException | None) -> None:
        """Log a change of state once: ok -> failed (WARNING for ConnectorError and timeouts, ERROR with traceback
        for anything else) and failed -> ok."""
        if error and not run.failed:
            if exc is None or isinstance(exc, ConnectorError):
                log.warning("connector %s (%s) failed: %s", run.name, run.type, error)
            else:
                # the traceback as redacted text, not exc_info: its last line is the raw exception text
                tb = self._ctx.redact("".join(traceback.format_exception(exc)))
                log.error("connector %s (%s) failed: %s\n%s", run.name, run.type, error, tb.rstrip())
        elif not error and run.failed:
            log.info("connector %s (%s) recovered", run.name, run.type)
        run.failed, run.error = bool(error), error

    def _collect(self, names: list[str]) -> tuple[dict[str, object], dict[str, str]]:
        """Collect the given instances in parallel: (name -> Batch or ConnectorFailure, meta status). A disabled
        instance has no entry (the merge treats it as off); a skipped, waiting or failed one a ConnectorFailure."""
        out: dict[str, object] = {}
        status: dict[str, str] = {}
        started: list[_Run] = []
        now = time.monotonic()
        for n in names:
            run = self._runs[n]
            if run.disabled:
                continue
            if run.thread is not None and run.thread.is_alive():
                if not run.skip_logged:
                    log.warning("connector %s (%s): %s", n, run.type, SKIPPED)
                    run.skip_logged = True
                continue
            run.skip_logged = False
            if now < run.retry_at:
                continue  # check() failed and its backoff has not passed: stays failed with that error
            with self._lock:
                run.gen += 1
                run.result = None
                run.phase = ""
            run.thread = threading.Thread(target=self._work, args=(run, run.gen, self._connectors[n], not run.checked),
                                          name=f"connector-{n}", daemon=True)
            run.started = time.monotonic()
            run.thread.start()
            started.append(run)
        for run in started:
            run.thread.join(max(0.0, run.started + run.timeout - time.monotonic()))
            with self._lock:
                res = run.result
                hung_in = run.phase
                if res is None:
                    run.gen += 1  # abandoned: whatever the thread returns later belongs to no poll
            if res is None:
                # a check() that hangs gets the check backoff, like a check() that fails
                phase, out_obj, ms = hung_in or "collect", None, run.timeout * 1000
            else:
                phase, out_obj, ms = res
            if phase == "collect":
                run.checked = True  # check() passed (or was not due): a failing collect() does not re-run it
            if isinstance(out_obj, Batch):
                self._outcome(run, "", None)
                # source filled, MACs normalised before anyone reads it (the uplink names, counts, the merge)
                out[run.name] = out_obj = normalise_batch(run.name, out_obj)
                status[f"conn.{run.name}.ms"] = str(ms)
                status[f"conn.{run.name}.count"] = str(len(out_obj.sightings) + len(out_obj.attachments))
                strategy = out_obj.stats.get("strategy")
                if isinstance(strategy, str):  # the switch's FDB strategy, shown so a per-VLAN fallback is visible
                    status[f"conn.{run.name}.strategy"] = strategy
                continue
            exc = out_obj if isinstance(out_obj, BaseException) else None
            if res is None:
                error = f"timed out after {run.timeout} s"
            elif exc is not None:
                # only a ConnectorError's text is meant for the UI (a bare one has none: its type name); any other
                # exception is shown as its type name, its text goes to the redacted log line only
                error = (self._ctx.redact(str(exc) or type(exc).__name__)[:200] if isinstance(exc, ConnectorError)
                         else type(exc).__name__)
            else:
                error = "collect() did not return a Batch"
            if phase == "check":
                # retry check() after POLL_SECONDS, doubling up to MAX_BACKOFF; after that wait, collect() every poll
                run.retry_at = time.monotonic() + min(run.backoff, MAX_BACKOFF)
                if run.backoff >= MAX_BACKOFF:
                    run.checked = True
                run.backoff *= 2
                error = f"check failed: {error}"
            self._outcome(run, error, exc)
            status[f"conn.{run.name}.ms"] = str(ms)
        ts = str(int(time.time()))
        for n in names:
            run = self._runs[n]
            if n in out:
                ok, error = True, ""
            else:
                ok = False
                error = SKIPPED if (not run.disabled and run.thread is not None and run.thread.is_alive()
                                    and run not in started) else run.error
                if not run.disabled:
                    out[n] = ConnectorFailure(n, error, int(time.time()))
            status.update({f"conn.{n}.type": run.type, f"conn.{n}.ok": "1" if ok else "0", f"conn.{n}.error": error,
                           f"conn.{n}.ts": ts, f"conn.{n}.enabled": "0" if run.disabled else "1"})
            status.setdefault(f"conn.{n}.ms", "0")
            status.setdefault(f"conn.{n}.count", "0")
            if n in ALIASES and run.type == ALIASES[n][0] and not run.disabled:
                _type, k_ok, k_err, k_count, stat = ALIASES[n]
                status[k_ok], status[k_err] = ("1" if ok else "0"), error
                if ok:
                    status[k_count] = str(out[n].stats.get(stat, 0))
        return out, status

    def _fail(self, msg: str, status: dict[str, str] | None = None) -> dict:
        now = int(time.time())
        with self.db.tx() as c:
            for k, v in (status or {}).items():
                self.db.set_meta(k, v, c)
            self.db.set_meta("last_error", msg, c)
            self.db.set_meta("last_error_ts", str(now), c)
            self.db.set_meta("last_poll_ok", "0", c)
            # the grace rule still applies while fw1 is unreachable: nothing stays "online" forever
            c.execute("UPDATE devices SET online=0 WHERE online=1 AND COALESCE(last_online,0)<?", (now - self.cfg.online_grace_minutes * 60,))
        return {"ok": False, "error": msg}

    def _write(self, c: sqlite3.Connection, prev: dict[str, dict], res: MergeResult, now: int) -> None:
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
        # a listing without presence keeps the last time this source vouched for the device
        c.executemany("INSERT INTO seen(mac,source,last_seen,last_present) VALUES(?,?,?,?) ON CONFLICT(mac,source) DO UPDATE "
                      "SET last_seen=excluded.last_seen, last_present=COALESCE(excluded.last_present, seen.last_present)", res.seen)
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
        producers = [n for n, r in self._runs.items() if "sighting" in r.produces]
        got, status = self._collect(producers)
        ok = {n: b for n, b in got.items() if isinstance(b, Batch)}
        if not ok:  # every sighting producer failed: the poll fails, so nothing stays online forever
            errors = [(n, b.error) for n, b in got.items()]
            msg = errors[0][1] if len(errors) == 1 else "; ".join(f"{n}: {e}" for n, e in errors) or "no sighting connector is enabled"
            return self._fail(msg, status)
        sightings = [s for b in ok.values() for s in b.sightings]
        raw_stats: dict[str, int] = {}
        for b in ok.values():
            for k, v in b.stats.items():
                raw_stats[k] = raw_stats.get(k, 0) + v
        # this poll's hostnames, read by _device_names() while the switch names its uplink ports
        self._poll_hosts = {mac: m.hostname for mac, m in merge([to_fw1(s) for s in sightings]).items()}
        more, enrich_status = self._collect([n for n in self._runs if n not in producers])
        got.update(more)
        enrich_status = {**status, **enrich_status}
        now = int(time.time())
        first_run = self.db.get_meta("first_run_done", "") != "1"
        prev_ok = self.db.get_meta("last_poll_ok", "1") == "1"
        if first_run and not sightings:
            log.warning("first poll returned no devices (%s); not taking a baseline", raw_stats)
            return self._fail("first poll returned no devices", enrich_status)
        batches = {n: got[n] for n in self._runs if n in got}
        # the controller role, not the type: any instance whose describe() says so (getattr: a type without roles)
        state = MergeState(self._no_lease_since, first_run, prev_ok,
                           frozenset(n for n, conn in self._connectors.items()
                                     if "controller" in getattr(conn.describe(), "roles", frozenset())))
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
            last_raw = f"{raw_stats.get('leases', 0)} leases, {raw_stats.get('arp', 0)} arp"
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
