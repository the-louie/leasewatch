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
from dataclasses import dataclass, field
from typing import Callable

from .config import Config
from .db import Database
from .connectors import (Batch, ConnectorError, HostContext, InstanceSpec, build_instance, instance_problems,
                         instances_context, registry)
from .connectors.merge import (INSERT_COLUMNS, UPDATE_COLUMNS, ConnectorFailure, MergeResult, MergeState,
                               is_private_mac, normalise_batch, to_fw1, merge as merge_batches)
from .connectors.merge import merge_sightings as merge  # noqa: F401  (the per-MAC identity merge, kept importable here)
from .fw1 import Fw1Client
from . import notify

log = logging.getLogger("leasewatch.collector")
HISTORY_PER_MAC = 200
EVENT_DAYS = 365
MAIL_BATCH = 50  # new devices per mail; the rest wait for the next poll
MAX_BACKOFF = 600  # check() retries back off from POLL_SECONDS up to this, then collect() is tried every poll
SKIPPED = "previous collection has not completed; skipped"


def setup_instance(spec: InstanceSpec, ctx: HostContext, client: object | None = None) -> tuple[object | None, list[str]]:
    """(connector, problems) for one instance: built with ctx and checked by instance_problems() (validate()); the
    connector is None when it cannot be built. No network I/O. Shared by the collector and the check/collect commands."""
    try:
        if registry().get(spec.type) is None:  # unknown or empty TYPE: validate()'s message, not build_instance's KeyError
            return None, instance_problems(spec)
        conn = build_instance(spec, ctx, client=client)
        return conn, instance_problems(spec, conn)
    # SystemExit too: a plugin calling sys.exit() on a bad setting only loses its instance, as at import (loader)
    except (Exception, SystemExit) as e:
        return None, [f"connector {spec.name} ({spec.type or '?'}): cannot be set up ({type(e).__name__})"]


def error_text(exc: BaseException, redact: Callable[[str], str]) -> str:
    """How a failed check()/collect() is shown: only a ConnectorError's text is meant for the UI (redacted, at most 200
    characters; a bare one has none: its type name); any other exception is shown as its type name, its text goes to
    the redacted log line only."""
    return redact(str(exc) or type(exc).__name__)[:200] if isinstance(exc, ConnectorError) else type(exc).__name__


@dataclass
class _Run:
    """Collection state of one instance. Only the collector thread changes it, except `result` and `phase`, which a
    worker thread sets under Collector._lock and only while `gen` is still the generation it was started with."""
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
    logged_unexpected: set = field(default_factory=set)  # unexpected failures (error, place) logged in this failed spell
    thread: threading.Thread | None = None
    started: float = 0.0
    gen: int = 0
    phase: str = ""             # the worker's phase ("check"/"collect"), so a timeout knows which call hung
    result: tuple | None = None
    skip_logged: bool = False
    answered: bool = False      # collected successfully at least once in this process (the baseline waits for it)
    waited: int = 0             # seconds of failed check()s retried every poll while the baseline waited (B-08.4)


class Collector:
    def __init__(self, cfg: Config, db: Database, client: Fw1Client | None = None):
        self.cfg = cfg
        self.db = db
        self._lock = threading.Lock()  # guards _Run.result/_Run.phase/_Run.gen between the worker threads and run_once
        specs = cfg.instances
        # one context for all instances: it lends them the device names (the switch names unnamed uplinks with them)
        self._ctx = instances_context(specs)
        self._ctx.device_names = self._device_names
        # before the instances are built: a connector may call device_names() in __init__
        self._poll_hosts: dict[str, str] = {}  # mac -> hostname from this poll's firewall data, for _device_names()
        self._connectors: dict = {}
        self._runs: dict[str, _Run] = {}  # in LW_CONNECTORS order: the merge's tie-break order
        for spec in specs:
            self._add(spec, client if spec.name == "fw1" else None)
        # an instance removed from the configuration (or renamed) would keep its "Seen by" line forever: its rows never
        # update again. Disabled instances are still configured, so theirs stay (writes to the seen table).
        # devices.loc_source naming such an instance would credit the location to a source that no longer exists
        names = [spec.name for spec in specs]
        marks = ','.join('?' * len(names))
        # housekeeping only: a database locked by another writer must not stop the start (the next start prunes)
        try:
            with db.tx() as c:
                pruned = c.execute(f"DELETE FROM seen WHERE source NOT IN ({marks})", names).rowcount
                cleared = c.execute(f"UPDATE devices SET loc_source='' WHERE loc_source != '' AND loc_source NOT IN ({marks})",
                                    names).rowcount
                # writes conn.<n>.enabled (and a disabled one's error) now: _collect writes them only after the first
                # good firewall poll, and until then the page would draw a disabled instance as a red dot
                for run in self._runs.values():
                    # a fixed instance must not show the previous start's "disabled: ..." until its first poll
                    if not run.disabled and c.execute("SELECT 1 FROM meta WHERE key=? AND value='0'",
                                                      (f"conn.{run.name}.enabled",)).fetchone():
                        self.db.set_meta(f"conn.{run.name}.error", "", c)
                    self.db.set_meta(f"conn.{run.name}.enabled", "0" if run.disabled else "1", c)
                    if run.disabled:
                        self.db.set_meta(f"conn.{run.name}.error", run.error, c)
        except sqlite3.Error as e:
            log.warning("cannot remove rows of instances that are no longer configured: %s", e)
            pruned = cleared = 0
        if pruned or cleared:
            log.info("removed %d seen rows and %d location sources of instances that are no longer configured",
                     pruned, cleared)
        self._no_lease_since: dict[str, int] = {}  # mac -> first poll that listed it without a lease (grace/immediate)
        self._undecided_since: dict[str, int] = {}  # new private MAC -> first poll it was held back (lease producer down)
        self._prune_ref: tuple[int, float] | None = None  # (event prune reference, monotonic time) of the last _write
        self._baseline_wait_logged = False  # the "baseline held back" warning is logged once, not every poll

    def _add(self, spec: InstanceSpec, client: object | None) -> None:
        """Build one instance; run validate() and disable the instance on problems."""
        cls = registry().get(spec.type)
        run = _Run(spec.name, spec.type, spec.timeout, cls.describe().produces if cls else frozenset(),
                   self.cfg.poll_seconds)
        self._runs[spec.name] = run
        conn, problems = setup_instance(spec, self._ctx, client)
        if problems:
            run.disabled = run.error = "disabled: " + "; ".join(problems)
            # each problem already starts with "connector <name> (<type>)"
            log.error("%s (instance disabled)", "; ".join(problems))
            return
        self._connectors[spec.name] = conn

    def _device_names(self) -> dict[str, str]:
        """mac -> name, else hostname, as the rows will read once this poll's firewall data is merged in."""
        hosts = self._poll_hosts
        out = dict(hosts)
        for r in self.db.q("SELECT mac, name, hostname FROM devices"):
            out[r["mac"]] = r["name"] or hosts.get(r["mac"]) or r["hostname"]
        # a merged private MAC goes by its device's name: the switch names an uplink after it
        for r in self.db.q("SELECT a.mac, a.device FROM aliases a JOIN devices d ON d.mac = a.device"):
            out[r["mac"]] = out.get(r["device"]) or hosts.get(r["mac"], "")
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
        for anything else) and failed -> ok. An unexpected exception that replaces another failure is logged too, so
        its traceback is not lost while the instance stays failed."""
        unexpected = exc is not None and not isinstance(exc, ConnectorError)
        # keyed by error and the place it was raised, and remembered for the whole failed spell: failures that flap
        # or alternate log each traceback once, and a second bug of the same type elsewhere still gets its own
        tb_last = traceback.extract_tb(exc.__traceback__)[-1:] if unexpected else []
        key = (error, *((tb_last[0].filename, tb_last[0].lineno) if tb_last else ()))
        if error and (not run.failed or (unexpected and key not in run.logged_unexpected)):
            if not unexpected:
                log.warning("connector %s (%s) failed: %s", run.name, run.type, error)
            else:
                # the traceback as redacted text, not exc_info: its last line is the raw exception text
                tb = self._ctx.redact("".join(traceback.format_exception(exc)))
                log.error("connector %s (%s) failed: %s\n%s", run.name, run.type, error, tb.rstrip())
            if not run.failed:
                run.logged_unexpected.clear()
            if unexpected:
                run.logged_unexpected.add(key)
        elif not error and run.failed:
            log.info("connector %s (%s) recovered", run.name, run.type)
        run.failed, run.error = bool(error), error

    def _collect(self, names: list[str], baseline_pending: bool = False) -> tuple[dict[str, object], dict[str, str]]:
        """Collect the given instances in parallel: (name -> Batch or ConnectorFailure, meta status). A disabled
        instance has no entry (the merge treats it as off); a skipped, waiting or failed one a ConnectorFailure.
        baseline_pending: the baseline is held back, so a failed check() of one that has not answered is retried
        every poll and not backed off."""
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
            try:
                run.thread.start()
            except RuntimeError as e:  # out of threads: only this instance fails this poll; the others still run
                run.thread = None
                self._outcome(run, "cannot start a collection thread", e)
                continue
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
                error = error_text(exc, self._ctx.redact)
            else:
                error = "collect() did not return a Batch"
            if phase == "check" and baseline_pending and not run.answered:
                # B-08.4: the baseline waits for this one, so a source that comes up late must be seen at the next
                # poll, not after up to MAX_BACKOFF; the backoff is not doubled and starts once the baseline is taken
                run.retry_at = time.monotonic() + self.cfg.poll_seconds
                # but collect() still takes over once MAX_BACKOFF has passed: a check() that keeps failing while
                # collect() works would otherwise never answer and hold the baseline back for good
                run.waited += self.cfg.poll_seconds
                if run.waited >= MAX_BACKOFF:
                    run.checked = True
                error = f"check failed: {error}"
            elif phase == "check":
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
            # like count, a strategy this poll did not report is reset (a failed walk, a type without one): the
            # stored one names a walk this poll did not make
            if f"conn.{n}.strategy" not in status and self.db.get_meta(f"conn.{n}.strategy"):
                status[f"conn.{n}.strategy"] = ""
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
        # the mail queue entry commits with the device row (S4 T-09). Only with mail on: turning mail on later must
        # not mail every older device. No new-device mail for a private MAC, merged or not (owner answer Q1): it
        # rotates, so it would mail again and again; it is still listed and marked new
        if self.cfg.mail_enabled:
            c.executemany("UPDATE devices SET mail_queued=? WHERE mac=?",
                          [(now, mac) for mac in res.new if not is_private_mac(mac)])
        for mac, h in res.history:
            c.execute("INSERT INTO history(mac,ts,ip,hostname,vlan,lease_type) VALUES(?,?,?,?,?,?)", (mac, now, h["ip"], h["hostname"], h["vlan"], h["lease_type"]))
        c.executemany("INSERT INTO aliases(mac,device,reason,detail,merged_ts,last_seen) VALUES(?,?,?,?,?,?)",
                      [(alias, dev, reason, detail, now, now) for alias, dev, reason, detail in res.aliases])
        c.executemany("UPDATE aliases SET last_seen=? WHERE mac=?", [(now, mac) for mac in res.alias_seen])
        for mac, kind, detail in res.events:
            c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now, mac, kind, detail))
        # a listing without presence keeps the last time this source vouched for the device
        c.executemany("INSERT INTO seen(mac,source,last_seen,last_present) VALUES(?,?,?,?) ON CONFLICT(mac,source) DO UPDATE "
                      "SET last_seen=excluded.last_seen, last_present=COALESCE(excluded.last_present, seen.last_present)", res.seen)
        # by id (insertion order), not ts: after the clock steps back the row just written would be the oldest
        for mac in dict.fromkeys(mac for mac, _ in res.history):
            c.execute("DELETE FROM history WHERE mac=? AND id NOT IN (SELECT id FROM history WHERE mac=? ORDER BY id DESC LIMIT ?)", (mac, mac, HISTORY_PER_MAC))
        # a clock that jumps ahead must not wipe the event log, however many polls it stays wrong: the prune reference
        # moves at most a day past the stored one at the first poll of a process, then at most twice as fast as the
        # monotonic clock (so a lag left by downtime catches up). last_poll_ts follows a wrong clock, so it is only
        # the fallback for a database without the stored reference.
        mono = time.monotonic()
        if self._prune_ref is None:
            rows = dict(c.execute("SELECT key, value FROM meta WHERE key IN ('events_prune_ts', 'last_poll_ts')").fetchall())
            # ASCII digits only: int() rejects some str.isdigit() characters ('²') and strings past 4300 digits;
            # 18 digits holds any real epoch second (as db.py's schema_version). A bad row falls to the next
            ts = {k: int(v) for k, v in rows.items() if isinstance(v, str) and len(v) <= 18 and v.isascii() and v.isdigit()}
            prune, polled = ts.get("events_prune_ts"), ts.get("last_poll_ts")
            # a future reference is trusted (a clock behind it cannot be told from a hand-edit; documented limit)
            last = prune if prune is not None else polled
            base, step = (last, 86400) if last is not None else (None, 0)
        else:
            base, step = self._prune_ref[0], int(2 * (mono - self._prune_ref[1]))
        ref = min(now, base + step) if base is not None else now
        if base is not None and ref < base:
            # the clock is behind the reference (no RTC before NTP sync): keep the reference and its monotonic start,
            # or the wrong clock would pin it in the past and pruning would lag for years. Pruned by the clock.
            self._prune_ref = self._prune_ref or (base, mono)
        else:
            self._prune_ref = (ref, mono)
            self.db.set_meta("events_prune_ts", str(ref), c)
        c.execute("DELETE FROM events WHERE ts<?", (ref - EVENT_DAYS * 86400,))

    def _notify(self) -> None:
        """Mail the queued new devices (devices.mail_queued), up to MAIL_BATCH per mail, oldest first.

        The batch goes to every channel; the queue is cleared when at least one delivered (owner answer S5 Q3: a
        channel that failed misses that batch, logged by notify), and kept when all failed.
        Delivery is at-least-once: if the mail goes out and the UPDATE that clears the queue fails (or the process
        dies in between), the same devices are mailed again at the next poll."""
        if not self.cfg.mail_enabled:
            return
        try:
            with self.db.tx() as c:
                # acked or archived devices leave the queue. No age limit (owner decision S4R01): mail_queued is wall
                # clock, so a clock step would drop devices that were never mailed
                c.execute("UPDATE devices SET mail_queued=NULL WHERE mail_queued IS NOT NULL "
                          "AND (acked=1 OR archived_ts IS NOT NULL)")
                # current rows: a device that changed IP or hostname since it was queued is mailed as it is now
                rows = [dict(r) for r in c.execute(
                    "SELECT mac, ip, hostname, vendor, vlan, lease_type FROM devices WHERE mail_queued IS NOT NULL "
                    "AND acked=0 AND archived_ts IS NULL ORDER BY mail_queued, mac LIMIT ?", (MAIL_BATCH,)).fetchall()]
        except sqlite3.Error as e:  # the queue stays in the database: retried at the next poll
            log.warning("cannot read the mail queue: %s", e)
            return
        if not rows:
            return
        try:
            notify.new_devices(self.cfg, rows)
        except Exception as e:  # never let mail break the collector; the queue is kept for the next poll
            log.warning("mail failed (%d device(s) queued): %s", len(rows), e)
            return
        macs = [r["mac"] for r in rows]
        try:
            self.db.q(f"UPDATE devices SET mail_queued=NULL WHERE mac IN ({','.join('?' * len(macs))})", tuple(macs))
        except sqlite3.Error as e:  # mailed again at the next poll (at-least-once)
            log.warning("mail sent but the queue was not cleared (%d device(s) will be mailed again): %s", len(macs), e)

    def run_once(self) -> dict:
        t0 = time.time()
        producers = [n for n, r in self._runs.items() if "sighting" in r.produces]
        # read again below after the collection; here only to keep a pending baseline's failed check()s from backing off
        got, status = self._collect(producers, self.db.get_meta("first_run_done", "") != "1")
        ok = {n: b for n, b in got.items() if isinstance(b, Batch)}
        if not ok:  # every sighting producer failed: the poll fails, so nothing stays online forever
            errors = [(n, b.error) for n, b in got.items()]
            msg = errors[0][1] if len(errors) == 1 else "; ".join(f"{n}: {e}" for n, e in errors) or "no sighting connector is enabled"
            return self._fail(msg, status)
        sightings = [s for b in ok.values() for s in b.sightings]
        raw_stats: dict[str, int] = {}
        for b in ok.values():
            for k, v in b.stats.items():
                if isinstance(v, int):  # a string stat (e.g. a strategy) is not a count
                    raw_stats[k] = raw_stats.get(k, 0) + v
        # this poll's hostnames, read by _device_names() while the switch names its uplink ports
        self._poll_hosts = {mac: m.hostname for mac, m in merge([to_fw1(s) for s in sightings]).items()}
        more, enrich_status = self._collect([n for n in self._runs if n not in producers])
        got.update(more)
        enrich_status = {**status, **enrich_status}
        now = int(time.time())
        first_run = self.db.get_meta("first_run_done", "") != "1"
        prev_ok = self.db.get_meta("last_poll_ok", "1") == "1"
        # only a truly first poll: during the baseline wait (S05x) devices are already stored, and an empty poll then is
        # an ordinary one that must run the merge (devices go offline), not fail as "first poll"
        if first_run and not sightings and not self.db.q("SELECT 1 FROM devices LIMIT 1"):
            log.warning("first poll returned no devices (%s); not taking a baseline", raw_stats)
            return self._fail("first poll returned no devices", enrich_status)
        # S05x: a baseline taken without a producer that has never answered would mail all of its devices as new once
        # it does. Until every enabled producer has answered, merge still runs as the first run (devices are recorded
        # as baseline, no "new" event, no mail) but the baseline is not stored as taken. A producer that never answers
        # holds it back for good (owner decision 2026-11-06). Not persisted: a restart before the baseline waits again
        # this poll's answers count here, but are kept only once the write below has committed (see after the tx)
        waiting = [n for n in producers if not self._runs[n].disabled and not self._runs[n].answered and n not in ok] if first_run else []
        if waiting and not self._baseline_wait_logged:
            log.warning("baseline held back until %s has answered once", ", ".join(waiting))
            self._baseline_wait_logged = True
        batches = {n: got[n] for n in self._runs if n in got}
        # the controller role, not the type: any instance whose describe() says so (getattr: a type without roles)
        # producers: only an instance that lists sightings can hold a lease, so a failed switch does not hold lease types
        state = MergeState(self._no_lease_since, first_run, prev_ok,
                           frozenset(n for n, conn in self._connectors.items()
                                     if "controller" in getattr(conn.describe(), "roles", frozenset())),
                           producers=frozenset(producers), held_back=bool(waiting),
                           undecided_since=self._undecided_since)
        with self.db.tx() as c:
            prev = {r["mac"]: dict(r) for r in c.execute("SELECT * FROM devices").fetchall()}
            # read with prev in one transaction, so the alias map and the rows it points to agree
            state.aliases = {r["mac"]: r["device"] for r in c.execute("SELECT mac, device FROM aliases").fetchall()}
            # keep the literal 'restored' in the SQL: a bound parameter cannot use the partial index events_restored
            if self.cfg.prune_days > 0:  # a restore by hand holds against PRUNE_DAYS (S4R07); only read when it runs
                state.restored = {r["mac"]: r["ts"] for r in c.execute(
                    "SELECT mac, MAX(ts) ts FROM events WHERE kind='restored' GROUP BY mac").fetchall()}
            res = merge_batches(prev, batches, self.cfg, now, state)
            self._write(c, prev, res, now)
            for k, v in enrich_status.items():
                self.db.set_meta(k, v, c)
            if not waiting:
                self.db.set_meta("first_run_done", "1", c)
            self.db.set_meta("last_poll_ts", str(now), c)
            self.db.set_meta("last_poll_ok", "1", c)
            self.db.set_meta("last_error", "", c)
            self.db.set_meta("last_poll_ms", str(int((time.time() - t0) * 1000)), c)
            last_raw = f"{raw_stats.get('leases', 0)} leases, {raw_stats.get('arp', 0)} arp"
            if "reservations" in raw_stats:  # only a Kea firewall reports them
                last_raw += f", {raw_stats['reservations']} reservations"
            self.db.set_meta("last_raw", last_raw, c)
            if first_run and not waiting:
                self.db.set_meta("baseline_ts", str(now), c)
        # only now: a poll whose write failed stored nothing, so its producers have not yet answered for the baseline
        for n in ok:
            self._runs[n].answered = True
        self._notify()
        st = res.stats
        log.info("poll ok: %d devices, %d new, %d changed, %d ms", st["devices"], st["new"], st["changed"], int((time.time() - t0) * 1000))
        return {"ok": True, "devices": st["devices"], "new": st["new"], "changed": st["changed"], "first_run": first_run}

    def loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("collector crashed in run_once; continuing")
                try:
                    self._fail("internal error in collector (see logs)")
                except Exception:  # usually the same database error: the status stays stale until the stale check
                    log.exception("cannot record the failed poll")
            stop_event.wait(self.cfg.poll_seconds)
