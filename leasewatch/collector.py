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
from .db import Database, db_error_text
from .connectors import (Batch, ConnectorError, HostContext, InstanceSpec, build_instance, instance_problems,
                         instances_context, registry)
from .connectors.merge import (INSERT_COLUMNS, UPDATE_COLUMNS, ConnectorFailure, MergeResult, MergeState,
                               is_private_mac, normalise_batch, to_fw1, merge as merge_batches)
from .connectors.merge import merge_sightings as merge  # noqa: F401  (the per-MAC identity merge, kept importable here)
from .fw1 import Fw1Client
from .mqtt import MqttError
from .mqtt_pub import Publisher
from . import __version__, notify

log = logging.getLogger("leasewatch.collector")
CLOSE_SECONDS = 5  # all connectors together, well inside the 30 s the container gets to stop
HISTORY_PER_MAC = 200
EVENT_DAYS = 365
MAIL_BATCH = 50  # new devices per mail; the rest wait for the next poll
MAX_BACKOFF = 600  # check() retries back off from POLL_SECONDS up to this, then collect() is tried every poll
SKIPPED = "previous collection has not completed; skipped"
SOURCE_DOWN_POLLS = 3  # failed polls in a row before an instance gets a source_down event (6 min at default polls)
ALERT_KINDS = ("source_down", "source_up")  # the event kinds MAIL_ON_SOURCE sends
WATCH_KINDS = ("offline", "online", "ip", "vlan", "port", "wifi")  # MAIL_ON_WATCH sends these of watched devices
ALERT_BATCH = 50  # events per alert message; the rest go at the next poll
ALERT_MARK = "notify.alert_event_id"  # meta: the events up to this id were considered (sent, or no alert then)
# one event: by its kind, with the error or the outage length from its detail (the subject cut to 80 characters)
ALERT_SUBJECTS = {"source_down": "{name} is down: {text}", "source_up": "{name} is back {text}"}


def outage_text(seconds: int) -> str:
    """An outage in whole minutes: "Ym", "XhYm", or "XdYh" from a day on."""
    m = max(0, seconds) // 60
    if m < 60:
        return f"{m}m"
    if m < 1440:
        return f"{m // 60}h{m % 60}m"
    return f"{m // 1440}d{m % 1440 // 60}h"


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


def close_connector(conn: object, name: str, timeout: float, log: logging.Logger | None = None,
                    busy: bool = False) -> bool:
    """conn.close(), in a daemon thread joined for `timeout` seconds: a check() or collect() abandoned at its
    deadline may still run and hold what close() waits for, and the caller must still end. `name` is the
    instance's, given by the caller: conn.name is the connector's own attribute and may raise. Errors are logged by
    exception type, never with their text. `busy`: the caller does not wait because the instance's worker still runs
    (named in the log, instead of the used-up shutdown budget). True when close() returned in time."""
    log = log or logging.getLogger("leasewatch")

    def work() -> None:
        try:
            conn.close()
        except Exception as e:  # a failing close() is named in the log, never its text
            log.warning("connector %s: close() failed (%s)", name, type(e).__name__)

    t = threading.Thread(target=work, name=f"close-{name}", daemon=True)
    try:
        t.start()
    except RuntimeError:  # out of threads: closing inline is the only way left
        work()
        return True
    # a disabled instance may have TIMEOUT out of range (14 digits): join() would raise OverflowError, so the
    # setting's own maximum caps it
    wait = max(0.0, min(timeout, 3600))
    t.join(wait)
    if t.is_alive():
        if busy:
            log.info("connector %s: close() started without waiting (worker still running)", name)
        elif wait <= 0:
            log.info("connector %s: close() started without waiting (shutdown budget used)", name)
        else:
            log.warning("connector %s: close() did not return within %.1f s", name, wait)
        return False
    return True


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
    waited: int = 0             # seconds of failed check()s retried every poll while the baseline waited
    fail_polls: int = 0         # polls in a row with conn.<name>.ok written 0, counted once the baseline is taken
    fail_since: int = 0         # wall clock of the first of those polls
    fail_error: str = ""        # that poll's error: the cause (a timeout), not the SKIPPED symptom of the polls after it
    down_since: int | None = None  # start of the spell a source_down event was written for (conn.<name>.down_since)


class Collector:
    def __init__(self, cfg: Config, db: Database, client: Fw1Client | None = None):
        self.cfg = cfg
        self.db = db
        # a restore by hand holds against PRUNE_DAYS and PRUNE_PRIVATE_DAYS only while its `restored` event exists
        # by the effective thresholds: the merge caps PRUNE_PRIVATE_DAYS at PRUNE_DAYS when both are on
        private = min(cfg.prune_private_days, cfg.prune_days) if cfg.prune_days > 0 else cfg.prune_private_days
        prune = max([(d, n) for d, n in ((cfg.prune_days, "PRUNE_DAYS"), (private, "PRUNE_PRIVATE_DAYS"))
                     if d > 0] or [(0, "")])
        if prune[0] > 0 and cfg.event_days < prune[0]:
            log.warning("EVENT_DAYS=%d is below %s=%d: a device restored by hand is protected for %d days only",
                        cfg.event_days, prune[1], prune[0], cfg.event_days)
        self._lock = threading.Lock()  # guards _Run.result/_Run.phase/_Run.gen between the worker threads and run_once
        specs = cfg.instances
        # one context for all instances: it lends them the device names (the switch names unnamed uplinks with them)
        self._ctx = instances_context(specs)
        self._ctx.device_names = self._device_names
        # before the instances are built: a connector may call device_names() in __init__
        self._poll_hosts: dict[str, str] = {}  # mac -> hostname from this poll's firewall data, for _device_names()
        self._connectors: dict = {}
        self._closed = False
        self._poll_spell: tuple | None = None  # key of the poll crash being logged; None when polls work
        self._poll_fails = 0  # failed polls in the current spell
        self._mail_backoff = notify.Backoff(cfg.poll_seconds)  # per channel wait after a failed send (this process only)
        self._mail_failing = False  # the queue could not be cleared since the last send that worked: warned once
        self._alert_failing = False  # alerts could not be sent since the last send that worked: warned once
        self._alert_mark_cleared = False  # alerts off: the mark was removed once in this process
        self._alert_started = False  # the first alert pass of this process has read the pending events
        self._notify_ok: dict[str, bool] = {}  # notify.<channel>.ok as last written to the meta table
        self._fail_unrecorded = False  # "cannot record the failed poll" already logged in this spell
        # MQTT presence (MQTT_URL set): published after each good poll; its retry wait is the "mqtt" channel's backoff
        self._mqtt = Publisher(cfg, db, __version__) if cfg.mqtt_on else None
        # the "mqtt" event channel publishes through the publisher's connection (none: it fails, the backoff waits)
        notify.set_shared_client(lambda: self._mqtt.client if self._mqtt and self._mqtt.connected else None)
        self._mqtt_failed_polls = 0  # failed polls in a row; at SOURCE_DOWN_POLLS the status goes offline
        self._mqtt_failing = False  # the broker could not be reached since the last publish that worked: warned once
        self._runs: dict[str, _Run] = {}  # in LW_CONNECTORS order: the merge's tie-break order
        # source_down/source_up events (ts, kind, detail) and conn.<name>.down_since changes ("" deletes) not yet
        # committed: written by whichever outcome transaction comes next, dropped only after it committed
        self._pending_src: list[tuple[int, str, str]] = []
        self._pending_down: dict[str, str] = {}
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
                # an outage of a removed instance never gets its source_up: its marker goes. "conn." is 5 characters
                # and ".down_since" 11, so the substr is the instance name
                c.execute(f"DELETE FROM meta WHERE key LIKE 'conn.%.down_since' "
                          f"AND substr(key, 6, length(key) - 16) NOT IN ({marks})", names)
                # an outage that outlived a restart: no second source_down, and source_up gets the whole length
                for run in self._runs.values():
                    row = c.execute("SELECT value FROM meta WHERE key=?", (f"conn.{run.name}.down_since",)).fetchone()
                    v = row[0] if row else ""
                    if isinstance(v, str) and 0 < len(v) <= 18 and v.isascii() and v.isdigit():
                        run.down_since = int(v)
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

    def close(self) -> None:
        """Close every built connector (a UniFi session logs out), each for at most its instance's TIMEOUT and all
        for at most CLOSE_SECONDS. An instance whose worker thread still runs is not waited for (its close() would
        queue behind the call the worker holds): close() is started in a daemon thread with no wait, so a logout is
        still tried, and it is named as busy. A close() still running is left in its daemon thread, and a late
        connector never delays the others. Safe to call twice."""
        if self._closed:
            return
        self._closed = True
        deadline = time.monotonic() + CLOSE_SECONDS
        if self._mqtt is not None:  # first, so Home Assistant learns "offline" at once; at most half of CLOSE_SECONDS
            self._mqtt.close(CLOSE_SECONDS / 2)
        late: list[str] = []
        busy: list[str] = []
        for name, conn in self._connectors.items():
            thread = self._runs[name].thread
            if thread is not None and thread.is_alive():
                busy.append(name)
                close_connector(conn, name, 0.0, busy=True)
                continue
            wait = min(self._runs[name].timeout, max(0.0, deadline - time.monotonic()))
            if not close_connector(conn, name, wait):
                late.append(name)
        if late or busy:
            parts = ([f"still busy: {', '.join(busy)}"] if busy else []) + \
                    ([f"still closing: {', '.join(late)}"] if late else [])
            log.warning("connectors not closed at shutdown, %s", "; ".join(parts))
        else:
            log.info("connectors closed")

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
        started = self._start(names, time.monotonic())
        for run in started:
            res, phase, out_obj, ms = self._join(run)
            if phase == "collect":
                run.checked = True  # check() passed (or was not due): a failing collect() does not re-run it
            if isinstance(out_obj, Batch):
                self._took_batch(run, out_obj, ms, out, status)
            else:
                self._failed(run, res, phase, out_obj, ms, baseline_pending, status)
        self._status(names, out, started, status)
        return out, status

    def _start(self, names: list[str], now: float) -> list[_Run]:
        """Start a collection thread for each instance that is due: not disabled, not still running, not backed
        off. Returns the runs that started."""
        started: list[_Run] = []
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
        return started

    def _join(self, run: _Run) -> tuple[object, str, object, int | float]:
        """Wait for one run until its deadline: (result or None, phase, Batch/exception/other, ms). A run that has
        not returned by then is abandoned."""
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
        return res, phase, out_obj, ms

    def _took_batch(self, run: _Run, batch: Batch, ms: object, out: dict[str, object], status: dict[str, str]) -> None:
        """Record a run that returned a Batch: the normalised batch into out, its ms, count and strategy into
        status."""
        self._outcome(run, "", None)
        # source filled, MACs normalised before anyone reads it (the uplink names, counts, the merge)
        out[run.name] = batch = normalise_batch(run.name, batch)
        status[f"conn.{run.name}.ms"] = str(ms)
        status[f"conn.{run.name}.count"] = str(len(batch.sightings) + len(batch.attachments))
        strategy = batch.stats.get("strategy")
        if isinstance(strategy, str):  # the switch's FDB strategy, shown so a per-VLAN fallback is visible
            status[f"conn.{run.name}.strategy"] = strategy

    def _failed(self, run: _Run, res: object, phase: str, out_obj: object, ms: object, baseline_pending: bool,
                status: dict[str, str]) -> None:
        """Record a run that did not return a Batch: timed out, raised or returned something else. A failed check()
        gets the check backoff."""
        exc = out_obj if isinstance(out_obj, BaseException) else None
        if res is None:
            error = f"timed out after {run.timeout} s"
        elif exc is not None:
            error = error_text(exc, self._ctx.redact)
        else:
            error = "collect() did not return a Batch"
        if phase == "check":
            self._check_backoff(run, baseline_pending)
            error = f"check failed: {error}"
        self._outcome(run, error, exc)
        status[f"conn.{run.name}.ms"] = str(ms)

    def _check_backoff(self, run: _Run, baseline_pending: bool) -> None:
        """Set when a failed check() is retried."""
        if baseline_pending and not run.answered:
            # the baseline waits for this one, so a source that comes up late must be seen at the next
            # poll, not after up to MAX_BACKOFF; the backoff is not doubled and starts once the baseline is taken
            run.retry_at = time.monotonic() + self.cfg.poll_seconds
            # but collect() still takes over once MAX_BACKOFF has passed: a check() that keeps failing while
            # collect() works would otherwise never answer and hold the baseline back for good
            run.waited += self.cfg.poll_seconds
            if run.waited >= MAX_BACKOFF:
                run.checked = True
        else:
            # retry check() after POLL_SECONDS, doubling up to MAX_BACKOFF; after that wait, collect() every poll
            run.retry_at = time.monotonic() + min(run.backoff, MAX_BACKOFF)
            if run.backoff >= MAX_BACKOFF:
                run.checked = True
            run.backoff *= 2

    def _status(self, names: list[str], out: dict[str, object], started: list[_Run], status: dict[str, str]) -> None:
        """Write the per-instance status rows, add a ConnectorFailure for each enabled instance without a Batch and
        count its failed spell."""
        ts = str(int(time.time()))
        counting = self.db.get_meta("first_run_done", "") == "1"
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
            if not run.disabled:
                self._source_spell(run, ok, error, int(ts), counting)

    def _source_spell(self, run: _Run, ok: bool, error: str, now: int, counting: bool) -> None:
        """Count failed polls of one instance; queue source_down on the SOURCE_DOWN_POLLS-th in a row (back-dated to
        the first) and source_up at the first ok poll after it. counting: the baseline is taken; before it a first
        install fixing its settings gets no events."""
        if ok:
            if run.down_since is not None:
                self._pending_src.append((now, "source_up", f"{run.name}: up after {outage_text(now - run.down_since)}"))
                self._pending_down[run.name] = ""
                run.down_since = None
            run.fail_polls = 0
            return
        if not counting:
            return
        run.fail_polls += 1
        if run.fail_polls == 1:
            run.fail_since = now
        if run.fail_polls == 1 or run.fail_error == SKIPPED:
            run.fail_error = error
        if run.fail_polls >= SOURCE_DOWN_POLLS and run.down_since is None:
            run.down_since = run.fail_since
            self._pending_src.append((run.fail_since, "source_down", f"{run.name}: {run.fail_error[:200]}"))
            self._pending_down[run.name] = str(run.fail_since)

    def _write_source_events(self, c: sqlite3.Connection) -> None:
        """Insert the queued source events (no device: mac '') and down_since changes in the caller's transaction."""
        c.executemany("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)",
                      [(ts, "", kind, detail) for ts, kind, detail in self._pending_src])
        for name, since in self._pending_down.items():
            if since:
                self.db.set_meta(f"conn.{name}.down_since", since, c)
            else:
                c.execute("DELETE FROM meta WHERE key=?", (f"conn.{name}.down_since",))

    def _source_events_written(self) -> None:
        self._pending_src.clear()
        self._pending_down.clear()

    @staticmethod
    def _count_poll(c: sqlite3.Connection, ok: bool, status: dict[str, str]) -> None:
        """Bump the persistent poll counters (meta polls_ok/polls_failed, conn.<n>.failures) in the outcome transaction."""
        keys = ["polls_ok" if ok else "polls_failed"] + [
            k[:-3] + ".failures" for k, v in status.items()
            if k.startswith("conn.") and k.endswith(".ok") and v == "0" and status.get(k[:-3] + ".enabled") == "1"]
        c.executemany("INSERT INTO meta(key,value) VALUES(?,'1') ON CONFLICT(key) DO UPDATE SET "
                      "value=CAST(COALESCE(CAST(value AS INTEGER),0)+1 AS TEXT)", [(k,) for k in keys])

    def _fail(self, msg: str, status: dict[str, str] | None = None) -> dict:
        now = int(time.time())
        with self.db.tx(immediate=True) as c:  # writes after reads (_count_poll): wait for another writer
            for k, v in (status or {}).items():
                self.db.set_meta(k, v, c)
            self.db.set_meta("last_error", msg, c)
            self.db.set_meta("last_error_ts", str(now), c)
            self.db.set_meta("last_poll_ok", "0", c)
            self._count_poll(c, False, status or {})
            self.db.set_meta("last_attempt_ts", str(now), c)  # a failed poll is still a poll: the loop is alive
            # the grace rule still applies while fw1 is unreachable: nothing stays "online" forever
            c.execute("UPDATE devices SET online=0 WHERE online=1 AND COALESCE(last_online,0)<?", (now - self.cfg.online_grace_minutes * 60,))
            self._write_source_events(c)
        self._source_events_written()
        self._alert()  # an all-sources-down poll is where a source_down event is written
        return {"ok": False, "error": msg}

    def _write(self, c: sqlite3.Connection, prev: dict[str, dict], res: MergeResult, now: int,
               ref: int | None = None, purge: bool = False) -> tuple[int, int]:
        """Write the merge result in the caller's transaction; returns (devices, rows) PURGE_DAYS deleted
        (only when purge is set: never at the first poll or while the baseline waits)."""
        # a stand-in result without folds (some callers build only the fields they need) folds nothing
        folds = getattr(res, "folds", ())
        for cand, dev, _, _ in folds:
            self._fold(c, cand, dev)
        for mac, row in res.rows.items():
            if mac in prev:
                c.execute(f"UPDATE devices SET {', '.join(k + '=?' for k in UPDATE_COLUMNS)} WHERE mac=?",
                          tuple(row[k] for k in UPDATE_COLUMNS) + (mac,))
            else:
                c.execute(f"INSERT INTO devices({','.join(INSERT_COLUMNS)}) VALUES({','.join('?' * len(INSERT_COLUMNS))})",
                          tuple(row[k] for k in INSERT_COLUMNS))
        # the mail queue entry commits with the device row. Only with mail on: turning mail on later must
        # not mail every older device. No new-device mail for a private MAC, merged or not: it
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
        days = self.cfg.wifi_presence_days
        if days > 0:
            # the seconds are the real gap between two sightings; a gap of more than one missed poll, or a clock step, counts one poll
            poll = self.cfg.poll_seconds
            # one missed poll is bridged: it ran up to the longest producer TIMEOUT (a controller that times out)
            # before the loop slept POLL_SECONDS, so the gap is up to 2 * poll + timeout, plus 60 s of slack
            cap = 2 * poll + max([r.timeout for r in self._runs.values() if not r.disabled] or [0]) + 60
            # one observation per device and SSID: two MACs of one device in a poll are one sighting
            c.executemany(
                "INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) "
                "VALUES (:mac, :ssid, :now, :now, :poll, 1, :ap) "
                "ON CONFLICT(mac, ssid) DO UPDATE SET "
                "seconds_seen = seconds_seen + CASE WHEN excluded.last_seen - last_seen BETWEEN 1 AND :cap "
                "THEN excluded.last_seen - last_seen ELSE :poll END, "
                "polls_seen = polls_seen + 1, first_seen = MIN(first_seen, excluded.first_seen), "
                "last_seen = MAX(last_seen, excluded.last_seen), last_ap = excluded.last_ap",
                [{"mac": mac, "ssid": ssid, "ap": ap, "now": now, "poll": poll, "cap": cap} for (mac, ssid), ap in {(m, s_): a for m, s_, a in res.wifi}.items()])
            # the start of the record, so a short history is not read as a short stay
            c.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('wifi_presence_since', ?)", (str(now),))
        else:
            c.execute("DELETE FROM meta WHERE key='wifi_presence_since'")  # turning it back on starts "since" again
        # by id (insertion order), not ts: after the clock steps back the row just written would be the oldest
        # a fold target is capped too: the moved rows count even when the device got no row this poll
        for mac in dict.fromkeys([mac for mac, _ in res.history] + [dev for _, dev, _, _ in folds]):
            c.execute("DELETE FROM history WHERE mac=? AND id NOT IN (SELECT id FROM history WHERE mac=? ORDER BY id DESC LIMIT ?)", (mac, mac, self.cfg.history_per_device))
        if ref is None:
            ref = self._prune_reference(c, now)
        c.execute("DELETE FROM events WHERE ts<?", (ref - self.cfg.event_days * 86400,))
        # 0 = off: nothing is written above, and what is stored is deleted
        c.execute("DELETE FROM wifi_presence WHERE last_seen<?", (ref - days * 86400,) if days > 0 else (2**62,))
        # after the row writes: a device back from the archive this poll has archived_ts cleared and is not selected
        return self._purge(c, ref) if purge and self.cfg.purge_days > 0 else (0, 0)

    # sqlite's default variable limit is 999 (older builds) or 32766; 500 per statement is safe everywhere
    _PURGE_CHUNK = 500

    def _purge(self, c: sqlite3.Connection, ref: int) -> tuple[int, int]:
        """Delete every device archived longer than PURGE_DAYS by the prune clock that is offline, that no source
        has listed for that long, has no name, note or tags and is not marked known or watched, with all its rows. Other devices'
        events that name it in detail stay. Returns (devices, rows), rows counting every deleted row."""
        cutoff = ref - self.cfg.purge_days * 86400
        # last_seen: a static reservation is listed every poll while offline; purged, it would come back as new
        macs = [r[0] for r in c.execute(
            "SELECT mac FROM devices WHERE archived_ts IS NOT NULL AND archived_ts<? AND online=0 "
            "AND last_seen<? AND name='' AND note='' AND tags='' AND acked=0 AND watch=0", (cutoff, cutoff)).fetchall()]
        rows = 0
        for i in range(0, len(macs), self._PURGE_CHUNK):
            chunk = macs[i:i + self._PURGE_CHUNK]
            marks = ",".join("?" * len(chunk))
            for table in ("history", "events", "seen", "wifi_presence"):
                rows += c.execute(f"DELETE FROM {table} WHERE mac IN ({marks})", chunk).rowcount
            rows += c.execute(f"DELETE FROM aliases WHERE device IN ({marks})", chunk).rowcount
            rows += c.execute(f"DELETE FROM devices WHERE mac IN ({marks})", chunk).rowcount
        return len(macs), rows

    @staticmethod
    def _fold(c: sqlite3.Connection, cand: str, dev: str) -> None:
        """Move the rows of the private MAC cand, which had its own device row, to the device dev, in the caller's
        transaction, then delete cand's device row. The alias row is written afterwards by the ordinary alias insert.

        Every row keyed by cand came from that MAC alone, so it belongs to dev as if the merge had happened at first
        sight. Its `new` event is deleted: a "new device" line inside a known device's timeline would be false, and the
        `merged` event says when the MAC appeared. Its mail_queued goes with the row (a private MAC is never mailed)."""
        c.execute("UPDATE history SET mac=? WHERE mac=?", (dev, cand))
        c.execute("DELETE FROM events WHERE mac=? AND kind='new'", (cand,))
        c.execute("UPDATE events SET mac=? WHERE mac=?", (dev, cand))
        # per source the later times; a NULL last_present stays only when both sides are NULL
        c.execute("INSERT INTO seen(mac,source,last_seen,last_present) "
                  "SELECT ?, source, last_seen, last_present FROM seen WHERE mac=? "
                  "ON CONFLICT(mac,source) DO UPDATE SET last_seen=MAX(seen.last_seen, excluded.last_seen), "
                  "last_present=MAX(COALESCE(seen.last_present, excluded.last_present), "
                  "COALESCE(excluded.last_present, seen.last_present))", (dev, cand))
        c.execute("DELETE FROM seen WHERE mac=?", (cand,))
        # per SSID: the stays add up, the span widens, and the AP is the one seen last
        c.execute("INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) "
                  "SELECT ?, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap FROM wifi_presence WHERE mac=? "
                  "ON CONFLICT(mac, ssid) DO UPDATE SET "
                  "first_seen=MIN(wifi_presence.first_seen, excluded.first_seen), "
                  "last_seen=MAX(wifi_presence.last_seen, excluded.last_seen), "
                  "seconds_seen=wifi_presence.seconds_seen + excluded.seconds_seen, "
                  "polls_seen=wifi_presence.polls_seen + excluded.polls_seen, "
                  "last_ap=CASE WHEN excluded.last_seen > wifi_presence.last_seen "
                  "THEN excluded.last_ap ELSE wifi_presence.last_ap END", (dev, cand))
        c.execute("DELETE FROM wifi_presence WHERE mac=?", (cand,))
        c.execute("DELETE FROM devices WHERE mac=?", (cand,))

    def _prune_reference(self, c: sqlite3.Connection, now: int) -> int:
        """The clock that prunes (events older than a year, devices offline for PRUNE_DAYS); stores it in meta."""
        # a clock that jumps ahead must not wipe the event log or archive devices, however many polls it stays wrong: the prune reference
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
        return ref

    def _notify(self) -> None:
        """Mail the queued new devices (devices.mail_queued), up to MAIL_BATCH per mail, oldest first.

        The batch goes to every channel; the queue is cleared when at least one delivered (a
        channel that failed or waits out its backoff misses that batch, logged by notify), and kept when all failed
        or wait. A channel in backoff is not called, so a dead server does not delay the poll.
        Delivery is at-least-once: if the mail goes out and the UPDATE that clears the queue fails (or the process
        dies in between), the same devices are mailed again at the next poll."""
        if not self.cfg.mail_enabled:
            return
        try:
            with self.db.tx() as c:
                # acked or archived devices leave the queue. No age limit: mail_queued is wall
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
            notify.new_devices(self.cfg, rows, backoff=self._mail_backoff)
        except notify.NotifyDeferred:  # no channel was called: nothing new to say, the queue stays
            log.debug("mail deferred (%d device(s) queued): every channel is in backoff", len(rows))
            self._write_notify_state()
            return
        except Exception as e:  # never let mail break the collector; the queue is kept for the next poll
            # one warning per failed spell of the queue: the text changes with whichever channels were due, and the
            # channels' own spell warnings say the rest
            log.log(logging.DEBUG if self._mail_failing else logging.WARNING,
                    "mail failed (%d device(s) queued): %s", len(rows), e)
            self._mail_failing = True
            self._write_notify_state()
            return
        if self._mail_failing:
            log.info("mail delivers again (%d device(s) queued)", len(rows))
            self._mail_failing = False
        self._write_notify_state()
        macs = [r["mac"] for r in rows]
        try:
            self.db.q(f"UPDATE devices SET mail_queued=NULL WHERE mac IN ({','.join('?' * len(macs))})", tuple(macs))
        except sqlite3.Error as e:  # mailed again at the next poll (at-least-once)
            log.warning("mail sent but the queue was not cleared (%d device(s) will be mailed again): %s", len(macs), e)

    def _alert(self) -> None:
        """Send the alert events written since the mark (meta notify.alert_event_id: the events up to this id were
        considered) as one message, at most ALERT_BATCH per poll, oldest first; on delivery the mark moves to the
        newest one sent when more are pending, else (and with none to send) to the newest event, so an event that was
        no alert when it was considered (a device watched later, a flag turned on later) is never sent as new. At the
        first pass of a process more than ALERT_BATCH pending are skipped with a WARNING (a stale mark). Alert events: the
        ALERT_KINDS with MAIL_ON_SOURCE=1, and the WATCH_KINDS of devices with watch=1 with MAIL_ON_WATCH=1 (one mark
        for both). Only with a channel. No mark yet (first start with alerts on): the mark is set to the newest event
        and nothing is sent, so old events are not sent at an upgrade. While both are off the mark is removed (once
        per process), so turning them on later does not send the events of the time they were off.
        At-least-once: when no channel delivered (or the mark cannot be written) the same events go at the next poll.
        Ack or archive of a device does not drop its alerts: they are events, not the mail queue.
        Never raises: a failure here does not stop the poll."""
        source, watch = self.cfg.mail_on_source, self.cfg.mail_on_watch
        what = "alert" if source and watch else "source alert" if source else "watch alert"
        try:
            if not (self.cfg.mail_enabled and (source or watch)):
                if not self._alert_mark_cleared:
                    self.db.q("DELETE FROM meta WHERE key=?", (ALERT_MARK,))
                    self._alert_mark_cleared = True
                return
            self._alert_mark_cleared = False
            mark = self.db.get_meta(ALERT_MARK, "")
            if not (mark.isascii() and mark.isdigit()):
                with self.db.tx() as c:
                    top = c.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
                    self.db.set_meta(ALERT_MARK, str(top), c)
                self._alert_started = True  # a fresh mark is no stale one
                return
            where, args = [], []
            if source:
                where.append(f"kind IN ({','.join('?' * len(ALERT_KINDS))})")
                args += ALERT_KINDS
            if watch:  # source events have mac '', which no device row has
                where.append(f"(kind IN ({','.join('?' * len(WATCH_KINDS))}) "
                             "AND mac IN (SELECT mac FROM devices WHERE watch=1))")
                args += WATCH_KINDS
            with self.db.tx() as c:  # one read: no event written between the two lands behind a moved mark unseen
                rows = c.execute(f"SELECT id, ts, mac, kind, detail FROM events WHERE id > ? AND "
                                 f"({' OR '.join(where)}) ORDER BY id LIMIT ?", (int(mark), *args, ALERT_BATCH + 1)).fetchall()
                top = c.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
                # the first pass of a process: more than one batch pending means a stale mark (an older version ran
                # in between and wrote events without moving it), not a short restart, so they are not sent
                skipped = 0
                if not self._alert_started and len(rows) > ALERT_BATCH:
                    skipped = c.execute(f"SELECT COUNT(*) FROM events WHERE id > ? AND ({' OR '.join(where)})",
                                        (int(mark), *args)).fetchone()[0]
                    self.db.set_meta(ALERT_MARK, str(top), c)
                # more than one batch pending: only up to the last one sent was considered; else every event up to
                # the newest was, so an event that was no alert then (an unwatched device's) is not sent later
                full = len(rows) > ALERT_BATCH
                rows = rows[:ALERT_BATCH]
                # nothing to send: every event up to the newest was considered, so a device watched later (or a flag
                # turned on later) gets only what is written after it
                if not rows and top > int(mark):
                    self.db.set_meta(ALERT_MARK, str(top), c)
            self._alert_started = True
            if skipped:
                log.warning("alerts: skipped %d events written before this start", skipped)
                return
            if not rows:
                return
            names = self._alert_names(rows)
            src = [r for r in rows if r["kind"] in ALERT_KINDS]
            msg = notify.build_alert(self.cfg, self._alert_subject(rows, names), self._alert_lines(rows, names),
                                     src[-1]["kind"] if src else "watch", self._alert_links(rows))
        except Exception as e:  # sqlite3.Error or a bug: the mark stays, tried again at the next poll
            log.warning("%s skipped: %s", what, db_error_text(e) if isinstance(e, sqlite3.Error) else type(e).__name__)
            return
        try:
            notify.send(self.cfg, msg, self._mail_backoff, what)
        except notify.NotifyDeferred:  # no channel was called: the mark stays
            log.debug("%s deferred (%d event(s)): every channel is in backoff", what, len(rows))
            self._write_notify_state()
            return
        except Exception as e:  # NotifyError texts name the channel and a code only; another exception by its type
            log.log(logging.DEBUG if self._alert_failing else logging.WARNING, "%s failed (%d event(s)): %s",
                    what, len(rows), e if isinstance(e, notify.NotifyError) else type(e).__name__)
            self._alert_failing = True
            self._write_notify_state()
            return
        if self._alert_failing:
            log.info("%ss deliver again", what)
            self._alert_failing = False
        self._write_notify_state()
        try:
            with self.db.tx() as c:
                self.db.set_meta(ALERT_MARK, str(rows[-1]["id"] if full else top), c)
        except sqlite3.Error as e:  # sent again at the next poll (at-least-once)
            log.warning("%s sent but not recorded (%d event(s) will be sent again): %s", what, len(rows),
                        db_error_text(e))

    def _alert_names(self, rows: list) -> dict[str, str]:
        """mac -> the device's display name (name, else hostname, else the MAC) for the device events in rows."""
        macs = sorted({r["mac"] for r in rows if r["mac"]})
        names = {m: m for m in macs}
        if macs:
            for d in self.db.q(f"SELECT mac, name, hostname FROM devices WHERE mac IN ({','.join('?' * len(macs))})",
                               tuple(macs)):
                names[d["mac"]] = d["name"] or d["hostname"] or d["mac"]
        return names

    @staticmethod
    def _alert_lines(rows: list, names: dict[str, str]) -> list[str]:
        """`<time> <kind>: <detail>` per source event; `<time> <name> <kind>[: <detail>]` per device event. The time
        is in the container's TZ."""
        lines = []
        for r in rows:
            at = time.strftime('%Y-%m-%d %H:%M', time.localtime(r["ts"]))
            if not r["mac"]:
                lines.append(f"{at} {r['kind']}: {r['detail']}")
                continue
            lines.append(f"{at} {names[r['mac']]} {r['kind']}" + (f": {r['detail']}" if r["detail"] else ""))
        return lines

    def _alert_links(self, rows: list) -> list[str]:
        """The page link of each device in rows (as in the new-device message), once per device in the order of
        first appearance; [] without PUBLIC_URL."""
        base = self.cfg.public_url.rstrip("/")  # a trailing slash must not give "//?device="
        if not base:
            return []
        return [f"{base}/?device={mac}" for mac in dict.fromkeys(r["mac"] for r in rows if r["mac"])]

    @staticmethod
    def _alert_subject(rows: list, names: dict[str, str]) -> str:
        """One event: by its kind and instance ("fw1 is down: timeout", "fw1 is back after 2h0m") or device ("printer: offline"); several: their count,
        named by what they are (source events, changes on watched devices, or alerts when both)."""
        if len(rows) > 1:
            devices = sum(1 for r in rows if r["mac"])
            what = ("source events" if not devices else "changes on watched devices" if devices == len(rows)
                    else "alerts")
            return f"{len(rows)} {what}"
        r = rows[0]
        if r["mac"]:
            return f"{names[r['mac']]}: {r['kind']}"
        # source_down/source_up details are "<instance>: <error>" and "<instance>: up after <length>"
        name, _, text = r["detail"].partition(": ")
        if text.startswith("up after "):
            text = text[len("up "):]
        return ALERT_SUBJECTS.get(r["kind"], "{name}: " + r["kind"]).format(name=name, text=text).rstrip(": ")[:80]

    def _write_notify_state(self) -> None:
        """notify.<channel>.ok (1/0) in the meta table, written only when it changed."""
        for name, ok in self._mail_backoff.states().items():
            if self._notify_ok.get(name) == ok:
                continue
            try:
                self.db.set_meta(f"notify.{name}.ok", "1" if ok else "0")
            except sqlite3.Error as e:  # written again at the next change of state
                log.debug("cannot record notify.%s.ok: %s", name, e)
                continue
            self._notify_ok[name] = ok

    def _mqtt_step(self, ok: bool) -> None:
        """MQTT after a poll. A good poll (re)connects when the "mqtt" backoff is due and publishes what changed; a
        failed poll publishes nothing, except status offline once at the SOURCE_DOWN_POLLS-th failed poll in a row (Home
        Assistant then shows the trackers unavailable, not every device away). A broker error never fails the poll."""
        pub = self._mqtt
        if pub is None:
            return
        try:
            if ok:
                was_down = self._mqtt_failed_polls >= SOURCE_DOWN_POLLS
                self._mqtt_failed_polls = 0
                if not pub.connected:
                    if not self._mail_backoff.due("mqtt"):
                        return
                    pub.connect()  # status online and a full publish
                    was_down = False
                elif was_down:  # the status was offline: everything again, then online
                    pub.full = True
                pub.publish_poll(self.db.devices(), self.db.stats(self.cfg.new_days))
                if was_down:
                    pub.publish_status(True)
                pub.ping_if_idle()
            else:
                self._mqtt_failed_polls += 1
                if not pub.connected:
                    return
                if self._mqtt_failed_polls == SOURCE_DOWN_POLLS:
                    pub.publish_status(False)
                pub.ping_if_idle()  # no message, but the session (and its Will) stays
                return
        except Exception as e:  # the publisher closed the client; the next due good poll reconnects and sends all
            text = str(e) if isinstance(e, (OSError, MqttError)) else f"{type(e).__name__}: {e}"
            self._mail_backoff.failed("mqtt", text)
            wait = self._mail_backoff.retry_in("mqtt")
            log.log(logging.DEBUG if self._mqtt_failing else logging.WARNING, "mqtt: %s (retry in %d s)",
                    text.removeprefix("mqtt: "), wait)
            self._mqtt_failing = True
            self._write_notify_state()
            return
        self._mail_backoff.delivered("mqtt")
        if self._mqtt_failing:
            log.info("mqtt: publishing again")
            self._mqtt_failing = False
        self._write_notify_state()

    def _sightings(self, producers: list[str]) -> tuple[dict[str, object], dict[str, str], dict[str, Batch]] | dict:
        """Collect the sighting producers: (every answer, status, the batches), or the failed poll when none answered."""
        # read again in run_once after the collection; here only to keep a pending baseline's failed check()s from backing off
        got, status = self._collect(producers, self.db.get_meta("first_run_done", "") != "1")
        ok = {n: b for n, b in got.items() if isinstance(b, Batch)}
        if not ok:  # every sighting producer failed: the poll fails, so nothing stays online forever
            errors = [(n, b.error) for n, b in got.items()]
            msg = errors[0][1] if len(errors) == 1 else "; ".join(f"{n}: {e}" for n, e in errors) or "no sighting connector is enabled"
            return self._fail(msg, status)
        return got, status, ok

    def _raw_stats(self, ok: dict[str, Batch]) -> tuple[list, dict[str, int]]:
        """This poll's sightings and the summed integer stats of its batches; sets _poll_hosts."""
        sightings = [s for b in ok.values() for s in b.sightings]
        raw_stats: dict[str, int] = {}
        for b in ok.values():
            for k, v in b.stats.items():
                if isinstance(v, int):  # a string stat (e.g. a strategy) is not a count
                    raw_stats[k] = raw_stats.get(k, 0) + v
        # this poll's hostnames, read by _device_names() while the switch names its uplink ports
        self._poll_hosts = {mac: m.hostname for mac, m in merge([to_fw1(s) for s in sightings]).items()}
        return sightings, raw_stats

    def _enrich(self, producers: list[str], got: dict[str, object], status: dict[str, str]) -> dict[str, str]:
        """Collect the other instances into got; returns the status of the whole collection."""
        more, enrich_status = self._collect([n for n in self._runs if n not in producers])
        got.update(more)
        return {**status, **enrich_status}

    def _baseline_gate(self, first_run: bool, sightings: list, ok: dict[str, Batch], producers: list[str],
                       raw_stats: dict[str, int], enrich_status: dict[str, str]) -> list[str] | dict:
        """The producers the baseline waits for, or the failed poll when a first poll found no devices."""
        # only a truly first poll: during the baseline wait devices are already stored, and an empty poll then is
        # an ordinary one that must run the merge (devices go offline), not fail as "first poll"
        if first_run and not sightings and not self.db.q("SELECT 1 FROM devices LIMIT 1"):
            log.warning("first poll returned no devices (%s); not taking a baseline", raw_stats)
            return self._fail("first poll returned no devices", enrich_status)
        # a baseline taken without a producer that has never answered would mail all of its devices as new once
        # it does. Until every enabled producer has answered, merge still runs as the first run (devices are recorded
        # as baseline, no "new" event, no mail) but the baseline is not stored as taken. A producer that never answers
        # holds it back for good. Not persisted: a restart before the baseline waits again
        # this poll's answers count here, but are kept only once the write below has committed (see after the tx)
        waiting = [n for n in producers if not self._runs[n].disabled and not self._runs[n].answered and n not in ok] if first_run else []
        if waiting and not self._baseline_wait_logged:
            log.warning("baseline held back until %s has answered once", ", ".join(waiting))
            self._baseline_wait_logged = True
        return waiting

    def _merge_state(self, first_run: bool, prev_ok: bool, producers: list[str], waiting: list[str]) -> MergeState:
        # the controller role, not the type: any instance whose describe() says so (getattr: a type without roles)
        # producers: only an instance that lists sightings can hold a lease, so a failed switch does not hold lease types
        return MergeState(self._no_lease_since, first_run, prev_ok,
                          frozenset(n for n, conn in self._connectors.items()
                                    if "controller" in getattr(conn.describe(), "roles", frozenset())),
                          producers=frozenset(producers), held_back=bool(waiting),
                          undecided_since=self._undecided_since)

    def _commit(self, c: sqlite3.Connection, state: MergeState, batches: dict, now: int, t0: float,
                raw_stats: dict[str, int], first_run: bool, waiting: list[str], status: dict[str, str]):
        """The poll's write, in the caller's transaction: merge against the stored rows, write, then the poll meta."""
        prev = {r["mac"]: dict(r) for r in c.execute("SELECT * FROM devices").fetchall()}
        # read with prev in one transaction, so the alias map and the rows it points to agree
        state.aliases = {r["mac"]: r["device"] for r in c.execute("SELECT mac, device FROM aliases").fetchall()}
        if self.cfg.prune_days > 0 or self.cfg.prune_private_days > 0:  # a restore by hand holds against pruning; only read when it runs
            state.restored = {r["mac"]: r["ts"] for r in c.execute(
                "SELECT mac, MAX(ts) ts FROM events WHERE kind='restored' GROUP BY mac").fetchall()}
        state.prune_now = self._prune_reference(c, now)
        res = merge_batches(prev, batches, self.cfg, now, state)
        purged = self._write(c, prev, res, now, state.prune_now, purge=not first_run)
        self._write_poll_meta(c, t0, now, raw_stats, first_run, waiting, status)
        self._write_source_events(c)
        return res, purged

    def _write_poll_meta(self, c: sqlite3.Connection, t0: float, now: int, raw_stats: dict[str, int], first_run: bool,
                         waiting: list[str], status: dict[str, str]) -> None:
        """The meta rows of a successful poll, in the caller's transaction."""
        for k, v in status.items():
            self.db.set_meta(k, v, c)
        if not waiting:
            self.db.set_meta("first_run_done", "1", c)
        self.db.set_meta("last_poll_ts", str(now), c)
        self.db.set_meta("last_attempt_ts", str(now), c)
        self.db.set_meta("last_poll_ok", "1", c)
        self._count_poll(c, True, status)
        self.db.set_meta("last_error", "", c)
        self.db.set_meta("last_poll_ms", str(int((time.time() - t0) * 1000)), c)
        last_raw = f"{raw_stats.get('leases', 0)} leases, {raw_stats.get('arp', 0)} arp"
        if "reservations" in raw_stats:  # Kea reservations or dnsmasq hosts, when the backend reads them
            last_raw += f", {raw_stats['reservations']} reservations"
        for key in ("ndp", "leases6"):  # IPv6 reads, present (0 included) when the setting is on
            if key in raw_stats:
                last_raw += f", {raw_stats[key]} {key}"
        for flag, text in (("ndp_unavailable", "ndp"), ("kea6_unavailable", "kea6")):  # the read was refused or failed
            if raw_stats.get(flag):
                last_raw += f", {text} unavailable"
        self.db.set_meta("last_raw", last_raw, c)
        if first_run and not waiting:
            self.db.set_meta("baseline_ts", str(now), c)

    def run_once(self) -> dict:
        t0 = time.time()
        producers = [n for n, r in self._runs.items() if "sighting" in r.produces]
        collected = self._sightings(producers)
        if isinstance(collected, dict):  # the failed poll
            self._mqtt_step(ok=False)
            return collected
        got, status, ok = collected
        sightings, raw_stats = self._raw_stats(ok)
        enrich_status = self._enrich(producers, got, status)
        now = int(time.time())
        first_run = self.db.get_meta("first_run_done", "") != "1"
        prev_ok = self.db.get_meta("last_poll_ok", "1") == "1"
        waiting = self._baseline_gate(first_run, sightings, ok, producers, raw_stats, enrich_status)
        if isinstance(waiting, dict):  # the failed poll
            self._mqtt_step(ok=False)
            return waiting
        batches = {n: got[n] for n in self._runs if n in got}
        state = self._merge_state(first_run, prev_ok, producers, waiting)
        # immediate: it reads the devices and then writes, so a deferred transaction would fail at its first write
        # when another writer (import-csv, reset-baseline) committed in between; this one waits up to busy_timeout
        with self.db.tx(immediate=True) as c:
            res, purged = self._commit(c, state, batches, now, t0, raw_stats, first_run, waiting, enrich_status)
        self._source_events_written()
        self._alert()
        self._mqtt_step(ok=True)  # after the commit: the published state is what the page shows
        # only now: a poll whose write failed stored nothing, so its producers have not yet answered for the baseline
        for n in ok:
            self._runs[n].answered = True
        self._notify()
        st = res.stats
        log.info("poll ok: %d devices, %d new, %d changed, %d ms", st["devices"], st["new"], st["changed"], int((time.time() - t0) * 1000))
        self._log_purge(purged)
        return {"ok": True, "devices": st["devices"], "new": st["new"], "changed": st["changed"], "first_run": first_run}

    def _log_purge(self, purged: tuple[int, int]) -> None:
        devices, rows = purged
        if devices > 0:
            log.info("purged %d archived devices (%d rows, PURGE_DAYS=%d)", devices, rows, self.cfg.purge_days)
            if rows > 1000:
                log.info('run "python -m leasewatch vacuum" to give the space back to the file system')

    def loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                res = self.run_once()
            except Exception as e:
                if stop_event.is_set() and isinstance(e, sqlite3.ProgrammingError):
                    log.debug("poll cut off by shutdown")  # the database was closed under a poll that outlived the join
                    break
                self._poll_crashed(e)
            else:
                # a returned {"ok": False} (every producer failed) is no recovery: the spell stays open and its
                # count unchanged (only a crash counts as a failed poll here)
                failed = isinstance(res, dict) and res.get("ok") is False
                if self._poll_spell is not None and not failed:
                    log.info("polls work again after %d failed poll(s)", self._poll_fails)
                    self._poll_spell, self._poll_fails, self._fail_unrecorded = None, 0, False
            stop_event.wait(self.cfg.poll_seconds)

    def _poll_crashed(self, e: Exception) -> None:
        """Log a failed poll (traceback once per spell and cause) and record it as last_error."""
        if isinstance(e, sqlite3.DatabaseError):
            msg = db_error_text(e)
            key: tuple = ("db", (getattr(e, "sqlite_errorcode", None) or 0) & 0xFF)
        else:
            msg = "internal error in collector (see logs)"
            last = traceback.extract_tb(e.__traceback__)[-1:]
            key = (type(e).__name__, *((last[0].filename, last[0].lineno) if last else ()))
        if self._poll_spell is None:
            self._poll_fails = 0
        self._poll_fails += 1
        if key != self._poll_spell:
            log.error("poll failed: %s", msg, exc_info=True)
        else:
            log.debug("poll failed again: %s", msg)
        self._poll_spell = key
        try:
            self._fail(msg)
        except Exception:  # usually the same database error: the status stays stale until the stale check
            if not self._fail_unrecorded:
                log.warning("cannot record the failed poll: %s", msg)
                self._fail_unrecorded = True
