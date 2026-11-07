"""Entry point: collector thread + web server. `python -m leasewatch`.

Helper commands (they never start the server or open the database):
`python -m leasewatch snmp-profiles` lists the built-in profiles and their match rules;
`python -m leasewatch snmp-detect <instance>` (or `--host ...`) prints what a switch reports and what the profile walks;
`python -m leasewatch check [instance ...]` prints the loaded connector types, the config problems and each instance's
validate()/check() result;
`python -m leasewatch collect <instance> [--json]` runs check() and collect() once and prints the batch as the host
would merge it;
`python -m leasewatch hash-password [--iterations N]` reads a password (prompt on a terminal, else one line from stdin)
and prints the AUTH_PASSWORD_HASH value;
`python -m leasewatch backup [--to PATH] [--keep N]` writes a consistent copy of the database (safe while the service
runs) and rotates DATA_DIR/backups/;
`python -m leasewatch vacuum` rebuilds the database file (stop the service first).
"""
from __future__ import annotations

import logging
import os
import signal
import sqlite3
import sys
import threading
import time
from typing import Callable

from . import __version__, maintenance
from .collector import Collector, close_connector, error_text, setup_instance
from .config import ENV_PREFIX, Config, parse_networks, removed_problems
from .db import Database
from .web import serve


SUBCOMMANDS = ("snmp-detect", "snmp-profiles", "check", "collect", "hash-password", "backup", "vacuum")
NO_PYSNMP = "pysnmp not installed: the SNMP switch connector and snmp-detect need it (pip install pysnmp)"


def _printable(text: str) -> str:
    # sysDescr and walk values come from the switch: an ESC or BEL in them would retitle the terminal or erase lines,
    # so every non-printable character is shown escaped (\x1b)
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def _out(line: str = "") -> None:
    # command output for the operator's terminal, not a log line
    line = _printable(line)
    # an ASCII-only stdout (PYTHONIOENCODING=ascii) would raise UnicodeEncodeError on a device's non-ASCII byte
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        line = line.encode(enc, "backslashreplace").decode(enc)
    except LookupError:
        pass
    sys.stdout.write(line + "\n")


def _findable(name: str) -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):  # ValueError: a sys.modules entry without __spec__
        return False


def _pysnmp_problem() -> str:
    """"" when pysnmp can be imported, else the one line snmp-profiles and snmp-detect print instead."""
    try:
        import pysnmp.hlapi.v3arch.asyncio  # noqa: F401
    except ImportError as e:
        from .connectors.snmp_switch import SnmpSwitchConnector
        # the connector's wording, as the server shows it: only a missing "pysnmp" itself is "not installed" (pip
        # install helps); a missing dependency or a pysnmp before 7 is named. A throwaway instance, no host, no I/O
        msg = str(SnmpSwitchConnector("switch", {})._error(e))
        if msg != "missing dependency pysnmp":
            return msg
        # a missing pysnmp raises ModuleNotFoundError with its name: a nameless one comes from inside it. A missing
        # "pysnmp.x" with the package still findable is a damaged install whose __init__ failed (Python then drops
        # "pysnmp" from sys.modules); a blocked or absent one has no spec (find_spec returns None for a None entry).
        # A plain ImportError naming pysnmp is "cannot import name" from inside an installed one
        if not isinstance(e, ModuleNotFoundError) or e.name is None or (e.name.startswith("pysnmp.") and _findable("pysnmp")):
            return "pysnmp cannot be imported (ImportError): pysnmp 7 and its dependencies are needed"
        return NO_PYSNMP
    except Exception as e:  # a broken install (incompatible pyasn1, a damaged file) is as unusable as a missing one
        logging.getLogger("leasewatch").warning("pysnmp is installed but cannot be imported (%s)", type(e).__name__)
        return f"pysnmp cannot be imported ({type(e).__name__}): pysnmp 7 and its dependencies are needed"
    return ""


def snmp_profiles_cmd(argv: list[str]) -> int:
    import argparse
    from . import snmp_profiles
    argparse.ArgumentParser(prog="python -m leasewatch snmp-profiles", description="List the built-in SNMP profiles.").parse_args(argv)
    problem = _pysnmp_problem()
    if problem:
        _out(problem)
    _out("detection order: " + ", ".join(snmp_profiles.DETECT_ORDER) + " (first match wins, else standard)")
    for name in snmp_profiles.BUILTIN:
        p = snmp_profiles.load(name)
        m = p["match"]
        rule = " and ".join(x for x in (
            "sysObjectID " + " | ".join(m["sysobjectid_prefix"]) + ".*" if m["sysobjectid_prefix"] else "",
            "sysDescr ~ " + " | ".join(m["sysdescr_regex"]) if m["sysdescr_regex"] else "") if x)
        if not rule:
            rule = "fallback when nothing matches" if name == "standard" else "by name only (profile setting)"
        _out(f"{name:<11} fdb {p['fdb']['strategy']:<15} match: {rule}")
    return 0


def _detect_connector(args: object) -> tuple[object | None, list[str], str]:
    """(SnmpSwitchConnector, its config problems, "") for the instance or the flags, or (None, the config problems
    that may explain it, error text)."""
    from .connectors.snmp_switch import SnmpSwitchConnector
    if args.host:
        # named here: validate() would only say AUTH_KEY is required, not which variable the operator has to set.
        # An empty value (X= or a compose ${X} with X unset) is the same mistake, and so is a blank one:
        # the server strips every variable (config._env)
        for flag, var in (("--auth-key-env", args.auth_key_env), ("--priv-key-env", args.priv_key_env)):
            if not var:  # no default: the key variables are the operator's own names
                return None, [], f"--host needs {flag} (the name of the environment variable that holds the key)"
            if not os.environ.get(var, "").strip():
                return None, [], f"environment variable {var} (from {flag}) is not set or empty"
        settings = {"host": args.host, "user": args.user, "auth": args.auth, "profile": args.profile or "",
                    "profile_file": args.profile_file or "", "min_macs": "",
                    # keys come from the environment only: argv is visible to every user in the process list
                    "auth_key": os.environ.get(args.auth_key_env, "").strip(),
                    "priv_key": os.environ.get(args.priv_key_env, "").strip()}
        conn = SnmpSwitchConnector(args.instance or "switch", settings)
        return conn, conn.validate(), ""
    if not args.instance:
        return None, [], "give an instance name or --host"
    from .connectors import build_instance, instance_problems, instances_context, registry
    cfg = Config()
    # a global problem (a removed 1.0 variable, a load problem, a malformed variable) stops the server whatever the
    # instances are called, so it always counts, and blocks the probe as it blocks the server, as `check` does
    glob = _global_problems(cfg)
    # the server checks these too: an unreadable AUTH_KEY_FILE, TIMEOUT=x, or a parse problem with one of the
    # instance's own variables (two spellings of a key, a name left out of LW_CONNECTORS). Another instance's
    # problems stay out: they do not stop this switch from answering. The name listed twice stops the server
    own = glob + _own_problems(cfg, args.instance, glob)
    named = next((s for s in cfg.instances if s.name == args.instance), None)
    if named is not None and named.type not in registry():  # a TYPE typo: name it as the server would
        return None, own, f"config: {instance_problems(named)[0]}"
    specs = [s for s in cfg.instances if s.type == "snmp_switch"]
    spec = next((s for s in specs if s.name == args.instance), None)
    conn = build_instance(spec, instances_context([spec])) if spec else None
    names = [s.name for s in specs]
    if not isinstance(conn, SnmpSwitchConnector):
        # every problem, not only the instance's own: when it is not built at all, the cause may be worded for the list
        # or for another instance (LW_CONNECTORS unset, an invalid name)
        return None, list(cfg.connector_problems), f"no snmp_switch instance {args.instance!r} configured (configured: {', '.join(names) or 'none'})"
    return conn, own + instance_problems(spec, conn), ""


def _belongs(problem: str, name: str) -> bool:
    return (problem.startswith((f"connector {name} ", f"LW_CONNECTORS: {name} "))
            or f"{ENV_PREFIX}{name.upper()}__" in problem.upper())


def _own_problems(cfg: Config, name: str, exclude: list[str]) -> list[str]:
    """cfg.connector_problems that belong to the instance `name` (its own variables, its LW_CONNECTORS entry), less
    `exclude` (the global ones, already counted: every caller passes _global_problems(), so a load problem whose
    path happens to contain LW_CONNECTOR__<NAME>__ does not also disable the instance)."""
    return [p for p in cfg.connector_problems if p not in exclude and _belongs(p, name)]


def snmp_detect_cmd(argv: list[str]) -> int:
    import argparse
    from . import snmp_profiles
    ap = argparse.ArgumentParser(prog="python -m leasewatch snmp-detect",
                                 description="Show sysObjectID, sysDescr, the SNMP profile and the first rows of each walk.")
    ap.add_argument("instance", nargs="?", help="configured snmp_switch instance (LW_CONNECTORS)")
    ap.add_argument("--host", help="switch address, instead of a configured instance")
    ap.add_argument("--user", default="leasewatch")
    ap.add_argument("--auth", default="SHA", choices=("SHA", "SHA256"))
    ap.add_argument("--auth-key-env", help="with --host: name of the environment variable with the auth key")
    ap.add_argument("--priv-key-env", help="with --host: name of the environment variable with the privacy key")
    ap.add_argument("--profile", help="built-in profile instead of detection")
    ap.add_argument("--profile-file", help="JSON profile file")
    ap.add_argument("--rows", type=int, default=5, help="rows shown per walk (default 5)")
    args = ap.parse_args(argv)
    problem = _pysnmp_problem()
    if problem:
        _out(problem)
        return 1
    conn, problems, err = _detect_connector(args)
    if conn is None:
        for p in problems:
            _out(f"config: {p}")
        _out(err)
        return 2
    if problems:
        for p in problems:
            _out(f"config: {p}")
        path = conn.settings.get("profile_file", "").strip()
        if path:
            try:
                snmp_profiles.load_file(path)
            except snmp_profiles.ProfileError as e:  # the operator's own file, on the operator's terminal
                _out(f"profile_file: {e}")
        return 2
    try:
        r = conn.client.detect_report(max(1, args.rows))
    except Exception as e:  # every failure is one line, never a traceback; pysnmp's own errors are not RuntimeError
        # redact() masks host, user and both keys: in --host mode they are the flags and the key variables
        _out(f"snmp error: {conn.redact(str(conn._error(e)))}")
        return 1
    _out(f"sysObjectID: {r['sysobjectid'] or '-'}")
    _out(f"sysDescr:    {r['sysdescr'] or '-'}")
    _out(f"detected:    {r['detected']}")
    _out(f"profile:     {r['profile']}" + (" (set by profile/profile_file)" if r["given"] else " (detected)"))
    for label, rows in r["walks"]:
        _out()
        _out(f"walk {label}:")
        if isinstance(rows, str):
            _out(f"  error: {conn.redact(rows)}")  # pysnmp's error indication may name the host
        elif not rows:
            _out("  (no rows)")
        for k, v in rows if not isinstance(rows, str) else []:
            _out(f"  {k} = {v}")
    return 0


def _global_problems(cfg: Config) -> list[str]:
    """The config problems that stop the server whatever the instance: a removed 1.0 variable, a load problem,
    LW_CONNECTORS unset, and any problem that belongs to no instance (LW_CONNECTOR__FW1_SECRET with one underscore,
    an invalid name in LW_CONNECTORS). All part of cfg.connector_problems, which Config() fills once."""
    from .connectors import load_problems
    loaded = load_problems()
    removed = removed_problems(os.environ)
    # every name a problem can be about: the listed instances and the names in LW_CONNECTOR__<NAME>__ variables (an
    # orphan's "zz is not in LW_CONNECTORS" is zz's problem, not this one's)
    names = {s.name for s in cfg.instances} | {
        n.lower() for k in os.environ if k.startswith(ENV_PREFIX)
        for n, sep, _ in (k[len(ENV_PREFIX):].partition("__"),) if n and sep}
    # removed and "not set" first: their hints name an example instance ("switch", FW1), which _belongs would match
    return [p for p in cfg.connector_problems
            if p in removed or p in loaded or p.startswith("LW_CONNECTORS is not set")
            or not any(_belongs(p, n) for n in names)]


def _redactor(ctx: object, conn: object | None, spec: object, hosts: bool = True) -> Callable[[str], str]:
    """The host's redact (every secret setting of every instance, as the collector uses it), then (hosts=True, for
    error and problem texts only) the instance's own redact() if it has one (a switch masks its host and user) and the
    host of the instance's URL/HOST setting, on the whole text except a leading "connector <name> (<type>): " head.
    hosts=False is for device data, which the collector merges unmasked."""
    from .connectors import make_host_mask
    if not hosts:
        return ctx.redact
    own = getattr(conn, "redact", None)
    # the whole text, not mask_url_host (which keeps everything before the first ": "): a third-party error that
    # starts with the host ("dhcp.example.lan: refused") must not show it. The instance's own head is kept instead,
    # so an instance named like its host stays recognisable
    masks = [make_host_mask(v) for k, v in spec.settings.items() if k in ("url", "host") and v.strip()]
    name = getattr(spec, "name", None)
    heads = (f"connector {name} ({getattr(spec, 'type', '')}): ", f"connector {name}: ") if name else ()

    def redact(text: str) -> str:
        text = ctx.redact(text)
        head = next((h for h in heads if text.startswith(h)), "")
        text = text[len(head):]
        if callable(own):
            try:
                out = own(text)
            except Exception:  # a connector's own helper must not turn a report into a traceback; the masks still run
                out = text
            # a third-party redact() that forgets `return text` gives None: the masks below need a str
            text = out if isinstance(out, str) else text
        for mask in masks:
            text = mask(text)
        return head + text
    return redact


def _problem_mask(ctx: object, specs: list) -> Callable[[str], str]:
    """The mask for a config problem text: a text that belongs to exactly one instance is masked as that instance
    masks its own (its "connector <name> ..." head kept); any other text (a global problem, a validate() text that
    starts with "connector " and names no instance) with every instance's URL/HOST host, as no instance vouches for
    it. This over-masks a name spelled like a host, e.g. "LW_CONNECTORS: <name> is listed twice": the safe direction,
    and the per-instance line's head still shows the name."""
    from .connectors import make_host_mask
    own = [(s.name, _redactor(ctx, None, s)) for s in specs]
    every = [make_host_mask(v) for s in specs for k, v in s.settings.items() if k in ("url", "host") and v.strip()]

    def mask(text: str) -> str:
        found = [f for n, f in own if _belongs(text, n)]
        if len(found) == 1:
            return found[0](text)
        text = ctx.redact(text)
        for m in every:
            text = m(text)
        return text
    return mask


def _probe(conn: object, steps: tuple[str, ...], timeout: int) -> tuple[str, object, int, bool]:
    """Call conn's methods `steps` in order in a daemon thread joined for `timeout` seconds (the collector's TIMEOUT
    rule): (phase reached, last return value or the exception, ms, timed out). A hung thread is abandoned."""
    state: dict = {"phase": steps[0], "out": None, "done": False}

    def work() -> None:
        out: object = None
        try:
            for step in steps:
                state["phase"] = step
                out = getattr(conn, step)()
        except BaseException as e:  # reported, never raised: the command prints one line (or one object) per outcome
            out = e
        state["out"] = out
        state["done"] = True  # last: the joining thread reads "out" only once this is set

    t0 = time.monotonic()
    t = threading.Thread(target=work, name=f"probe-{getattr(conn, 'name', '')}", daemon=True)
    try:
        t.start()
    except RuntimeError as e:  # out of threads
        return steps[0], e, 0, False
    t.join(timeout)
    if not state["done"]:
        return state["phase"], None, timeout * 1000, True
    return state["phase"], state["out"], int((time.monotonic() - t0) * 1000), False


def _probe_error(phase: str, out: object, timed_out: bool, timeout: int, redact: Callable[[str], str]) -> str:
    """The collector's error text for a probe result, "" when it succeeded."""
    from .connectors import Batch
    if timed_out:
        return f"timed out after {timeout} s"
    if isinstance(out, BaseException):
        return error_text(out, redact)
    if phase == "collect" and not isinstance(out, Batch):
        return "collect() did not return a Batch"
    return ""


def check_cmd(argv: list[str]) -> int:
    import argparse
    from .connectors import broken_types, instances_context
    ap = argparse.ArgumentParser(prog="python -m leasewatch check",
                                 description="Show the loaded connector types and config problems, then run validate() "
                                             "and check() for each instance (collect() is never called).")
    ap.add_argument("instance", nargs="*", help="instance names (default: every instance in LW_CONNECTORS)")
    args = ap.parse_args(argv)
    cfg = Config()
    ctx = instances_context(cfg.instances)
    specs = {s.name: s for s in cfg.instances}
    names = list(dict.fromkeys(args.instance))
    glob = _global_problems(cfg)
    _out(types_line())
    for type_, why in sorted(broken_types().items()):
        _out(f"plugin: {type_} not loaded: {ctx.redact(why)}")
    # each named instance is built once, here, and the same connector is checked and closed below
    built = {n: setup_instance(specs[n], ctx) for n in names if n in specs}
    if names:  # global problems plus the named instances' own; another instance's problem does not count
        problems = glob + [p for n in names for p in _own_problems(cfg, n, glob)]
        problems += [p for n in built for p in built[n][1]]
    else:
        problems = cfg.validate()
    problems = list(dict.fromkeys(problems))
    # a problem text may echo a URL or HOST (a third-party validate())
    mask_one = _problem_mask(ctx, cfg.instances)
    for p in problems:
        _out(f"config: {mask_one(p)}")
    unknown = failed = False
    for name in names or list(specs):
        spec = specs.get(name)
        if spec is None:
            _out(f"{name}: not configured (configured: {', '.join(specs) or 'none'})")
            unknown = True
            continue
        conn, own = built[name] if name in built else setup_instance(spec, ctx)
        own = list(dict.fromkeys(_own_problems(cfg, name, glob) + own))
        mask = _redactor(ctx, conn, spec)
        # the "<name> (<type>): " head is not host-masked: an instance named like its host must stay recognisable
        head = ctx.redact(f"{name} ({spec.type}): ")
        if own or conn is None:
            _out(head + "disabled: " + "; ".join(mask(p) for p in own))
            if conn is not None:
                close_connector(conn, name, spec.timeout)
            continue
        try:
            phase, out, ms, timed_out = _probe(conn, ("check",), spec.timeout)
        finally:
            close_connector(conn, name, spec.timeout)
        error = _probe_error(phase, out, timed_out, spec.timeout, mask)
        failed = failed or bool(error)
        _out(head + (f"check failed: {error}" if error else f"ok ({ms} ms)"))
    return 2 if problems or unknown else 1 if failed else 0


def _record_dict(kind: str, record: object) -> dict:
    """The record's declared fields only: a connector's subclass may add fields that the host neither checks nor
    merges, and they must not reach the output unchecked."""
    import dataclasses
    from .connectors import Attachment, Sighting
    return {f.name: getattr(record, f.name) for f in dataclasses.fields(Sighting if kind == "sighting" else Attachment)}


def _record_line(kind: str, record: object) -> str:
    return kind + " " + " ".join(f"{k}={v}" for k, v in _record_dict(kind, record).items() if v not in ("", None))


def _safe_str(x: object) -> str:
    try:
        return str.__str__(str(x))  # a plain str: a str subclass's own __format__ may raise in the human line
    except Exception:  # a connector's own type whose __str__ raises
        return type(x).__name__


def _stat_value(v: object) -> object:
    if isinstance(v, int):
        try:
            v = int(v)  # a plain int: an int subclass's own __str__/__format__ is never called by the output
            str(v)  # more than 4300 digits: int-to-text raises ValueError, in json.dumps and the human line alike
            return v
        except Exception:
            pass
    return _safe_str(v)


def _report_stats(stats: dict) -> dict:
    """Batch.stats as dict[str, int] promises it: a key that is not a str is shown as text (json.dumps refuses it),
    a value that is not an int as text (NaN and inf are not JSON; a raising __str__ is shown as its type)."""
    out = {k: _stat_value(v) for k, v in stats.items() if type(k) is str}
    # the other keys after the str ones (the host's "dropped" among them), each under a free name: 1 and "1" both
    # stay, as "1" and "1#2", and no connector key replaces the host's
    for k, v in stats.items():
        if type(k) is not str:
            key = base = _safe_str(k)
            n = 1
            while key in out:
                n += 1
                key = f"{base}#{n}"
            out[key] = _stat_value(v)
    return out


def collect_cmd(argv: list[str]) -> int:
    import argparse
    import json
    from .connectors import instances_context
    from .connectors.merge import normalise_batch
    ap = argparse.ArgumentParser(prog="python -m leasewatch collect",
                                 description="Run validate(), check() and collect() once for one instance and print the "
                                             "batch as the host would merge it.")
    ap.add_argument("instance", help="configured instance (LW_CONNECTORS)")
    ap.add_argument("--json", action="store_true", help="print exactly one JSON object, also on failure")
    args = ap.parse_args(argv)
    cfg = Config()
    ctx = instances_context(cfg.instances)
    name = args.instance
    spec = next((s for s in cfg.instances if s.name == name), None)
    report: dict = {"instance": name, "type": spec.type if spec else "", "ok": False, "phase": "validate", "error": "",
                    "ms": 0, "problems": [], "stats": {}, "sightings": [], "attachments": []}
    # redact (secrets) runs on all output; mask (secrets and the URL/HOST host) only on error and problem texts, as the
    # collector does: device data may name the source's own address (a firewall's ARP list) and is shown unmasked
    redact: Callable[[str], str] = ctx.redact
    mask: Callable[[str], str] = _redactor(ctx, None, spec) if spec else ctx.redact
    glob = _global_problems(cfg)
    problems = glob + _own_problems(cfg, name, glob)
    # a global problem is not this instance's: masked as check masks it, with every instance's host
    glob_mask = _problem_mask(ctx, cfg.instances)
    batch = None
    if spec is None:
        report["error"] = f"not configured (configured: {', '.join(s.name for s in cfg.instances) or 'none'})"
        rc = 2
    else:
        conn, own = setup_instance(spec, ctx)
        problems += own
        if conn is not None:
            mask = _redactor(ctx, conn, spec)
        if problems or conn is None:
            report["error"] = "disabled: " + "; ".join((glob_mask if p in glob else mask)(p)
                                                       for p in dict.fromkeys(problems))
            rc = 2
            if conn is not None:
                close_connector(conn, name, spec.timeout)
        else:
            try:
                phase, out, ms, timed_out = _probe(conn, ("check", "collect"), spec.timeout)
            finally:
                close_connector(conn, name, spec.timeout)
            error = _probe_error(phase, out, timed_out, spec.timeout, mask)
            report.update(phase=phase, ms=ms, error=error, ok=not error)
            rc = 1 if error else 0
            if not error:
                batch = normalise_batch(name, out)  # source filled, MACs normalised, stats["dropped"] set
                report.update(stats=_report_stats(batch.stats),
                              sightings=[_record_dict("sighting", r) for r in batch.sightings],
                              attachments=[_record_dict("attachment", r) for r in batch.attachments])
    report["problems"] = [(glob_mask if p in glob else mask)(p) for p in dict.fromkeys(problems)]
    # error is masked where it is made (the problems one by one, the probe's by _probe_error): masking the joined
    # text again would treat "disabled" as the label and mask an instance name that matches the host
    if args.json:
        # one object; the whole text redacted (the redactor also matches JSON-escaped secrets). default=str: a stat
        # value that is not JSON (a connector's own type) must not turn the object into a traceback
        for line in redact(json.dumps(report, ensure_ascii=True, indent=2, default=str)).splitlines():
            _out(line)
        return rc
    for p in report["problems"]:
        _out(f"config: {p}")
    head = f"{name} ({spec.type})" if spec else name
    if batch is not None:
        _out(redact(f"{head}: {len(batch.sightings)} sightings, {len(batch.attachments)} attachments, {report['ms']} ms"))
        _out(redact("stats: " + " ".join(f"{k}={v}" for k, v in sorted(report["stats"].items()))))
        for kind, records in (("sighting", batch.sightings), ("attachment", batch.attachments)):
            for r in records:
                _out(redact(_record_line(kind, r)))
    elif report["phase"] == "validate":  # the head is not host-masked: see check_cmd
        _out(ctx.redact(f"{head}: {report['error']}"))
    else:
        _out(ctx.redact(f"{head}: {report['phase']} failed: {report['error']}"))
    return rc


def startup_line(cfg: Config, version: str) -> str:
    """The INFO line at start: version, instances (name and type only; URLs and hosts stay out of the log), poll, mail."""
    conns = ", ".join(f"{s.name} ({s.type})" for s in cfg.instances)
    mail = f"on ({', '.join(cfg.mail_channels)})" if cfg.mail_enabled else "off"  # channel names only, no settings
    line = f"leasewatch {version}, connectors {conns or 'none'}; poll {cfg.poll_seconds} s; mail {mail}"
    if cfg.read_only_on:  # READ_ONLY wins over WRITE_ALLOW
        return line + "; writes off"
    n = len(parse_networks(cfg.write_allow)[0])
    return line + (f"; writes from {n} network{'s' if n != 1 else ''}" if n else "")


def hash_password_cmd(argv: list[str]) -> int:
    import argparse
    import getpass
    from . import auth
    ap = argparse.ArgumentParser(prog="python -m leasewatch hash-password",
                                 description="Read a password (prompted twice on a terminal, else one line from stdin) "
                                             "and print its AUTH_PASSWORD_HASH value.")
    ap.add_argument("--iterations", type=int, default=auth.DEFAULT_ITERATIONS,
                    help=f"PBKDF2 iterations (default {auth.DEFAULT_ITERATIONS})")
    args = ap.parse_args(argv)
    if not auth.MIN_ITERATIONS <= args.iterations <= auth.MAX_ITERATIONS:
        sys.stderr.write(f"--iterations must be {auth.MIN_ITERATIONS}-{auth.MAX_ITERATIONS}\n")
        return 1
    # never on argv: the process list would show it
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            password = getpass.getpass("Password: ")
            if getpass.getpass("Password again: ") != password:
                sys.stderr.write("the passwords do not match\n")
                return 1
        else:
            # one line, its line break dropped (printf '%s' sends none, echo sends one); blanks are part of it
            password = (sys.stdin.readline() if sys.stdin is not None else "").removesuffix("\n").removesuffix("\r")
        # a C/C.UTF-8 locale reads a non-UTF-8 byte as a surrogate; make_hash would raise on it, and no login could
        # send it (parse_basic decodes strict UTF-8)
        password.encode("utf-8")
    except (EOFError, UnicodeDecodeError, UnicodeEncodeError):
        sys.stderr.write("cannot read the password\n")
        return 1
    if not password:
        sys.stderr.write("empty password refused\n")
        return 1
    if len(password) < 12:
        sys.stderr.write("warning: a password shorter than 12 characters is easy to guess\n")
    _out(auth.make_hash(password, args.iterations))
    return 0


def types_line() -> str:
    """The INFO line after startup_line(): every loaded connector type and where it comes from (no settings, and no
    path other than the configured LW_CONNECTORS_DIR)."""
    from .connectors import type_help
    # names and versions come from package metadata: a newline in one would forge a second line in the start log
    return _printable("connector types: " + type_help())


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in SUBCOMMANDS:
        logging.basicConfig(level="WARNING", format="%(levelname)s %(name)s: %(message)s")
        rc = None
        try:
            try:
                rc = {"snmp-detect": snmp_detect_cmd, "snmp-profiles": snmp_profiles_cmd, "check": check_cmd,
                      "collect": collect_cmd, "hash-password": hash_password_cmd,
                      "backup": lambda a: maintenance.backup_cmd(a, _out),
                      "vacuum": lambda a: maintenance.vacuum_cmd(a, _out)}[argv[0]](argv[1:])
            except SystemExit as e:  # argparse's --help or usage error: its output is flushed below like any other
                rc = e.code if isinstance(e.code, int) else 0 if e.code is None else 1
            sys.stdout.flush()  # here, not at exit: a reader that has gone away is caught below
            return rc
        except BrokenPipeError:
            # `... | head` closed the pipe: the operator has what they wanted. stdout goes to /dev/null so the
            # interpreter's flush at exit does not raise again (sys.stdout's file descriptor 1 is replaced)
            try:
                fd = sys.stdout.fileno()  # before os.open: a stdout without a descriptor must not leak /dev/null
                devnull = os.open(os.devnull, os.O_WRONLY)
                try:
                    os.dup2(devnull, fd)
                finally:
                    os.close(devnull)
            except (OSError, ValueError, AttributeError):  # io.UnsupportedOperation is an OSError and ValueError
                pass
            # a failed run stays failed (set -o pipefail); one that broke off mid-output had nothing left to report
            return 0 if rc is None else rc
        except AttributeError:
            if sys.stdout is not None:
                raise
            # started with stdout closed (>&-): nowhere to write the output; a code the command set stays
            # (backup and vacuum have done their work by then: their code stays, 0 included)
            return 1 if not rc and argv[0] not in ("backup", "vacuum") else rc
        except KeyboardInterrupt:  # Ctrl-C while a switch is slow to answer: the operator stopped it, no traceback
            return 130  # 128 + SIGINT, as the shell reports an interrupted command
    level = (os.environ.get("LOG_LEVEL") or "INFO").strip().upper()
    known = isinstance(logging.getLevelName(level), int)
    logging.basicConfig(level=level if known else "INFO", format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("leasewatch")
    if not known:
        log.warning("LOG_LEVEL=%r is not a log level, using INFO", level)
    cfg = Config()
    problems = cfg.validate()
    if problems:
        for p in problems:
            log.error("config: %s", p)
        return 2
    try:
        os.makedirs(cfg.data_dir, exist_ok=True)
        db = Database(cfg.db_path)
    except (OSError, sqlite3.Error) as e:
        log.error("cannot open %s: %s", cfg.db_path, e)
        return 2
    stop = threading.Event()
    collector = Collector(cfg, db)
    t = threading.Thread(target=collector.loop, args=(stop,), name="collector", daemon=True)
    try:
        srv = serve(cfg, db, __version__)
    except OSError as e:
        log.error("cannot listen on %s:%d: %s", cfg.listen_host, cfg.listen_port, e)
        return 2
    t.start()  # only once the port is ours: a failed bind must not leave a poller running (and mailing) without a UI

    def shutdown(*_):
        log.info("shutting down")
        stop.set()
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    log.info("%s", startup_line(cfg, __version__))
    log.info("%s", types_line())
    srv.serve_forever()
    srv.server_close()
    verifier = getattr(srv.RequestHandlerClass, "verifier", None)
    if verifier is not None:  # failed logins still held back for the next log line
        verifier.flush()
    t.join(10)  # let a poll in flight commit before the interpreter goes away
    if t.is_alive():
        log.warning("collector still busy after 10 s; closing the database anyway")
    collector.close()  # a connector may be logging out of its device, which the poll in flight could still use
    db.close()  # last: merges the WAL into the main file
    return 0


if __name__ == "__main__":
    sys.exit(main())
