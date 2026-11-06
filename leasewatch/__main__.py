"""Entry point: collector thread + web server. `python -m leasewatch`.

Two helper commands for writing SNMP profiles (they never start the server):
`python -m leasewatch snmp-profiles` lists the built-in profiles and their match rules;
`python -m leasewatch snmp-detect <instance>` (or `--host ...`) prints what a switch reports and what the profile walks.
"""
from __future__ import annotations

import logging
import os
import signal
import sqlite3
import sys
import threading

from . import __version__
from .collector import Collector
from .config import ENV_PREFIX, Config, removed_problems
from .db import Database
from .web import serve


SUBCOMMANDS = ("snmp-detect", "snmp-profiles")
NO_PYSNMP = "pysnmp not installed: the SNMP switch connector and snmp-detect need it (pip install pysnmp)"


def _out(line: str = "") -> None:
    # command output for the operator's terminal, not a log line.
    # sysDescr and walk values come from the switch: an ESC or BEL in them would retitle the terminal or erase lines,
    # so every non-printable character is shown escaped (\x1b)
    line = "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in line)
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
    # a removed 1.0 variable is global: the server refuses to start with it whatever the instances are called, so it
    # always counts, and blocks the probe as it blocks the server. Not matched by text below: its hint names the
    # instance "switch", which would make only an instance of that name pick it up
    removed = removed_problems(os.environ)
    # the server checks these too: an unreadable AUTH_KEY_FILE, TIMEOUT=x, or a parse problem with one of the
    # instance's own variables (two spellings of a key, a name left out of LW_CONNECTORS). Another instance's
    # problems stay out: they do not stop this switch from answering. The name listed twice stops the server
    own = removed + [p for p in cfg.connector_problems if p not in removed and (
        p.startswith((f"connector {args.instance} ", f"LW_CONNECTORS: {args.instance} "))
        or f"{ENV_PREFIX}{args.instance.upper()}__" in p.upper())]
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


def startup_line(cfg: Config, version: str) -> str:
    """The INFO line at start: version, instances (name and type only; URLs and hosts stay out of the log), poll, mail."""
    conns = ", ".join(f"{s.name} ({s.type})" for s in cfg.instances)
    return f"leasewatch {version}, connectors {conns or 'none'}; poll {cfg.poll_seconds} s; mail {'on' if cfg.mail_enabled else 'off'}"


def types_line() -> str:
    """The INFO line after startup_line(): every loaded connector type and where it comes from (no settings, and no
    path other than the configured LW_CONNECTORS_DIR)."""
    from .connectors import registry, type_origins
    from .connectors.loader import BUILTIN, DIR
    reg, origins = registry(), type_origins()
    parts = [f"{', '.join(sorted(t for t in reg if origins.get(t) and origins[t].kind == BUILTIN))} (built-in)"]
    for o, t in sorted(((o, t) for t, o in origins.items() if o.kind != BUILTIN and t in reg),
                       key=lambda ot: (ot[0].kind == DIR, ot[1])):  # entry points, then the dir, as they are loaded
        where = f"LW_CONNECTORS_DIR {o.location}" if o.kind == DIR else o.kind
        parts.append(f"{t} {o.type_version} ({f'{o.dist} {o.version}'.strip()}, {where})")
    return "connector types: " + "; ".join(parts)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in SUBCOMMANDS:
        logging.basicConfig(level="WARNING", format="%(levelname)s %(name)s: %(message)s")
        rc = None
        try:
            try:
                rc = (snmp_detect_cmd if argv[0] == "snmp-detect" else snmp_profiles_cmd)(argv[1:])
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
    t.join(10)  # let a poll in flight commit before the interpreter goes away
    return 0


if __name__ == "__main__":
    sys.exit(main())
