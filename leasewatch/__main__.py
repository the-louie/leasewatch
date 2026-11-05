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
from .config import Config
from .db import Database
from .web import serve


SUBCOMMANDS = ("snmp-detect", "snmp-profiles")
NO_PYSNMP = "pysnmp not installed: the SNMP switch connector and snmp-detect need it (pip install pysnmp)"


def _out(line: str = "") -> None:
    # command output for the operator's terminal, not a log line
    sys.stdout.write(line + "\n")


def _have_pysnmp() -> bool:
    try:
        import pysnmp.hlapi.v3arch.asyncio  # noqa: F401
    except ImportError:
        return False
    return True


def snmp_profiles_cmd(argv: list[str]) -> int:
    import argparse
    from . import snmp_profiles
    argparse.ArgumentParser(prog="python -m leasewatch snmp-profiles", description="List the built-in SNMP profiles.").parse_args(argv)
    if not _have_pysnmp():
        _out(NO_PYSNMP)
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


def _detect_connector(args: object) -> tuple[object | None, str]:
    """(SnmpSwitchConnector, "") for the instance or the flags, or (None, error text)."""
    from .connectors.snmp_switch import SnmpSwitchConnector
    if args.host:
        settings = {"host": args.host, "user": args.user, "auth": args.auth, "profile": args.profile or "",
                    "profile_file": args.profile_file or "", "min_macs": "",
                    # keys come from the environment only: argv is visible to every user in the process list
                    "auth_key": os.environ.get(args.auth_key_env, ""), "priv_key": os.environ.get(args.priv_key_env, "")}
        return SnmpSwitchConnector(args.instance or "switch", settings), ""
    if not args.instance:
        return None, "give an instance name or --host"
    from .connectors import build_instance, instances_context
    # Config.instances is a property: LW_CONNECTORS, or the legacy SNMP_* variables as instance "switch"
    specs = [s for s in Config().instances if s.type == "snmp_switch"]
    spec = next((s for s in specs if s.name == args.instance), None)
    conn = build_instance(spec, instances_context([spec])) if spec else None
    names = [s.name for s in specs]
    if not isinstance(conn, SnmpSwitchConnector):
        return None, f"no snmp_switch instance {args.instance!r} configured (configured: {', '.join(names) or 'none'})"
    return conn, ""


def snmp_detect_cmd(argv: list[str]) -> int:
    import argparse
    from . import snmp_profiles
    ap = argparse.ArgumentParser(prog="python -m leasewatch snmp-detect",
                                 description="Show sysObjectID, sysDescr, the SNMP profile and the first rows of each walk.")
    ap.add_argument("instance", nargs="?", help="configured snmp_switch instance (the SNMP_* variables are instance 'switch')")
    ap.add_argument("--host", help="switch address, instead of a configured instance")
    ap.add_argument("--user", default="leasewatch")
    ap.add_argument("--auth", default="SHA", choices=("SHA", "SHA256"))
    ap.add_argument("--auth-key-env", default="SNMP_AUTH_KEY", help="name of the environment variable with the auth key")
    ap.add_argument("--priv-key-env", default="SNMP_PRIV_KEY", help="name of the environment variable with the privacy key")
    ap.add_argument("--profile", help="built-in profile instead of detection")
    ap.add_argument("--profile-file", help="JSON profile file")
    ap.add_argument("--rows", type=int, default=5, help="rows shown per walk (default 5)")
    args = ap.parse_args(argv)
    if not _have_pysnmp():
        _out(NO_PYSNMP)
        return 1
    conn, err = _detect_connector(args)
    if conn is None:
        _out(err)
        return 2
    problems = conn.validate()
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


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in SUBCOMMANDS:
        logging.basicConfig(level="WARNING", format="%(levelname)s %(name)s: %(message)s")
        return (snmp_detect_cmd if argv[0] == "snmp-detect" else snmp_profiles_cmd)(argv[1:])
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
    srv.serve_forever()
    srv.server_close()
    t.join(10)  # let a poll in flight commit before the interpreter goes away
    return 0


if __name__ == "__main__":
    sys.exit(main())
