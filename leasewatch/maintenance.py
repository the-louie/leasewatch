"""The `backup` and `vacuum` commands: they open the database file directly (never through Database, so nothing is
migrated or created) and never start the server."""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
import time
import urllib.parse
from typing import Callable

from .config import Config

BACKUP_NAME_RE = re.compile(r"^leasewatch-(\d{8}-\d{6})(?:-(\d+))?\.sqlite3$")


def _open_source(db_path: str) -> sqlite3.Connection:
    # mode=rw never creates a file: a wrong DATA_DIR is an error, not an empty database
    conn = sqlite3.connect("file:" + urllib.parse.quote(db_path) + "?mode=rw", uri=True, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _fail(prefix: str, text: object) -> int:
    sys.stderr.write(f"{prefix} failed: {text}\n")
    return 1


def _mb(path: str) -> str:
    return f"{os.path.getsize(path) / 1e6:.1f} MB"


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _free_name(directory: str) -> str:
    base = f"leasewatch-{_stamp()}"
    name, n = base + ".sqlite3", 0
    while os.path.lexists(os.path.join(directory, name)):
        n += 1
        name = f"{base}-{n}.sqlite3"
    return name


def _rotate(directory: str, keep: int) -> tuple[int, int]:
    """Delete all but the newest `keep` backups (0 = all are kept). Returns (kept, removed)."""
    found = []
    for name in os.listdir(directory):
        m = BACKUP_NAME_RE.match(name)
        if m:
            found.append((m.group(1), int(m.group(2) or 0), name))
    found.sort()  # by stamp, then by the -N suffix as a number ("-10" after "-2", "-1" after the plain name)
    doomed = found[:-keep] if keep and len(found) > keep else []
    removed = 0
    for _, _, name in doomed:
        try:
            os.unlink(os.path.join(directory, name))
            removed += 1
        except OSError:
            pass
    return len(found) - removed, removed


def _copy(src: sqlite3.Connection, final: str) -> str:
    """Write a consistent copy to final. Returns its size text, or "!" plus the failure text."""
    directory, name = os.path.split(final)
    part = os.path.join(directory, f".{name}.part")
    old_umask = os.umask(0o077)
    try:
        dst = sqlite3.connect(part, isolation_level=None)
    finally:
        os.umask(old_umask)
    done = False
    try:
        try:
            src.backup(dst)
            dst.execute("PRAGMA journal_mode=DELETE")
            res = dst.execute("PRAGMA quick_check").fetchone()
        finally:
            dst.close()
        if res is None or res[0] != "ok":
            return f"!integrity check: {res[0] if res else 'no result'}"
        fd = os.open(part, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(part, final)
        done = True
        _fsync_dir(directory)
        return _mb(final)
    finally:
        if not done:
            for suffix in ("", "-journal", "-wal", "-shm"):
                try:
                    os.unlink(part + suffix)
                except OSError:
                    pass


def _say(out: Callable[[str], None], line: str, rc: int) -> int:
    try:
        out(line)
    except AttributeError:
        if sys.stdout is not None:  # started with stdout closed (>&-): the result is the exit code
            raise
    return rc


def backup_cmd(argv: list[str], out: Callable[[str], None]) -> int:
    ap = argparse.ArgumentParser(prog="python -m leasewatch backup",
                                 description="Write a consistent copy of the database (safe while the service runs).")
    ap.add_argument("--to", metavar="PATH", help="write the copy to this new file (default: DATA_DIR/backups/, rotated)")
    ap.add_argument("--keep", type=int, metavar="N", help="backups to keep in DATA_DIR/backups/ (0 = all; default BACKUP_KEEP)")
    args = ap.parse_args(argv)
    if args.to is not None and args.keep is not None:
        ap.error("--keep applies to the default destination only, not to --to")
    if args.keep is not None and not 0 <= args.keep <= 1000:
        ap.error("--keep must be 0-1000")
    # Config() only collects problems and never raises; validate() is not called, so a bad connector setting
    # does not stop a backup
    cfg = Config()
    if args.to is not None and os.path.lexists(args.to):
        sys.stderr.write(f"backup: {args.to} exists\n")
        return 2
    try:
        try:
            src = _open_source(cfg.db_path)
        except sqlite3.Error as e:
            return _fail("backup", f"cannot open {cfg.db_path}: {e}")
        try:
            if args.to is not None:
                final, directory = args.to, None
            else:
                directory = os.path.join(cfg.data_dir, "backups")
                os.makedirs(directory, mode=0o700, exist_ok=True)
                final = os.path.join(directory, _free_name(directory))
            res = _copy(src, final)
        finally:
            src.close()
        if res.startswith("!"):
            return _fail("backup", res[1:])
        if directory is None:
            return _say(out, f"backup: {final} ({res})", 0)
        keep = cfg.backup_keep if args.keep is None else args.keep
        kept, removed = _rotate(directory, keep)
        return _say(out, f"backup: {final} ({res}; {kept} kept, {removed} removed)", 0)
    except (OSError, sqlite3.Error) as e:
        return _fail("backup", e)


def vacuum_cmd(argv: list[str], out: Callable[[str], None]) -> int:
    argparse.ArgumentParser(prog="python -m leasewatch vacuum",
                            description="Rebuild the database file to give free pages back (stop the service first).").parse_args(argv)
    cfg = Config()
    try:
        try:
            conn = _open_source(cfg.db_path)
        except sqlite3.Error as e:
            return _fail("vacuum", f"cannot open {cfg.db_path}: {e}")
        try:
            before = _mb(cfg.db_path)
            conn.execute("VACUUM")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            conn.execute("PRAGMA optimize")
        finally:
            conn.close()
        return _say(out, f"vacuum: {before} -> {_mb(cfg.db_path)}", 0)
    except (OSError, sqlite3.Error) as e:
        return _fail("vacuum", e)
