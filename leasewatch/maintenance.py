"""The `backup`, `vacuum` and `reset-baseline` commands: they open the database file directly (never through Database, so nothing is
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
    # one leading slash only: "file://tmp/x" would read "tmp" as the authority
    path = "/" + os.path.abspath(db_path).lstrip("/")
    conn = sqlite3.connect("file:" + urllib.parse.quote(path) + "?mode=rw", uri=True, isolation_level=None)
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


def _publish(part: str, directory: str) -> str:
    """Give the finished `part` file its backup name in `directory`, never replacing a file another run holds: a hard
    link fails with EEXIST when the name is taken, and the next name is tried. The final name never exists as an
    empty file, so a killed run leaves at most a .part file. Returns the final path."""
    while True:
        final = os.path.join(directory, _free_name(directory))
        try:
            os.link(part, final)
        except FileExistsError:
            continue  # taken between the check and the link: the next name is free
        except OSError:  # the file system has no hard links: rename, after a check (a rare race remains)
            if os.path.lexists(final):
                continue
            os.rename(part, final)
        return final


def _stale_parts(directory: str, now: float | None = None) -> None:
    """Remove .part files a killed run left (older than a day, so a running backup's file stays)."""
    cutoff = (time.time() if now is None else now) - 86400
    for name in os.listdir(directory):
        if name.startswith(".leasewatch-") and name.endswith(".part"):
            path = os.path.join(directory, name)
            try:
                if os.stat(path).st_mtime < cutoff:
                    os.unlink(path)
            except OSError:
                pass


def _rotate(directory: str, keep: int, current: str) -> tuple[int, int]:
    """Delete all but the newest `keep` backups (0 = all are kept); the file `current`, just written, always stays.
    Empty files with a backup name are no backups: they are not counted and not deleted. Returns (kept, removed)."""
    _stale_parts(directory)
    found = []
    for name in os.listdir(directory):
        m = BACKUP_NAME_RE.match(name)
        try:
            if m and os.stat(os.path.join(directory, name)).st_size > 0:
                found.append((m.group(1), int(m.group(2) or 0), name))
        except OSError:
            pass
    found.sort()  # by stamp, then by the -N suffix as a number ("-10" after "-2", "-1" after the plain name)
    others = [f for f in found if f[2] != current]
    room = keep - 1  # the new file takes one of the places
    doomed = [] if not keep else others[:len(others) - room] if len(others) > room else []
    removed = 0
    for _, _, name in doomed:
        try:
            os.unlink(os.path.join(directory, name))
            removed += 1
        except OSError:
            pass
    return len(found) - removed, removed


def _copy(src: sqlite3.Connection, final: str | None, directory: str | None = None) -> tuple[str, str]:
    """Write a consistent copy to `final`, or to a free backup name in `directory` if `final` is None. Returns
    (path, size text), or ("", "!" plus the failure text)."""
    if final is None:
        assert directory is not None
        part = os.path.join(directory, f".leasewatch-{_stamp()}.{os.getpid()}.{os.urandom(4).hex()}.part")
    else:
        directory, name = os.path.split(final)
        part = os.path.join(directory, f".{name}.{os.getpid()}.part")
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
            return "", f"!integrity check: {res[0] if res else 'no result'}"
        fd = os.open(part, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        if final is None:
            final = _publish(part, directory)
            try:
                os.unlink(part)  # gone already after the rename fallback
            except OSError:
                pass
        else:
            os.replace(part, final)
        done = True
        _fsync_dir(directory)
        return final, _mb(final)
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
    raw_keep = os.environ.get("BACKUP_KEEP", "").strip()
    if args.keep is None and raw_keep:
        try:
            ok = 0 <= int(raw_keep) <= 1000
        except ValueError:
            ok = False
        if not ok:
            sys.stderr.write("backup: BACKUP_KEEP must be 0-1000\n")
            return 2
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
                directory = None
                final, res = _copy(src, args.to)
            else:
                directory = os.path.join(cfg.data_dir, "backups")
                os.makedirs(directory, mode=0o700, exist_ok=True)
                final, res = _copy(src, None, directory)
        finally:
            src.close()
        if res.startswith("!"):
            return _fail("backup", res[1:])
        if directory is None:
            return _say(out, f"backup: {final} ({res})", 0)
        keep = cfg.backup_keep if args.keep is None else args.keep
        kept, removed = _rotate(directory, keep, os.path.basename(final))
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
            # after an unclean stop the data sits in the -wal file; the checkpoint below moves it into the main file
            before_bytes = os.path.getsize(cfg.db_path)
            try:
                before_bytes += os.path.getsize(cfg.db_path + "-wal")
            except OSError:
                pass
            before = f"{before_bytes / 1e6:.1f} MB"
            conn.execute("VACUUM")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            conn.execute("PRAGMA optimize")
        finally:
            conn.close()
        return _say(out, f"vacuum: {before} -> {_mb(cfg.db_path)}", 0)
    except (OSError, sqlite3.Error) as e:
        return _fail("vacuum", e)


def reset_baseline_cmd(argv: list[str], out: Callable[[str], None]) -> int:
    ap = argparse.ArgumentParser(prog="python -m leasewatch reset-baseline",
                                 description="Mark every listed device as baseline (already present: it never merges and "
                                             "never mails) without deleting the database. No events are written.")
    ap.add_argument("--yes", action="store_true", help="confirm (required when stdin is not a terminal)")
    ap.add_argument("--clear-acks", action="store_true", help="also set every targeted device to not acknowledged")
    ap.add_argument("--include-archived", action="store_true", help="also mark archived devices (default: untouched)")
    args = ap.parse_args(argv)
    interactive = sys.stdin is not None and sys.stdin.isatty()
    if not args.yes and not interactive:
        sys.stderr.write("reset-baseline: add --yes to confirm\n")
        return 2
    cfg = Config()
    where = "" if args.include_archived else " WHERE archived_ts IS NULL"
    try:
        try:
            conn = _open_source(cfg.db_path)
        except sqlite3.Error as e:
            return _fail("reset-baseline", f"cannot open {cfg.db_path}: {e}")
        try:
            total = conn.execute("SELECT count(*) FROM devices" + where).fetchone()[0]
            if not args.yes:
                sys.stderr.write(f"Mark {total} devices as baseline? [y/N] ")
                sys.stderr.flush()
                if sys.stdin.readline().strip().lower() not in ("y", "yes"):
                    sys.stderr.write("reset-baseline: cancelled\n")
                    return 1
            conn.execute("BEGIN IMMEDIATE")  # the count and the update see the same rows
            try:
                total = conn.execute("SELECT count(*) FROM devices" + where).fetchone()[0]
                new = conn.execute("SELECT count(*) FROM devices WHERE baseline=0"
                                   + (" AND archived_ts IS NULL" if not args.include_archived else "")).fetchone()[0]
                sets = "baseline=1, mail_queued=NULL" + (", acked=0, acked_at=NULL" if args.clear_acks else "")
                conn.execute("UPDATE devices SET " + sets + where)
                conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('baseline_ts', ?)", (str(int(time.time())),))
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()
        line = f"reset-baseline: {total} devices marked as baseline ({new} were new)"
        return _say(out, line + (", acks cleared" if args.clear_acks else ""), 0)
    except (OSError, sqlite3.Error) as e:
        return _fail("reset-baseline", e)
