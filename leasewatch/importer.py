"""The `import-csv` command: restore name, note, acked, archived and watch from the device CSV export
(GET /api/devices.csv), also after a round trip through a spreadsheet. parse_csv is pure; the writing and its policy
(fill-empty or overwrite, events) are Database.import_user_fields."""
from __future__ import annotations

import argparse
import csv
import io
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from .config import Config
from .db import Database
from .fw1 import MAC_RE, norm_mac
from .maintenance import _fail, _say

FIELDS = ("name", "note", "acked", "archived", "watch")
MAX_BYTES = 1024 * 1024  # the export of a large home network is well below this
MAX_ROWS = 20_000
MAX_LISTED = 20  # unknown MACs and skipped lines printed after the summary
_TRUE = ("1", "true", "yes")
_FALSE = ("0", "false", "no")
_SEPARATORS = ";\r\n"  # the places _csv_cell in web.py guards besides the cell start
_FORMULA = "=+-@\t\r"
_BLANK = re.compile(r'[\s"]')  # what the export's lookahead skips before a formula character


@dataclass
class ParsePlan:
    """What parse_csv read: rows for Database.import_user_fields, (line number, reason) of each skipped row, the
    header columns that are not imported and the number of data rows read (rows plus skipped)."""
    rows: list[dict] = field(default_factory=list)
    bad: list[tuple[int, str]] = field(default_factory=list)
    ignored_columns: list[str] = field(default_factory=list)
    total: int = 0


def uncell(s: str) -> str:
    """Undo web._csv_cell: drop each apostrophe the export put in, at the cell start and after ';', CR or LF, where
    the text after it (as exported) starts with a formula character, optionally behind blanks and quotes. Read from
    the right, so the text after an apostrophe is already restored when it is judged. A typed apostrophe in the same
    place (a note that starts with "'-") cannot be told apart from the export's and is dropped too."""
    out: list[str] = []  # the restored text, reversed
    formula_next = False  # the restored text after the current position matches [\s"]*[=+\-@\t\r]
    for i in range(len(s) - 1, -1, -1):
        ch = s[i]
        if ch == "'" and out:
            if i == 0:
                drop = out[-1] in _FORMULA
            else:
                # the export never puts an apostrophe between the CR and the LF of one line break
                drop = s[i - 1] in _SEPARATORS and formula_next and not (s[i - 1] == "\r" and out[-1] == "\n")
            if drop:
                continue
        out.append(ch)
        if ch in _FORMULA:
            formula_next = True
        elif not _BLANK.match(ch):
            formula_next = False
    return "".join(reversed(out))


def _flag(value: str) -> bool:
    v = value.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise ValueError


def _check_fields(fields: Iterable[str]) -> tuple[str, ...]:
    out = []
    for f in fields:
        f = f.strip().lower()
        if not f:
            continue
        if f not in FIELDS:
            raise ValueError(f"unknown field {f!r} (choose from {','.join(FIELDS)})")
        if f not in out:
            out.append(f)
    if not out:
        raise ValueError("no field to import")
    return tuple(out)


def _header(line: str) -> tuple[str, list[str]]:
    """The delimiter (',' or ';', the one that yields a mac column; ',' when both do) and the header cells."""
    for delim in (",", ";"):
        cells = [c.strip().lower() for c in next(csv.reader([line], delimiter=delim), [])]
        if "mac" in cells:
            return delim, cells
    raise ValueError("no mac column in the header")


def parse_csv(data: str | bytes, fields: Iterable[str] = FIELDS) -> ParsePlan:
    """Read the device CSV (bytes as UTF-8 with or without BOM, or str). ValueError: too large, not UTF-8, no mac
    column, too many rows or an unknown field. A row with a bad MAC or a bad 0/1 value is skipped and listed;
    columns other than mac and the chosen fields are ignored. An empty acked or watch cell leaves the field as it is."""
    want = _check_fields(fields)
    if len(data) > MAX_BYTES:
        raise ValueError("file larger than 1 MiB")
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ValueError("not UTF-8 (save the file as CSV UTF-8)") from None
    else:
        text = data[1:] if data.startswith("﻿") else data
    first = text.split("\n", 1)[0].rstrip("\r")
    delim, header = _header(first)
    col: dict[str, int] = {}
    for i, name in enumerate(header):
        col.setdefault(name, i)  # a repeated column: the first one counts
    plan = ParsePlan(ignored_columns=[h for h in dict.fromkeys(header) if h != "mac" and h not in want])
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delim)
    line = 1

    def records() -> Iterator[list[str]]:
        # csv.Error (a cell over the csv field size limit, an unterminated quote with strict quoting) is a bad file
        try:
            yield from reader
        except csv.Error as e:
            raise ValueError(f"line {line}: {e}") from None

    rows = records()
    next(rows, None)
    line = reader.line_num + 1  # the first physical line of the next record
    for cells in rows:
        start, line = line, reader.line_num + 1
        if not any(c.strip() for c in cells):
            continue  # a blank line, or a spreadsheet's row of empty cells
        plan.total += 1
        if plan.total > MAX_ROWS:
            raise ValueError(f"more than {MAX_ROWS} rows")
        # a short row: its missing cells are not given
        got = {name: cells[i] for name, i in col.items() if i < len(cells)}
        raw_mac = got.get("mac") or ""
        mac = norm_mac(raw_mac)
        if not mac or not MAC_RE.fullmatch(mac):  # fullmatch: "$" lets a trailing "\n" through
            plan.bad.append((start, f"bad MAC {raw_mac[:40]!r}"))
            continue
        row: dict = {"mac": mac}
        try:
            for f in want:
                v = got.get(f)
                if v is None:
                    continue
                if f in ("name", "note"):
                    row[f] = uncell(v)
                elif f == "archived":
                    row[f] = bool(v.strip())
                elif v.strip():
                    try:
                        row[f] = _flag(v)
                    except ValueError:
                        raise ValueError(f"{f} is {v[:20]!r}, not 0 or 1") from None
        except ValueError as e:
            plan.bad.append((start, str(e)))
            continue
        plan.rows.append(row)
    return plan


def _usage(text: str) -> int:
    sys.stderr.write(f"import-csv: {text}\n")
    return 2


def import_csv_cmd(argv: list[str], out: Callable[[str], None]) -> int:
    ap = argparse.ArgumentParser(prog="python -m leasewatch import-csv",
                                 description="Restore name, note, acked, archived and watch from the device CSV export "
                                             "(also after a spreadsheet saved it with ';'). Unknown MACs are listed, "
                                             "never added.")
    ap.add_argument("file", metavar="FILE", help="the CSV file (UTF-8)")
    ap.add_argument("--dry-run", action="store_true", help="count what would change, write nothing")
    ap.add_argument("--fields", default=",".join(FIELDS), metavar="LIST",
                    help=f"comma-separated fields to import (default {','.join(FIELDS)})")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--fill-empty", action="store_true",
                      help="only fill an empty name or note and only set acked, archived or watch (default)")
    mode.add_argument("--overwrite", action="store_true", help="apply every imported value as it is in the file")
    args = ap.parse_args(argv)
    try:
        fields = _check_fields(args.fields.split(","))
    except ValueError as e:
        return _usage(str(e))
    try:
        with open(args.file, "rb") as f:
            data = f.read(MAX_BYTES + 1)  # one byte more tells a file over the cap without reading it all
    except OSError as e:
        return _usage(f"cannot read {args.file}: {e.strerror or e}")
    try:
        plan = parse_csv(data, fields)
    except ValueError as e:
        return _usage(str(e))
    cfg = Config()
    if not os.path.exists(cfg.db_path):  # Database() would create an empty file
        return _fail("import-csv", f"no database at {cfg.db_path}")
    try:
        db = Database(cfg.db_path)
        try:
            target = db
            if args.dry_run:
                # import_user_fields commits its own transaction: a dry run imports into an in-memory copy
                target = Database(":memory:")
                with db._lock:
                    db._c().backup(target._c())
            try:
                res = target.import_user_fields(plan.rows, overwrite=args.overwrite, actor="import-csv")
            finally:
                if target is not db:
                    target.close()
        finally:
            db.close()
    except (OSError, sqlite3.Error) as e:
        return _fail("import-csv", e)
    parts = [f"{plan.total} rows", f"{res.updated} updated", f"{res.unchanged} unchanged"]
    if res.unknown:
        parts.append(f"{len(res.unknown)} unknown MAC")
    if res.duplicates:
        parts.append(f"{len(res.duplicates)} duplicates")
    if plan.bad:
        parts.append(f"{len(plan.bad)} skipped (bad row)")
    lines = [("import-csv (dry run): " if args.dry_run else "import-csv: ") + ", ".join(parts)]
    details = [f"  unknown: {m}" for m in res.unknown] + [f"  skipped line {n}: {r}" for n, r in plan.bad]
    lines += details[:MAX_LISTED]
    rc = 0
    for line in lines:
        rc = _say(out, line, 0)
    return rc
