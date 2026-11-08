"""SQLite storage: devices (one row per MAC), change history, events, meta."""
from __future__ import annotations

import logging
import re
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

log = logging.getLogger("leasewatch.db")

_DB_ERROR_TEXT = {
    13: "database full (disk or size limit)",
    5: "database locked by another process",
    6: "database locked by another process",
    10: "database I/O error",
    8: "database is read-only (check DATA_DIR permissions)",
    11: "database file is damaged (restore a backup)",
    26: "database file is damaged (restore a backup)",
}


def db_error_text(e: sqlite3.Error) -> str:
    """The text for last_error, by the primary SQLite result code (not the message, which may change)."""
    code = getattr(e, "sqlite_errorcode", None)
    if code is not None and (code & 0xFF) in _DB_ERROR_TEXT:
        return _DB_ERROR_TEXT[code & 0xFF]
    return f"database error ({getattr(e, 'sqlite_errorname', None) or type(e).__name__})"

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    last_online INTEGER,
    ip          TEXT NOT NULL DEFAULT '',
    hostname    TEXT NOT NULL DEFAULT '',
    vendor      TEXT NOT NULL DEFAULT '',
    vlan        TEXT NOT NULL DEFAULT '',
    iface       TEXT NOT NULL DEFAULT '',
    lease_type  TEXT NOT NULL DEFAULT '',
    sources     TEXT NOT NULL DEFAULT '',
    online      INTEGER NOT NULL DEFAULT 0,
    baseline    INTEGER NOT NULL DEFAULT 0,
    acked       INTEGER NOT NULL DEFAULT 0,
    acked_at    INTEGER,
    name        TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL, ts INTEGER NOT NULL,
    ip TEXT NOT NULL, hostname TEXT NOT NULL, vlan TEXT NOT NULL, lease_type TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS history_mac ON history(mac, ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL, mac TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_mac ON events(mac, ts);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
# columns added after 1.0.0 (ALTER TABLE ... ADD COLUMN is applied when missing)
MIGRATIONS = [
    ("devices", "sw_port", "TEXT NOT NULL DEFAULT ''"), ("devices", "sw_via", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "wifi_ssid", "TEXT NOT NULL DEFAULT ''"), ("devices", "wifi_ap", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "wifi_signal", "INTEGER"), ("devices", "wifi_radio", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "wifi_alias", "TEXT NOT NULL DEFAULT ''"), ("devices", "link", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "loc_source", "TEXT NOT NULL DEFAULT ''"),
    # schema v3: the normalised DHCP client-id ('' when none), when the device was archived and when its new-device
    # mail was queued (NULL = in the list / nothing to mail), so an archive and a pending mail survive a restart
    ("devices", "client_id", "TEXT NOT NULL DEFAULT ''"), ("devices", "archived_ts", "INTEGER"),
    ("devices", "mail_queued", "INTEGER"),
    # the device key this MAC was split from (NULL = never split); a later merge pass reads it to not fold the MAC back
    ("devices", "split_from", "TEXT"),
    # operator-written text from the DHCP source (a reservation's description); a display fallback, never an identity
    ("devices", "label", "TEXT NOT NULL DEFAULT ''"),
]
# meta.schema_version: the steps below run in order on open for every version below SCHEMA_VERSION. A DB without the
# key predates the versioning and is version 1 (the 1.0 tables plus the columns above)
SCHEMA_VERSION = 4
VERSION_STEPS = {
    # per-source freshness: when each connector instance last listed a MAC and last saw it on the wire
    2: "CREATE TABLE IF NOT EXISTS seen (mac TEXT, source TEXT, last_seen INTEGER NOT NULL, last_present INTEGER, PRIMARY KEY(mac, source))",
    # merged private MACs: each alias MAC points to the device key (devices.mac, the first MAC seen) it was merged
    # into, so the key and every row keyed by it stay valid; one statement, as the loop and the table regex expect
    3: "CREATE TABLE IF NOT EXISTS aliases (mac TEXT PRIMARY KEY, device TEXT NOT NULL, reason TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', merged_ts INTEGER NOT NULL, last_seen INTEGER NOT NULL)",
    # which SSIDs each device was ever seen on: one row per device key and SSID (as the controller sends it);
    # no ssid index, the per-SSID read scans a table of a few hundred rows
    4: "CREATE TABLE IF NOT EXISTS wifi_presence (mac TEXT NOT NULL, ssid TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, seconds_seen INTEGER NOT NULL, polls_seen INTEGER NOT NULL, last_ap TEXT NOT NULL DEFAULT '', PRIMARY KEY (mac, ssid))",
}
# run on every open (after the version steps, also for a newer schema); CREATE INDEX IF NOT EXISTS is cheap when present
INDEXES = (
    "CREATE INDEX IF NOT EXISTS aliases_device ON aliases(device)",
    # the events view filtered by kind (and a date range): kind first, then the time order of the page
    "CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts)",  # the events filter by kind, and the per-poll 'restored' lookup
)

# strip NUL/C0/C1 control, invisible and bidi-override characters from user text (keeps tab/newline for notes).
# U+200C/U+200D (ZWNJ/ZWJ) stay: emoji sequences and several scripts need them.
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b\u200e\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\u061c\ufeff]")


class AlreadyADevice(Exception):
    """split_alias found a devices row with the alias MAC; nothing was written."""


class UnknownDevices(LookupError):
    """A bulk update named MACs that are neither a device nor an alias; nothing was written."""

    def __init__(self, macs: list[str]):
        super().__init__(f"{len(macs)} unknown device(s)")
        self.macs = macs


class Database:
    history_cap = 200  # rows history() returns by default (the drawer); the web handler sets HISTORY_PER_DEVICE

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(SCHEMA)  # executescript commits by itself; keep it outside tx()
        have = {(t, r[1]) for t in ("devices",) for r in self._conn.execute(f"PRAGMA table_info({t})")}
        for table, col, decl in MIGRATIONS:
            if (table, col) not in have:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        if not self.get_meta("schema_version"):
            self.set_meta("schema_version", "1")
        raw = self.get_meta("schema_version")
        if isinstance(raw, bytes):  # a value stored by hand as a BLOB (X'32'); the str regex below would raise on it
            raw = raw.decode("utf-8", "replace")
        # only the plain ASCII form this code writes: int() also takes "1_0" (10), " 2 " and non-ASCII digits, and
        # a damaged "1_0" read as 10 would block every later step for good. The digit cap keeps int() below its
        # 4300-digit limit, where it would raise instead of parsing; no real version comes near 18 digits
        if re.fullmatch(r"-?[0-9]{1,18}", raw):
            version = int(raw)
        else:  # a hand-edited or damaged value: the steps are idempotent, so re-running them is safe
            log.warning("database schema_version %r is not a number; treated as 1", raw[:40])
            version = 1
        if version < 1:  # "0" or "-1" would ask for a step 1 that does not exist; same damage as a non-number
            log.warning("database schema_version %r is below 1; treated as 1", raw[:40])
            version = 1
        if version > SCHEMA_VERSION:  # written by a newer leasewatch: never step it down or touch its tables
            log.warning("database schema %d is newer than this version (%d); no migration", version, SCHEMA_VERSION)
            # a hand-edited version can skip a step whose table this code needs: create only what is missing
            # (IF NOT EXISTS leaves a newer leasewatch's tables alone) and keep the version as it is
            have_tables = {r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for step in range(2, SCHEMA_VERSION + 1):
                table = re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", VERSION_STEPS[step]).group(1)
                if table not in have_tables:
                    log.warning("database schema %d lacks table %s; creating it", version, table)
                    with self.tx() as c:
                        c.execute(VERSION_STEPS[step])
        for step in range(version + 1, SCHEMA_VERSION + 1):
            with self.tx() as c:  # the step and its version number together, so a crash in between re-runs the step
                c.execute(VERSION_STEPS[step])
                self.set_meta("schema_version", str(step), c)
        for stmt in INDEXES:
            with self.tx() as c:
                c.execute(stmt)
        if sqlite3.sqlite_version_info >= (3, 46, 0):  # a bounded ANALYZE of what the schema has not seen yet
            try:
                self._conn.execute("PRAGMA analysis_limit=400")
                self._conn.execute("PRAGMA optimize=0x10002")
            except sqlite3.Error as e:
                log.debug("startup optimize skipped: %s", e)

    def _c(self) -> sqlite3.Connection:
        conn = self._conn
        if conn is None:
            raise sqlite3.ProgrammingError("database is closed")
        return conn

    def close(self, timeout: float = 5.0) -> bool:
        """Merge the WAL into the main file and close the connection. False: a query held the lock, nothing done."""
        if not self._lock.acquire(timeout=timeout):
            log.warning("database busy at shutdown; the WAL is not merged")
            return False
        try:
            conn = self._conn
            if conn is None:
                return True
            if conn.in_transaction:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error as e:
                    log.warning("rollback at shutdown failed: %s", e)
            try:
                conn.execute("PRAGMA optimize")
            except sqlite3.Error as e:
                log.warning("PRAGMA optimize at shutdown failed: %s", e)
            try:
                row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if row is not None and row[0] == 1:
                    log.warning("WAL checkpoint incomplete at shutdown (another process reads the database)")
            except sqlite3.Error as e:
                log.warning("WAL checkpoint at shutdown failed: %s", e)
            try:
                conn.close()
            except sqlite3.Error as e:
                log.warning("closing the database failed: %s", e)
            self._conn = None
        finally:
            self._lock.release()
        log.info("database closed")
        return True

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._c().in_transaction:  # a failed COMMIT+ROLLBACK must not wedge every later transaction
                self._c().execute("ROLLBACK")
            self._c().execute("BEGIN")
            try:
                yield self._c()
                self._c().execute("COMMIT")
            except BaseException:  # also KeyboardInterrupt/GeneratorExit: never leave the transaction open
                try:
                    self._c().execute("ROLLBACK")
                except Exception:  # e.g. already rolled back; the original exception is the one that matters
                    pass
                raise

    def q(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._c().execute(sql, params).fetchall()

    def version(self) -> int:
        """A number that moves with every row change made through this connection (every writer uses it): the
        API's ETag. It starts again at 0 with a new connection, so the ETag adds a per-start id."""
        with self._lock:
            return self._c().total_changes

    # --- meta ---------------------------------------------------------------
    def get_meta(self, key: str, default: str = "") -> str:
        r = self.q("SELECT value FROM meta WHERE key=?", (key,))
        return r[0]["value"] if r else default

    def set_meta(self, key: str, value: str, conn: sqlite3.Connection | None = None) -> None:
        # a lone surrogate (e.g. from a JSON-escaped controller error text) would raise UnicodeEncodeError here and
        # roll back the whole poll transaction around it, so it is stored as "?"
        value = str(value).encode("utf-8", "replace").decode("utf-8")
        with self._lock:  # RLock: harmless inside tx(), required outside it
            (conn or self._c()).execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def all_meta(self) -> dict:
        return {r["key"]: r["value"] for r in self.q("SELECT key, value FROM meta")}

    # --- devices ------------------------------------------------------------
    def devices(self) -> list[dict]:
        """Every device row, each with `aliases`: the merged MACs, newest merge first, [] without any."""
        with self._lock:  # one hold: the two reads must not straddle a collector write
            c = self._c()
            rows = [dict(r) for r in c.execute("SELECT * FROM devices ORDER BY first_seen DESC, mac")]
            by_dev: dict[str, list[str]] = {}
            for r in c.execute("SELECT device, mac FROM aliases ORDER BY merged_ts DESC, mac"):  # one query, not one per device
                by_dev.setdefault(r["device"], []).append(r["mac"])
        for d in rows:
            d["aliases"] = by_dev.get(d["mac"], [])
        return rows

    def devices_with_presence(self) -> list[dict]:
        """devices(), each also with `wifi_presence` (as wifi_presence(), [] without any), all read in one lock hold."""
        with self._lock:  # re-entrant: devices() and the presence read share this hold
            rows = self.devices()
            wifi = self._wifi_presence_all(self._c())
        for d in rows:
            d["wifi_presence"] = wifi.get(d["mac"], [])
        return rows

    def device(self, mac: str) -> dict | None:
        r = self.q("SELECT * FROM devices WHERE mac=?", (mac,))
        return dict(r[0]) if r else None

    def device_detail(self, mac: str) -> dict | None:
        """The drawer's device, history, events, seen rows and merged MACs, or None for an unknown MAC."""
        with self._lock:  # one hold, as stats(): the five reads must not straddle a collector write
            d = self.device(mac) or self.device(self._alias_owner(self._c(), mac))  # design-s4 §1: an alias MAC opens its device
            return {"device": d, "history": self.history(d["mac"]), "events": self.events(d["mac"]),
                    "seen": self.seen(d["mac"]), "aliases": self.aliases(d["mac"]),
                    "wifi_presence": self.wifi_presence(d["mac"])} if d else None

    @staticmethod
    def _alias_owner(c: sqlite3.Connection, mac: str) -> str:
        """The device key a merged private MAC points to, or "" if mac is no alias."""
        r = c.execute("SELECT device FROM aliases WHERE mac=?", (mac,)).fetchone()
        return r["device"] if r else ""

    def aliases(self, mac: str) -> list[dict]:
        """The private MACs merged into the device mac, newest merge first."""
        return [dict(r) for r in self.q("SELECT mac, reason, detail, merged_ts, last_seen FROM aliases WHERE device=? ORDER BY merged_ts DESC, mac", (mac,))]

    _WIFI_COLS = "mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap"

    def wifi_presence(self, mac: str) -> list[dict]:
        """The SSIDs the device key mac was seen on, most recently seen first."""
        return [{k: r[k] for k in r.keys() if k != "mac"} for r in self.q(
            f"SELECT {self._WIFI_COLS} FROM wifi_presence WHERE mac=? ORDER BY last_seen DESC, ssid", (mac,))]

    def wifi_presence_all(self) -> dict[str, list[dict]]:
        """wifi_presence of every device that has rows, by device key, in one query."""
        with self._lock:
            return self._wifi_presence_all(self._c())

    def _wifi_presence_all(self, c: sqlite3.Connection) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for r in c.execute(f"SELECT {self._WIFI_COLS} FROM wifi_presence ORDER BY last_seen DESC, ssid"):
            out.setdefault(r["mac"], []).append({k: r[k] for k in r.keys() if k != "mac"})
        return out

    @staticmethod
    def _wifi_ssid_counts(c: sqlite3.Connection) -> tuple[list, dict]:
        """Per SSID: rows (ssid, n, last_seen) with n = devices not archived seen on it, and {ssid: devices not archived
        online on it now}. The caller holds the lock."""
        ever = c.execute(
            "SELECT p.ssid, SUM(d.mac IS NOT NULL AND d.archived_ts IS NULL) n, MAX(p.last_seen) last_seen "
            "FROM wifi_presence p LEFT JOIN devices d ON d.mac = p.mac GROUP BY p.ssid").fetchall()
        now_on = c.execute("SELECT wifi_ssid, COUNT(*) n FROM devices WHERE online=1 AND archived_ts IS NULL AND wifi_ssid != '' "
                           "GROUP BY wifi_ssid").fetchall()
        return ever, {r["wifi_ssid"]: r["n"] for r in now_on}

    def wifi_ssids(self) -> dict:
        """Per SSID ever seen: devices not archived that were seen on it, those online now with it as wifi_ssid, and
        the latest sighting of any device; most devices first. `since` is when the presence table started filling."""
        with self._lock:  # one hold: the two counts and `since` must not straddle a collector write
            ever, now_by = self._wifi_ssid_counts(self._c())
            since = self.get_meta("wifi_presence_since", "")
        rows = [{"ssid": r["ssid"], "devices": r["n"] or 0, "devices_now": now_by.get(r["ssid"], 0), "last_seen": r["last_seen"]} for r in ever]
        rows.sort(key=lambda x: (-x["devices"], x["ssid"]))
        return {"since": int(since) if since.isdigit() else None, "ssids": rows}

    def wifi_devices(self, ssid: str) -> dict:
        """Every device (archived included) seen on exactly this SSID, by first sighting there, with its presence row."""
        with self._lock:
            rows = self._c().execute(
                "SELECT d.mac, d.name, d.wifi_alias, d.hostname, d.label, d.vendor, d.ip, d.archived_ts, d.online, d.wifi_ssid, "
                "p.first_seen, p.last_seen, p.seconds_seen, p.polls_seen, p.last_ap "
                "FROM wifi_presence p JOIN devices d ON d.mac = p.mac WHERE p.ssid = ? "
                "ORDER BY p.first_seen, d.mac", (ssid,)).fetchall()
            since = self.get_meta("wifi_presence_since", "")
        return {"since": int(since) if since.isdigit() else None, "devices": [dict(r) for r in rows]}

    def seen(self, mac: str) -> list[dict]:
        return [dict(r) for r in self.q("SELECT source, last_seen, last_present FROM seen WHERE mac=? ORDER BY last_seen DESC, source", (mac,))]

    def history(self, mac: str, limit: int | None = None) -> list[dict]:
        limit = self.history_cap if limit is None else limit
        return [dict(r) for r in self.q("SELECT ts, ip, hostname, vlan, lease_type FROM history WHERE mac=? ORDER BY ts DESC, id DESC LIMIT ?", (mac, limit))]

    def events(self, mac: str | None = None, limit: int = 200, kinds: list[str] | None = None, since: int | None = None,
               until: int | None = None, before: int | None = None) -> list[dict]:
        """One device's events (`mac`), or else all of them with the filters. Newest first (ts DESC, id DESC).
        since is inclusive, until exclusive. `before` is an event id: only rows older than it in that order; an id
        that no longer exists gives no rows."""
        if mac:
            rows = self.q("SELECT e.ts, e.mac, e.kind, e.detail FROM events e WHERE mac=? ORDER BY e.ts DESC, e.id DESC LIMIT ?", (mac, limit))
            return [dict(r) for r in rows]
        kinds = list(dict.fromkeys(kinds)) if kinds else None
        where: list[str] = []
        params: list = []
        if kinds and len(kinds) == 1:
            where.append("e.kind = ?"); params.append(kinds[0])
        if since is not None:
            where.append("e.ts >= ?"); params.append(since)
        if until is not None:
            where.append("e.ts < ?"); params.append(until)
        if before is not None:
            row = self.q("SELECT ts FROM events WHERE id=?", (before,))
            if not row:
                return []
            where.append("(e.ts, e.id) < (?, ?)"); params += [row[0]["ts"], before]
        order = " ORDER BY e.ts DESC, e.id DESC LIMIT ?"
        cols = "e.id, e.ts, e.mac, e.kind, e.detail, d.name, d.hostname, d.vlan"
        if kinds and len(kinds) > 1:
            # one index range per kind with its own LIMIT, so the final sort sees at most len(kinds) * limit rows
            # instead of every matching row in a temp B-tree
            branch_where = " WHERE " + " AND ".join(["e.kind = ?", *where])
            branch = ("SELECT * FROM (SELECT e.id, e.ts, e.mac, e.kind, e.detail FROM events e" + branch_where + order + ")")
            top = "SELECT * FROM (" + " UNION ALL ".join([branch] * len(kinds)) + ") e" + order
            sql = f"SELECT {cols} FROM ({top}) e LEFT JOIN devices d USING(mac)" + order
            args: list = []
            for k in kinds:
                args += [k, *params, limit]
            return [dict(r) for r in self.q(sql, (*args, limit, limit))]
        sql = (f"SELECT {cols} FROM events e LEFT JOIN devices d USING(mac)"
               + (" WHERE " + " AND ".join(where) if where else "") + order)
        return [dict(r) for r in self.q(sql, (*params, limit))]

    def update_user_fields(self, mac: str, acked: bool | None, name: str | None, note: str | None,
                           archived: bool | None = None) -> dict | None:
        with self.tx() as c:
            key = self._resolve(c, mac)
            if not key:
                return None
            return self._apply_user_fields(c, key, int(time.time()), acked, name, note, archived)[0]

    def split_alias(self, device_mac: str, alias: str) -> tuple[dict, dict] | None:
        """Turn the alias MAC of a device back into a device of its own: (the device, the new row), or None when
        alias is no alias of that device. The device keeps its history, events and seen rows, because they cannot be
        told apart by MAC. Raises AlreadyADevice (nothing written) when alias already has a devices row."""
        with self.tx() as c:
            key = self._resolve(c, device_mac)
            if not key:
                return None
            a = c.execute("SELECT * FROM aliases WHERE mac=?", (alias,)).fetchone()
            if a is None or a["device"] != key:
                return None
            if c.execute("SELECT 1 FROM devices WHERE mac=?", (alias,)).fetchone():
                raise AlreadyADevice(alias)
            now = int(time.time())
            day = time.strftime("%Y-%m-%d", time.localtime(a["merged_ts"]))
            # both rows keep the client-id after a client-id merge; a hostname merge says nothing about it
            cid = c.execute("SELECT client_id FROM devices WHERE mac=?", (key,)).fetchone()["client_id"] if a["reason"] == "client-id" else ""
            c.execute("DELETE FROM aliases WHERE mac=?", (alias,))
            c.execute("INSERT INTO devices (mac, first_seen, last_seen, last_online, online, client_id, baseline, acked, split_from) "
                      "VALUES (?, ?, ?, NULL, 0, ?, 0, 0, ?)", (alias, now, a["last_seen"], cid, key))
            c.execute("INSERT INTO events (ts, mac, kind, detail) VALUES (?, ?, 'split', ?)",
                      (now, key, f"{alias} split off (merged by {a['reason']} {a['detail']} on {day})"))
            c.execute("INSERT INTO events (ts, mac, kind, detail) VALUES (?, ?, 'split', ?)", (now, alias, f"split from {key}"))
            out = []
            for m in (key, alias):
                d = dict(c.execute("SELECT * FROM devices WHERE mac=?", (m,)).fetchone())
                d["aliases"] = [r["mac"] for r in c.execute("SELECT mac FROM aliases WHERE device=? ORDER BY merged_ts DESC, mac", (m,))]
                out.append(d)
            return out[0], out[1]

    def update_many(self, macs: list[str], acked: bool | None = None,
                    archived: bool | None = None) -> tuple[list[str], list[str]]:
        """Set acked or archived on several devices in one transaction: (changed keys, unchanged keys). An alias MAC
        counts as its device, and a device named twice counts once. Raises UnknownDevices (nothing written) when any
        MAC is neither a device nor an alias."""
        with self.tx() as c:
            keys: list[str] = []
            unknown: list[str] = []
            for mac in macs:
                key = self._resolve(c, mac)
                if not key:
                    if mac not in unknown:
                        unknown.append(mac)
                elif key not in keys:
                    keys.append(key)
            if unknown:  # before any write, so the rollback has nothing to undo
                raise UnknownDevices(unknown)
            now = int(time.time())  # one time for the whole batch
            changed: list[str] = []
            unchanged: list[str] = []
            for key in keys:
                (changed if self._apply_user_fields(c, key, now, acked, None, None, archived)[1] else unchanged).append(key)
            return changed, unchanged

    def _resolve(self, c: sqlite3.Connection, mac: str) -> str:
        """The device key for mac: itself when it is a device, the owner when it is an alias (an alias MAC copied
        from the drawer updates the device it was merged into), else ""."""
        if c.execute("SELECT 1 FROM devices WHERE mac=?", (mac,)).fetchone():
            return mac
        owner = self._alias_owner(c, mac)
        return owner if owner and c.execute("SELECT 1 FROM devices WHERE mac=?", (owner,)).fetchone() else ""

    @staticmethod
    def _apply_user_fields(c: sqlite3.Connection, mac: str, now: int, acked: bool | None, name: str | None,
                           note: str | None, archived: bool | None) -> tuple[dict, bool]:
        """Write the user fields of the existing device mac inside the caller's transaction: (the row, whether an
        acked/unacked or archived/restored event was written)."""
        cur = c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
        sets, params = [], []
        if acked is not None:
            sets.append("acked=?"); params.append(1 if acked else 0)
            if not acked or not cur["acked"]:  # a re-ack keeps the time of the first ack
                sets.append("acked_at=?"); params.append(now if acked else None)
        if name is not None:
            sets.append("name=?"); params.append(_CTRL.sub("", name).replace("\n", " ").replace("\t", " ").strip()[:80].strip())  # strip first too: leading blanks must not use up the limit
        if note is not None:
            sets.append("note=?"); params.append(_CTRL.sub("", note).strip()[:1000].rstrip())  # the cut can end on a blank
        # archive: the device leaves the list and the mail queue; the same state again changes nothing
        arch_change = archived is not None and (cur["archived_ts"] is not None) != archived
        if arch_change:
            sets.append("archived_ts=?"); params.append(now if archived else None)
            if archived:
                sets.append("mail_queued=NULL")
        ack_change = acked is not None and bool(cur["acked"]) != bool(acked)
        if sets:
            params.append(mac)
            c.execute(f"UPDATE devices SET {', '.join(sets)} WHERE mac=?", tuple(params))
            if ack_change:
                c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now, mac, "acked" if acked else "unacked", ""))
            if arch_change:
                c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (now, mac, "archived" if archived else "restored", ""))
        return dict(c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()), ack_change or arch_change

    def stats(self, new_days: int) -> dict:
        now = int(time.time())
        with self._lock:  # one lock hold: the three counts must not straddle a collector write
            # archived devices are not in the list, so not in its counts; the arrivals chart below keeps them
            rows = self._c().execute("SELECT vlan, COUNT(*) n, SUM(online) online FROM devices WHERE archived_ts IS NULL GROUP BY vlan ORDER BY n DESC").fetchall()
            # every network any device row carries, archived included: the browser indexes its colours by this list, so
            # archiving a network's last device must not shift the colours of the networks after it
            allv = self._c().execute("SELECT DISTINCT vlan FROM devices WHERE vlan != '' ORDER BY vlan").fetchall()
            recent = self._c().execute("SELECT first_seen FROM devices WHERE baseline=0 AND first_seen>=? ORDER BY first_seen", (now - 30 * 86400,)).fetchall()
            ever, now_by = self._wifi_ssid_counts(self._c())
            tot = self._c().execute("SELECT COUNT(*) n, SUM(online) online, SUM(CASE WHEN acked=0 AND baseline=0 THEN 1 ELSE 0 END) unacked, SUM(CASE WHEN baseline=1 AND acked=0 THEN 1 ELSE 0 END) baseline_unchecked, SUM(CASE WHEN baseline=0 AND first_seen>=? THEN 1 ELSE 0 END) new FROM devices WHERE archived_ts IS NULL", (now - new_days * 86400,)).fetchone()
        ssids = sorted(({"ssid": r["ssid"], "devices_ever": r["n"] or 0, "devices_now": now_by.get(r["ssid"], 0)} for r in ever),
                       key=lambda x: (-x["devices_ever"], x["ssid"]))
        return {
            "total": tot["n"], "online": tot["online"] or 0, "unacked": tot["unacked"] or 0, "baseline_unchecked": tot["baseline_unchecked"] or 0, "new": tot["new"] or 0,
            "vlans": [{"vlan": r["vlan"], "n": r["n"], "online": r["online"] or 0} for r in rows],
            "all_vlans": [r["vlan"] for r in allv],
            "ssids": ssids,
            "new_recent": [r["first_seen"] for r in recent],  # epochs; the browser buckets them by its own local day
        }
