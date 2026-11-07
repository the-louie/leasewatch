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
]
# meta.schema_version: the steps below run in order on open for every version below SCHEMA_VERSION. A DB without the
# key predates the versioning and is version 1 (the 1.0 tables plus the columns above)
SCHEMA_VERSION = 3
VERSION_STEPS = {
    # per-source freshness: when each connector instance last listed a MAC and last saw it on the wire
    2: "CREATE TABLE IF NOT EXISTS seen (mac TEXT, source TEXT, last_seen INTEGER NOT NULL, last_present INTEGER, PRIMARY KEY(mac, source))",
    # merged private MACs: each alias MAC points to the device key (devices.mac, the first MAC seen) it was merged
    # into, so the key and every row keyed by it stay valid; one statement, as the loop and the table regex expect
    3: "CREATE TABLE IF NOT EXISTS aliases (mac TEXT PRIMARY KEY, device TEXT NOT NULL, reason TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', merged_ts INTEGER NOT NULL, last_seen INTEGER NOT NULL)",
}

# strip NUL/C0/C1 control, invisible and bidi-override characters from user text (keeps tab/newline for notes).
# U+200C/U+200D (ZWNJ/ZWJ) stay: emoji sequences and several scripts need them.
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b\u200e\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\u061c\ufeff]")


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
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

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._conn.in_transaction:  # a failed COMMIT+ROLLBACK must not wedge every later transaction
                self._conn.execute("ROLLBACK")
            self._conn.execute("BEGIN")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:  # also KeyboardInterrupt/GeneratorExit: never leave the transaction open
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:  # e.g. already rolled back; the original exception is the one that matters
                    pass
                raise

    def q(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    # --- meta ---------------------------------------------------------------
    def get_meta(self, key: str, default: str = "") -> str:
        r = self.q("SELECT value FROM meta WHERE key=?", (key,))
        return r[0]["value"] if r else default

    def set_meta(self, key: str, value: str, conn: sqlite3.Connection | None = None) -> None:
        # a lone surrogate (e.g. from a JSON-escaped controller error text) would raise UnicodeEncodeError here and
        # roll back the whole poll transaction around it, so it is stored as "?"
        value = str(value).encode("utf-8", "replace").decode("utf-8")
        with self._lock:  # RLock: harmless inside tx(), required outside it
            (conn or self._conn).execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def all_meta(self) -> dict:
        return {r["key"]: r["value"] for r in self.q("SELECT key, value FROM meta")}

    # --- devices ------------------------------------------------------------
    def devices(self) -> list[dict]:
        return [dict(r) for r in self.q("SELECT * FROM devices ORDER BY first_seen DESC, mac")]

    def device(self, mac: str) -> dict | None:
        r = self.q("SELECT * FROM devices WHERE mac=?", (mac,))
        return dict(r[0]) if r else None

    def device_detail(self, mac: str) -> dict | None:
        """The drawer's device, history, events, seen rows and merged MACs, or None for an unknown MAC."""
        with self._lock:  # one hold, as stats(): the five reads must not straddle a collector write
            d = self.device(mac)
            return {"device": d, "history": self.history(d["mac"]), "events": self.events(d["mac"]),
                    "seen": self.seen(d["mac"]), "aliases": self.aliases(d["mac"])} if d else None

    def aliases(self, mac: str) -> list[dict]:
        """The private MACs merged into the device mac, newest merge first."""
        return [dict(r) for r in self.q("SELECT mac, reason, detail, merged_ts, last_seen FROM aliases WHERE device=? ORDER BY merged_ts DESC, mac", (mac,))]

    def seen(self, mac: str) -> list[dict]:
        return [dict(r) for r in self.q("SELECT source, last_seen, last_present FROM seen WHERE mac=? ORDER BY last_seen DESC, source", (mac,))]

    def history(self, mac: str, limit: int = 200) -> list[dict]:
        return [dict(r) for r in self.q("SELECT ts, ip, hostname, vlan, lease_type FROM history WHERE mac=? ORDER BY ts DESC, id DESC LIMIT ?", (mac, limit))]

    def events(self, mac: str | None = None, limit: int = 200) -> list[dict]:
        if mac:
            rows = self.q("SELECT e.ts, e.mac, e.kind, e.detail FROM events e WHERE mac=? ORDER BY e.ts DESC, e.id DESC LIMIT ?", (mac, limit))
        else:
            rows = self.q("SELECT e.ts, e.mac, e.kind, e.detail, d.name, d.hostname, d.vlan FROM events e LEFT JOIN devices d USING(mac) ORDER BY e.ts DESC, e.id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def update_user_fields(self, mac: str, acked: bool | None, name: str | None, note: str | None) -> dict | None:
        with self.tx() as c:
            cur = c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()
            if not cur:
                return None
            sets, params = [], []
            if acked is not None:
                sets.append("acked=?"); params.append(1 if acked else 0)
                if not acked or not cur["acked"]:  # a re-ack keeps the time of the first ack
                    sets.append("acked_at=?"); params.append(int(time.time()) if acked else None)
            if name is not None:
                sets.append("name=?"); params.append(_CTRL.sub("", name).replace("\n", " ").replace("\t", " ").strip()[:80].strip())  # strip first too: leading blanks must not use up the limit
            if note is not None:
                sets.append("note=?"); params.append(_CTRL.sub("", note).strip()[:1000].rstrip())  # the cut can end on a blank
            if sets:
                params.append(mac)
                c.execute(f"UPDATE devices SET {', '.join(sets)} WHERE mac=?", tuple(params))
                if acked is not None and bool(cur["acked"]) != bool(acked):
                    c.execute("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (int(time.time()), mac, "acked" if acked else "unacked", ""))
            return dict(c.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone())

    def stats(self, new_days: int) -> dict:
        now = int(time.time())
        with self._lock:  # one lock hold: the three counts must not straddle a collector write
            rows = self._conn.execute("SELECT vlan, COUNT(*) n, SUM(online) online FROM devices GROUP BY vlan ORDER BY n DESC").fetchall()
            recent = self._conn.execute("SELECT first_seen FROM devices WHERE baseline=0 AND first_seen>=? ORDER BY first_seen", (now - 30 * 86400,)).fetchall()
            tot = self._conn.execute("SELECT COUNT(*) n, SUM(online) online, SUM(CASE WHEN acked=0 AND baseline=0 THEN 1 ELSE 0 END) unacked, SUM(CASE WHEN baseline=0 AND first_seen>=? THEN 1 ELSE 0 END) new FROM devices", (now - new_days * 86400,)).fetchone()
        return {
            "total": tot["n"], "online": tot["online"] or 0, "unacked": tot["unacked"] or 0, "new": tot["new"] or 0,
            "vlans": [{"vlan": r["vlan"], "n": r["n"], "online": r["online"] or 0} for r in rows],
            "new_recent": [r["first_seen"] for r in recent],  # epochs; the browser buckets them by its own local day
        }
