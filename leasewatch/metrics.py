"""Prometheus text exposition (format 0.0.4) for GET /metrics.

render() reads the database and two file sizes; it holds no state. The two _total counters are meta rows the
collector bumps in its outcome transaction (polls_ok, polls_failed, conn.<name>.failures), so they survive a
restart. Label values never carry error texts: those can name hosts and would make the series count unbounded.
"""
from __future__ import annotations

import math
import os
import time

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _esc(v: object) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _num(v: float) -> str:
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "+Inf" if v > 0 else "-Inf"
        return repr(v)
    return str(int(v))


def _int(v: object, default: int = 0) -> int:
    try:
        return int(v)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return default


def _size(path: str) -> int:
    try:
        return os.stat(path).st_size
    except OSError:
        return 0


class _Out:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def family(self, name: str, kind: str, help_: str, samples: list[tuple[dict, float]]) -> None:
        """One metric with its HELP and TYPE; nothing at all when there is no sample."""
        if not samples:
            return
        self.lines.append(f"# HELP {name} {help_.replace(chr(92), chr(92) * 2).replace(chr(10), ' ')}")
        self.lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{lab}}} {_num(value)}" if lab else f"{name} {_num(value)}")


def render(cfg: object, db: object, version: str) -> str:
    """The metrics text for the current database state."""
    now = int(time.time())
    meta = db.all_meta()
    st = db.stats(cfg.new_days)
    archived = db.q("SELECT COUNT(*) n FROM devices WHERE archived_ts IS NOT NULL")[0]["n"]
    queued = db.q("SELECT COUNT(*) n FROM devices WHERE mail_queued IS NOT NULL AND acked=0 AND archived_ts IS NULL")[0]["n"]
    o = _Out()
    g = "gauge"
    o.family("leasewatch_build_info", g, "Build information; the value is always 1.", [({"version": version}, 1)])
    o.family("leasewatch_devices", g, "Listed devices per network (archived ones excluded).",
             [({"network": v["vlan"] or ""}, v["n"]) for v in st["vlans"]])
    o.family("leasewatch_devices_online", g, "Online devices per network.",
             [({"network": v["vlan"] or ""}, v["online"]) for v in st["vlans"]])
    o.family("leasewatch_devices_new", g, "Devices first seen within NEW_DAYS and not in the baseline.", [({}, st["new"])])
    o.family("leasewatch_devices_unacked", g, "Devices not acknowledged (baseline devices excluded).", [({}, st["unacked"])])
    o.family("leasewatch_devices_archived", g, "Archived devices.", [({}, archived)])
    if "last_poll_ok" in meta:
        o.family("leasewatch_poll_ok", g, "1 if the last poll succeeded, else 0.", [({}, _int(meta["last_poll_ok"]))])
    if "last_poll_ms" in meta:
        o.family("leasewatch_poll_duration_seconds", g, "Duration of the last successful poll.", [({}, _int(meta["last_poll_ms"]) / 1000)])
    if _int(meta.get("last_poll_ts")):
        o.family("leasewatch_poll_age_seconds", g, "Seconds since the last successful poll.", [({}, abs(now - _int(meta["last_poll_ts"])))])
    if _int(meta.get("last_attempt_ts")):
        o.family("leasewatch_poll_attempt_age_seconds", g, "Seconds since the last poll attempt, ok or not.",
                 [({}, abs(now - _int(meta["last_attempt_ts"])))])
    o.family("leasewatch_polls_total", "counter", "Polls finished, by result.",
             [({"result": "ok"}, _int(meta.get("polls_ok"))), ({"result": "failed"}, _int(meta.get("polls_failed")))])

    ok_s, en_s, ms_s, cnt_s, fail_s = [], [], [], [], []
    for spec in cfg.instances:
        lab = {"name": spec.name, "type": spec.type}
        k = f"conn.{spec.name}."
        enabled = meta.get(k + "enabled", "1") == "1"
        en_s.append((lab, 1 if enabled else 0))
        if enabled and k + "ok" in meta:
            ok_s.append((lab, 1 if meta[k + "ok"] == "1" else 0))
        if k + "ms" in meta:
            ms_s.append((lab, _int(meta[k + "ms"]) / 1000))
        if k + "count" in meta:
            cnt_s.append((lab, _int(meta[k + "count"])))
        fail_s.append((lab, _int(meta.get(k + "failures"))))
    o.family("leasewatch_connector_ok", g, "1 if the instance answered in the last poll, else 0 (enabled instances).", ok_s)
    o.family("leasewatch_connector_enabled", g, "1 if the instance is enabled, else 0.", en_s)
    o.family("leasewatch_connector_duration_seconds", g, "Time the instance took in the last poll.", ms_s)
    o.family("leasewatch_connector_count", g, "Records the instance returned in the last poll.", cnt_s)
    o.family("leasewatch_connector_failures_total", "counter", "Polls in which the instance failed.", fail_s)
    o.family("leasewatch_db_bytes", g, "Size of the database file.", [({}, _size(db.path))])
    o.family("leasewatch_wal_bytes", g, "Size of the write-ahead log file (0 when absent).", [({}, _size(db.path + "-wal"))])
    o.family("leasewatch_mail_queued", g, "New devices waiting for a notification mail.", [({}, queued)])
    o.family("leasewatch_notify_ok", g, "1 if the last send over the channel worked, else 0 (configured channels).",
             [({"channel": ch}, 1 if meta[f"notify.{ch}.ok"] == "1" else 0) for ch in cfg.mail_channels if f"notify.{ch}.ok" in meta])
    return "\n".join(o.lines) + "\n"
