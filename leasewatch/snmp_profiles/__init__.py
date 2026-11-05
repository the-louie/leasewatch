"""SNMP switch profiles: which tables to walk and which vendor quirks to apply, as JSON data.

A profile is a JSON object (schema: standard.json, which every built-in profile extends). `extends` names a built-in
profile; the child's keys replace the parent's, dicts are merged one level deep (so `oids` and `fdb` add/override single
keys), and `match` is never inherited: a child that does not set it is never auto-detected.

Detection (`detect`) tries the built-in profiles in DETECT_ORDER, first match wins, else "standard". A profile matches
when its sysObjectID prefix list (if not empty) has a prefix of the agent's sysObjectID on an arc boundary, and its
sysDescr regex list (if not empty) has a case-insensitive `re.search` hit; both lists given = both must match. A profile
with both lists empty never matches.
"""
from __future__ import annotations

import copy
import functools
import json
import re
from pathlib import Path

API_VERSION = 1

# first match wins; standard is the fallback, not tried. Vendors with a narrow sysObjectID come before broad ones.
DETECT_ORDER = ("comware", "cisco_ios", "routeros", "jetstream", "zynos", "edgeswitch")
BUILTIN = ("standard",) + DETECT_ORDER

# schema keys that are documented (and kept in the JSON) but not acted on yet; their 1.0 behaviour applies:
# fdb.vlan_map (the FDB id is taken as the VLAN), lldp.v2_fallback (LLDP-MIB only), port_name.prefer (ifName only),
# uplink.trunk (no trunk walk), snmp.allow_unordered (a walk still stops at a non-increasing OID).
IGNORED_KEYS = ("fdb.vlan_map", "lldp.v2_fallback", "port_name.prefer", "uplink.trunk", "snmp.allow_unordered")

STRATEGIES = ("qbridge", "bridge", "cisco_per_vlan", "private")
INDEX_FIXES = ("none", "length_byte", "zynos", "row_number")
BRIDGE_PORT_STRATEGIES = ("dot1dBasePortIfIndex", "identity")
LLDP_LOCAL_PORT = ("auto", "ifindex")

_DIR = Path(__file__).resolve().parent
_NAME_RE = re.compile(r"^[a-z0-9_]{1,40}$")


class ProfileError(ValueError):
    """A profile that cannot be used: unknown name, unreadable file, bad JSON, wrong api_version or bad value."""


def _read(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:  # ValueError covers JSONDecodeError and bad encodings
        raise ProfileError(f"snmp profile {path.name}: {type(e).__name__}") from None
    if not isinstance(data, dict):
        raise ProfileError(f"snmp profile {path.name}: not a JSON object")
    return data


@functools.lru_cache(maxsize=None)
def _builtin_raw(name: str) -> dict:
    # cached for the process lifetime; callers only ever get deep copies (see load)
    if name not in BUILTIN:
        raise ProfileError(f"unknown snmp profile {name!r} (built-in: {', '.join(BUILTIN)})")
    return _read(_DIR / f"{name}.json")


def _merge(parent: dict, child: dict) -> dict:
    out = {k: copy.deepcopy(v) for k, v in parent.items() if k != "match"}
    for k, v in child.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k != "match":
            out[k] = {**out[k], **copy.deepcopy(v)}
        else:
            out[k] = copy.deepcopy(v)
    out.setdefault("match", {"sysobjectid_prefix": [], "sysdescr_regex": []})
    return out


def _resolve(raw: dict, seen: tuple[str, ...]) -> dict:
    if raw.get("api_version") != API_VERSION:
        raise ProfileError(f"snmp profile {raw.get('profile')!r}: api_version {raw.get('api_version')!r}, this leasewatch reads {API_VERSION}")
    parent = raw.get("extends")
    if parent is None:
        return copy.deepcopy(raw)
    if not isinstance(parent, str) or parent in seen:
        raise ProfileError(f"snmp profile {raw.get('profile')!r}: bad or circular extends {parent!r}")
    return _merge(_resolve(_builtin_raw(parent), seen + (parent,)), raw)


def _validate(p: dict) -> dict:
    name = p.get("profile")
    try:
        fdb, bpm, snmp = p["fdb"], p["bridge_port_map"], p["snmp"]
        problems = []
        if not isinstance(name, str) or not name:
            problems.append("profile name missing")
        if fdb["strategy"] not in STRATEGIES:
            problems.append(f"fdb.strategy {fdb['strategy']!r}")
        if fdb["index_fix"] not in INDEX_FIXES:
            problems.append(f"fdb.index_fix {fdb['index_fix']!r}")
        if bpm["strategy"] not in BRIDGE_PORT_STRATEGIES:
            problems.append(f"bridge_port_map.strategy {bpm['strategy']!r}")
        if bpm["fallback"] not in ("identity", "drop"):
            problems.append(f"bridge_port_map.fallback {bpm['fallback']!r}")
        nm = bpm["name_match"]
        if nm is not False and not (isinstance(nm, list) and all(isinstance(t, str) and "{port}" in t for t in nm)):
            problems.append("bridge_port_map.name_match must be false or a list of templates with {port}")
        if p["lldp"]["local_port"] not in LLDP_LOCAL_PORT:
            problems.append(f"lldp.local_port {p['lldp']['local_port']!r}")
        if not isinstance(p["port_name"]["short"], dict):
            problems.append("port_name.short must be an object")
        for key in ("offset",):
            if not isinstance(bpm[key], int) or isinstance(bpm[key], bool):
                problems.append(f"bridge_port_map.{key} must be an integer")
        if not isinstance(p["uplink"]["min_macs"], int) or p["uplink"]["min_macs"] < 1:
            problems.append("uplink.min_macs must be an integer >= 1")
        if not isinstance(snmp["max_repetitions"], int) or not 1 <= snmp["max_repetitions"] <= 128:
            problems.append("snmp.max_repetitions must be 1..128")  # 128: the Zabbix hard cap
        if not isinstance(snmp["timeout"], (int, float)) or snmp["timeout"] <= 0 or not isinstance(snmp["retries"], int) or snmp["retries"] < 0:
            problems.append("snmp.timeout/retries")
        for key in ("sysobjectid_prefix", "sysdescr_regex"):
            if not isinstance(p["match"].get(key, []), list):
                problems.append(f"match.{key} must be a list")
        for rx in p["match"].get("sysdescr_regex", []):
            re.compile(rx)
        if fdb["strategy"] == "cisco_per_vlan" and fdb["vlan_source"] not in p["oids"]:
            problems.append(f"fdb.vlan_source {fdb['vlan_source']!r} is not a key in oids")
        if not all(isinstance(v, int) for v in fdb["keep_status"]) or not all(isinstance(v, int) for v in fdb["skip_vlans"]):
            problems.append("fdb.keep_status/skip_vlans must be integer lists")
    except (KeyError, TypeError, AttributeError) as e:
        raise ProfileError(f"snmp profile {name!r}: missing or malformed key {e}") from None
    except re.error as e:
        raise ProfileError(f"snmp profile {name!r}: bad sysdescr_regex: {e}") from None
    if problems:
        raise ProfileError(f"snmp profile {name!r}: " + "; ".join(problems))
    return p


def load(name: str) -> dict:
    """A built-in profile by name, with `extends` resolved. Returns a fresh dict the caller may change."""
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ProfileError(f"unknown snmp profile {name!r} (built-in: {', '.join(BUILTIN)})")
    return _validate(_resolve(_builtin_raw(name), (name,)))


def load_file(path: str | Path) -> dict:
    """An operator's profile from a JSON file; it may `extends` a built-in profile (not another file)."""
    raw = _read(Path(path))
    return _validate(_resolve(raw, (str(raw.get("profile")),)))


def matches(profile: dict, sysobjectid: str, sysdescr: str) -> bool:
    m = profile.get("match") or {}
    prefixes, regexes = m.get("sysobjectid_prefix") or [], m.get("sysdescr_regex") or []
    if not prefixes and not regexes:
        return False
    oid = sysobjectid.strip().lstrip(".")
    if prefixes and not any(oid == p.strip(".") or oid.startswith(p.strip(".") + ".") for p in prefixes):
        return False
    if regexes and not any(re.search(rx, sysdescr or "", re.I) for rx in regexes):
        return False
    return True


def detect(sysobjectid: str, sysdescr: str) -> str:
    """Name of the first built-in profile in DETECT_ORDER that matches, else "standard"."""
    for name in DETECT_ORDER:
        if matches(load(name), sysobjectid or "", sysdescr or ""):
            return name
    return "standard"
