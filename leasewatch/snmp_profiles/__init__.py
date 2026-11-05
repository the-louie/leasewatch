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
import string
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
    except (OSError, ValueError, RecursionError) as e:  # ValueError: JSONDecodeError, bad encodings; RecursionError: deep nesting
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


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_str_list(v: object) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _template_ok(t: object) -> bool:
    """A name_match template whose only replacement field is {port} (anything else would fail or leak at format())."""
    if not isinstance(t, str):
        return False
    try:
        fields = [(f, spec, conv) for _, f, spec, conv in string.Formatter().parse(t) if f is not None]
    except ValueError:  # unbalanced braces
        return False
    return bool(fields) and all(f == "port" and not spec and conv is None for f, spec, conv in fields)


SECTIONS = ("match", "fdb", "bridge_port_map", "lldp", "port_name", "uplink", "snmp")


def _structure_problems(p: dict, std: dict) -> list[str]:
    """Unknown, missing and non-object keys against standard.json. A profile without `extends` must carry every key
    itself (oids included); the value checks below index these keys, so they run only when this list is empty."""
    problems = []
    # typo guard: a key standard.json does not know would be silently ignored
    problems += [f"unknown key {key!r}" for key in p if key not in std and key != "extends" and not key.startswith("_")]
    problems += [f"missing key {key!r}" for key in std if key not in p and not key.startswith("_")]
    for sec in SECTIONS + ("oids",):
        if sec not in p:
            continue
        if not isinstance(p[sec], dict):
            problems.append(f"{sec} must be an object")
            continue
        if sec != "oids":  # oids may add names (private tables)
            problems += [f"unknown key {sec}.{k}" for k in p[sec] if k not in std[sec]]
        if sec != "match":  # an empty match is "never detected"
            problems += [f"missing key {sec}.{k}" for k in std[sec] if k not in p[sec]]
    return problems


def _validate(p: dict) -> dict:
    """Every problem of a resolved profile in one ProfileError. Messages name the key and quote only the profile's own
    values, never Python's error text."""
    name = p.get("profile")
    problems = _structure_problems(p, _builtin_raw("standard"))
    if not problems:
        try:
            _value_problems(p, problems)
        except (KeyError, TypeError, AttributeError, ValueError):  # a shape the checks above did not foresee
            problems.append("malformed value (compare with standard.json)")
    if problems:
        raise ProfileError(f"snmp profile {name!r}: " + "; ".join(problems))
    return p


def _value_problems(p: dict, problems: list[str]) -> None:
    """Appends to `problems` (so the ones found before an unexpected shape are kept)."""
    name = p.get("profile")
    fdb, bpm, snmp, match = p["fdb"], p["bridge_port_map"], p["snmp"], p["match"]
    if not _is_int(p.get("api_version")):
        problems.append("api_version must be an integer")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in p["oids"].items()):
        problems.append("oids must map names to OID strings")
    short = p["port_name"]["short"]
    if not isinstance(short, dict):
        problems.append("port_name.short must be an object")
    elif not all(isinstance(v, str) for v in short.values()):
        problems.append("port_name.short values must be strings")
    if not isinstance(snmp["bulk"], bool):
        problems.append("snmp.bulk must be true or false")
    if not _is_str_list(snmp["no_bulk"]) or not _is_str_list(snmp["allow_unordered"]):
        problems.append("snmp.no_bulk/allow_unordered must be string lists")
    if fdb["index_fix"] == "row_number" and fdb["strategy"] != "bridge":
        problems.append("fdb.index_fix row_number needs fdb.strategy bridge (only it walks dot1dTpFdbAddress)")
    if not isinstance(name, str) or not name:
        problems.append("profile name missing")
    if fdb["strategy"] not in STRATEGIES:
        problems.append(f"fdb.strategy {fdb['strategy']!r}")
    if fdb["index_fix"] not in INDEX_FIXES:
        problems.append(f"fdb.index_fix {fdb['index_fix']!r}")
    if not isinstance(fdb["context_prefix"], str):
        problems.append("fdb.context_prefix must be a string")
    if not _is_str_list(fdb["private_oids"]):
        problems.append("fdb.private_oids must be a string list")
    if bpm["strategy"] not in BRIDGE_PORT_STRATEGIES:
        problems.append(f"bridge_port_map.strategy {bpm['strategy']!r}")
    if bpm["fallback"] not in ("identity", "drop"):
        problems.append(f"bridge_port_map.fallback {bpm['fallback']!r}")
    nm = bpm["name_match"]
    if nm is not False and not (isinstance(nm, list) and all(_template_ok(t) for t in nm)):
        problems.append("bridge_port_map.name_match must be false or a list of templates with only {port}")
    if p["lldp"]["local_port"] not in LLDP_LOCAL_PORT:
        problems.append(f"lldp.local_port {p['lldp']['local_port']!r}")
    if not _is_int(bpm["offset"]):
        problems.append("bridge_port_map.offset must be an integer")
    if not _is_int(p["uplink"]["min_macs"]) or p["uplink"]["min_macs"] < 1:
        problems.append("uplink.min_macs must be an integer >= 1")
    if not isinstance(p["uplink"]["lldp_neighbor"], bool):
        problems.append("uplink.lldp_neighbor must be true or false")
    if not _is_int(snmp["max_repetitions"]) or not 1 <= snmp["max_repetitions"] <= 128:
        problems.append("snmp.max_repetitions must be 1..128")  # 128: the Zabbix hard cap
    if (isinstance(snmp["timeout"], bool) or not isinstance(snmp["timeout"], (int, float)) or snmp["timeout"] <= 0
            or not _is_int(snmp["retries"]) or snmp["retries"] < 0):
        problems.append("snmp.timeout must be a number > 0 and snmp.retries an integer >= 0")
    for key in ("sysobjectid_prefix", "sysdescr_regex"):
        if not _is_str_list(match.get(key, [])):
            problems.append(f"match.{key} must be a string list")
    for i, rx in enumerate(match.get("sysdescr_regex", []) if _is_str_list(match.get("sysdescr_regex", [])) else []):
        try:
            re.compile(rx)
        except re.error:  # its text quotes the pattern; the entry number is enough to find it
            problems.append(f"match.sysdescr_regex entry {i + 1} is not a valid regular expression")
    if fdb["strategy"] == "cisco_per_vlan" and not (isinstance(fdb["vlan_source"], str) and fdb["vlan_source"] in p["oids"]):
        problems.append(f"fdb.vlan_source {fdb['vlan_source']!r} is not a key in oids")
    if (not isinstance(fdb["keep_status"], list) or not all(_is_int(v) for v in fdb["keep_status"])
            or not isinstance(fdb["skip_vlans"], list) or not all(_is_int(v) for v in fdb["skip_vlans"])):
        problems.append("fdb.keep_status/skip_vlans must be integer lists")


def load(name: str) -> dict:
    """A built-in profile by name, with `extends` resolved. Returns a fresh dict the caller may change."""
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ProfileError(f"unknown snmp profile {name!r} (built-in: {', '.join(BUILTIN)})")
    return _validate(_resolve(_builtin_raw(name), (name,)))


def load_file(path: str | Path) -> dict:
    """An operator's profile from a JSON file; it may `extends` a built-in profile (not another file)."""
    raw = _read(Path(path))
    # seen starts empty: a file may share its name with the built-in it extends (e.g. a local "comware"); a file
    # cannot be extended, so it cannot be part of a cycle
    return _validate(_resolve(raw, ()))


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
