"""Connector contract: the records a data source hands to the host, and the protocol a source implements.

A connector is one configured instance of a source type (an OPNsense firewall, an SNMP switch, a UniFi controller).
The host builds it from a flat dict of string settings, asks it to validate them (no I/O), probes it once with
check(), then calls collect() once per poll. The connector returns plain records in a Batch; it never writes to
the database or to the device it reads from.

What the host does with a Batch (merge.normalise_batch): it sets every record's `source` to the instance name (a
connector may leave it ""), normalises `mac` with norm_mac() and drops records that fail it (logged once per
instance, counted in stats["dropped"]). Errors: only a ConnectorError's text is shown in the UI and status; any
other exception from check()/collect() is shown as its type name only (and logged with a traceback).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import ssl
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Callable, ClassVar, Iterable, Mapping, Protocol, runtime_checkable
from urllib.parse import urlparse

from ..fw1 import _NoRedirect, norm_mac

# the public names for connector code (contrib/README.md lists the same; tests/test_contrib_layout.py checks it)
__all__ = ["API_VERSION", "ConnectorInfo", "Setting", "Sighting", "Attachment", "Batch", "ConnectorError",
           "HostContext", "SettingsMixin", "build_opener", "make_redactor", "url_problems", "parse_bool",
           "Connector", "make_host_mask"]

API_VERSION = 1

TRUE_WORDS = ("1", "true", "yes", "on")
FALSE_WORDS = ("0", "false", "no", "off")


@dataclass(frozen=True)
class Setting:
    """One key a connector type accepts. Values always arrive as strings; `default` is a string too.
    A `secret` value is never logged, shown in status or echoed in an error."""
    key: str
    required: bool = False
    default: str = ""
    secret: bool = False
    choices: tuple[str, ...] = ()
    help: str = ""
    kind: str = "str"  # "int": the value must parse as an integer within min..max (either bound optional)
    min: int | None = None
    max: int | None = None


@dataclass(frozen=True)
class ConnectorInfo:
    """What a connector type is: its name ([a-z0-9_]+), its own version, the contract version it was written
    against (must equal API_VERSION), which record kinds it emits ("sighting", "attachment") and its settings.
    roles: "controller" = its attachments are a Wi-Fi controller's complete client list, so a device missing from
    an answered batch has left Wi-Fi, and a failed poll leaves Wi-Fi devices "blind" (see merge.py)."""
    type: str
    version: str
    api_version: int
    produces: frozenset[str]
    settings: tuple[Setting, ...]
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Sighting:
    """L2/L3 identity of one device, as one source saw it.

    mac: as the source gives it; the host normalises it to "aa:bb:cc:dd:ee:ff" and drops the record if it is not a
    MAC. source: the connector instance name, filled in by the host (the connector may leave it ""). kind: what the
    evidence is, "dhcp" | "arp" | "client" | "scan" (ranking in merge.py). presence: True only if the source saw the
    device on the wire now (an ARP entry, ISC's "online" lease status, an active controller client); a lease or
    reservation alone is False. Only presence=True makes a device online and moves last_online, for every kind.
    observed_at: epoch seconds when the connector collected it; informational in API 1 (reserved as a tie-break
    for C6). network: human interface name (LAN, IOT), the "vlan" column today. iface: source-specific interface
    id (opt3). lease_type: "static" | "dynamic" | "", only kind "dhcp" sets it. client_id: DHCP client-id / DUID
    when known (reserved, unused so far)."""
    mac: str
    source: str
    kind: str
    presence: bool
    observed_at: int
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    network: str = ""
    iface: str = ""
    lease_type: str = ""
    client_id: str = ""


@dataclass(frozen=True)
class Attachment:
    """Where one device hangs: a switch port, a Wi-Fi AP, a port behind a controller-managed switch.

    mac, source, observed_at: as for Sighting (the host normalises mac and fills source; observed_at is
    informational: the merge never ranks by it, a walk stamps all its rows with one time). link: exactly "wired" or "wifi"; any other value is ignored by the host (logged once).
    From an instance with the "controller" role, "wired" means the controller sees the device on a cable: its
    Wi-Fi details are cleared. device: the switch/AP name as the operator knows it. port: short port label
    ("GE1/0/14"), "" for Wi-Fi. uplink: the port leads to more infrastructure, so it is not where the device
    really is; via: what sits behind that port (LLDP neighbour or "7 devices"). vlan: VLAN id, if the source knows
    it. ssid/ap/signal (dBm)/alias: Wi-Fi details and the name set in the controller. radio: free text, shown as
    given ("2.4 GHz", "5 GHz", "6 GHz" suggested). present: the source vouches the device is connected now (a
    controller's active client); it feeds the per-source "on the wire" (seen.last_present), never `online`, which
    only sightings set. An FDB entry is not present (it ages out slower than the device leaves)."""
    mac: str
    source: str
    observed_at: int
    link: str
    device: str = ""
    port: str = ""
    via: str = ""
    uplink: bool = False
    vlan: int | None = None
    ssid: str = ""
    ap: str = ""
    signal: int | None = None
    radio: str = ""
    alias: str = ""
    present: bool = False


@dataclass
class Batch:
    """The result of one collect(). stats: raw counts for status, all optional (the host reads a missing key as 0):
    "leases", "arp", "reservations" (sighting producers), "macs" (switch), "clients" (controller); the host adds
    "dropped" (malformed records dropped: an invalid MAC or the wrong type). Values are ints, except these documented string keys: "strategy"
    (switch: the FDB strategy that produced the rows; the host copies it to meta conn.<name>.strategy)."""
    sightings: list[Sighting] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


class ConnectorError(Exception):
    """The one exception a connector raises from check()/collect(). Its text is shown in the UI and logs, so it
    must never contain a secret, a URL with credentials or a response body."""


def _redact_nothing(text: str) -> str:
    return text


def build_opener(verify_tls: bool = True, use_env_proxy: bool = False) -> urllib.request.OpenerDirector:
    """An HTTP(S) opener that never follows redirects (a 3xx would resend credentials) and ignores http(s)_proxy
    unless asked (the sources are on the LAN)."""
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers: list = [_NoRedirect(), urllib.request.HTTPSHandler(context=ctx)]
    if not use_env_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


MIN_SECRET_LEN = 4


def make_redactor(secrets: Iterable[str]) -> Callable[[str], str]:
    """Replace every given secret value in a text by "***" (longest first, so a secret containing another is whole).
    Each secret is also matched in its repr and JSON escaped forms, because a `{x!r}`, a KeyError or a JSON body
    echoes it with a quote or backslash escaped, and the literal would then not match. A secret shorter than
    MIN_SECRET_LEN is skipped: it cannot be masked without destroying unrelated text ("s" would turn "snmp timeout"
    into "***nmp timeout"), and a value that short is not a real secret."""
    forms = {f for s in secrets if s and len(s) >= MIN_SECRET_LEN for f in (s, repr(s)[1:-1], json.dumps(s)[1:-1])}
    values = sorted((f for f in forms if f), key=len, reverse=True)
    if not values:
        return _redact_nothing

    def redact(text: str) -> str:
        # mark every occurrence of every form first, then mask each covered run once: replacing one secret after
        # another would break an overlapping one ("pass1234" + "1234word" in "pass1234word") so it no longer matches
        covered = bytearray(len(text))
        for v in values:
            i = text.find(v)
            while i != -1:
                covered[i:i + len(v)] = b"\x01" * len(v)
                i = text.find(v, i + 1)
        if not any(covered):
            return text
        out, i = [], 0
        while i < len(text):
            if covered[i]:
                while i < len(text) and covered[i]:
                    i += 1
                out.append("***")
            else:
                out.append(text[i])
                i += 1
        return "".join(out)
    return redact


@dataclass
class HostContext:
    """What the host lends a connector. Nothing here writes to the database or to a device."""
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("leasewatch.connectors"))
    now: Callable[[], int] = field(default=lambda: int(time.time()))
    norm_mac: Callable[[str], str] = field(default=norm_mac)
    redact: Callable[[str], str] = field(default=_redact_nothing)
    opener_factory: Callable[..., urllib.request.OpenerDirector] = field(default=build_opener)
    # mac -> the device's name, else its hostname, as the host knows it (read-only); lets a switch name an unnamed
    # uplink port after the AP or switch behind it
    device_names: Callable[[], dict[str, str]] = field(default=lambda: {})
    # the instance's TIMEOUT (a host key, so absent from settings); set per instance by build_instance, so a
    # connector can cap its own I/O there instead of running on after the host has abandoned the collect
    timeout: int = 60


@runtime_checkable
class Connector(Protocol):
    """Lifecycle: describe() (class level, no instance) -> __init__ (no I/O) -> validate() (no I/O, list of
    problems, empty = fine) -> check() (one cheap probe, raises ConnectorError; the host calls it once before the
    first collect() and again, with backoff, after it failed) -> collect() once per poll (raises ConnectorError)
    -> close() (never raises). Third-party libraries are imported inside check()/collect(), never at module
    import. Only a ConnectorError's text reaches the UI; any other exception is shown as its type name."""

    @classmethod
    def describe(cls) -> ConnectorInfo: ...

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext) -> None: ...

    def validate(self) -> list[str]: ...

    def check(self) -> None: ...

    def collect(self) -> Batch: ...

    def close(self) -> None: ...


# --- helpers shared by the built-in connectors ----------------------------------------------------------------

def parse_bool(value: str) -> bool | None:
    """The same words config.py accepts; None when the text is none of them."""
    v = (value or "").strip().lower()
    if v in TRUE_WORDS:
        return True
    if v in FALSE_WORDS:
        return False
    return None


# a host or user name shorter than this is not masked: replacing "1" or "sw" would garble every number and word in the
# message while hiding nothing (such a name is no secret anyway)
MIN_REDACT = 3


def _forms(value: str) -> set[str]:
    """Spellings of a host or user name as it may appear in an error text: as given, lower-cased, without the
    trailing dot of an FQDN, and an IPv6 address both compressed and exploded."""
    v = value.strip()
    out = {v, v.lower(), v.rstrip("."), v.lower().rstrip(".")}
    try:
        ip = ipaddress.ip_address(v.strip("[]"))
    except ValueError:
        pass
    else:
        out |= {ip.compressed, str(ip)}
        try:
            out.add(ip.exploded)
        except ValueError:  # a scoped IPv6 address ("fe80::2%eth0") has no exploded form
            pass
    return {f for f in out if len(f) >= MIN_REDACT}


def _bounded(forms: set[str]) -> list[re.Pattern]:
    """Case-insensitive patterns for whole occurrences only: "10.0.0.2" must not hit "10.0.0.25", "sw" not "switch"."""
    out = []
    # not inside a name/number on either side; a trailing "." is allowed (end of sentence, FQDN root) unless more follows.
    # An IPv6 form must also not touch another ":" group ("fe80::2" is not "fe80::2:5" or "fe80::2:beef", but
    # "fe80::2: timeout" and "fe80::2:failed" are the host); for the others ":" is the port. Not the word inside an
    # earlier "<host>"/"<user>" mask, so the user mask never hits it; any other host after "<" is still masked.
    for group, colon in (([f for f in forms if ":" not in f], ""), ([f for f in forms if ":" in f], ":")):
        if group:
            alts = "|".join(re.escape(f) for f in sorted(group, key=len, reverse=True))
            ahead = r"(?![\w-]|\.\w|:(?::|[0-9a-f]{1,4}(?!\w)))" if colon else r"(?![\w-]|\.\w)"
            out.append(re.compile(rf"(?<![\w.{colon}-])(?!(?<=<)(?:host|user)>)(?:{alts}){ahead}", re.I))
    return out


def make_host_mask(url_or_host: str) -> Callable[[str], str]:
    """A function that replaces whole occurrences of a host by "<host>" ("10.0.0.1" is not "10.0.0.15"): a source's
    address is internal infrastructure, not for the UI, and e.g. ssl's hostname-mismatch text echoes it.
    url_or_host: a URL (with "://"; its hostname is used) or a bare host name or address. Masked spellings: as
    given, lower case, without a trailing dot, the IDNA (punycode) form, an IPv6 address compressed and exploded.
    A spelling shorter than MIN_REDACT (3) characters is never masked ("fw" stays): it would garble every word."""
    host = url_or_host
    if "://" in url_or_host:
        try:
            host = urlparse(url_or_host).hostname or ""
        except ValueError:  # e.g. an unclosed "[": such a URL is refused by url_problems() and never connected to
            host = ""
    forms = _forms(host)
    try:  # ssl and the resolver use the IDNA (punycode) name, so a TLS name mismatch echoes that spelling
        forms |= _forms(host.encode("idna").decode("ascii"))
    except UnicodeError:  # a label idna cannot encode (empty, too long): such a host is never connected to
        pass
    rxs = _bounded(forms)

    def mask(text: str) -> str:
        for rx in rxs:
            text = rx.sub("<host>", text)
        return text
    return mask


def mask_url_host(text: str, url: str) -> str:
    """`text` with the host of `url` masked as "<host>" (see make_host_mask). The clients' own "fw1 <path>: " /
    "unifi: " label is kept as is, so a host named "fw1" does not mask it."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return text
    if not host:
        return text
    head, sep, tail = text.partition(": ")
    if not sep:
        head, tail = "", text
    return head + sep + make_host_mask(host)(tail)


_URL_BAD_CHAR_RE = re.compile(r"[\x00-\x20\x7f]")  # what http.client refuses in a request URL


def url_has_credentials(url: str) -> bool:
    """True when a "user@" or "user:pass@" may precede the host. Config.validate() and url_problems() share it."""
    if "@" not in url:
        return False
    # a "#", "/" or "?" in a password that starts with digits ("u:1234/x@fw") ends the netloc before the "@",
    # so a "user:" before the first "/?#" and a later "@" counts too; an "@" in a path, query or fragment without
    # such a ":" does not (a ":" after the "/?#" is path data). An empty user info ("https://@fw") counts:
    # urllib keeps the "@" in the host. The ":"s of a leading IPv6 literal ("[::1]/a@b") are not a "user:".
    # Limitation: a user name containing "/?#" ("us/er:pw@h") is not caught, as before 1.1
    before_at = url.split("//", 1)[-1].split("@", 1)[0]
    if before_at.startswith("[") and "]" in before_at:
        before_at = before_at.split("]", 1)[1]  # user info cannot start with "["
    authority = re.split(r"[/?#]", before_at, maxsplit=1)[0]
    return ":" in authority or authority == before_at


def url_problems(key: str, url: str, hint: str) -> list[str]:
    """The URL checks Config.validate() makes: a scheme, a host, and no credentials in it (they would end up in logs).
    Also a port that is a number in 1..65535 and no control characters or spaces, which otherwise pass here and
    only fail at the first request."""
    if not url.lower().startswith(("http://", "https://")):  # urllib reads the scheme case-insensitively
        return [f"{key} must be a URL ({hint})"]
    out = []
    try:
        parsed = urlparse(url)
        if not parsed.hostname or parsed.port == 0 or _URL_BAD_CHAR_RE.search(url):
            out.append(f"{key} is not a valid URL")
    except ValueError:  # e.g. an unclosed "[" or a port that is not a number in 0..65535
        out.append(f"{key} is not a valid URL")
    if url_has_credentials(url):
        out.append(f"{key} must not contain credentials")
    return out


class SettingsMixin:
    """Settings lookup with the type's declared defaults, plus the generic checks describe() makes possible."""
    INFO: ClassVar[ConnectorInfo]

    def _init_settings(self, name: str, settings: Mapping[str, str], ctx: HostContext | None) -> None:
        self.name = name
        self.ctx = ctx or HostContext()
        defaults = {s.key: s.default for s in self.INFO.settings}
        self.settings = {**defaults, **{k: str(v) for k, v in settings.items()}}

    @classmethod
    def describe(cls) -> ConnectorInfo:
        return cls.INFO

    def _generic_problems(self) -> list[str]:
        return setting_problems(self.name, self.INFO.type, self.INFO.settings, self.settings)

    def __repr__(self) -> str:
        # declared secrets, plus anything that looks like one (a key outside describe(), a path to a secret file)
        secret = {s.key for s in self.INFO.settings if s.secret}
        hidden = lambda k: (k in secret or k.lower().endswith("_file")
                            or any(w in k.lower() for w in ("key", "secret", "pass", "token", "community", "credential")))
        shown = {k: ("***" if hidden(k) and v else v) for k, v in self.settings.items()}
        return f"{type(self).__name__}({self.name!r}, {shown!r})"


# --- instances: the registry of types and the configured instances built from it -------------------------------

# letters and digits only: LW_CONNECTOR__<NAME>__<KEY> must be a name a POSIX shell can export
NAME_RE = re.compile(r"^[a-z0-9]+$")
# keys every instance accepts besides its type's own settings; the host reads them, the connector never sees them
HOST_SETTINGS = (
    # not a literal list: plugins add types at load time (type_help() and `python -m leasewatch check` list them)
    Setting("type", required=True, help="connector type: a built-in or a loaded third-party one (see type_help())"),
    Setting("timeout", default="60", kind="int", min=1, max=3600, help="seconds a collect may run before this poll abandons it"),
)
HOST_KEYS = frozenset(s.key for s in HOST_SETTINGS)


# an integer with its leading zeros split off; "[1-9][0-9]*|0" leaves one way to split a zero run, so a long run
# of zeros before a non-digit fails in linear time ("0*([0-9]+)" backtracks quadratically)
_INT_RE = re.compile(r"\s*([+-]?)0*([1-9][0-9]*|0)\s*")


def setting_problems(name: str, type_: str, settings: Iterable[Setting], values: Mapping[str, str]) -> list[str]:
    """The checks describe() makes possible: required keys, choices, integer ranges. Never echoes a value."""
    out = []
    for s in settings:
        v = values.get(s.key, "")
        label = f"connector {name} ({type_}): {s.key.upper()}"
        if not v:
            if s.required:
                out.append(f"{label} is required")
            elif s.choices and s.default and s.key in values:  # absent: the connector applies the default
                # an explicitly empty value overrides the default; with choices it would silently pick another path
                # (an empty dhcp_backend would read ISC leases)
                out.append(f"{label} must be one of {', '.join(s.choices)}")
        elif s.choices and v not in s.choices:
            out.append(f"{label} must be one of {', '.join(s.choices)}")
        elif s.kind == "int":
            try:
                n = int(v)
            except ValueError:
                # more digits than int() converts (sys.int_info.str_digits_check_threshold) is still an integer.
                # Leading zeros add no value, so it is retried without them; what is still too long is out of range
                m = _INT_RE.fullmatch(v)
                try:
                    if not m:
                        raise ValueError(v)
                    n = int(m.group(1) + m.group(2))
                except ValueError:
                    if m and s.max is not None and m.group(1) != "-":
                        out.append(f"{label} must be at most {s.max}")
                    elif m and s.min is not None and m.group(1) == "-":
                        out.append(f"{label} must be at least {s.min}")
                    else:
                        out.append(f"{label} must be an integer")
                    continue
            if s.min is not None and n < s.min:
                out.append(f"{label} must be at least {s.min}")
            elif s.max is not None and n > s.max:
                out.append(f"{label} must be at most {s.max}")
    return out


@dataclass(frozen=True, repr=False)
class InstanceSpec:
    """One configured instance: its name ([a-z0-9]+), its type, and its settings (lower-case keys, TYPE excluded,
    TIMEOUT included). The repr names the keys only, so secrets never reach a log line."""
    name: str
    type: str
    settings: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"InstanceSpec({self.name!r}, {self.type!r}, keys={sorted(self.settings)!r})"

    @property
    def timeout(self) -> int:
        v = self.settings.get("timeout") or "60"
        m = _INT_RE.fullmatch(v)  # without leading zeros, as setting_problems() reads it
        try:
            return max(1, int(m.group(1) + m.group(2)) if m else int(v))
        except ValueError:
            return 60  # reported by instance_problems()


# The loaded types, cached process-wide with the key they were loaded under: (LW_CONNECTORS_DIR, cwd, sys.path). A
# changed key (a test's own dir or fake dist-info, never production) rebuilds it, so no test patches the registry.
_LOADED = None  # loader.LoadResult
_KEY: tuple | None = None
_BUILDING = False
_LOCK = threading.RLock()


def _key() -> tuple:
    # the cwd too: a relative LW_CONNECTORS_DIR is resolved against it, and the loader never scans it on sys.path
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = ""
    return (os.environ.get("LW_CONNECTORS_DIR", "").strip(), cwd, tuple(sys.path))


def _loaded():  # -> loader.LoadResult (not imported here: loader imports this module)
    global _LOADED, _KEY, _BUILDING
    with _LOCK:
        if _LOADED is not None and _KEY == _key():
            return _LOADED
        if _BUILDING:  # a plugin calling registry() while it is imported would otherwise recurse into the loader
            raise RuntimeError("registry() used while the connector types are being loaded")
        from . import loader
        _BUILDING = True
        try:
            if _LOADED is not None:
                loader.unload(_LOADED)  # drops the previous load's LW_CONNECTORS_DIR modules from sys.modules
                _LOADED = None
            result = loader.load(os.environ)
        finally:
            _BUILDING = False
        # the key after the load: a plugin that edits sys.path while importing must not force a rebuild per call
        _LOADED, _KEY = result, _key()
        return _LOADED


def _reset_registry() -> None:
    """Forget the loaded types (and their LW_CONNECTORS_DIR modules); the next registry() call loads again."""
    global _LOADED, _KEY
    with _LOCK:
        if _LOADED is not None:
            from . import loader
            loader.unload(_LOADED)
        _LOADED, _KEY = None, None


def registry() -> dict[str, type]:
    """type -> connector class: the built-ins plus the third-party types (see loader.py). Loaded on first use (the
    built-in modules import this one) and again when LW_CONNECTORS_DIR, the working directory or sys.path has
    changed."""
    return _loaded().types


def load_problems() -> list[str]:
    """Loading problems that stop the start whatever the instances use (e.g. LW_CONNECTORS_DIR is not a directory)."""
    return list(_loaded().problems)


def type_origins() -> dict:
    """type -> loader.Origin for every registered type."""
    return dict(_loaded().origins)


def broken_types() -> dict[str, str]:
    """type -> why it is not loaded, for every declared type that was refused or failed to import. A plugin that
    declares a built-in type name is not here: the built-in stays loaded, and the refusal is an ERROR in the log."""
    return dict(_loaded().broken)


def type_help() -> str:
    """Every loaded type and where it comes from: the built-ins, then the entry points, then LW_CONNECTORS_DIR (the
    order they are loaded in). No settings, and no path other than the configured LW_CONNECTORS_DIR."""
    from .loader import BUILTIN, DIR
    reg, origins = registry(), type_origins()
    parts = [f"{', '.join(sorted(t for t in reg if origins.get(t) and origins[t].kind == BUILTIN))} (built-in)"]
    for o, t in sorted(((o, t) for t, o in origins.items() if o.kind != BUILTIN and t in reg),
                       key=lambda ot: (ot[0].kind == DIR, ot[1])):
        where = f"LW_CONNECTORS_DIR {o.location}" if o.kind == DIR else o.kind
        parts.append(f"{t} {o.type_version} ({f'{o.dist} {o.version}'.strip()}, {where})")
    return "; ".join(parts)


def secret_keys(type_: str) -> frozenset[str]:
    cls = registry().get(type_)
    return frozenset(s.key for s in cls.describe().settings if s.secret) if cls else frozenset()


def instances_context(specs: Iterable[InstanceSpec]) -> HostContext:
    """One context for all instances, redacting every secret value any of them holds."""
    return HostContext(redact=make_redactor([v for sp in specs for k, v in sp.settings.items() if k in secret_keys(sp.type)]))


def build_instance(spec: InstanceSpec, ctx: HostContext, client: object | None = None) -> Connector:
    """The connector object for a spec (no network I/O; an snmp_switch with PROFILE_FILE reads that local file).
    Raises KeyError for an unknown type. client: an already built client to wrap instead of a new one (the built-in
    wrappers accept it)."""
    cls = registry()[spec.type]
    settings = {k: v for k, v in spec.settings.items() if k not in HOST_KEYS}
    ctx = replace(ctx, timeout=spec.timeout)  # a copy: the shared context is lent to every instance
    return cls(spec.name, settings, ctx, client=client) if client is not None else cls(spec.name, settings, ctx)


def instance_problems(spec: InstanceSpec, conn: Connector | None = None) -> list[str]:
    """Everything wrong with one instance, as "connector <name> (<type>): ..." lines: the type, the host keys,
    unknown keys, the type's declared settings, then the instance's own validate(). No network I/O (see build_instance)."""
    if not spec.type:
        return [f"connector {spec.name}: TYPE is required"]
    cls = registry().get(spec.type)
    if cls is None and spec.type in _loaded().broken:  # declared but refused or failed: say why, not "unknown"
        return [f"connector {spec.name} ({spec.type}): cannot be loaded: {_loaded().broken[spec.type]}"]
    if cls is None:
        return [f"connector {spec.name}: unknown type {spec.type!r} (known: {', '.join(sorted(registry()))})"]
    info = cls.describe()
    head = f"connector {spec.name} ({spec.type})"
    if info.api_version != API_VERSION:
        return [f"{head}: written for connector API {info.api_version}, this host has {API_VERSION}"]
    problems = setting_problems(spec.name, spec.type, HOST_SETTINGS[1:], spec.settings)
    known = {s.key for s in info.settings} | HOST_KEYS
    problems += [f"{head}: unknown setting {k.upper()}" for k in sorted(spec.settings) if k not in known]
    try:
        conn = conn or build_instance(spec, HostContext())
        own = conn.validate()
    except Exception as e:  # a constructor that chokes on a value: name the type of failure, never the value
        return problems + [f"{head}: cannot be set up ({type(e).__name__})"]
    generic = setting_problems(spec.name, spec.type, info.settings, getattr(conn, "settings", spec.settings))
    problems += generic
    problems += [p if p.startswith("connector ") else f"{head}: {p}" for p in own if p not in generic]
    return problems
