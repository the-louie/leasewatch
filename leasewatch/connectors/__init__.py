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

import logging
import re
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, ClassVar, Iterable, Mapping, Protocol, runtime_checkable
from urllib.parse import urlparse

from ..fw1 import _NoRedirect, norm_mac

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
    informational in API 1). link: exactly "wired" or "wifi"; any other value is ignored by the host (logged once).
    From an instance with the "controller" role, "wired" means the controller sees the device on a cable: its
    Wi-Fi details are cleared. device: the switch/AP name as the operator knows it. port: short port label
    ("GE1/0/14"), "" for Wi-Fi. uplink: the port leads to more infrastructure, so it is not where the device
    really is; via: what sits behind that port (LLDP neighbour or "7 devices"). vlan: VLAN id, if the source knows
    it. ssid/ap/signal (dBm)/alias: Wi-Fi details and the name set in the controller. radio: free text, shown as
    given ("2.4 GHz", "5 GHz", "6 GHz" suggested)."""
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


@dataclass
class Batch:
    """The result of one collect(). stats: raw counts for status, all optional (the host reads a missing key as 0):
    "leases", "arp", "reservations" (sighting producers), "macs" (switch), "clients" (controller); the host adds
    "dropped" (records with an invalid MAC)."""
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


def make_redactor(secrets: Iterable[str]) -> Callable[[str], str]:
    """Replace every given secret value in a text by "***" (longest first, so a secret containing another is whole)."""
    values = sorted({s for s in secrets if s}, key=len, reverse=True)
    if not values:
        return _redact_nothing

    def redact(text: str) -> str:
        for v in values:
            text = text.replace(v, "***")
        return text
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


def url_problems(key: str, url: str, hint: str) -> list[str]:
    """The URL checks Config.validate() makes: a scheme, a host, and no credentials in it (they would end up in logs)."""
    if not url.startswith(("http://", "https://")):
        return [f"{key} must be a URL ({hint})"]
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return [f"{key} is not a valid URL"]
        netloc = parsed.netloc
    except ValueError:  # e.g. an unclosed "["
        return [f"{key} is not a valid URL"]
    return [f"{key} must not contain credentials"] if "@" in netloc else []


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
                            or any(w in k.lower() for w in ("key", "secret", "password", "token")))
        shown = {k: ("***" if hidden(k) and v else v) for k, v in self.settings.items()}
        return f"{type(self).__name__}({self.name!r}, {shown!r})"


# --- instances: the registry of types and the configured instances built from it -------------------------------

NAME_RE = re.compile(r"^[a-z0-9-]+$")
# keys every instance accepts besides its type's own settings; the host reads them, the connector never sees them
HOST_SETTINGS = (
    Setting("type", required=True, help="connector type (opnsense, snmp_switch, unifi)"),
    Setting("timeout", default="60", kind="int", min=1, max=3600, help="seconds a collect may run before this poll abandons it"),
)
HOST_KEYS = frozenset(s.key for s in HOST_SETTINGS)


def setting_problems(name: str, type_: str, settings: Iterable[Setting], values: Mapping[str, str]) -> list[str]:
    """The checks describe() makes possible: required keys, choices, integer ranges. Never echoes a value."""
    out = []
    for s in settings:
        v = values.get(s.key, "")
        label = f"connector {name} ({type_}): {s.key.upper()}"
        if not v:
            if s.required:
                out.append(f"{label} is required")
        elif s.choices and v not in s.choices:
            out.append(f"{label} must be one of {', '.join(s.choices)}")
        elif s.kind == "int":
            try:
                n = int(v)
            except ValueError:
                out.append(f"{label} must be an integer")
                continue
            if s.min is not None and n < s.min:
                out.append(f"{label} must be at least {s.min}")
            elif s.max is not None and n > s.max:
                out.append(f"{label} must be at most {s.max}")
    return out


@dataclass(frozen=True, repr=False)
class InstanceSpec:
    """One configured instance: its name ([a-z0-9-]+), its type, and its settings (lower-case keys, TYPE excluded,
    TIMEOUT included). The repr names the keys only, so secrets never reach a log line."""
    name: str
    type: str
    settings: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"InstanceSpec({self.name!r}, {self.type!r}, keys={sorted(self.settings)!r})"

    @property
    def timeout(self) -> int:
        try:
            return max(1, int(self.settings.get("timeout") or 60))
        except ValueError:
            return 60  # reported by instance_problems()


_REGISTRY: dict[str, type] | None = None


def registry() -> dict[str, type]:
    """type -> connector class. Built on first use (the built-in modules import this one) and cached in _REGISTRY."""
    global _REGISTRY
    if _REGISTRY is None:
        from .builtin import BUILTIN
        _REGISTRY = {cls.describe().type: cls for cls in BUILTIN}
    return _REGISTRY


def secret_keys(type_: str) -> frozenset[str]:
    cls = registry().get(type_)
    return frozenset(s.key for s in cls.describe().settings if s.secret) if cls else frozenset()


def instances_context(specs: Iterable[InstanceSpec]) -> HostContext:
    """One context for all instances, redacting every secret value any of them holds."""
    return HostContext(redact=make_redactor([v for sp in specs for k, v in sp.settings.items() if k in secret_keys(sp.type)]))


def build_instance(spec: InstanceSpec, ctx: HostContext, client: object | None = None) -> Connector:
    """The connector object for a spec (no I/O). Raises KeyError for an unknown type. client: an already built
    client to wrap instead of a new one (the built-in wrappers accept it)."""
    cls = registry()[spec.type]
    settings = {k: v for k, v in spec.settings.items() if k not in HOST_KEYS}
    return cls(spec.name, settings, ctx, client=client) if client is not None else cls(spec.name, settings, ctx)


def instance_problems(spec: InstanceSpec, conn: Connector | None = None) -> list[str]:
    """Everything wrong with one instance, as "connector <name> (<type>): ..." lines: the type, the host keys,
    unknown keys, the type's declared settings, then the instance's own validate(). No I/O."""
    if not spec.type:
        return [f"connector {spec.name}: TYPE is required"]
    cls = registry().get(spec.type)
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
