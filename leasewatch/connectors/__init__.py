"""Connector contract: the records a data source hands to the host, and the protocol a source implements.

A connector is one configured instance of a source type (an OPNsense firewall, an SNMP switch, a UniFi controller).
The host builds it from a flat dict of string settings, asks it to validate them (no I/O), probes it once with
check(), then calls collect() once per poll. The connector returns plain records in a Batch; it never writes to
the database or to the device it reads from.
"""
from __future__ import annotations

import logging
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, ClassVar, Iterable, Mapping, Protocol, runtime_checkable
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


@dataclass(frozen=True)
class ConnectorInfo:
    """What a connector type is: its name ([a-z0-9_]+), its own version, the contract version it was written
    against (must equal API_VERSION), which record kinds it emits ("sighting", "attachment") and its settings."""
    type: str
    version: str
    api_version: int
    produces: frozenset[str]
    settings: tuple[Setting, ...]


@dataclass(frozen=True)
class Sighting:
    """L2/L3 identity of one device, as one source saw it.

    mac: normalised "aa:bb:cc:dd:ee:ff". source: the connector instance name. kind: what the evidence is,
    "dhcp" | "arp" | "client" | "scan". presence: True only if the source saw the device on the wire now (an ARP
    entry, ISC's "online" lease status, an active controller client); a lease or reservation alone is False.
    observed_at: epoch seconds when the connector collected it. network: human interface name (LAN, IOT), the
    "vlan" column today. iface: source-specific interface id (opt3). lease_type: "static" | "dynamic" | "",
    only kind "dhcp" sets it. client_id: DHCP client-id / DUID when known (reserved, unused so far)."""
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

    link: "wired" | "wifi". device: the switch/AP name as the operator knows it. port: short port label
    ("GE1/0/14"), "" for Wi-Fi. uplink: the port leads to more infrastructure, so it is not where the device
    really is; via: what sits behind that port (LLDP neighbour or "7 devices"). vlan: VLAN id, if the source knows
    it. ssid/ap/signal (dBm)/radio/alias: Wi-Fi details and the name set in the controller."""
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
    """The result of one collect(). stats: raw counts for status (e.g. leases/arp). extra: source-specific objects
    the host still reads directly while the merge is being moved over (the switch snapshot, the UniFi client map);
    not part of the stable contract."""
    sightings: list[Sighting] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)


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


@runtime_checkable
class Connector(Protocol):
    """Lifecycle: describe() (class level, no instance) -> __init__ (no I/O) -> validate() (no I/O, list of
    problems, empty = fine) -> check() (one cheap probe, raises ConnectorError, may be retried) -> collect() once
    per poll (raises ConnectorError) -> close() (never raises). Third-party libraries are imported inside
    check()/collect(), never at module import."""

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
        out = []
        for s in self.INFO.settings:
            v = self.settings.get(s.key, "")
            if s.required and not v:
                out.append(f"connector {self.name} ({self.INFO.type}) requires {s.key}")
            elif v and s.choices and v not in s.choices:
                out.append(f"connector {self.name} ({self.INFO.type}): {s.key} must be one of {', '.join(s.choices)}")
        return out

    def __repr__(self) -> str:
        secret = {s.key for s in self.INFO.settings if s.secret}
        shown = {k: ("***" if k in secret and v else v) for k, v in self.settings.items()}
        return f"{type(self).__name__}({self.name!r}, {shown!r})"
