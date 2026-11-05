"""Configuration from environment variables (see .env.example)."""
from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlparse

from .connectors import NAME_RE, InstanceSpec, instance_problems, registry, secret_keys

ENV_PREFIX = "LW_CONNECTOR__"
MAX_SECRET_FILE = 64 * 1024  # bytes of a <KEY>_FILE; a secret is a few hundred at most


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        logging.getLogger("leasewatch").warning("%s=%r is not an integer, using %d", name, _env(name), default)
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = _env(name, "1" if default else "0").lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    logging.getLogger("leasewatch").warning("%s=%r is not a boolean, using %s", name, v, default)
    return default


def _host_only(entry: str) -> str:
    """An ALLOWED_HOSTS entry in the same form host_allowed() compares: lower case, no port, no trailing dot."""
    h = entry.strip().lower()
    if h.startswith("["):
        h = h[1:h.find("]")] if "]" in h else h
    elif h.count(":") == 1:
        h = h.rsplit(":", 1)[0]
    return h.rstrip(".") if h != "*" else h


def parse_instances(environ: Mapping[str, str]) -> tuple[list[InstanceSpec], list[str]]:
    """LW_CONNECTORS (instance names, in merge order) and LW_CONNECTOR__<NAME>__<KEY> into specs, plus the problems
    found while parsing. A secret key also accepts <KEY>_FILE: the file's stripped content is the value (read here)."""
    problems: list[str] = []
    by_name: dict[str, dict[str, str]] = {}
    var_of: dict[tuple[str, str], str] = {}  # (name, key) -> the variable that set it, for the messages below
    for k in sorted(environ):
        if k.startswith(ENV_PREFIX):
            name, sep, key = k[len(ENV_PREFIX):].partition("__")
            if sep and key:
                name, key = name.lower(), key.lower()
                if (name, key) in var_of:
                    # which of the two wins would depend on the environment's order; never echo the values
                    problems.append(f"{var_of[name, key]} and {k} differ only in case")
                    continue
                var_of[name, key] = k
                by_name.setdefault(name, {})[key] = environ[k].strip()
    listed = {n.strip() for n in environ.get("LW_CONNECTORS", "").split(",")}
    # a typo in an instance name (or one dropped from the list) would otherwise silently ignore its settings
    for name in sorted(set(by_name) - listed):
        first = var_of[name, min(by_name[name])]
        problems.append(f"{first} set but {name} is not in LW_CONNECTORS")
    specs: list[InstanceSpec] = []
    for name in (n.strip() for n in environ.get("LW_CONNECTORS", "").split(",")):
        if not name:
            continue
        if not NAME_RE.match(name):
            problems.append(f"LW_CONNECTORS: {name!r} is not a valid instance name (a-z, 0-9 and -)")
            continue
        if any(sp.name == name for sp in specs):
            problems.append(f"LW_CONNECTORS: {name} is listed twice")
            continue
        settings = dict(by_name.get(name, {}))
        type_ = settings.pop("type", "").lower()
        for key in sorted(secret_keys(type_)):
            path = settings.pop(key + "_file", "")
            if not path:
                continue
            if settings.get(key):
                problems.append(f"connector {name} ({type_}): set {key.upper()} or {key.upper()}_FILE, not both")
                continue
            label = f"connector {name} ({type_}): cannot read {key.upper()}_FILE"
            # a FIFO, a device such as /dev/zero or a huge file would block or stall the start
            if os.path.exists(path) and not os.path.isfile(path):
                problems.append(f"{label} (not a regular file)")
                continue
            try:
                if os.path.getsize(path) > MAX_SECRET_FILE:
                    problems.append(f"{label} (larger than 64 KiB)")
                    continue
                with open(path, encoding="utf-8") as f:
                    value = f.read(MAX_SECRET_FILE + 1)  # the file may grow between the size check and the read
                if len(value) > MAX_SECRET_FILE:
                    problems.append(f"{label} (larger than 64 KiB)")
                    continue
                settings[key] = value.strip()
            except (OSError, UnicodeDecodeError) as e:
                problems.append(f"connector {name} ({type_}): cannot read {key.upper()}_FILE ({getattr(e, 'strerror', None) or type(e).__name__})")
        specs.append(InstanceSpec(name, type_, settings))
    return specs, problems


@dataclass
class Config:
    fw1_url: str = field(default_factory=lambda: _env("FW1_URL", ""))
    fw1_key: str = field(default_factory=lambda: _env("FW1_KEY"), repr=False)
    fw1_secret: str = field(default_factory=lambda: _env("FW1_SECRET"), repr=False)
    fw1_verify_tls: bool = field(default_factory=lambda: _env_bool("FW1_VERIFY_TLS", True))
    # which OPNsense DHCPv4 server to read leases from: "kea" (default) or "isc" (end-of-life in OPNsense, a plugin from 26.1)
    dhcp_backend: str = field(default_factory=lambda: _env("DHCP_BACKEND", "kea").lower())
    # what a device whose lease is gone shows as lease type: "keep" the last one, clear it after the "grace" period, or "immediate"ly
    lease_type_mode: str = field(default_factory=lambda: _env("LEASE_TYPE_MODE", "keep").lower())
    # honour http(s)_proxy for the LAN clients (firewall, UniFi); off by default so a proxy meant for the internet
    # never sees the firewall API key. Mail (Mailgun) always uses the environment's proxy settings.
    lan_proxy: bool = field(default_factory=lambda: _env_bool("PROXY_FOR_LAN", False))
    poll_seconds: int = field(default_factory=lambda: _env_int("POLL_SECONDS", 120))
    data_dir: str = field(default_factory=lambda: _env("DATA_DIR", "/data"))
    listen_host: str = field(default_factory=lambda: _env("LISTEN_HOST", "0.0.0.0"))
    listen_port: int = field(default_factory=lambda: _env_int("LISTEN_PORT", 8080))
    site_name: str = field(default_factory=lambda: _env("SITE_NAME", "Leasewatch"))
    new_days: int = field(default_factory=lambda: _env_int("NEW_DAYS", 7))
    # a device not seen for this long is "offline" even if a lease is still active
    online_grace_minutes: int = field(default_factory=lambda: _env_int("ONLINE_GRACE_MINUTES", 10))
    # mail on new devices (Mailgun HTTP API); leave MAILGUN_KEY empty to disable
    mailgun_key: str = field(default_factory=lambda: _env("MAILGUN_KEY"), repr=False)
    mailgun_domain: str = field(default_factory=lambda: _env("MAILGUN_DOMAIN"))
    mail_to: str = field(default_factory=lambda: _env("MAIL_TO"))
    mail_from_name: str = field(default_factory=lambda: _env("MAIL_FROM_NAME", "leasewatch"))
    # EU-region domains use https://api.eu.mailgun.net
    mailgun_api_base: str = field(default_factory=lambda: _env("MAILGUN_API_BASE", "https://api.mailgun.net").rstrip("/"))
    public_url: str = field(default_factory=lambda: _env("PUBLIC_URL", "").rstrip("/"))
    # Host header values that may use the API (DNS-rebinding guard). Default: the host of PUBLIC_URL. "*" = any.
    # IP literals and localhost are always accepted, because a rebinding attack has to use a name.
    allowed_hosts: tuple = field(default_factory=lambda: tuple(_host_only(x) for x in _env("ALLOWED_HOSTS").split(",") if x.strip()))
    # interfaces to ignore completely (comma separated interface identifiers, e.g. "wan,opt6")
    ignore_interfaces: tuple = field(default_factory=lambda: tuple(x for x in _env("IGNORE_INTERFACES", "wan,lo0").split(",") if x))

    # optional enrichers: switch port over SNMPv3 (empty SNMP_HOST = off), Wi-Fi from a UniFi controller (empty UNIFI_URL = off)
    snmp_host: str = field(default_factory=lambda: _env("SNMP_HOST"))
    snmp_name: str = field(default_factory=lambda: _env("SNMP_NAME", "switch"))
    snmp_user: str = field(default_factory=lambda: _env("SNMP_USER", "leasewatch"))
    snmp_auth: str = field(default_factory=lambda: _env("SNMP_AUTH", "SHA").upper().replace("-", ""))
    snmp_auth_key: str = field(default_factory=lambda: _env("SNMP_AUTH_KEY"), repr=False)
    snmp_priv_key: str = field(default_factory=lambda: _env("SNMP_PRIV_KEY"), repr=False)
    # SNMP profile of the switch: empty = detected from sysObjectID/sysDescr; PROFILE_FILE (own JSON) wins over PROFILE
    snmp_profile: str = field(default_factory=lambda: _env("SNMP_PROFILE"))
    snmp_profile_file: str = field(default_factory=lambda: _env("SNMP_PROFILE_FILE"))
    # MACs on a port without an LLDP neighbour that make it an uplink; empty = the profile's uplink.min_macs
    snmp_min_macs: str = field(default_factory=lambda: _env("SNMP_MIN_MACS"))
    unifi_url: str = field(default_factory=lambda: _env("UNIFI_URL").rstrip("/"))
    unifi_site: str = field(default_factory=lambda: _env("UNIFI_SITE", "default"))
    unifi_user: str = field(default_factory=lambda: _env("UNIFI_USER"))
    unifi_password: str = field(default_factory=lambda: _env("UNIFI_PASSWORD"), repr=False)
    unifi_verify_tls: bool = field(default_factory=lambda: _env_bool("UNIFI_VERIFY_TLS", True))
    # connector instances from LW_CONNECTORS (None when unset: the legacy variables above describe them)
    connector_specs: list | None = field(default=None, init=False)
    connector_problems: list = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        if _env("LW_CONNECTORS"):
            self.connector_specs, self.connector_problems = parse_instances(os.environ)

    @property
    def instances(self) -> list[InstanceSpec]:
        """The configured connector instances, in LW_CONNECTORS order (the merge tie-break order)."""
        if self.connector_specs is not None:
            return self.connector_specs
        from .connectors.legacy import legacy_specs  # legacy.py imports this module
        return legacy_specs(self)

    @property
    def snmp_enabled(self) -> bool:
        return bool(self.snmp_host and self.snmp_auth_key and self.snmp_priv_key)

    @property
    def unifi_enabled(self) -> bool:
        return bool(self.unifi_url and self.unifi_user and self.unifi_password)

    def host_allowed(self, host: str) -> bool:
        """`host` as sent in the Host header (may carry a port). See allowed_hosts."""
        h = (host or "").strip().lower()
        if not h:
            return True  # HTTP/1.0 clients; a browser always sends Host
        if h.startswith("["):
            h = h[1:h.find("]")] if "]" in h else h
        elif h.count(":") == 1:
            h = h.rsplit(":", 1)[0]
        if h in ("localhost", "localhost.") or "*" in self.allowed_hosts:
            return True
        try:
            ipaddress.ip_address(h)
            return True
        except ValueError:
            pass
        allowed = set(self.allowed_hosts) or ({(urlparse(self.public_url).hostname or "").rstrip(".")} if self.public_url else set())
        return h in allowed or h.rstrip(".") in allowed

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "leasewatch.sqlite3")

    @property
    def mail_enabled(self) -> bool:
        return bool(self.mailgun_key and self.mailgun_domain and self.mail_to)

    def validate(self) -> list[str]:
        problems = []
        # with LW_CONNECTORS the FW1_*/SNMP_*/UNIFI_* variables are not read; the instances are checked instead
        legacy = self.connector_specs is None
        if legacy and (not self.fw1_key or not self.fw1_secret):
            problems.append("FW1_KEY / FW1_SECRET missing")
        if legacy and not self.fw1_url.startswith(("http://", "https://")):
            problems.append("FW1_URL must be set (https://<opnsense>)")
        if self.public_url and not self.public_url.startswith(("http://", "https://")):
            problems.append("PUBLIC_URL must be a URL (https://<host>)")
        if legacy and self.unifi_url and not self.unifi_url.startswith(("http://", "https://")):
            problems.append("UNIFI_URL must be a URL (https://<controller>)")
        legacy_urls = (("FW1_URL", self.fw1_url), ("UNIFI_URL", self.unifi_url)) if legacy else ()
        # a URL without a host, or with an unclosed "[", passes the scheme check but fails on every request
        for name, url in legacy_urls[:1] + (("PUBLIC_URL", self.public_url),) + legacy_urls[1:]:
            if not url.startswith(("http://", "https://")):
                continue  # empty or reported above
            try:
                if not urlparse(url).hostname:
                    problems.append(f"{name} is not a valid URL")
            except ValueError:
                problems.append(f"{name} is not a valid URL")
        if not self.mailgun_api_base.startswith(("http://", "https://")):
            problems.append("MAILGUN_API_BASE must be a URL (https://api.mailgun.net or https://api.eu.mailgun.net)")
        # user:pass@host would end up in logs and error messages; credentials have their own variables
        for name, url in legacy_urls + (("PUBLIC_URL", self.public_url), ("MAILGUN_API_BASE", self.mailgun_api_base)):
            try:
                netloc = urlparse(url).netloc
            except ValueError:  # e.g. an unclosed "[": reported above
                netloc = url
            if "@" in netloc:
                problems.append(f"{name} must not contain credentials")
        if not 1 <= self.listen_port <= 65535:
            problems.append("LISTEN_PORT must be 1-65535")
        if self.new_days < 1:
            problems.append("NEW_DAYS must be at least 1")
        if self.new_days > 3650:
            problems.append("NEW_DAYS must be at most 3650")
        if self.online_grace_minutes < 0:
            problems.append("ONLINE_GRACE_MINUTES must not be negative")
        if self.online_grace_minutes > 10080:
            problems.append("ONLINE_GRACE_MINUTES must be at most 10080")
        if legacy and self.dhcp_backend not in ("isc", "kea"):
            problems.append("DHCP_BACKEND must be isc or kea")
        if self.lease_type_mode not in ("keep", "grace", "immediate"):
            problems.append("LEASE_TYPE_MODE must be keep, grace or immediate")
        if self.poll_seconds < 15:
            problems.append("POLL_SECONDS below 15 is unreasonable for the firewall")
        if self.poll_seconds > 86400:
            problems.append("POLL_SECONDS must be at most 86400")
        if legacy and self.snmp_host and not self.snmp_enabled:
            problems.append("SNMP_HOST set but SNMP_AUTH_KEY/SNMP_PRIV_KEY missing")
        if legacy and self.snmp_host and self.snmp_auth not in ("SHA", "SHA256"):
            problems.append("SNMP_AUTH must be SHA or SHA256")
        if legacy and self.snmp_enabled and (self.snmp_profile or self.snmp_profile_file or self.snmp_min_macs):
            # the switch wrapper checks these; its "connector switch (snmp_switch): PROFILE ..." lines are renamed to the
            # variables the operator actually set
            from .connectors.legacy import legacy_specs  # legacy.py imports this module
            head = "connector switch (snmp_switch): "
            spec = next(sp for sp in legacy_specs(self) if sp.name == "switch")
            problems += ["SNMP_" + p[len(head):] for p in instance_problems(spec)
                         if p.startswith(head) and p[len(head):].startswith(("PROFILE", "MIN_MACS"))]
        if legacy and self.unifi_url and not self.unifi_enabled:
            problems.append("UNIFI_URL set but UNIFI_USER/UNIFI_PASSWORD missing")
        if not legacy:
            problems += self.connector_problems
            for spec in self.connector_specs:
                problems += instance_problems(spec)
            if not any("sighting" in cls.describe().produces for sp in self.connector_specs
                       for cls in (registry().get(sp.type),) if cls):
                problems.append("LW_CONNECTORS: at least one connector must produce sightings (e.g. type opnsense)")
        return problems
