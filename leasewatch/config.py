"""Configuration from environment variables (see .env.example)."""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import stringprep
import unicodedata
from dataclasses import dataclass, field
from encodings.idna import nameprep
from typing import Mapping
from urllib.parse import urlparse

from .connectors import (_URL_BAD_CHAR_RE, NAME_RE, InstanceSpec, instance_problems, load_problems, registry, secret_keys,
                         url_has_credentials)

ENV_PREFIX = "LW_CONNECTOR__"
MAX_SECRET_FILE = 64 * 1024  # bytes of a <KEY>_FILE; a secret is a few hundred at most

log = logging.getLogger("leasewatch.config")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    v = _env(name)
    if not v:
        return default  # "NEW_DAYS=" in an env file means the default, not a typo
    try:
        return int(v)
    except ValueError:
        # capped: a long junk value would otherwise fill the log line
        log.warning("%s=%r is not an integer, using %d", name, v[:40], default)
        return default


def _is_http(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))  # urllib reads the scheme case-insensitively


# the ideographic and fullwidth full stops, which the IDNA codec reads as label separators
_IDN_DOTS = str.maketrans("\u3002\uff0e\uff61", "...")


# the UTS-46 deviation characters: the stdlib codec (IDNA2003) maps them to "ss", "σ" or nothing, browsers
# (UTS-46 nontransitional) keep them
_IDN_DEVIATIONS = re.compile("([\u00df\u03c2\u200c\u200d])")


def _nameprep_map(text: str) -> str:
    """The mapping step of nameprep (tables B.1 and B.2, then NFKC) without its checks."""
    # Unicode 3.2 as nameprep: a later NFKC leaves some characters upper case (U+1D2C gives "A")
    return unicodedata.ucd_3_2_0.normalize("NFKC", "".join(stringprep.map_table_b2(c) for c in text if not stringprep.in_table_b1(c)))


def _idn_label(label: str) -> str:
    if not label:
        raise UnicodeError("empty label")  # as the codec does for the whole name: such a name matches nothing
    if _IDN_DEVIATIONS.search(label):
        # nameprep on the whole label checks it (prohibited characters, bidi) as the codec would; per piece the bidi
        # rule would reject an RTL label with a digit before a joiner
        nameprep(label)
        # the text around the deviations is mapped as nameprep maps it (case, soft hyphen, NFKC); they stay as they are
        pieces = _IDN_DEVIATIONS.split(label)
        mapped = "".join(p if i % 2 else _nameprep_map(p) for i, p in enumerate(pieces))
        return "xn--" + mapped.encode("punycode").decode("ascii")
    return label.encode("idna").decode("ascii")


def _host_only(entry: str) -> str:
    """An ALLOWED_HOSTS entry in the same form host_allowed() compares: lower case, no port, no trailing dot, punycode."""
    # "Σ" first: str.lower() makes a word-final one "ς", which a browser would send as "σ"
    h = entry.strip().replace("\u03a3", "\u03c3").lower()
    if h == "*":
        return h
    if h.startswith("["):
        h = h[1:h.find("]")] if "]" in h else h
    elif h.count(":") == 1:
        h = h.rsplit(":", 1)[0]
    h = h.translate(_IDN_DOTS).rstrip(".")
    if not h.isascii():
        # a browser sends a non-ASCII name in its punycode form
        try:
            h = ".".join(_idn_label(label) for label in h.split("."))
        except UnicodeError:
            pass  # matches nothing; a browser could not send it either
    # only the literal "*" turns the check off: "*." or "*:80" becomes "", an entry without a host (validate() reports it)
    return "" if h == "*" else h


def parse_instances(environ: Mapping[str, str]) -> tuple[list[InstanceSpec], list[str]]:
    """LW_CONNECTORS (instance names, in merge order) and LW_CONNECTOR__<NAME>__<KEY> into specs, plus the problems
    found while parsing. A secret key also accepts <KEY>_FILE: the file's stripped content is the value (read here)."""
    problems: list[str] = []
    by_name: dict[str, dict[str, str]] = {}
    var_of: dict[tuple[str, str], str] = {}  # (name, key) -> the variable that set it, for the messages below
    for k in sorted(environ):
        if k.startswith(ENV_PREFIX):
            name, sep, key = k[len(ENV_PREFIX):].partition("__")
            if not (name and sep and key):
                # LW_CONNECTOR__FW1_SECRET (one underscore) or an empty name or key would otherwise vanish silently
                problems.append(f"{k} is not of the form LW_CONNECTOR__<NAME>__<KEY>")
                continue
            name, key = name.lower(), key.lower()
            if (name, key) in var_of:
                # which of the two wins would depend on the environment's order; never echo the values
                problems.append(f"{var_of[name, key]} and {k} differ only in case")
                continue
            var_of[name, key] = k
            by_name.setdefault(name, {})[key] = environ[k].strip()
    # lower-cased as by_name is: an upper-case entry (FW1) gets only its invalid-name problem below, not a false
    # "fw1 is not in LW_CONNECTORS" next to it
    listed = {n.strip().lower() for n in environ.get("LW_CONNECTORS", "").split(",")}
    # a typo in an instance name (or one dropped from the list) would otherwise silently ignore its settings
    for name in sorted(set(by_name) - listed):
        first = var_of[name, min(by_name[name])]
        problems.append(f"{first} set but {name} is not in LW_CONNECTORS")
    specs: list[InstanceSpec] = []
    for name in (n.strip() for n in environ.get("LW_CONNECTORS", "").split(",")):
        if not name:
            continue
        if not NAME_RE.match(name):
            problems.append(f"LW_CONNECTORS: {name!r} is not a valid instance name (only a-z and 0-9)")
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
                # utf-8-sig: a BOM from a Windows editor would otherwise become part of the secret
                with open(path, encoding="utf-8-sig") as f:
                    value = f.read(MAX_SECRET_FILE + 1)  # the file may grow between the size check and the read
                if len(value) > MAX_SECRET_FILE:
                    problems.append(f"{label} (larger than 64 KiB)")
                    continue
                settings[key] = value.strip()
            except (OSError, UnicodeDecodeError) as e:
                problems.append(f"connector {name} ({type_}): cannot read {key.upper()}_FILE ({getattr(e, 'strerror', None) or type(e).__name__})")
        specs.append(InstanceSpec(name, type_, settings))
    return specs, problems


# The 1.0 source variables, removed in 1.1: a deployment that still sets one would otherwise run without that source
# unnoticed. (variable -> key on the instance, what it configured, the instance name and type to use, a note)
REMOVED_VARS = (
    ({"FW1_URL": "URL", "FW1_KEY": "KEY", "FW1_SECRET": "SECRET", "FW1_VERIFY_TLS": "VERIFY_TLS"},
     "the firewall", "fw1", "opnsense", ""),
    ({"DHCP_BACKEND": "DHCP_BACKEND"}, "the firewall", "fw1", "opnsense", " (default kea)"),
    ({"IGNORE_INTERFACES": "IGNORE_INTERFACES"}, "the firewall", "fw1", "opnsense", " (default wan,lo0)"),
    ({"PROXY_FOR_LAN": "PROXY"}, "the firewall", "fw1", "opnsense", " (default 0; a unifi instance takes PROXY too)"),
    ({"SNMP_HOST": "HOST", "SNMP_NAME": "NAME", "SNMP_USER": "USER", "SNMP_AUTH": "AUTH", "SNMP_AUTH_KEY": "AUTH_KEY",
      "SNMP_PRIV_KEY": "PRIV_KEY", "SNMP_PROFILE": "PROFILE", "SNMP_PROFILE_FILE": "PROFILE_FILE", "SNMP_MIN_MACS": "MIN_MACS"},
     "the switch", "switch", "snmp_switch", ""),
    ({"UNIFI_URL": "URL", "UNIFI_SITE": "SITE", "UNIFI_USER": "USER", "UNIFI_PASSWORD": "PASSWORD", "UNIFI_VERIFY_TLS": "VERIFY_TLS"},
     "the UniFi controller", "unifi", "unifi", ""),
)


def removed_problems(environ: Mapping[str, str]) -> list[str]:
    """One problem per family of removed 1.0 variables present in `environ` (also when empty: the line is still in
    the env file). Names only, never a value: several of them are secrets."""
    out = []
    for names, what, inst, type_, note in REMOVED_VARS:
        found = [k for k in names if k in environ]
        if not found:
            continue
        listed = inst if inst == "fw1" else f"fw1,{inst}"
        new = ", ".join(f"{ENV_PREFIX}{inst.upper()}__{names[k]}=…" for k in found)
        out.append(f"{', '.join(found)} {'is' if len(found) == 1 else 'are'} no longer supported: configure {what} as "
                   f"LW_CONNECTORS={listed} with {ENV_PREFIX}{inst.upper()}__TYPE={type_}, {new}{note} (see .env.example)")
    return out


@dataclass
class Config:
    # what a device whose lease is gone shows as lease type: "keep" the last one, clear it after the "grace" period, or "immediate"ly
    lease_type_mode: str = field(default_factory=lambda: _env("LEASE_TYPE_MODE", "keep").lower())
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
    # connector instances from LW_CONNECTORS (the only way to configure a source)
    connector_specs: list = field(default_factory=list, init=False)
    connector_problems: list = field(default_factory=list, init=False, repr=False)
    connectors_listed: bool = field(default=False, init=False, repr=False)  # LW_CONNECTORS was set (not empty)

    def __post_init__(self) -> None:
        # B-08.1: load the third-party types first, so parse_instances() -> secret_keys() knows a plugin type's
        # secret keys and reads its <KEY>_FILE instead of calling it an unknown setting
        registry()
        self.connector_specs, problems = parse_instances(os.environ)
        self.connectors_listed = bool(_env("LW_CONNECTORS"))
        if not self.connectors_listed:
            problems.append("LW_CONNECTORS is not set: list the connector instances, e.g. LW_CONNECTORS=fw1 with "
                            f"{ENV_PREFIX}FW1__TYPE=opnsense (see .env.example)")
        self.connector_problems = removed_problems(os.environ) + load_problems() + problems

    @property
    def instances(self) -> list[InstanceSpec]:
        """The configured connector instances, in LW_CONNECTORS order (the merge tie-break order)."""
        return self.connector_specs

    @property
    def unifi_enabled(self) -> bool:
        # only the instance the collector writes unifi_ok/unifi_clients for (collector.ALIASES), as web.py does for
        # meta.switch; another name would show a dot that never turns green
        return any(sp.name == "unifi" and sp.type == "unifi" for sp in self.connector_specs)

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
        # "" (an entry without a host, reported by validate()) must neither match nor replace the PUBLIC_URL default
        allowed = {a for a in self.allowed_hosts if a} or ({_host_only(urlparse(self.public_url).hostname or "")} if self.public_url else set())
        return h in allowed or h.rstrip(".") in allowed

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "leasewatch.sqlite3")

    @property
    def mail_enabled(self) -> bool:
        return bool(self.mailgun_key and self.mailgun_domain and self.mail_to)

    def validate(self) -> list[str]:
        problems = []
        if self.public_url and not _is_http(self.public_url):
            problems.append("PUBLIC_URL must be a URL (https://<host>)")
        # a URL without a host, with an unclosed "[" or a bad port passes the scheme check but fails on every request
        for name, url in (("PUBLIC_URL", self.public_url), ("MAILGUN_API_BASE", self.mailgun_api_base)):
            if not _is_http(url):
                continue  # empty or reported above
            try:
                parts = urlparse(url)
                # .port raises ValueError for a non-numeric or out-of-range port; 0 and spaces or control characters
                # pass urlparse but fail at the first request (url_problems refuses them too)
                if not parts.hostname or parts.port == 0 or _URL_BAD_CHAR_RE.search(url):
                    problems.append(f"{name} is not a valid URL")
            except ValueError:
                problems.append(f"{name} is not a valid URL")
        if not _is_http(self.mailgun_api_base):
            problems.append("MAILGUN_API_BASE must be a URL (https://api.mailgun.net or https://api.eu.mailgun.net)")
        # user:pass@host would end up in logs and error messages; credentials have their own variables
        for name, url in (("PUBLIC_URL", self.public_url), ("MAILGUN_API_BASE", self.mailgun_api_base)):
            if url_has_credentials(url):
                problems.append(f"{name} must not contain credentials")
        if not 1 <= self.listen_port <= 65535:
            problems.append("LISTEN_PORT must be 1-65535")
        if self.new_days < 1:
            problems.append("NEW_DAYS must be at least 1")
        if self.new_days > 3650:
            problems.append("NEW_DAYS must be at most 3650")
        if "" in self.allowed_hosts:
            problems.append("ALLOWED_HOSTS: an entry has no host name")
        if self.online_grace_minutes < 0:
            problems.append("ONLINE_GRACE_MINUTES must not be negative")
        if self.online_grace_minutes > 10080:
            problems.append("ONLINE_GRACE_MINUTES must be at most 10080")
        if self.lease_type_mode not in ("keep", "grace", "immediate"):
            problems.append("LEASE_TYPE_MODE must be keep, grace or immediate")
        if self.poll_seconds < 15:
            problems.append("POLL_SECONDS below 15 is unreasonable for the firewall")
        if self.poll_seconds > 86400:
            problems.append("POLL_SECONDS must be at most 86400")
        problems += self.connector_problems
        for spec in self.connector_specs:
            problems += instance_problems(spec)
        # without the list at all, "LW_CONNECTORS is not set" already says it
        if self.connectors_listed and not any("sighting" in cls.describe().produces for sp in self.connector_specs
                                              for cls in (registry().get(sp.type),) if cls):
            problems.append("LW_CONNECTORS: at least one connector must produce sightings (e.g. type opnsense)")
        return problems
