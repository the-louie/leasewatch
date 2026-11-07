"""Configuration from environment variables (see .env.example)."""
from __future__ import annotations

import base64
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

from .auth import parse_hash
from .connectors import (_URL_BAD_CHAR_RE, NAME_RE, InstanceSpec, instance_problems, load_problems, parse_bool, registry,
                         secret_keys, url_has_credentials, url_problems)

ENV_PREFIX = "LW_CONNECTOR__"
SMTP_PORTS = {"starttls": 587, "tls": 465, "none": 25}  # SMTP_TLS -> default SMTP_PORT
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


def _is_address(addr: str) -> bool:
    """A plausible mail address: an "@" with text on both sides, no blank or control character (a CR/LF would
    inject a header)."""
    a = addr.strip()
    local, at, domain = a.rpartition("@")
    return bool(local and at and domain) and not any(c.isspace() or unicodedata.category(c) == "Cc" for c in a)


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
    # archive devices not online for this many days that have no name and are not marked known; 0 = off
    prune_days: int = field(default_factory=lambda: _env_int("PRUNE_DAYS", 0))
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
    # optional basic auth for every path; on only when both are set (python -m leasewatch hash-password)
    auth_user: str = field(default_factory=lambda: _env("AUTH_USER"))
    auth_password_hash: str = field(default_factory=lambda: _env("AUTH_PASSWORD_HASH"), repr=False)
    # mail through an SMTP server (on when SMTP_HOST, SMTP_FROM and MAIL_TO are set). TLS: starttls (required, never
    # downgraded), tls (implicit, SMTPS) or none; SMTP_PORT -1 = the default for the TLS mode (set in __post_init__)
    smtp_host: str = field(default_factory=lambda: _env("SMTP_HOST"))
    smtp_tls: str = field(default_factory=lambda: _env("SMTP_TLS", "starttls").lower() or "starttls")
    smtp_port: int = field(default_factory=lambda: _env_int("SMTP_PORT", -1))
    smtp_user: str = field(default_factory=lambda: _env("SMTP_USER"))
    smtp_password: str = field(default_factory=lambda: _env("SMTP_PASSWORD"), repr=False)
    smtp_from: str = field(default_factory=lambda: _env("SMTP_FROM"))
    smtp_verify_tls: str = field(default_factory=lambda: _env("SMTP_VERIFY_TLS", "1"))
    # a POST per batch of new devices; the URL often carries the token (Discord, Home Assistant), so it is a secret
    webhook_url: str = field(default_factory=lambda: _env("WEBHOOK_URL"), repr=False)
    webhook_secret: str = field(default_factory=lambda: _env("WEBHOOK_SECRET"), repr=False)
    webhook_format: str = field(default_factory=lambda: _env("WEBHOOK_FORMAT", "json").lower() or "json")
    # connector instances from LW_CONNECTORS (the only way to configure a source)
    connector_specs: list = field(default_factory=list, init=False)
    connector_problems: list = field(default_factory=list, init=False, repr=False)
    connectors_listed: bool = field(default=False, init=False, repr=False)  # LW_CONNECTORS was set (not empty)

    def __post_init__(self) -> None:
        # B-08.1: load the third-party types first, so parse_instances() -> secret_keys() knows a plugin type's
        # secret keys and reads its <KEY>_FILE instead of calling it an unknown setting
        registry()
        if self.smtp_port == -1:
            self.smtp_port = SMTP_PORTS.get(self.smtp_tls, 587)
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
    def auth_enabled(self) -> bool:
        return bool(self.auth_user and self.auth_password_hash)

    @property
    def mail_channels(self) -> list[str]:
        """The notification channels whose settings are complete, in send order."""
        out = []
        if self.mailgun_key and self.mailgun_domain and self.mail_to:
            out.append("mailgun")
        if self.smtp_host and self.smtp_from and self.mail_to:
            out.append("smtp")
        if self.webhook_url:
            out.append("webhook")
        return out

    @property
    def mail_enabled(self) -> bool:
        """Any notification channel is configured (the name predates SMTP and webhooks)."""
        return bool(self.mail_channels)

    def _notify_problems(self) -> list[str]:
        """SMTP and webhook settings. Never echoes a value: the password, the URL (token) and the secret are secrets,
        and the addresses are personal data."""
        problems = []
        if self.smtp_tls not in SMTP_PORTS:
            problems.append("SMTP_TLS must be starttls, tls or none")
        if self.smtp_host:
            if not 1 <= self.smtp_port <= 65535:
                problems.append("SMTP_PORT must be 1-65535")
            if not _is_address(self.smtp_from):
                problems.append("SMTP_FROM must be an e-mail address (required with SMTP_HOST)")
            if not self.mail_to or not all(_is_address(a) for a in self.mail_to.split(",")):
                problems.append("MAIL_TO must be one or more e-mail addresses, comma separated (required with SMTP_HOST)")
            if bool(self.smtp_user) != bool(self.smtp_password):
                problems.append("SMTP_USER and SMTP_PASSWORD must be set together")
            if self.smtp_password and self.smtp_tls == "none":
                # the password would cross the network in clear text
                problems.append("SMTP_PASSWORD needs SMTP_TLS=starttls or tls")
            if parse_bool(self.smtp_verify_tls) is None:
                problems.append("SMTP_VERIFY_TLS must be 1 or 0")
        if self.webhook_url:
            problems += url_problems("WEBHOOK_URL", self.webhook_url, "https://<host>/<path>")
            if self.webhook_format == "ntfy" and _is_http(self.webhook_url):
                try:
                    topic = urlparse(self.webhook_url).path.rstrip("/").rsplit("/", 1)[-1]
                except ValueError:
                    topic = "-"  # reported by url_problems
                if not topic:
                    problems.append("WEBHOOK_URL needs a topic (https://<host>/<topic>) with WEBHOOK_FORMAT=ntfy")
        if self.webhook_format not in ("json", "ntfy", "discord"):
            problems.append("WEBHOOK_FORMAT must be json, ntfy or discord")
        if self.webhook_secret.startswith("whsec_"):
            try:
                base64.b64decode(self.webhook_secret[6:], validate=True)
            except ValueError:
                problems.append("WEBHOOK_SECRET: the whsec_ value is not valid base64")
        return problems

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
        if self.prune_days < 0:
            problems.append("PRUNE_DAYS must not be negative")
        if self.prune_days > 3650:
            problems.append("PRUNE_DAYS must be at most 3650")
        if self.lease_type_mode not in ("keep", "grace", "immediate"):
            problems.append("LEASE_TYPE_MODE must be keep, grace or immediate")
        if self.poll_seconds < 15:
            problems.append("POLL_SECONDS below 15 is unreasonable for the firewall")
        if self.poll_seconds > 86400:
            problems.append("POLL_SECONDS must be at most 86400")
        # never echo the values: the hash is a secret
        if bool(self.auth_user) != bool(self.auth_password_hash):
            problems.append("AUTH_USER and AUTH_PASSWORD_HASH must be set together")
        if ":" in self.auth_user or any(unicodedata.category(c) == "Cc" for c in self.auth_user):
            problems.append("AUTH_USER must not contain ':' or control characters")  # Basic splits on the first ':'
        if self.auth_password_hash and parse_hash(self.auth_password_hash) is None:
            problems.append("AUTH_PASSWORD_HASH is not a valid hash (make one with python -m leasewatch hash-password)")
        problems += self._notify_problems()
        problems += self.connector_problems
        for spec in self.connector_specs:
            problems += instance_problems(spec)
        # without the list at all, "LW_CONNECTORS is not set" already says it
        if self.connectors_listed and not any("sighting" in cls.describe().produces for sp in self.connector_specs
                                              for cls in (registry().get(sp.type),) if cls):
            problems.append("LW_CONNECTORS: at least one connector must produce sightings (e.g. type opnsense)")
        return problems
