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


def _read_secret(name: str) -> tuple[str, str]:
    """(value, problem) of a secret given as <NAME> or <NAME>_FILE. The file's stripped content is the value; the
    problem (never the value or the path) is "" when there is none."""
    plain, path = _env(name), _env(name + "_FILE")
    if not path:
        return plain, ""
    if plain:
        return plain, f"set {name} or {name}_FILE, not both"
    label = f"cannot read {name}_FILE"
    # a FIFO, a device such as /dev/zero or a huge file would block or stall the start
    if os.path.exists(path) and not os.path.isfile(path):
        return "", f"{label} (not a regular file)"
    try:
        if os.path.getsize(path) > MAX_SECRET_FILE:
            return "", f"{label} (larger than 64 KiB)"
        with open(path, encoding="utf-8-sig") as f:  # utf-8-sig: a BOM would become part of the secret
            value = f.read(MAX_SECRET_FILE + 1)
    except (OSError, UnicodeDecodeError) as e:
        return "", f"{label} ({getattr(e, 'strerror', None) or type(e).__name__})"
    if len(value) > MAX_SECRET_FILE:
        return "", f"{label} (larger than 64 KiB)"
    return value.strip(), ""


def _secret_env(name: str) -> str:
    """The value of a core secret setting <NAME>, or the content of the file <NAME>_FILE names. The core-key
    counterpart of the connectors' <KEY>_FILE rule. An unreadable file gives "" here; validate() reports why."""
    return _read_secret(name)[0]


def _is_address(addr: str) -> bool:
    """A plain local@domain: exactly one "@" with text on both sides, no blank or control character (a CR/LF would
    inject a header), and none of <>,;:"()[]\\ (the sender wraps it in <...> itself; a list, a "mailto:", quotes or
    brackets would mangle the header and the envelope)."""
    a = addr.strip()
    local, at, domain = a.partition("@")
    return (bool(local and at and domain) and "@" not in domain
            and not any(c.isspace() or c in '<>,;:"()[]\\' or unicodedata.category(c) == "Cc" for c in a))


def _smtp_tls_env() -> str:
    return _env("SMTP_TLS", "starttls").lower() or "starttls"


def _ui_lang_env() -> str:
    # the page's language: a typo must not stop the start, so it warns and lets the browser choose
    v = _env("UI_LANG", "auto").lower() or "auto"
    if v not in ("auto", "en", "sv"):
        log.warning("UI_LANG=%r is not auto, en or sv: using auto", v[:40])
        return "auto"
    return v


def _smtp_port_env() -> int:
    # empty: -1, the default for SMTP_TLS (set in __post_init__); a junk value falls back to that same default, so
    # its warning names the port actually used
    if not _env("SMTP_PORT"):
        return -1
    default = SMTP_PORTS.get(_smtp_tls_env(), 587)
    port = _env_int("SMTP_PORT", default)
    if port == -1:  # the "use the default" marker; set by hand it is no port
        log.warning("SMTP_PORT=-1 is not a port, using %d", default)
        return default
    return port


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



def parse_networks(text: str) -> tuple[list, list[str]]:
    """The networks in a comma list of addresses and CIDRs, and the entries that are neither (shortened and quoted,
    so a long or odd entry cannot fill a log line). Empty entries are skipped."""
    nets, bad = [], []
    for raw in text.split(","):
        entry = raw.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            bad.append(ascii(entry[:40]))
    return nets, bad

@dataclass
class Config:
    # what a device whose lease is gone shows as lease type: "keep" the last one, clear it after the "grace" period, or "immediate"ly
    lease_type_mode: str = field(default_factory=lambda: _env("LEASE_TYPE_MODE", "keep").lower())
    poll_seconds: int = field(default_factory=lambda: _env_int("POLL_SECONDS", 120))
    data_dir: str = field(default_factory=lambda: _env("DATA_DIR", "/data"))
    listen_host: str = field(default_factory=lambda: _env("LISTEN_HOST", "0.0.0.0"))
    listen_port: int = field(default_factory=lambda: _env_int("LISTEN_PORT", 8080))
    site_name: str = field(default_factory=lambda: _env("SITE_NAME", "Leasewatch"))
    # UI language: auto (the browser's: Swedish or English), en or sv
    ui_lang: str = field(default_factory=_ui_lang_env)
    new_days: int = field(default_factory=lambda: _env_int("NEW_DAYS", 7))
    # a device not seen for this long is "offline" even if a lease is still active
    online_grace_minutes: int = field(default_factory=lambda: _env_int("ONLINE_GRACE_MINUTES", 10))
    # archive devices not online for this many days that have no name and are not marked known; 0 = off
    prune_days: int = field(default_factory=lambda: _env_int("PRUNE_DAYS", 0))
    # archive private-MAC devices that never merged (no name, note, ack, split or alias) after this many days offline; 0 = use prune_days
    prune_private_days: int = field(default_factory=lambda: _env_int("PRUNE_PRIVATE_DAYS", 0))
    # delete devices archived this many days (by the prune clock) that are offline, unnamed, without a note and not known; 0 = off
    purge_days: int = field(default_factory=lambda: _env_int("PURGE_DAYS", 0))
    # days a Wi-Fi presence row (per device and SSID) is kept after it was last seen; 0 = off (nothing stored, stored rows deleted)
    wifi_presence_days: int = field(default_factory=lambda: _env_int("WIFI_PRESENCE_DAYS", 365))
    # days an event is kept (by the prune clock); history rows kept per device (and shown in the drawer)
    event_days: int = field(default_factory=lambda: _env_int("EVENT_DAYS", 365))
    history_per_device: int = field(default_factory=lambda: _env_int("HISTORY_PER_DEVICE", 200))
    backup_keep: int = field(default_factory=lambda: _env_int("BACKUP_KEEP", 7))  # dated backups the backup command keeps
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
    # optional second login that can read but not change anything; needs AUTH_USER/AUTH_PASSWORD_HASH
    auth_ro_user: str = field(default_factory=lambda: _env("AUTH_RO_USER"))
    auth_ro_password_hash: str = field(default_factory=lambda: _env("AUTH_RO_PASSWORD_HASH"), repr=False)
    # no changes through the API (every POST refused); an empty value means the default (off)
    read_only: str = field(default_factory=lambda: _env("READ_ONLY", "0") or "0")
    # addresses and networks (comma list) that may change data; empty = everyone. An empty list is the default, so
    # "WRITE_ALLOW=" in an env file is not an error
    write_allow: str = field(default_factory=lambda: _env("WRITE_ALLOW"))
    # mail through an SMTP server (on when SMTP_HOST, SMTP_FROM and MAIL_TO are set). TLS: starttls (required, never
    # downgraded), tls (implicit, SMTPS) or none; SMTP_PORT -1 = the default for the TLS mode (set in __post_init__)
    smtp_host: str = field(default_factory=lambda: _env("SMTP_HOST"))
    smtp_tls: str = field(default_factory=_smtp_tls_env)
    smtp_port: int = field(default_factory=_smtp_port_env)
    smtp_user: str = field(default_factory=lambda: _env("SMTP_USER"))
    smtp_password: str = field(default_factory=lambda: _env("SMTP_PASSWORD"), repr=False)
    smtp_from: str = field(default_factory=lambda: _env("SMTP_FROM"))
    smtp_verify_tls: str = field(default_factory=lambda: _env("SMTP_VERIFY_TLS", "1") or "1")  # empty = the default
    # a POST per batch of new devices; the URL often carries the token (Discord, Home Assistant), so it is a secret
    webhook_url: str = field(default_factory=lambda: _env("WEBHOOK_URL"), repr=False)
    webhook_secret: str = field(default_factory=lambda: _env("WEBHOOK_SECRET"), repr=False)
    webhook_format: str = field(default_factory=lambda: _env("WEBHOOK_FORMAT", "json").lower() or "json")
    # MQTT (on when MQTT_URL is set): mqtt:// (1883) or mqtts:// (8883). The raw strings; the flags are properties
    mqtt_url: str = field(default_factory=lambda: _env("MQTT_URL"))
    mqtt_user: str = field(default_factory=lambda: _env("MQTT_USER"))
    mqtt_password: str = field(default_factory=lambda: _secret_env("MQTT_PASSWORD"), repr=False)
    mqtt_verify_tls: str = field(default_factory=lambda: _env("MQTT_VERIFY_TLS", "1") or "1")
    mqtt_ca_file: str = field(default_factory=lambda: _env("MQTT_CA_FILE"))
    mqtt_topic: str = field(default_factory=lambda: _env("MQTT_TOPIC", "leasewatch"))
    mqtt_client_id: str = field(default_factory=lambda: _env("MQTT_CLIENT_ID"))  # empty = derived (mqtt_client_id_effective)
    mqtt_discovery: str = field(default_factory=lambda: _env("MQTT_DISCOVERY", "1") or "1")
    mqtt_discovery_prefix: str = field(default_factory=lambda: _env("MQTT_DISCOVERY_PREFIX", "homeassistant"))
    mqtt_devices: str = field(default_factory=lambda: _env("MQTT_DEVICES", "watched").lower() or "watched")
    mqtt_events: str = field(default_factory=lambda: _env("MQTT_EVENTS", "0") or "0")
    # MAIL_ON_SOURCE: the source_down/source_up events also go to the channels (1/0; empty = the default, off).
    # The text as given; the flag is the mail_on_source property
    mail_on_source_raw: str = field(default_factory=lambda: _env("MAIL_ON_SOURCE", "0") or "0")
    # MAIL_ON_WATCH: what happens to a watched device (devices.watch=1) also goes to the channels (1/0; empty = the
    # default, off). The text as given; the flag is the mail_on_watch property
    mail_on_watch_raw: str = field(default_factory=lambda: _env("MAIL_ON_WATCH", "0") or "0")
    # connector instances from LW_CONNECTORS (the only way to configure a source)
    connector_specs: list = field(default_factory=list, init=False)
    connector_problems: list = field(default_factory=list, init=False, repr=False)
    connectors_listed: bool = field(default=False, init=False, repr=False)  # LW_CONNECTORS was set (not empty)

    def __post_init__(self) -> None:
        # load the third-party types first, so parse_instances() -> secret_keys() knows a plugin type's
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
    def auth_ro_enabled(self) -> bool:
        return self.auth_enabled and bool(self.auth_ro_user and self.auth_ro_password_hash)

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
        if self.mqtt_on and self.mqtt_events_on:
            out.append("mqtt")
        return out

    @property
    def mqtt_on(self) -> bool:
        """MQTT_URL is set: leasewatch publishes to the broker."""
        return bool(self.mqtt_url)

    @property
    def mqtt_verify_tls_on(self) -> bool:
        return parse_bool(self.mqtt_verify_tls) is True

    @property
    def mqtt_discovery_on(self) -> bool:
        return parse_bool(self.mqtt_discovery) is True

    @property
    def mqtt_events_on(self) -> bool:
        """MQTT_EVENTS is on: events also go out as a notification channel."""
        return parse_bool(self.mqtt_events) is True

    @property
    def mqtt_endpoint(self) -> tuple[str, int, bool]:
        """(host, port, tls) of MQTT_URL; the port defaults to 1883 (mqtt) or 8883 (mqtts). ("", 0, False) for a URL
        validate() refuses."""
        try:
            parts = urlparse(self.mqtt_url)
            scheme = parts.scheme.lower()
            if scheme not in ("mqtt", "mqtts") or not parts.hostname:
                return "", 0, False
            tls = scheme == "mqtts"
            return parts.hostname, parts.port or (8883 if tls else 1883), tls
        except ValueError:
            return "", 0, False

    @property
    def mqtt_client_id_effective(self) -> str:
        """MQTT_CLIENT_ID, or leasewatch-<site name as a slug>: lower case, other characters "-", at most 23 characters."""
        if self.mqtt_client_id:
            return self.mqtt_client_id
        slug = re.sub(r"[^a-z0-9]+", "-", self.site_name.lower()).strip("-")[:12].strip("-")
        return f"leasewatch-{slug}" if slug else "leasewatch"

    @property
    def mail_on_source(self) -> bool:
        """MAIL_ON_SOURCE is on: a source_down/source_up event is sent through the channels."""
        return parse_bool(self.mail_on_source_raw) is True

    @property
    def mail_on_watch(self) -> bool:
        """MAIL_ON_WATCH is on: an offline/online/ip/vlan/port/wifi event of a watched device is sent through the channels."""
        return parse_bool(self.mail_on_watch_raw) is True

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
            # ASCII: formataddr() refuses anything else, before the server could offer SMTPUTF8
            if not _is_address(self.smtp_from) or not self.smtp_from.isascii():
                problems.append("SMTP_FROM must be an e-mail address (required with SMTP_HOST)")
            # empty pieces ("a@example.com,") are dropped, as the sender drops them
            to = [a for a in self.mail_to.split(",") if a.strip()]
            if not to or not all(_is_address(a) for a in to):
                problems.append("MAIL_TO must be one or more e-mail addresses, comma separated (required with SMTP_HOST)")
            if bool(self.smtp_user) != bool(self.smtp_password):
                problems.append("SMTP_USER and SMTP_PASSWORD must be set together")
            if not (self.smtp_user + self.smtp_password).isascii():
                problems.append("SMTP_USER and SMTP_PASSWORD must be ASCII")  # smtplib's AUTH encodes them as ASCII
            if self.smtp_password and self.smtp_tls == "none":
                # the password would cross the network in clear text
                problems.append("SMTP_PASSWORD needs SMTP_TLS=starttls or tls")
            if parse_bool(self.smtp_verify_tls) is None:
                problems.append("SMTP_VERIFY_TLS must be 1 or 0")
        if self.webhook_url:
            problems += url_problems("WEBHOOK_URL", self.webhook_url, "https://<host>/<path>")
            # http.client sends the request line as ASCII (the host alone is IDNA-encoded)
            try:
                parts = urlparse(self.webhook_url)
                rest = parts.path + parts.params + parts.query  # the fragment is never sent
            except ValueError:
                rest = ""  # reported by url_problems
            if not rest.isascii():
                problems.append("WEBHOOK_URL: the path and query must be ASCII (percent-encode other characters)")
            if self.webhook_format == "ntfy" and _is_http(self.webhook_url):
                try:
                    topic = urlparse(self.webhook_url).path.rstrip("/").rsplit("/", 1)[-1]
                except ValueError:
                    topic = "-"  # reported by url_problems
                if not topic:
                    problems.append("WEBHOOK_URL needs a topic (https://<host>/<topic>) with WEBHOOK_FORMAT=ntfy")
        if self.webhook_format not in ("json", "ntfy", "discord"):
            problems.append("WEBHOOK_FORMAT must be json, ntfy or discord")
        # checked as notify signs with it: whsec_ base64-decoded (strictly), any other value as UTF-8
        if self.webhook_secret.startswith("whsec_"):
            try:
                if not base64.b64decode(self.webhook_secret[6:], validate=True):
                    # an empty HMAC key: anyone could sign
                    problems.append("WEBHOOK_SECRET: the whsec_ value is empty")
            except ValueError:
                problems.append("WEBHOOK_SECRET: the whsec_ value is not valid base64")
        else:
            try:
                self.webhook_secret.encode()
            except UnicodeEncodeError:  # bytes the environment could not decode, kept as surrogates
                problems.append("WEBHOOK_SECRET is not valid UTF-8")
        problems += self._mqtt_problems()
        return problems

    def _mqtt_problems(self) -> list[str]:
        """MQTT settings, checked only with MQTT_URL set (as SMTP_* with SMTP_HOST). Never echoes a value."""
        if not self.mqtt_url:
            return []
        problems = []
        low = self.mqtt_url.lower()
        if not low.startswith(("mqtt://", "mqtts://")):
            problems.append("MQTT_URL must be a URL (mqtt://<host>[:1883] or mqtts://<host>[:8883])")
        else:
            # the same checks as an http URL (host, port, no credentials, no control characters) on the same text
            problems += url_problems("MQTT_URL", "http://" + self.mqtt_url.split("://", 1)[1], "mqtt://<host>[:1883]")
            try:
                parts = urlparse(self.mqtt_url)
                if parts.path not in ("", "/") or parts.params or parts.query or parts.fragment:
                    problems.append("MQTT_URL must have no path or query")
            except ValueError:
                pass  # reported by url_problems
        password_problem = _read_secret("MQTT_PASSWORD")[1]
        if password_problem:
            problems.append(password_problem)
        elif bool(self.mqtt_user) != bool(self.mqtt_password):
            problems.append("MQTT_USER and MQTT_PASSWORD must be set together")
        if parse_bool(self.mqtt_verify_tls) is None:
            problems.append("MQTT_VERIFY_TLS must be 1 or 0")
        if self.mqtt_ca_file:
            # a FIFO would block the open for ever
            if os.path.exists(self.mqtt_ca_file) and not os.path.isfile(self.mqtt_ca_file):
                problems.append("MQTT_CA_FILE is not a regular file")
            else:
                try:
                    with open(self.mqtt_ca_file, "rb"):
                        pass
                except OSError:
                    problems.append("MQTT_CA_FILE cannot be read")
        # the client sends these as UTF-8 with a 2-byte length
        for key, value in (("MQTT_USER", self.mqtt_user), ("MQTT_PASSWORD", self.mqtt_password),
                           ("MQTT_TOPIC", self.mqtt_topic), ("MQTT_DISCOVERY_PREFIX", self.mqtt_discovery_prefix),
                           ("MQTT_CLIENT_ID", self.mqtt_client_id)):
            try:
                if len(value.encode("utf-8")) > 65535:
                    problems.append(f"{key} is longer than 65535 bytes")
            except UnicodeEncodeError:  # a byte the environment could not decode, kept as a surrogate
                problems.append(f"{key} must be valid UTF-8 text")
        for key, value in (("MQTT_TOPIC", self.mqtt_topic), ("MQTT_DISCOVERY_PREFIX", self.mqtt_discovery_prefix)):
            if (not value or any(c in value for c in "+#\0") or value[0] in "$/" or value.endswith("/")):
                problems.append(f"{key} must be a topic without +, # or a leading $ or /, and no trailing /")
        if self.mqtt_client_id and not re.fullmatch(r"[0-9a-zA-Z-]{1,23}", self.mqtt_client_id):
            problems.append("MQTT_CLIENT_ID must be 1-23 characters of 0-9, a-z, A-Z and -")
        if self.mqtt_devices not in ("watched", "named", "known", "all"):
            problems.append("MQTT_DEVICES must be watched, named, known or all")
        if parse_bool(self.mqtt_discovery) is None:
            problems.append("MQTT_DISCOVERY must be 1 or 0")
        if parse_bool(self.mqtt_events) is None:
            problems.append("MQTT_EVENTS must be 1 or 0")
        return problems

    @property
    def read_only_on(self) -> bool:
        return parse_bool(self.read_only) is True

    def write_allowed(self, addr: str) -> bool:
        """May a client at this address change data? False when READ_ONLY is on or the address is not an IP address;
        with an empty WRITE_ALLOW every address may. An IPv4-mapped IPv6 address counts as its IPv4 form."""
        if self.read_only_on:
            return False
        if not self.write_allow.replace(",", "").strip():
            return True
        try:
            ip = ipaddress.ip_address(addr.strip())
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        # a bad entry is left out; validate() stops the start, so only a test or a later edit gets here with one
        return any(ip.version == n.version and ip in n for n in parse_networks(self.write_allow)[0])

    def validate(self) -> list[str]:
        problems = []
        if parse_bool(self.read_only) is None:
            problems.append("READ_ONLY must be 1 or 0")
        if parse_bool(self.mail_on_source_raw) is None:
            problems.append("MAIL_ON_SOURCE must be 1 or 0")
        if parse_bool(self.mail_on_watch_raw) is None:
            problems.append("MAIL_ON_WATCH must be 1 or 0")
        nets, bad = parse_networks(self.write_allow)
        problems += [f"WRITE_ALLOW: not an address or network: {b}" for b in bad]
        # web.Server listens on IPv4 only, so an IPv6 entry could never match
        problems += [f"WRITE_ALLOW: IPv6 is not supported: {n}" for n in nets if n.version == 6]
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
        raw_private = _env("PRUNE_PRIVATE_DAYS")
        if raw_private and not re.fullmatch(r"[+-]?\d+", raw_private):
            problems.append("PRUNE_PRIVATE_DAYS must be a whole number")
        elif self.prune_private_days < 0 or self.prune_private_days == 1:
            problems.append("PRUNE_PRIVATE_DAYS must be at least 2 (0 = use PRUNE_DAYS)")
        elif self.prune_private_days > 3650:
            problems.append("PRUNE_PRIVATE_DAYS must be at most 3650")
        raw_purge = _env("PURGE_DAYS")
        if raw_purge and not re.fullmatch(r"[+-]?\d+", raw_purge):
            problems.append("PURGE_DAYS must be a whole number")
        elif self.purge_days < 0:
            problems.append("PURGE_DAYS must not be negative")
        elif self.purge_days > 3650:
            problems.append("PURGE_DAYS must be at most 3650")
        raw_wifi = _env("WIFI_PRESENCE_DAYS")
        if raw_wifi and not re.fullmatch(r"[+-]?\d+", raw_wifi):
            problems.append("WIFI_PRESENCE_DAYS must be a whole number")
        elif self.wifi_presence_days < 0:
            problems.append("WIFI_PRESENCE_DAYS must not be negative")
        elif self.wifi_presence_days > 3650:
            problems.append("WIFI_PRESENCE_DAYS must be at most 3650")
        raw_events = _env("EVENT_DAYS")
        if raw_events and not re.fullmatch(r"[+-]?\d+", raw_events):
            problems.append("EVENT_DAYS must be a whole number")
        elif self.event_days < 1:
            problems.append("EVENT_DAYS must be at least 1")
        elif self.event_days > 3650:
            problems.append("EVENT_DAYS must be at most 3650")
        raw_hist = _env("HISTORY_PER_DEVICE")
        if raw_hist and not re.fullmatch(r"[+-]?\d+", raw_hist):
            problems.append("HISTORY_PER_DEVICE must be a whole number")
        elif not 10 <= self.history_per_device <= 1000:
            problems.append("HISTORY_PER_DEVICE must be 10-1000")
        raw_keep = _env("BACKUP_KEEP")
        if raw_keep and not re.fullmatch(r"[+-]?\d+", raw_keep):
            problems.append("BACKUP_KEEP must be a whole number")
        elif not 0 <= self.backup_keep <= 1000:
            problems.append("BACKUP_KEEP must be 0-1000")
        if self.lease_type_mode not in ("keep", "grace", "immediate"):
            problems.append("LEASE_TYPE_MODE must be keep, grace or immediate")
        if self.poll_seconds < 15:
            problems.append("POLL_SECONDS below 15 is unreasonable for the firewall")
        if self.poll_seconds > 86400:
            problems.append("POLL_SECONDS must be at most 86400")
        # never echo the values: the hash is a secret
        if bool(self.auth_user) != bool(self.auth_password_hash):
            problems.append("AUTH_USER and AUTH_PASSWORD_HASH must be set together")
        if ":" in self.auth_user or any(unicodedata.category(c) in ("Cc", "Cs") for c in self.auth_user):
            problems.append("AUTH_USER must not contain ':' or control characters")  # Basic splits on the first ':'
        if self.auth_password_hash and parse_hash(self.auth_password_hash) is None:
            problems.append("AUTH_PASSWORD_HASH is not a valid hash (make one with python -m leasewatch hash-password)")
        if bool(self.auth_ro_user) != bool(self.auth_ro_password_hash):
            problems.append("AUTH_RO_USER and AUTH_RO_PASSWORD_HASH must be set together")
        if (self.auth_ro_user or self.auth_ro_password_hash) and not self.auth_enabled:
            problems.append("AUTH_RO_USER needs AUTH_USER")
        if self.auth_ro_user and self.auth_ro_user == self.auth_user:
            problems.append("AUTH_RO_USER must differ from AUTH_USER")
        if ":" in self.auth_ro_user or any(unicodedata.category(c) in ("Cc", "Cs") for c in self.auth_ro_user):
            problems.append("AUTH_RO_USER must not contain ':' or control characters")
        if self.auth_ro_password_hash and parse_hash(self.auth_ro_password_hash) is None:
            problems.append("AUTH_RO_PASSWORD_HASH is not a valid hash (make one with python -m leasewatch hash-password)")
        # the answer time of a login must not tell whether the read-only name exists: one iteration count for both
        if self.auth_ro_password_hash and self.auth_password_hash:
            main, ro = parse_hash(self.auth_password_hash), parse_hash(self.auth_ro_password_hash)
            if main and ro and main[0] != ro[0]:
                problems.append("AUTH_RO_PASSWORD_HASH must use the same iteration count as AUTH_PASSWORD_HASH")
        problems += self._notify_problems()
        problems += self.connector_problems
        for spec in self.connector_specs:
            problems += instance_problems(spec)
        # without the list at all, "LW_CONNECTORS is not set" already says it
        if self.connectors_listed and not any("sighting" in cls.describe().produces for sp in self.connector_specs
                                              for cls in (registry().get(sp.type),) if cls):
            problems.append("LW_CONNECTORS: at least one connector must produce sightings (e.g. type opnsense)")
        return problems
