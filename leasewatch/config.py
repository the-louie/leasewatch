"""Configuration from environment variables (see .env.example)."""
from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


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


@dataclass
class Config:
    fw1_url: str = field(default_factory=lambda: _env("FW1_URL", ""))
    fw1_key: str = field(default_factory=lambda: _env("FW1_KEY"), repr=False)
    fw1_secret: str = field(default_factory=lambda: _env("FW1_SECRET"), repr=False)
    fw1_verify_tls: bool = field(default_factory=lambda: _env_bool("FW1_VERIFY_TLS", True))
    # which OPNsense DHCPv4 server to read leases from: "isc" or "kea"
    dhcp_backend: str = field(default_factory=lambda: _env("DHCP_BACKEND", "isc").lower())
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
    unifi_url: str = field(default_factory=lambda: _env("UNIFI_URL").rstrip("/"))
    unifi_site: str = field(default_factory=lambda: _env("UNIFI_SITE", "default"))
    unifi_user: str = field(default_factory=lambda: _env("UNIFI_USER"))
    unifi_password: str = field(default_factory=lambda: _env("UNIFI_PASSWORD"), repr=False)
    unifi_verify_tls: bool = field(default_factory=lambda: _env_bool("UNIFI_VERIFY_TLS", True))

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
        if not self.fw1_key or not self.fw1_secret:
            problems.append("FW1_KEY / FW1_SECRET missing")
        if not self.fw1_url.startswith(("http://", "https://")):
            problems.append("FW1_URL must be set (https://<opnsense>)")
        if self.public_url and not self.public_url.startswith(("http://", "https://")):
            problems.append("PUBLIC_URL must be a URL (https://<host>)")
        if self.unifi_url and not self.unifi_url.startswith(("http://", "https://")):
            problems.append("UNIFI_URL must be a URL (https://<controller>)")
        # a URL without a host, or with an unclosed "[", passes the scheme check but fails on every request
        for name, url in (("FW1_URL", self.fw1_url), ("PUBLIC_URL", self.public_url), ("UNIFI_URL", self.unifi_url)):
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
        for name, url in (("FW1_URL", self.fw1_url), ("UNIFI_URL", self.unifi_url), ("PUBLIC_URL", self.public_url),
                          ("MAILGUN_API_BASE", self.mailgun_api_base)):
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
        if self.dhcp_backend not in ("isc", "kea"):
            problems.append("DHCP_BACKEND must be isc or kea")
        if self.poll_seconds < 15:
            problems.append("POLL_SECONDS below 15 is unreasonable for the firewall")
        if self.poll_seconds > 86400:
            problems.append("POLL_SECONDS must be at most 86400")
        if self.snmp_host and not self.snmp_enabled:
            problems.append("SNMP_HOST set but SNMP_AUTH_KEY/SNMP_PRIV_KEY missing")
        if self.snmp_host and self.snmp_auth not in ("SHA", "SHA256"):
            problems.append("SNMP_AUTH must be SHA or SHA256")
        if self.unifi_url and not self.unifi_enabled:
            problems.append("UNIFI_URL set but UNIFI_USER/UNIFI_PASSWORD missing")
        return problems
