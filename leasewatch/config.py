"""Configuration from environment variables (see .env.example)."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field


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
    return v in ("1", "true", "yes", "on")


@dataclass
class Config:
    fw1_url: str = field(default_factory=lambda: _env("FW1_URL", ""))
    fw1_key: str = field(default_factory=lambda: _env("FW1_KEY"))
    fw1_secret: str = field(default_factory=lambda: _env("FW1_SECRET"))
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
    mailgun_key: str = field(default_factory=lambda: _env("MAILGUN_KEY"))
    mailgun_domain: str = field(default_factory=lambda: _env("MAILGUN_DOMAIN"))
    mail_to: str = field(default_factory=lambda: _env("MAIL_TO"))
    mail_from_name: str = field(default_factory=lambda: _env("MAIL_FROM_NAME", "leasewatch"))
    public_url: str = field(default_factory=lambda: _env("PUBLIC_URL", ""))
    # interfaces to ignore completely (comma separated interface identifiers, e.g. "wan,opt6")
    ignore_interfaces: tuple = field(default_factory=lambda: tuple(x for x in _env("IGNORE_INTERFACES", "wan,lo0").split(",") if x))

    # optional enrichers: switch port over SNMPv3 (empty SNMP_HOST = off), Wi-Fi from a UniFi controller (empty UNIFI_URL = off)
    snmp_host: str = field(default_factory=lambda: _env("SNMP_HOST"))
    snmp_name: str = field(default_factory=lambda: _env("SNMP_NAME", "switch"))
    snmp_user: str = field(default_factory=lambda: _env("SNMP_USER", "leasewatch"))
    snmp_auth: str = field(default_factory=lambda: _env("SNMP_AUTH", "SHA").upper().replace("-", ""))
    snmp_auth_key: str = field(default_factory=lambda: _env("SNMP_AUTH_KEY"))
    snmp_priv_key: str = field(default_factory=lambda: _env("SNMP_PRIV_KEY"))
    unifi_url: str = field(default_factory=lambda: _env("UNIFI_URL").rstrip("/"))
    unifi_site: str = field(default_factory=lambda: _env("UNIFI_SITE", "default"))
    unifi_user: str = field(default_factory=lambda: _env("UNIFI_USER"))
    unifi_password: str = field(default_factory=lambda: _env("UNIFI_PASSWORD"))
    unifi_verify_tls: bool = field(default_factory=lambda: _env_bool("UNIFI_VERIFY_TLS", True))

    @property
    def snmp_enabled(self) -> bool:
        return bool(self.snmp_host and self.snmp_auth_key and self.snmp_priv_key)

    @property
    def unifi_enabled(self) -> bool:
        return bool(self.unifi_url and self.unifi_user and self.unifi_password)

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
        if not self.fw1_url.startswith("http"):
            problems.append("FW1_URL must be set (https://<opnsense>)")
        if self.dhcp_backend not in ("isc", "kea"):
            problems.append("DHCP_BACKEND must be isc or kea")
        if self.poll_seconds < 15:
            problems.append("POLL_SECONDS below 15 is unreasonable for the firewall")
        if self.snmp_host and not self.snmp_enabled:
            problems.append("SNMP_HOST set but SNMP_AUTH_KEY/SNMP_PRIV_KEY missing")
        if self.snmp_auth not in ("SHA", "SHA256"):
            problems.append("SNMP_AUTH must be SHA or SHA256")
        if self.unifi_url and not self.unifi_enabled:
            problems.append("UNIFI_URL set but UNIFI_USER/UNIFI_PASSWORD missing")
        return problems
