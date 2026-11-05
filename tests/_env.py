"""Clean-environment helper for tests that build Config() from os.environ.

Tests must not see the developer's or CI's own settings (a real UNIFI_URL or SNMP_HOST would make a test talk to
the network, a different NEW_DAYS would change results), so every variable config.py reads is removed first.
"""
from __future__ import annotations

import os

# Every name read through _env/_env_int/_env_bool in leasewatch/config.py, plus LOG_LEVEL (__main__.py).
# Derived with: grep -oE '_env(_int|_bool)?\("[A-Z0-9_]+"' leasewatch/config.py. Keep in sync when a setting is added.
CONFIG_VARS = (
    "ALLOWED_HOSTS", "DATA_DIR", "DHCP_BACKEND", "LEASE_TYPE_MODE", "PROXY_FOR_LAN", "FW1_KEY", "FW1_SECRET", "FW1_URL", "FW1_VERIFY_TLS",
    "IGNORE_INTERFACES", "LISTEN_HOST", "LISTEN_PORT", "MAIL_FROM_NAME", "MAILGUN_API_BASE", "MAILGUN_DOMAIN",
    "MAILGUN_KEY", "MAIL_TO", "NEW_DAYS", "ONLINE_GRACE_MINUTES", "POLL_SECONDS", "PUBLIC_URL", "SITE_NAME",
    "SNMP_AUTH", "SNMP_AUTH_KEY", "SNMP_HOST", "SNMP_NAME", "SNMP_PRIV_KEY", "SNMP_USER",
    "SNMP_PROFILE", "SNMP_PROFILE_FILE", "SNMP_MIN_MACS", "UNIFI_PASSWORD",
    "UNIFI_SITE", "UNIFI_URL", "UNIFI_USER", "UNIFI_VERIFY_TLS", "LOG_LEVEL", "LW_CONNECTORS",
)
# the per-instance settings LW_CONNECTOR__<NAME>__<KEY> have open-ended names: clean_env() drops them by prefix
CONFIG_PREFIXES = ("LW_CONNECTOR__",)


def clean_env(overrides: dict | None = None) -> dict:
    """Drop every config variable, apply `overrides`, and return the full original environment for restore()."""
    saved = dict(os.environ)
    for k in CONFIG_VARS:
        os.environ.pop(k, None)
    for k in [k for k in os.environ if k.startswith(CONFIG_PREFIXES)]:
        del os.environ[k]
    os.environ.update(overrides or {})
    return saved


def restore(saved: dict) -> None:
    os.environ.clear()
    os.environ.update(saved)
