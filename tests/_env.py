"""Clean-environment helper for tests that build Config() from os.environ.

Tests must not see the developer's or CI's own settings (a real connector URL or host would make a test talk to
the network, a different NEW_DAYS would change results), so every variable config.py reads is removed first.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from leasewatch.config import REMOVED_VARS  # noqa: E402
import _netguard  # noqa: E402

# a module run on its own (not through discover) is guarded too; see _netguard.py
_netguard.install()

# Every name read through _env/_env_int in leasewatch/config.py, plus LOG_LEVEL and LOG_FORMAT (__main__.py) and
# LW_CONNECTORS_DIR (connectors/__init__.py: a developer's own plugin dir must not reach the tests).
# Derived with: grep -oE '_env(_int)?\("[A-Z0-9_]+"' leasewatch/config.py. Keep in sync when a setting is added.
CONFIG_VARS = (
    "ALLOWED_HOSTS", "DATA_DIR", "LEASE_TYPE_MODE", "LISTEN_HOST", "LISTEN_PORT", "MAIL_FROM_NAME", "MAILGUN_API_BASE",
    "MAILGUN_DOMAIN", "MAILGUN_KEY", "MAIL_TO", "NEW_DAYS", "ONLINE_GRACE_MINUTES", "POLL_SECONDS", "PRUNE_DAYS", "PRUNE_PRIVATE_DAYS", "PUBLIC_URL",
    "SITE_NAME", "LOG_LEVEL", "LOG_FORMAT", "LW_CONNECTORS", "LW_CONNECTORS_DIR", "AUTH_USER", "AUTH_PASSWORD_HASH", "BACKUP_KEEP",
    "SMTP_HOST", "SMTP_PORT", "SMTP_TLS", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_VERIFY_TLS",
    "WIFI_PRESENCE_DAYS", "EVENT_DAYS", "PURGE_DAYS", "HISTORY_PER_DEVICE", "WEBHOOK_URL", "WEBHOOK_SECRET", "WEBHOOK_FORMAT", "READ_ONLY", "WRITE_ALLOW",
)
# the removed 1.0 source variables: a shell that still exports one would make every Config() refuse to start
REMOVED = tuple(k for names, *_ in REMOVED_VARS for k in names)
# one firewall instance named "fw1" (synthetic values): the smallest valid source configuration
FW1_ENV = {"LW_CONNECTORS": "fw1", "LW_CONNECTOR__FW1__TYPE": "opnsense", "LW_CONNECTOR__FW1__URL": "https://fw1.example.lan",
           "LW_CONNECTOR__FW1__KEY": "k", "LW_CONNECTOR__FW1__SECRET": "s"}
# a switch named "switch" and a controller named "unifi": the instances the 1.0 meta aliases follow
SWITCH_ENV = {"LW_CONNECTOR__SWITCH__TYPE": "snmp_switch", "LW_CONNECTOR__SWITCH__HOST": "10.0.0.2",
              "LW_CONNECTOR__SWITCH__AUTH_KEY": "a" * 8, "LW_CONNECTOR__SWITCH__PRIV_KEY": "p" * 8}
UNIFI_ENV = {"LW_CONNECTOR__UNIFI__TYPE": "unifi", "LW_CONNECTOR__UNIFI__URL": "https://unifi.example.lan",
             "LW_CONNECTOR__UNIFI__USER": "ro", "LW_CONNECTOR__UNIFI__PASSWORD": "pw"}


def sources(*names: str) -> dict:
    """FW1_ENV plus the named extra instances ("switch", "unifi"), listed in that order after fw1."""
    out = dict(FW1_ENV)
    for n in names:
        out.update({"switch": SWITCH_ENV, "unifi": UNIFI_ENV}[n])
    out["LW_CONNECTORS"] = ",".join(("fw1",) + names)
    return out


def swap_client(collector: object, name: str, obj: object) -> None:
    """Make instance `name`'s connector wrap the test double `obj` (it has no check(), so none is run)."""
    collector._connectors[name].client = obj
    collector._runs[name].checked = True


# the per-instance settings LW_CONNECTOR__<NAME>__<KEY> have open-ended names: clean_env() drops them by prefix
CONFIG_PREFIXES = ("LW_CONNECTOR__",)


def clean_env(overrides: dict | None = None) -> dict:
    """Drop every config variable, apply `overrides`, and return the full original environment for restore()."""
    saved = dict(os.environ)
    for k in CONFIG_VARS + REMOVED:
        os.environ.pop(k, None)
    for k in [k for k in os.environ if k.startswith(CONFIG_PREFIXES)]:
        del os.environ[k]
    os.environ.update(overrides or {})
    return saved


def restore(saved: dict) -> None:
    os.environ.clear()
    os.environ.update(saved)
