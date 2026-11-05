"""Connector instances from today's variables (FW1_*, SNMP_*, UNIFI_*), so no deployment has to change.

Instance names: "fw1" (opnsense, always), "switch" (snmp_switch, when SNMP is enabled), "unifi" (when UniFi is).
"""
from __future__ import annotations

from ..config import Config
from . import Connector, HostContext, make_redactor
from .opnsense import OpnsenseConnector
from .snmp_switch import SnmpSwitchConnector
from .unifi import UnifiConnector


def _b(v: bool) -> str:
    return "1" if v else "0"


def fw1_settings(cfg: Config) -> dict[str, str]:
    return {"url": cfg.fw1_url, "key": cfg.fw1_key, "secret": cfg.fw1_secret, "verify_tls": _b(cfg.fw1_verify_tls),
            "dhcp_backend": cfg.dhcp_backend, "ignore_interfaces": ",".join(cfg.ignore_interfaces), "proxy": _b(cfg.lan_proxy)}


def switch_settings(cfg: Config) -> dict[str, str]:
    return {"host": cfg.snmp_host, "name": cfg.snmp_name, "user": cfg.snmp_user, "auth": cfg.snmp_auth,
            "auth_key": cfg.snmp_auth_key, "priv_key": cfg.snmp_priv_key}


def unifi_settings(cfg: Config) -> dict[str, str]:
    return {"url": cfg.unifi_url, "site": cfg.unifi_site, "user": cfg.unifi_user, "password": cfg.unifi_password,
            "verify_tls": _b(cfg.unifi_verify_tls), "proxy": _b(cfg.lan_proxy)}


def legacy_context(cfg: Config) -> HostContext:
    return HostContext(redact=make_redactor([cfg.fw1_key, cfg.fw1_secret, cfg.snmp_auth_key, cfg.snmp_priv_key, cfg.unifi_password]))


def legacy_instances(cfg: Config, fw1_client: object | None = None) -> dict[str, Connector]:
    """fw1_client: an already built firewall client (the Collector's injected one), used instead of a new Fw1Client."""
    ctx = legacy_context(cfg)
    out: dict[str, Connector] = {"fw1": OpnsenseConnector("fw1", fw1_settings(cfg), ctx, client=fw1_client)}
    if cfg.snmp_enabled:
        out["switch"] = SnmpSwitchConnector("switch", switch_settings(cfg), ctx)
    if cfg.unifi_enabled:
        out["unifi"] = UnifiConnector("unifi", unifi_settings(cfg), ctx)
    return out
