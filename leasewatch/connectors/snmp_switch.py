"""A managed switch over SNMPv3 as a connector: which port each MAC is learned on (Q-BRIDGE FDB, IF-MIB, LLDP).

A thin wrapper around switch.SwitchClient. pysnmp stays a lazy import inside the client.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from ..switch import SwitchClient, SwitchSnapshot
from . import API_VERSION, Attachment, Batch, ConnectorError, ConnectorInfo, HostContext, Setting, SettingsMixin


@dataclass
class _SnmpCfg:
    """The Config attributes SwitchClient reads; secrets kept out of repr like Config does."""
    snmp_host: str
    snmp_user: str
    snmp_auth: str
    snmp_auth_key: str = field(repr=False)
    snmp_priv_key: str = field(repr=False)


def to_attachments(snap: SwitchSnapshot, source: str, device: str, observed_at: int) -> list[Attachment]:
    """One wired attachment per learned MAC, with the same port label and via text as SwitchSnapshot.describe()."""
    out = []
    for mac, (ifindex, vlan) in snap.by_mac.items():
        port, via = snap.describe(mac)
        p = snap.ports.get(ifindex)
        out.append(Attachment(mac=mac, source=source, observed_at=observed_at, link="wired", device=device,
                              port=port, via=via, uplink=bool(p and p.uplink), vlan=vlan))
    return out


class SnmpSwitchConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="snmp_switch", version="1.0", api_version=API_VERSION, produces=frozenset({"attachment"}),
        settings=(
            Setting("host", required=True, help="switch address"),
            Setting("name", default="switch", help="switch name shown in the UI"),
            Setting("user", default="leasewatch", help="SNMPv3 user"),
            Setting("auth", default="SHA", choices=("SHA", "SHA256"), help="SNMPv3 auth protocol"),
            Setting("auth_key", required=True, secret=True, help="SNMPv3 auth key"),
            Setting("priv_key", required=True, secret=True, help="SNMPv3 privacy key (AES-128)"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None, client: object | None = None) -> None:
        self._init_settings(name, settings, ctx)
        self.settings["auth"] = self.settings["auth"].upper().replace("-", "")
        s = self.settings
        # read at call time: the host (and tests) may swap the client object
        self.client = client or SwitchClient(_SnmpCfg(s["host"], s["user"], s["auth"], s["auth_key"], s["priv_key"]))  # type: ignore[arg-type]

    def validate(self) -> list[str]:
        return self._generic_problems()

    def check(self) -> None:
        # a full walk is not a cheap probe; until a sysObjectID GET exists, check that the library is there
        try:
            import pysnmp  # noqa: F401
        except ImportError as e:
            raise ConnectorError("missing dependency pysnmp") from e

    def collect(self) -> Batch:
        try:
            snap = self.client.snapshot()
        except RuntimeError as e:
            raise ConnectorError(str(e) or type(e).__name__) from e
        return Batch(attachments=to_attachments(snap, self.name, self.settings["name"], self.ctx.now()),
                     stats={"macs": len(snap.by_mac)}, extra={"snapshot": snap})

    def close(self) -> None:
        pass  # each snapshot opens and closes its own SNMP engine
