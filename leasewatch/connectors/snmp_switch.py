"""A managed switch over SNMPv3 as a connector: which port each MAC is learned on (Q-BRIDGE FDB, IF-MIB, LLDP).

A thin wrapper around switch.SwitchClient. pysnmp stays a lazy import inside the client.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Callable, Mapping

from .. import snmp_profiles
from ..switch import SwitchClient, SwitchSnapshot
from . import API_VERSION, Attachment, Batch, ConnectorError, ConnectorInfo, HostContext, Setting, SettingsMixin

INFRA_RE = re.compile(r"^(ap|apu|sw|switch|xgs|gs|usw|uap)[-_0-9]", re.I)  # hostnames that mean "another AP/switch hangs on this port"

@dataclass
class _SnmpCfg:
    """The Config attributes SwitchClient reads; secrets kept out of repr like Config does."""
    snmp_host: str
    snmp_user: str
    snmp_auth: str
    snmp_auth_key: str = field(repr=False)
    snmp_priv_key: str = field(repr=False)


def name_uplinks(snap: SwitchSnapshot, device_names: Callable[[], dict[str, str]]) -> None:
    """An uplink port without an LLDP name: if an infrastructure device (AP, switch) sits on it, name the port after
    it. Sets PortInfo.neighbor in the snapshot (in place), so the via text of every attachment is final."""
    unnamed = [p for p in snap.ports.values() if p.uplink and not p.neighbor]
    if not unnamed:
        return
    names = device_names()  # the host's device names: reads its database, so only when a port needs one
    for p in unnamed:
        infra = sorted(n for mac, (ifi, _vlan) in snap.by_mac.items() if ifi == p.ifindex
                       for n in (names.get(mac),) if n and INFRA_RE.match(n))
        if infra:
            p.neighbor = infra[0]


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
            Setting("profile", choices=snmp_profiles.BUILTIN, help="built-in SNMP profile; empty = detect from sysObjectID/sysDescr"),
            Setting("profile_file", help="path to a JSON SNMP profile; wins over profile"),
            Setting("min_macs", help="MACs on a port without LLDP that make it an uplink; empty = the profile's uplink.min_macs"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None, client: object | None = None) -> None:
        self._init_settings(name, settings, ctx)
        # stripped before validate()'s choices check, which compares the value as given
        for k in ("auth", "profile", "profile_file", "min_macs"):
            self.settings[k] = self.settings[k].strip()
        self.settings["auth"] = self.settings["auth"].upper().replace("-", "")
        s = self.settings
        # problems with profile/profile_file/min_macs, reported by validate(); collect()/check() refuse to run with one,
        # so a bad profile setting never falls back to detection unnoticed
        self.profile_problems: list[str] = []
        self._bad_profile_name = False
        profile = self._profile()
        min_macs = self._min_macs()
        # read at call time: the host (and tests) may swap the client object
        self.client = client or SwitchClient(_SnmpCfg(s["host"], s["user"], s["auth"], s["auth_key"], s["priv_key"]),  # type: ignore[arg-type]
                                             profile=profile, min_macs=min_macs, name=name)

    def _profile(self) -> dict | None:
        """profile_file > profile > None (detection). Reads the file (a local config file, not the device)."""
        path, name = self.settings["profile_file"].strip(), self.settings["profile"].strip()
        where = f"connector {self.name} ({self.INFO.type})"
        if path:
            if not (os.path.isfile(path) and os.access(path, os.R_OK)):
                self.profile_problems.append(f"{where}: PROFILE_FILE cannot be read")
                return None
            try:
                return snmp_profiles.load_file(path)
            except snmp_profiles.ProfileError:
                # the detail quotes values from the file; it is shown by `python -m leasewatch snmp-detect`, not here
                self.profile_problems.append(f"{where}: PROFILE_FILE is not a valid snmp profile (run: python -m leasewatch snmp-detect {self.name})")
                return None
        if name:
            try:
                return snmp_profiles.load(name)
            except snmp_profiles.ProfileError:
                self._bad_profile_name = True  # validate() reports it through the generic choices check
                return None
        return None

    def _min_macs(self) -> int | None:
        v = self.settings["min_macs"].strip()
        if not v:
            return None
        try:  # int(), not isdigit(): "²" is a digit to isdigit() but int() rejects it
            n = int(v)
        except ValueError:
            n = 0
        if n >= 1:
            return n
        self.profile_problems.append(f"connector {self.name} ({self.INFO.type}): MIN_MACS must be an integer >= 1")
        return None

    def validate(self) -> list[str]:
        return self._generic_problems() + self.profile_problems

    def _refuse_if_invalid(self) -> None:
        if self.profile_problems or self._bad_profile_name:
            raise ConnectorError("invalid profile settings (see the configuration check)")

    def _error(self, e: Exception) -> ConnectorError:
        """The one exception type for every failure. The client's own messages never contain the host or the keys,
        but pysnmp's do (PySnmpError: "Bad IPv4/UDP transport address <host>@161"), so the host is taken out of all
        of them; the keys are redacted by the host."""
        if isinstance(e, ConnectorError):
            return e
        if isinstance(e, ImportError):
            return ConnectorError("missing dependency pysnmp")
        text = str(e) or type(e).__name__
        host = self.settings["host"].strip()
        return ConnectorError(text.replace(host, "<host>") if host else text)

    def check(self) -> None:
        """One GET of sysObjectID and sysDescr: reachability and credentials, without a walk."""
        self._refuse_if_invalid()
        try:
            self.client.probe()
        except Exception as e:
            err = self._error(e)
            if err is e:
                raise
            raise err from e

    def collect(self) -> Batch:
        self._refuse_if_invalid()
        try:
            snap = self.client.snapshot()
            name_uplinks(snap, self.ctx.device_names)
            # "strategy" is a string (the FDB strategy that produced the rows; cisco_per_vlan may fall back to qbridge):
            # stats may carry strings besides the counts. The host sums stats of sighting producers only, not this one.
            return Batch(attachments=to_attachments(snap, self.name, self.settings["name"], self.ctx.now()),
                         stats={"macs": len(snap.by_mac), "strategy": snap.strategy})  # type: ignore[dict-item]
        except Exception as e:
            err = self._error(e)
            if err is e:
                raise
            raise err from e

    def close(self) -> None:
        pass  # each snapshot opens and closes its own SNMP engine
