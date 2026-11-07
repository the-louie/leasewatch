"""A managed switch over SNMPv3 as a connector: which port each MAC is learned on (Q-BRIDGE FDB, IF-MIB, LLDP).

A thin wrapper around switch.SwitchClient. pysnmp stays a lazy import inside the client.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Mapping

from .. import snmp_profiles
from ..switch import AUTH_NAMES, PRIV_NAMES, SwitchClient, SwitchSnapshot, unsupported_protocols
from . import (API_VERSION, Attachment, Batch, ConnectorError, ConnectorInfo, HostContext, Setting, SettingsMixin,
               _bounded, _forms, make_redactor)

INFRA_RE = re.compile(r"^(ap|apu|sw|switch|xgs|gs|usw|uap)[-_0-9]", re.I)  # hostnames that mean "another AP/switch hangs on this port"


@dataclass
class _SnmpCfg:
    """The attributes SwitchClient reads (the 1.0 Config field names); secrets kept out of repr."""
    snmp_host: str
    snmp_user: str
    snmp_auth: str
    snmp_auth_key: str = field(repr=False)
    snmp_priv_key: str = field(repr=False)
    snmp_port: int = 161
    snmp_priv: str = "AES"


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
                              port=port, via=via, uplink=bool(p and p.uplink), vlan=vlan or None))  # 0: bridge FDB, VLAN unknown
    return out


class SnmpSwitchConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="snmp_switch", version="1.1", api_version=API_VERSION, produces=frozenset({"attachment"}),
        settings=(
            Setting("host", required=True, help="switch address"),
            Setting("name", default="switch", help="switch name shown in the UI"),
            Setting("user", default="leasewatch", help="SNMPv3 user"),
            Setting("port", default="161", kind="int", min=1, max=65535, help="switch SNMP UDP port"),
            Setting("auth", default="SHA", choices=tuple(AUTH_NAMES), help="SNMPv3 auth protocol"),
            Setting("auth_key", required=True, secret=True, help="SNMPv3 auth key"),
            Setting("priv_key", required=True, secret=True, help="SNMPv3 privacy key"),
            Setting("priv", default="AES", choices=tuple(PRIV_NAMES), help="SNMPv3 privacy protocol: AES = AES-128; AES192/AES256 extend the key as Cisco does, AES192B/AES256B as the Blumenthal draft"),
            Setting("profile", choices=snmp_profiles.BUILTIN, help="built-in SNMP profile; empty = detect from sysObjectID/sysDescr"),
            Setting("profile_file", help="path to a JSON SNMP profile; wins over profile"),
            Setting("min_macs", help="MACs on a port without LLDP that make it an uplink; empty = the profile's uplink.min_macs"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None, client: object | None = None) -> None:
        self._init_settings(name, settings, ctx)
        # stripped before validate()'s choices check, which compares the value as given
        for k in ("auth", "priv", "profile", "profile_file", "min_macs"):
            self.settings[k] = self.settings[k].strip()
        self.settings["auth"] = self.settings["auth"].upper().replace("-", "")
        self.settings["priv"] = self.settings["priv"].upper().replace("-", "")
        s = self.settings
        # problems with profile/profile_file/min_macs, reported by validate(); collect()/check() refuse to run with one,
        # so a bad profile setting never falls back to detection unnoticed
        self.profile_problems: list[str] = []
        self._bad_profile_name = False
        profile = self._profile()
        min_macs = self._min_macs()
        # read at call time: the host (and tests) may swap the client object
        self.client = client if client is not None else SwitchClient(_SnmpCfg(s["host"], s["user"], s["auth"], s["auth_key"], s["priv_key"], self._port(), s["priv"]),  # type: ignore[arg-type]
                                                                     profile=profile, min_macs=min_macs, name=name, timeout=self.ctx.timeout)

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
            except (snmp_profiles.ProfileError, RecursionError):  # RecursionError: a deeply nested value, copied later
                # the detail quotes values from the file; it is shown by `python -m leasewatch snmp-detect`, not here
                self.profile_problems.append(f"{where}: PROFILE_FILE is not a valid snmp profile (run: python -m leasewatch snmp-detect {self.name})")
                return None
        if name:
            try:
                return snmp_profiles.load(name)
            except snmp_profiles.ProfileError:
                self._bad_profile_name = True  # a name outside BUILTIN is reported by the generic choices check
                if name in snmp_profiles.BUILTIN:  # a shipped profile that fails to load: a broken install
                    self.profile_problems.append(f"{where}: built-in PROFILE {name} cannot be loaded")
                return None
        return None

    def _port(self) -> int:
        """The PORT setting; a bad value is reported by validate(), so the client gets the default meanwhile."""
        try:
            n = int(self.settings["port"].strip())
        except ValueError:
            return 161
        return n if 1 <= n <= 65535 else 161

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
        # an explicitly empty USER overrides the default and can never authenticate
        user = [] if self.settings["user"].strip() else [f"connector {self.name} ({self.INFO.type}): USER is required"]
        generic = self._generic_problems()
        # only a known value: an unknown one is already reported above
        crypto = [] if generic else unsupported_protocols(self.settings["auth"], self.settings["priv"])
        where = f"connector {self.name} ({self.INFO.type}): "
        return generic + user + self.profile_problems + [where + t for t in crypto]

    def _refuse_if_invalid(self) -> None:
        if self.profile_problems or self._bad_profile_name:
            raise ConnectorError("invalid profile settings (see the configuration check)")
        crypto = unsupported_protocols(self.settings["auth"], self.settings["priv"])
        if crypto:
            raise ConnectorError(crypto[0])

    def redact(self, text: str) -> str:
        """`text` with the host, the USM user name and the secret settings (via make_redactor: repr/JSON forms, not
        under MIN_SECRET_LEN) masked. Host and user match whole occurrences only and not when shorter than MIN_REDACT
        (see there). Host and user go first: a key that is a substring of the host ("0.0" in "10.0.0.2") would
        otherwise break the host apart so its whole-occurrence pattern no longer matches the rest. A secret that contains
        the host or user ("admin@2024x" with user "admin") goes before them, or their mask would leave its rest, unless
        it is itself part of the host ("admin-sw01" in "admin-sw01.example.lan"): then the host goes first, as above."""
        hosts = {f.lower() for f in _forms(self.settings.get("host", ""))}
        names = hosts | {f.lower() for f in _forms(self.settings.get("user", ""))}
        secrets = [self.settings.get(st.key, "") for st in self.INFO.settings if st.secret]
        text = make_redactor(v for v in secrets if any(n in v.lower() for n in names)
                             and not any(v.lower() in h for h in hosts))(text)
        for key, mask in (("host", "<host>"), ("user", "<user>")):
            for rx in _bounded(_forms(self.settings.get(key, ""))):
                text = rx.sub(mask, text)
        return make_redactor(secrets)(text)

    def _error(self, e: Exception) -> ConnectorError:
        """The one exception type for every failure. The client's own messages never contain the host or the keys,
        but pysnmp's do (PySnmpError: "Bad IPv4/UDP transport address <host>@161"), so every text goes through
        redact()."""
        if isinstance(e, ConnectorError):
            return e
        if isinstance(e, ImportError):
            # only "pysnmp" itself missing means it is not installed. Anything else is named, as pysnmp is then there:
            # a module of its own or a name in one (a pysnmp before 7), or a module it needs (a crypto backend, "imp"
            # for a pysnmp 4.x). A module name is no secret; e.msg is not used, it may carry a file path. A missing
            # "pysnmp.x" counts as an older pysnmp only when the package itself was imported (read from sys.modules,
            # not changed): a None entry there, as a blocked import leaves it, means pysnmp is not usable at all.
            own = e.name is not None and e.name.startswith("pysnmp.")
            if e.name and e.name != "pysnmp" and (not own or sys.modules.get("pysnmp") is not None):
                what = f"no module {e.name}" if isinstance(e, ModuleNotFoundError) else f"a name is missing in {e.name}"
                return ConnectorError(f"pysnmp cannot be imported: {what} (pysnmp 7 and its dependencies are needed)")
            return ConnectorError("missing dependency pysnmp")
        return ConnectorError(self.redact(str(e) or type(e).__name__))

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
