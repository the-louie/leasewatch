"""OPNsense firewall as a connector: DHCPv4 leases (ISC or Kea, plus Kea reservations) and the ARP table.

A thin wrapper around fw1.Fw1Client; the client and its normalised fw1.Sighting stay the internal type for now.
"""
from __future__ import annotations

from typing import Mapping

from ..fw1 import Fw1Client, Fw1Error
from ..fw1 import Sighting as Fw1Sighting
from . import (API_VERSION, Batch, ConnectorError, ConnectorInfo, HostContext, Setting, SettingsMixin, Sighting,
               parse_bool, url_problems)


def to_sighting(s: Fw1Sighting, source: str, observed_at: int) -> Sighting:
    """fw1's record in the connector shape: its "source" (dhcp/arp) is the kind, "online" the presence claim,
    "vlan" the network name; source becomes the instance name."""
    return Sighting(mac=s.mac, source=source, kind=s.source, presence=s.online, observed_at=observed_at,
                    ip=s.ip, hostname=s.hostname, vendor=s.vendor, network=s.vlan, iface=s.iface, lease_type=s.lease_type)


class OpnsenseConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="opnsense", version="1.0", api_version=API_VERSION, produces=frozenset({"sighting"}),
        settings=(
            Setting("url", required=True, help="https://<opnsense>"),
            Setting("key", required=True, secret=True, help="API key"),
            Setting("secret", required=True, secret=True, help="API secret"),
            Setting("verify_tls", default="1", help="check the firewall's certificate"),
            Setting("dhcp_backend", default="kea", choices=("isc", "kea"), help="DHCPv4 server to read leases from"),
            Setting("ignore_interfaces", default="wan,lo0", help="comma-separated identifiers, devices or descriptions"),
            Setting("proxy", default="0", help="honour http(s)_proxy for this connection"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None, client: Fw1Client | None = None) -> None:
        self._init_settings(name, settings, ctx)
        self.settings["dhcp_backend"] = self.settings["dhcp_backend"].lower()
        self.ignore_interfaces = tuple(x for x in self.settings["ignore_interfaces"].split(",") if x)
        verify = parse_bool(self.settings["verify_tls"])
        proxy = parse_bool(self.settings["proxy"])
        # building the client is no I/O (an SSL context and an opener); read at call time so the host can swap it
        self.client = client or Fw1Client(self.settings["url"], self.settings["key"], self.settings["secret"],
                                          True if verify is None else verify, dhcp_backend=self.settings["dhcp_backend"],
                                          use_env_proxy=bool(proxy))

    def validate(self) -> list[str]:
        problems = self._generic_problems()
        if self.settings["url"]:
            problems += url_problems("url", self.settings["url"], "https://<opnsense>")
        for key in ("verify_tls", "proxy"):
            if parse_bool(self.settings[key]) is None:
                problems.append(f"{key} must be a boolean (1/0, true/false, yes/no, on/off)")
        return problems

    def check(self) -> None:
        try:
            self.client.arp_raw()
        except Fw1Error as e:
            raise ConnectorError(str(e)) from e

    def collect(self) -> Batch:
        try:
            sightings, stats = self.client.sightings(self.ignore_interfaces)
        except Fw1Error as e:
            raise ConnectorError(str(e)) from e
        now = self.ctx.now()
        return Batch(sightings=[to_sighting(s, self.name, now) for s in sightings], stats=dict(stats))

    def close(self) -> None:
        pass  # each call opens and closes its own connection
