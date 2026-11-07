"""A UniFi Network controller (self-hosted, or a UniFi OS console) as a connector: Wi-Fi SSID/AP/signal per client, or "wired" for a
client the controller sees on a cable. A thin wrapper around unifi.UnifiClient (read-only user).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from ..unifi import UnifiClient, WifiInfo
from . import (API_VERSION, Attachment, Batch, ConnectorError, ConnectorInfo, HostContext, Setting, SettingsMixin,
               mask_url_host, parse_bool, url_problems)


@dataclass
class _UnifiCfg:
    """The attributes UnifiClient reads (the 1.0 Config field names); the password kept out of repr."""
    unifi_url: str
    unifi_site: str
    unifi_user: str
    unifi_password: str = field(repr=False)
    unifi_verify_tls: bool = True
    lan_proxy: bool = False
    platform: str = "classic"  # "auto", "classic" or "unifi_os"; the connector always passes its PLATFORM setting


def to_attachments(wifi: dict[str, WifiInfo], source: str, observed_at: int) -> list[Attachment]:
    out = []
    for mac, w in wifi.items():
        out.append(Attachment(mac=mac, source=source, observed_at=observed_at, link="wired" if w.wired else "wifi",
                              ssid=w.ssid, ap=w.ap, signal=w.signal, radio=w.radio, alias=w.alias,
                              present=True))  # the controller lists only active clients
    return out


class UnifiConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="unifi", version="1.1", api_version=API_VERSION, produces=frozenset({"attachment"}),
        roles=frozenset({"controller"}),
        settings=(
            Setting("url", required=True, help="https://<controller>"),
            Setting("site", default="default", help="UniFi site id"),
            Setting("user", required=True, help="read-only controller user"),
            Setting("password", required=True, secret=True, help="its password"),
            Setting("verify_tls", default="1", help="check the controller's certificate"),
            Setting("proxy", default="0", help="honour http(s)_proxy for this connection"),
            Setting("platform", default="auto", choices=("auto", "classic", "unifi_os"),
                    help="auto = detect; classic = self-hosted Network app; unifi_os = UDM/UCG/UniFi OS console"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None, client: object | None = None) -> None:
        self._init_settings(name, settings, ctx)
        s = self.settings
        s["url"] = s["url"].rstrip("/") or s["url"]  # "/" stays, so validate() calls it malformed, not missing
        verify = parse_bool(s["verify_tls"])
        # read at call time: the host (and tests) may swap the client object
        self.client = client if client is not None else UnifiClient(_UnifiCfg(s["url"], s["site"], s["user"], s["password"],  # type: ignore[arg-type]
                                                                                  True if verify is None else verify, bool(parse_bool(s["proxy"])),
                                                                                  s["platform"]))

    def validate(self) -> list[str]:
        problems = self._generic_problems()
        if self.settings["url"]:
            problems += url_problems("url", self.settings["url"], "https://<controller>")
        for key in ("verify_tls", "proxy"):
            if parse_bool(self.settings[key]) is None:
                problems.append(f"{key} must be a boolean (1/0, true/false, yes/no, on/off)")
        return problems

    def check(self) -> None:
        try:
            self.client.clients()  # two reads on the kept session (login first if there is none)
        except ConnectorError:
            raise
        except Exception as e:  # never the URL or the password, but a TLS name mismatch echoes the host
            raise ConnectorError(mask_url_host(str(e) or type(e).__name__, self.settings["url"])) from e

    def collect(self) -> Batch:
        try:
            wifi = self.client.clients()
            return Batch(attachments=to_attachments(wifi, self.name, self.ctx.now()), stats={"clients": len(wifi)})
        except ConnectorError:
            raise
        except Exception as e:  # never the URL or the password, but a TLS name mismatch echoes the host
            raise ConnectorError(mask_url_host(str(e) or type(e).__name__, self.settings["url"])) from e

    def close(self) -> None:
        close = getattr(self.client, "close", None)  # a stand-in client (tests, host) may have none
        if callable(close):
            close()  # logs out of the kept session
