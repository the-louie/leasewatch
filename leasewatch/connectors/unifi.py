"""A self-hosted UniFi Network controller as a connector: Wi-Fi SSID/AP/signal per client, or "wired" for a
client the controller sees on a cable. A thin wrapper around unifi.UnifiClient (read-only user).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from ..unifi import UnifiClient, WifiInfo
from . import (API_VERSION, Attachment, Batch, ConnectorError, ConnectorInfo, HostContext, Setting, SettingsMixin,
               parse_bool, url_problems)


@dataclass
class _UnifiCfg:
    """The Config attributes UnifiClient reads; the password kept out of repr like Config does."""
    unifi_url: str
    unifi_site: str
    unifi_user: str
    unifi_password: str = field(repr=False)
    unifi_verify_tls: bool = True
    lan_proxy: bool = False


def to_attachments(wifi: dict[str, WifiInfo], source: str, observed_at: int) -> list[Attachment]:
    out = []
    for mac, w in wifi.items():
        out.append(Attachment(mac=mac, source=source, observed_at=observed_at, link="wired" if w.wired else "wifi",
                              ssid=w.ssid, ap=w.ap, signal=w.signal, radio=w.radio, alias=w.alias))
    return out


class UnifiConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="unifi", version="1.0", api_version=API_VERSION, produces=frozenset({"attachment"}),
        settings=(
            Setting("url", required=True, help="https://<controller>"),
            Setting("site", default="default", help="UniFi site id"),
            Setting("user", required=True, help="read-only controller user"),
            Setting("password", required=True, secret=True, help="its password"),
            Setting("verify_tls", default="1", help="check the controller's certificate"),
            Setting("proxy", default="0", help="honour http(s)_proxy for this connection"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None, client: object | None = None) -> None:
        self._init_settings(name, settings, ctx)
        s = self.settings
        s["url"] = s["url"].rstrip("/")
        verify = parse_bool(s["verify_tls"])
        # read at call time: the host (and tests) may swap the client object
        self.client = client or UnifiClient(_UnifiCfg(s["url"], s["site"], s["user"], s["password"],  # type: ignore[arg-type]
                                                      True if verify is None else verify, bool(parse_bool(s["proxy"]))))

    def validate(self) -> list[str]:
        problems = self._generic_problems()
        if self.settings["url"]:
            problems += url_problems("url", self.settings["url"], "https://<controller>")
        for key in ("verify_tls", "proxy"):
            if parse_bool(self.settings[key]) is None:
                problems.append(f"{key} must be a boolean (1/0, true/false, yes/no, on/off)")
        return problems

    def _clients(self) -> dict[str, WifiInfo]:
        try:
            return self.client.clients()
        except RuntimeError as e:
            raise ConnectorError(str(e) or type(e).__name__) from e

    def check(self) -> None:
        self._clients()  # login, two reads, logout: the smallest call the classic API offers

    def collect(self) -> Batch:
        wifi = self._clients()
        return Batch(attachments=to_attachments(wifi, self.name, self.ctx.now()), stats={"clients": len(wifi)},
                     extra={"wifi": wifi})

    def close(self) -> None:
        pass  # each call logs in and out on its own opener
