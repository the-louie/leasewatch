"""Wi-Fi details per MAC from a self-hosted UniFi Network controller (classic session API, read-only user).

GET /api/s/<site>/stat/sta gives every active client: ap_mac, essid, channel, radio, signal, is_wired,
and the operator-set alias ("name"). /stat/device maps ap_mac to the AP's name.
"""
from __future__ import annotations

import http.client
import http.cookiejar
import json
import logging
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

from .config import Config
from .fw1 import MAX_BODY, _NoRedirect, norm_mac

log = logging.getLogger("leasewatch.unifi")


@dataclass
class WifiInfo:
    ssid: str = ""
    ap: str = ""
    signal: int | None = None   # dBm
    radio: str = ""             # "2.4 GHz" / "5 GHz" / "6 GHz"
    channel: int | None = None
    wired: bool = False         # seen by UniFi as a wired client (behind a UniFi switch/AP port)
    alias: str = ""             # name set in the UniFi controller


RADIO_NAMES = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz", "ac": "5 GHz", "ax": "5 GHz"}


def parse_clients(sta: list[dict], devices: list[dict]) -> dict[str, WifiInfo]:
    """Pure function over the two API payloads (unit-testable)."""
    # a device without a usable MAC must not map "" -> name, or every client without ap_mac would get that AP
    ap_names = {norm_mac(d.get("mac", "")): (d.get("name") or d.get("hostname") or d.get("mac", "")) for d in devices
                if norm_mac(d.get("mac", ""))}
    out: dict[str, WifiInfo] = {}
    for c in sta:
        mac = norm_mac(c.get("mac", ""))
        if not mac:
            continue
        wired = bool(c.get("is_wired"))
        sig = c.get("signal")  # dBm; "rssi" is an SNR-like positive number, not a usable fallback
        try:
            sig = int(sig) if sig is not None else None
        except (TypeError, ValueError):
            sig = None
        radio = str(c.get("radio") or "")
        out[mac] = WifiInfo(
            ssid="" if wired else str(c.get("essid") or ""),
            ap="" if wired else ap_names.get(norm_mac(c.get("ap_mac", "")), ""),
            signal=None if wired else sig,
            radio="" if wired else RADIO_NAMES.get(radio, radio),
            channel=None if wired else (int(c["channel"]) if str(c.get("channel", "")).isdigit() else None),
            wired=wired, alias=str(c.get("name") or ""),
        )
    return out


class UnifiClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._ctx = ssl.create_default_context()
        if not cfg.unifi_verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _opener(self):
        cj = http.cookiejar.CookieJar()
        # no redirects: a 3xx on /api/login would carry the password to wherever it points
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=self._ctx), _NoRedirect())

    def _get(self, op, path: str) -> list[dict]:
        with op.open(urllib.request.Request(self.cfg.unifi_url + path, headers={"Accept": "application/json"}), timeout=20) as r:
            raw = r.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise RuntimeError("unifi: response too large")
        body = json.loads(raw.decode())
        if not isinstance(body, dict):
            raise RuntimeError("unifi: unexpected response shape")
        meta = body.get("meta")
        if isinstance(meta, dict) and "rc" in meta and meta["rc"] != "ok":
            raise RuntimeError(f"unifi: {meta.get('msg') or 'api error'}")
        data = body.get("data", [])
        if not isinstance(data, list):
            raise RuntimeError("unifi: unexpected response shape")
        return data

    def clients(self) -> dict[str, WifiInfo]:
        """Blocking. Raises on failure."""
        op = self._opener()
        try:
            body = json.dumps({"username": self.cfg.unifi_user, "password": self.cfg.unifi_password}).encode()
            with op.open(urllib.request.Request(self.cfg.unifi_url + "/api/login", data=body, headers={"Content-Type": "application/json"}), timeout=20) as r:
                r.read()
            site = self.cfg.unifi_site
            sta = self._get(op, f"/api/s/{site}/stat/sta")
            devices = self._get(op, f"/api/s/{site}/stat/device")
            return parse_clients(sta, devices)
        except urllib.error.HTTPError as e:
            e.close()  # the error carries the open response; release its socket
            raise RuntimeError(f"unifi: HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError, OSError) as e:
            raise RuntimeError(f"unifi: {e}") from e
        except (TypeError, AttributeError, ValueError, OverflowError, RecursionError, http.client.HTTPException) as e:
            # no exception text: an InvalidURL/ValueError can echo UNIFI_URL, credentials included
            raise RuntimeError("unifi: unexpected response") from e
        finally:
            try:
                op.open(urllib.request.Request(self.cfg.unifi_url + "/api/logout", data=b"", method="POST"), timeout=10).read()
            except Exception:
                pass
