"""The text of an SSDP announcement (UPnP Device Architecture 1.1), read into the fields the connector uses.

parse_notify() accepts only a NOTIFY request ("NOTIFY * HTTP/1.1", or HTTP/1.0) whose NTS is "ssdp:alive". It reads
at most MAX_BYTES bytes and MAX_LINES header lines; header names are case-insensitive, split on the first ":", values
are stripped and the first occurrence of a name wins. Lines end with CRLF or LF; the body after the blank line is
ignored. Bytes that are not UTF-8 are read as text with replacement characters. An M-SEARCH, an HTTP response, a
byebye, a malformed or an oversized datagram gives (None, reason). It never raises.

LOCATION is read for its host text only and is never fetched: the module makes no network call of any kind.

product_label() turns SERVER ("OS/version UPnP/1.0 product/version") into a label: the tokens after the "UPnP/"
token, unless the product is a generic UPnP stack (GENERIC), which names the software library, not the device.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .dns import _clean

MAX_BYTES = 2048  # bytes of a datagram read; a longer one is refused as oversized
MAX_LINES = 32  # header lines read; a datagram with more is malformed
REQUEST_LINES = frozenset({"NOTIFY * HTTP/1.1", "NOTIFY * HTTP/1.0"})  # matched case-sensitively
# lower-cased names of UPnP stacks and SDKs: a product token with one of these names says nothing about the device
GENERIC = frozenset({
    "portable sdk for upnp devices", "upnp-device-host", "miniupnpd", "platinum", "cling", "dlnadoc",
    "samsung upnp sdk", "libupnp", "intelupnp", "windowsmediaplayer",
})
_SPLIT = re.compile(r"[\s,]+")  # SERVER tokens are separated by white space and commas
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
_HOST = re.compile(r"[A-Za-z0-9._-]+")


@dataclass(frozen=True)
class Notify:
    server: str  # "" when absent
    location_host: str  # the host part of LOCATION; "" when absent or unparsable
    nts: str
    usn: str


def _host(location: str) -> str:
    """The host of a URL as text ("10.0.0.40", "sonos.example.lan", "2001:db8::40"), or "" when it does not parse."""
    scheme, sep, rest = location.strip().partition("://")
    if not sep or not _SCHEME.fullmatch(scheme):
        return ""
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    authority = authority.rpartition("@")[2]
    if authority.startswith("["):
        inside, close, port = authority[1:].partition("]")
        if not close or (port and not (port.startswith(":") and port[1:].isdigit())):
            return ""
        try:
            return str(ipaddress.IPv6Address(inside))
        except ValueError:
            return ""
    host, colon, port = authority.partition(":")
    if colon and not (port.isascii() and port.isdigit()):
        return ""
    return host if _HOST.fullmatch(host) else ""


def parse_notify(data: bytes) -> tuple[Notify | None, str]:
    """(Notify, "") for an ssdp:alive NOTIFY; else (None, reason): "not_notify", "byebye", "malformed",
    "oversized"."""
    if len(data) > MAX_BYTES:
        return None, "oversized"
    text = data.decode("utf-8", errors="replace")
    if "\n" not in text:
        return None, "malformed"
    lines = text.split("\n")
    if lines[0].removesuffix("\r") not in REQUEST_LINES:
        return None, "not_notify"
    headers: dict[str, str] = {}
    count = 0
    for line in lines[1:]:
        line = line.removesuffix("\r")
        if not line:
            break  # the blank line: the body after it is ignored
        count += 1
        if count > MAX_LINES:
            return None, "malformed"
        key, colon, value = line.partition(":")
        key = key.strip().lower()
        if not colon or not key:
            return None, "malformed"
        headers.setdefault(key, value.strip())
    nts = headers.get("nts", "")
    if nts.lower() == "ssdp:byebye":
        return None, "byebye"
    if nts.lower() != "ssdp:alive":
        return None, "not_notify"
    return Notify(server=headers.get("server", ""), location_host=_host(headers.get("location", "")),
                  nts=nts, usn=headers.get("usn", "")), ""


def _tail(server: str) -> list[str] | None:
    """The SERVER tokens after the first "UPnP/" token, or None when there is no such token."""
    tokens = [t for t in _SPLIT.split(server) if t]
    for i, token in enumerate(tokens):
        if token.lower().startswith("upnp/"):
            return tokens[i + 1:]
    return None


def _generic(tail: list[str]) -> bool:
    if tail[0].split("/", 1)[0].lower() in GENERIC:
        return True
    joined = " ".join(tail).lower()  # a generic name with spaces in it spans several tokens
    return any(joined == g or joined.startswith((g + "/", g + " ")) for g in GENERIC if " " in g)


def is_generic(server: str) -> bool:
    """True when SERVER has a "UPnP/" token and the product after it is a generic UPnP stack."""
    tail = _tail(server)
    return bool(tail) and _generic(tail)


def product_label(server: str) -> str:
    """The product text after the "UPnP/" token of SERVER, cleaned and cut to 64 characters; "" when there is no
    "UPnP/" token, nothing after it, or the product is generic."""
    tail = _tail(server)
    if not tail or _generic(tail):
        return ""
    return _clean(" ".join(tail))
