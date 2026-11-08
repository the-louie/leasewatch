"""The DNS wire format of an mDNS response, read into the (hostname, IPv4 address, label) triples the connector
caches.

parse_response() reads the header (RFC 1035), skips the questions and walks the answer, authority and additional
records, at most MAX_RECORDS of them. Names may be compressed; a pointer must point before the start of the name
being read and before every earlier pointer target of that name, so a loop or a forward pointer is refused. The
class field's top bit (the mDNS cache-flush bit, RFC 6762) is masked; records of a class other than IN are skipped.

A records give a host and its IPv4 address. DNS-SD records (RFC 6763) give the label: an SRV record ties a service
instance to its target host, the instance's TXT record gives the text ("fn=", else "md=", else "model=", else
"ty=", else "product=" without its parentheses). One triple per A record (host, address); an instance whose target
host has no A record in the packet gives nothing. A query (QR bit clear) gives nothing and is not an error. A record
with TTL 0 (a goodbye) is returned like any other. A packet that stops parsing part way sets `malformed` and keeps
the triples of the records read before. It never raises.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

HEADER = 12
MAX_RECORDS = 64  # answer + authority + additional records read at most; the rest is left unread
MAX_NAME = 255  # bytes of a name on the wire, uncompressed (RFC 1035 2.3.4)
MAX_LABELS = 128
MAX_LABEL_TEXT = 64  # characters of a label kept

TYPE_A, TYPE_PTR, TYPE_TXT, TYPE_SRV = 1, 12, 16, 33
CLASS_IN = 1
_LABEL_KEYS = ("fn", "md", "model", "ty", "product")  # the TXT keys that give a label, the best first


@dataclass
class ParsedPacket:
    names: list[tuple[str, str, str]] = field(default_factory=list)  # (hostname, ipv4, label)
    malformed: bool = False
    truncated: bool = False  # more than MAX_RECORDS records; the first ones were read


class _Bad(Exception):
    """The packet does not parse from here on."""


def _name(data: bytes, off: int) -> tuple[list[bytes], int]:
    """The labels of the name at `off` and the offset just after it (after its first pointer, if any)."""
    labels: list[bytes] = []
    size = 1  # the root label's length byte
    end = -1
    limit = off  # a pointer must point before this: the name's start, then the previous pointer target
    while True:
        if off >= len(data):
            raise _Bad
        n = data[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise _Bad
            target = (n & 0x3F) << 8 | data[off + 1]
            if target >= limit:
                raise _Bad
            if end < 0:
                end = off + 2
            limit = off = target
            continue
        if n & 0xC0:  # 0x40 and 0x80: label types that are not in use
            raise _Bad
        if n == 0:
            return labels, (off + 1 if end < 0 else end)
        if off + 1 + n > len(data):
            raise _Bad
        labels.append(data[off + 1:off + 1 + n])
        size += n + 1
        if size > MAX_NAME or len(labels) > MAX_LABELS:
            raise _Bad
        off += 1 + n


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _key(labels: list[bytes]) -> str:
    return ".".join(_text(x) for x in labels).lower()


def _clean(text: str) -> str:
    """Control characters removed, cut to MAX_LABEL_TEXT characters."""
    return "".join(ch for ch in text if ch >= " " and not "\x7f" <= ch <= "\x9f").strip()[:MAX_LABEL_TEXT].strip()


def _txt(data: bytes, start: int, end: int) -> dict[str, str]:
    entries: dict[str, str] = {}
    off = start
    while off < end:
        n = data[off]
        if off + 1 + n > end:
            raise _Bad
        item = data[off + 1:off + 1 + n]
        off += 1 + n
        key, eq, value = item.partition(b"=")
        if not eq or not key:
            continue
        k = _text(key).lower()
        if k not in entries:
            entries[k] = _text(value)
    return entries


def _label(key: str, value: str) -> str:
    value = value.strip()
    if key == "product" and value.startswith("(") and value.endswith(")"):
        value = value[1:-1]
    return _clean(value)


def _parse(data: bytes, out: ParsedPacket) -> tuple[list[tuple[str, str, str]], dict[str, str],
                                                       dict[str, dict[str, str]]]:
    """Walk the records into (A records as (host key, hostname, ip), SRV instance -> host, TXT instance -> entries).

    A parse error sets out.malformed and returns what was read before it."""
    a_records: list[tuple[str, str, str]] = []
    srv: dict[str, str] = {}
    txt: dict[str, dict[str, str]] = {}
    if len(data) < HEADER:
        out.malformed = True
        return a_records, srv, txt
    _id, flags, qd, an, ns, ar = struct.unpack_from("!6H", data)
    if not flags & 0x8000:
        return a_records, srv, txt
    total = an + ns + ar
    if total > MAX_RECORDS:
        out.truncated = True
        total = MAX_RECORDS
    try:
        off = HEADER
        for _ in range(qd):
            _labels, off = _name(data, off)
            off += 4  # type, class
            if off > len(data):
                raise _Bad
        for _ in range(total):
            owner, off = _name(data, off)
            if off + 10 > len(data):
                raise _Bad
            rtype, rclass, _ttl, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            start, off = off, off + rdlen
            if off > len(data):
                raise _Bad
            if rclass & 0x7FFF != CLASS_IN:
                continue
            if rtype == TYPE_A:
                if rdlen != 4 or not owner:
                    raise _Bad
                ip = ".".join(str(b) for b in data[start:off])
                a_records.append((_key(owner), _clean(_text(owner[0])), ip))
            elif rtype == TYPE_PTR:
                _target, end = _name(data, start)  # read for its bounds: the instance is known by its SRV/TXT
                if end > off:
                    raise _Bad
            elif rtype == TYPE_SRV:
                if rdlen < 7:
                    raise _Bad
                target, end = _name(data, start + 6)
                if end > off:
                    raise _Bad
                srv.setdefault(_key(owner), _key(target))
            elif rtype == TYPE_TXT:
                txt.setdefault(_key(owner), _txt(data, start, off))
    except _Bad:
        out.malformed = True
    return a_records, srv, txt


def parse_response(data: bytes) -> ParsedPacket:
    """The names in one mDNS packet. Never raises: anything unexpected is a malformed packet without names."""
    out = ParsedPacket()
    try:
        a_records, srv, txt = _parse(data, out)
        labels: dict[str, str] = {}
        for key in _LABEL_KEYS:  # the best key of any instance on the host wins
            for instance, host in srv.items():
                if host not in labels:
                    label = _label(key, txt.get(instance, {}).get(key, ""))
                    if label:
                        labels[host] = label
        seen: set[tuple[str, str]] = set()
        for host, hostname, ip in a_records:
            if not hostname or (host, ip) in seen:
                continue
            seen.add((host, ip))
            out.names.append((hostname, ip, labels.get(host, "")))
    except Exception:  # noqa: BLE001 - the contract is that the parser never raises
        return ParsedPacket(malformed=True)
    return out
