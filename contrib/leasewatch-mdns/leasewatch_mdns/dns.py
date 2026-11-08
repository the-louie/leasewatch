"""The DNS wire format of an mDNS response, read into the (hostname, IPv4 address, label) triples the connector
caches.

To be implemented: parse_response() will read the header, skip the questions and walk the answer, authority and
additional records with name compression (loops and out-of-range pointers refused). A records give hostname and
IPv4 address; PTR/SRV/TXT records of DNS-SD services give the label (the model from a TXT "md=" or "model="
entry, else the service instance name). Queries (QR bit clear) give nothing. A record with TTL 0 (a goodbye) is
returned like any other. Anything that does not parse sets `malformed`. It never raises.

Until then it returns an empty packet, so the connector's listener runs but hears no names.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedPacket:
    names: list[tuple[str, str, str]] = field(default_factory=list)  # (hostname, ipv4, label)
    malformed: bool = False


def parse_response(data: bytes) -> ParsedPacket:
    """The names in one mDNS packet. Not implemented yet: always an empty packet."""
    return ParsedPacket()
