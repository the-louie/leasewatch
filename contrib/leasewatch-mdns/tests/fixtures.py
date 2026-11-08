"""Handcrafted mDNS packets for the parser tests, built from bytes here (no binary files). Synthetic data only."""
from __future__ import annotations

import struct

A, PTR, TXT, SRV = 1, 12, 16, 33
IN = 1
FLUSH = 0x8000  # the mDNS cache-flush bit in the class field
HEADER = 12


def name(dotted: str = "", pointer: int | None = None) -> bytes:
    """A name on the wire: the labels of `dotted`, then the root label, or a pointer to `pointer` instead of it."""
    out = b"".join(bytes([len(x)]) + x for x in (p.encode() for p in dotted.split(".") if p))
    return out + (b"\x00" if pointer is None else struct.pack("!H", 0xC000 | pointer))


def rr(owner: str | bytes, rtype: int, rdata: bytes, ttl: int = 120, rclass: int = IN | FLUSH) -> bytes:
    """One resource record; `owner` is a dotted name or a name already on the wire."""
    if isinstance(owner, str):
        owner = name(owner)
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def question(dotted: str, qtype: int = PTR) -> bytes:
    return name(dotted) + struct.pack("!HH", qtype, IN)


def a(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def srv(target: bytes | str, port: int) -> bytes:
    return struct.pack("!HHH", 0, 0, port) + (name(target) if isinstance(target, str) else target)


def txt(*items: str) -> bytes:
    return b"".join(bytes([len(b)]) + b for b in (i.encode() for i in items))


def packet(answers=(), authority=(), additional=(), qr: int = 1, questions=()) -> bytes:
    flags = 0x8400 if qr else 0  # a response is authoritative in mDNS
    head = struct.pack("!6H", 0, flags, len(questions), len(answers), len(authority), len(additional))
    return head + b"".join(questions) + b"".join(answers) + b"".join(authority) + b"".join(additional)


# an iPad: A record plus Apple's device-info TXT, tied to the host by an SRV record
APPLE = packet(
    answers=[rr("Alex-iPad.local", A, a("10.0.0.21"))],
    additional=[rr("Alex-iPad._device-info._tcp.local", SRV, srv("Alex-iPad.local", 0)),
                rr("Alex-iPad._device-info._tcp.local", TXT, txt("model=iPad13,1", "osxvers=21"))],
)

# the same device as Apple sends it most often: the device-info TXT with no SRV record, tied to the host by the
# instance's first label
APPLE_NO_SRV = packet(
    answers=[rr("Alex-iPad.local", A, a("10.0.0.21"))],
    additional=[rr("Alex-iPad._device-info._tcp.local", TXT, txt("model=iPad13,1", "osxvers=21"))],
)


def _printer() -> bytes:
    instance = "Brother HL-L2350DW._ipp._tcp.local"
    host = "BRW020000000030.local"
    ptr = rr("_ipp._tcp.local", PTR, name(instance), rclass=IN)
    first = packet([ptr])
    inst_off = first.find(name(instance))  # the instance name inside the PTR rdata
    srv_rr = rr(name(pointer=inst_off), SRV, srv(host, 631))
    txt_rr = rr(name(pointer=inst_off), TXT, txt("txtvers=1", "ty=Brother HL-L2350DW series",
                                                 "product=(Brother HL-L2350DW)", "note"))
    second = packet([ptr, srv_rr, txt_rr])
    host_off = second.find(name(host))  # the host name inside the SRV rdata
    return packet([ptr, srv_rr, txt_rr, rr(name(pointer=host_off), A, a("10.0.0.30"))])


# a printer: PTR + SRV + TXT + A; the SRV/TXT owners and the A owner are compression pointers
PRINTER = _printer()

# a cast device: "fn=" wins over "md="
CHROMECAST = packet(
    answers=[rr("_googlecast._tcp.local", PTR, name("Chromecast-0a1b._googlecast._tcp.local"), rclass=IN)],
    additional=[rr("Chromecast-0a1b._googlecast._tcp.local", TXT, txt("id=0a1b", "md=Chromecast",
                                                                      "fn=Living Room TV")),
                rr("Chromecast-0a1b._googlecast._tcp.local", SRV, srv("0a1b-cast.local", 8009)),
                rr("0a1b-cast.local", A, a("10.0.0.40"))],
)

# a goodbye: TTL 0
GOODBYE = packet([rr("printer.local", A, a("10.0.0.50"), ttl=0)])

# a query with a known answer: not a response
QUERY = packet([rr("printer.local", A, a("10.0.0.50"))], qr=0, questions=[question("_ipp._tcp.local")])

# one whole A record, then a TXT record whose rdata is cut short
TRUNCATED = packet([rr("printer.local", A, a("10.0.0.50")),
                    rr("printer._ipp._tcp.local", TXT, txt("ty=Synthetic P1"))])[:-5]

# an owner name that is a pointer to itself (offset 12, the first byte after the header)
POINTER_LOOP = packet([rr(name(pointer=HEADER), A, a("10.0.0.60"))])

# one host, two addresses
TWO_IPS = packet([rr("nas.local", A, a("10.0.0.70")), rr("nas.local", A, a("10.0.0.71"))])

# 100 A records: the parser reads 64
TOO_MANY = packet([rr(f"host-{i}.local", A, a(f"10.0.1.{i}")) for i in range(100)])

ALL = {"APPLE": APPLE, "APPLE_NO_SRV": APPLE_NO_SRV, "PRINTER": PRINTER, "CHROMECAST": CHROMECAST, "GOODBYE": GOODBYE, "QUERY": QUERY,
       "TRUNCATED": TRUNCATED, "POINTER_LOOP": POINTER_LOOP, "TWO_IPS": TWO_IPS, "TOO_MANY": TOO_MANY}
