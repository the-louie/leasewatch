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



def _pointer_chains(size: int = 9000) -> bytes:
    """A hostile response: one question with the root name, then one pointer every 2 bytes, each to the one before.
    Read as questions, every name is a chain of pointers back to the start (about 1500 questions)."""
    body = bytearray(b"\x00" + struct.pack("!HH", PTR, IN))
    prev, off = HEADER, HEADER + len(body)
    while off + 2 <= size:
        body += struct.pack("!H", 0xC000 | prev)
        prev, off = off, off + 2
    count = 1 + (len(body) - 5) // 6
    return struct.pack("!6H", 0, 0x8400, count, 0, 0, 0) + bytes(body)


PAD = 99  # a record type the parser skips: its rdata can hold names for later pointers to point into
_PAD_RDATA = HEADER + len(name("pad.local")) + 10  # where the rdata of a first record owned by "pad.local" starts


def chain(hops: int) -> bytes:
    """A response whose A record owner reaches "host.local" through `hops` pointers: hops - 1 of them laid out,
    each to the one before, in a skipped record, and the owner itself a pointer to the last one."""
    rdata = bytearray(name("host.local"))
    prev = _PAD_RDATA
    for _ in range(hops - 1):
        here = _PAD_RDATA + len(rdata)
        rdata += struct.pack("!H", 0xC000 | prev)
        prev = here
    return packet([rr("pad.local", PAD, bytes(rdata), rclass=IN), rr(name(pointer=prev), A, a("10.0.0.80"))])


def expansion(records: int) -> bytes:
    """A response with `records` PTR records whose owner and target both point to one 253-byte name."""
    long_name = ".".join(c * 63 for c in "abc") + "." + "d" * 59
    target = name(pointer=_PAD_RDATA)
    return packet([rr("pad.local", PAD, name(long_name), rclass=IN)]
                  + [rr(target, PTR, target, rclass=IN) for _ in range(records)])


QUADRATIC = _pointer_chains()

ALL = {"APPLE": APPLE, "APPLE_NO_SRV": APPLE_NO_SRV, "PRINTER": PRINTER, "CHROMECAST": CHROMECAST, "GOODBYE": GOODBYE, "QUERY": QUERY,
       "TRUNCATED": TRUNCATED, "POINTER_LOOP": POINTER_LOOP, "TWO_IPS": TWO_IPS, "TOO_MANY": TOO_MANY}


# SSDP: handcrafted announcement texts for the ssdp parser tests

def notify(server: str, location: str = "http://10.0.0.40:1400/desc.xml", nts: str = "ssdp:alive",
           usn: str = "uuid:0000-0000::upnp:rootdevice", extra=()) -> bytes:
    """A NOTIFY request with CRLF line ends; `extra` header lines go after the usual ones."""
    lines = ["NOTIFY * HTTP/1.1", "HOST: 239.255.255.250:1900", "CACHE-CONTROL: max-age=1800",
             f"LOCATION: {location}", "NT: upnp:rootdevice", f"NTS: {nts}", f"SERVER: {server}", f"USN: {usn}",
             *extra]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


SONOS_SERVER = "Linux/4.9 UPnP/1.0 Sonos/70.3-35220"
SONOS = notify(SONOS_SERVER, location="http://10.0.0.40:1400/xml/device_description.xml")
# a Hue bridge: the tokens are separated by commas
HUE = notify("FreeRTOS/10.4.3, UPnP/1.0, IpBridge/1.65.0", location="http://10.0.0.41:80/description.xml")
GENERIC_LIBUPNP = notify("Linux/3.14 UPnP/1.0 libupnp/1.6.18", location="http://10.0.0.42:49152/desc.xml")
PORTABLE_SDK = notify("Windows/10.0 UPnP/1.0 Portable SDK for UPnP devices/1.6.18",
                      location="http://10.0.0.43:49152/desc.xml")
BYEBYE = notify(SONOS_SERVER, nts="ssdp:byebye")
# a query from another host
MSEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           b"ST: ssdp:all\r\n\r\n")
# an answer to an M-SEARCH
HTTP_RESPONSE = (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\n"
                 b"LOCATION: http://10.0.0.40:1400/desc.xml\r\nSERVER: " + SONOS_SERVER.encode()
                 + b"\r\nST: upnp:rootdevice\r\nUSN: uuid:0000-0000::upnp:rootdevice\r\n\r\n")
MALFORMED = notify(SONOS_SERVER, extra=("A HEADER LINE WITHOUT A COLON",))
OVERSIZED = notify(SONOS_SERVER, extra=("X-PAD: " + "a" * 3000,))
# a Sonos SERVER from a source whose LOCATION names another address (a relay re-sent it)
MISMATCH = notify(SONOS_SERVER, location="http://10.0.0.99:1400/desc.xml")
LOCATION_NAME = notify(SONOS_SERVER, location="http://sonos-kitchen.example.lan:1400/desc.xml")
LOCATION_V6 = notify(SONOS_SERVER, location="http://[2001:db8::40]:1400/desc.xml")
LF_ONLY = SONOS.replace(b"\r\n", b"\n")
# lower-case header names and HTTP/1.0
CASE = (b"NOTIFY * HTTP/1.0\r\nhost: 239.255.255.250:1900\r\nlocation: http://10.0.0.40:1400/desc.xml\r\n"
        b"nts: ssdp:alive\r\nserver: " + SONOS_SERVER.encode() + b"\r\nusn: uuid:0000-0000::upnp:rootdevice\r\n\r\n")

SSDP_ALL = {"SONOS": SONOS, "HUE": HUE, "GENERIC_LIBUPNP": GENERIC_LIBUPNP, "PORTABLE_SDK": PORTABLE_SDK,
            "BYEBYE": BYEBYE, "MSEARCH": MSEARCH, "HTTP_RESPONSE": HTTP_RESPONSE, "MALFORMED": MALFORMED,
            "OVERSIZED": OVERSIZED, "MISMATCH": MISMATCH, "LOCATION_NAME": LOCATION_NAME,
            "LOCATION_V6": LOCATION_V6, "LF_ONLY": LF_ONLY, "CASE": CASE}
