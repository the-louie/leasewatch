"""mDNS/DNS-SD as a connector: device names and models heard in the announcements on the LAN.

Listen-only. One daemon thread binds UDP 5353, joins the group 224.0.0.251 and receives; it never transmits a packet
(no query, no probe, no answer). What it hears is a name and an IPv4 address; the host's device_ips() turns the
address into the device's MAC. A name whose address the host does not know is counted as unmapped and dropped.

The names live in a cache keyed by MAC between polls. collect() returns a snapshot of it as sightings of kind "scan"
with presence False: a cached name says nothing about the device being on the wire now. The IP address is left
out of the sighting (the host already has it from the source that mapped it).
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from leasewatch.connectors import (API_VERSION, Batch, ConnectorError, ConnectorInfo, HostContext, Setting,
                                   SettingsMixin, Sighting)

from . import dns

log = logging.getLogger("leasewatch.contrib.mdns")

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
RECV_SIZE = 9000  # the largest mDNS packet RFC 6762 allows over a jumbo-frame link
RECV_TIMEOUT = 1.0  # seconds; the listener checks its stop event at least this often
RATE_LIMIT = 200  # packets parsed per second; the rest are counted in dropped_rate and skipped
WARN_INTERVAL = 3600.0  # seconds between two malformed-packet warnings for one source address
MAX_WARNED = 1024  # source addresses remembered for that; the memory is cleared when it is full
WARN_BUDGET = 10  # malformed-packet warnings per WARN_INTERVAL from all sources together; the rest go to DEBUG
JOIN_TIMEOUT = 2.0  # seconds close() waits for the listener thread
DAY = 86400
# Linux: a socket with this option set (the default) also receives the groups that other sockets joined, on any
# interface; cleared, it hears only its own memberships
IP_MULTICAST_ALL = getattr(socket, "IP_MULTICAST_ALL", 49)
# RFC 6762 11: the link checks. IP_RECVTTL hands over the IP TTL of each packet (as a control message of type IP_TTL
# on Linux, which Python does not name the option for), IP_PKTINFO its destination address (struct in_pktinfo:
# ifindex, spec_dst, addr). Without both the listener falls back to recvfrom() and accepts any source
IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12 if sys.platform.startswith("linux") else None)
IP_PKTINFO = getattr(socket, "IP_PKTINFO", None)
_TTL_TYPES = frozenset(t for t in (socket.IP_TTL, getattr(socket, "IP_RECVTTL", None)) if t is not None)
ANC_SIZE = socket.CMSG_SPACE(4) + socket.CMSG_SPACE(12)
LINK_TTL = 255  # a router decrements the TTL, so only a sender on the link arrives with 255
NEEDS_HOST = "needs leasewatch 1.5 or later (device_ips)"

# a Linux interface name: at most 15 characters (IFNAMSIZ - 1), no "/", no white space; ":" (an alias) is left out
# because an alias has no index of its own to join the group on
_IFNAME_RE = re.compile(r"\A[A-Za-z0-9_.-]{1,15}\Z")


@dataclass(frozen=True)
class _Entry:
    ip: str
    hostname: str
    label: str
    heard_at: int


def _int(value: str, default: str) -> int:
    try:
        return int(value)
    except ValueError:
        return int(default)


def _errno_text(e: OSError) -> str:
    return e.strerror or str(e) or type(e).__name__


def _link_reject(ancdata: Any) -> str:
    """The stats key a packet with these control messages is rejected under, or "" to accept it: "off_link" when
    its IP TTL is not 255 (or missing), "unicast" when its destination is not the group (or missing)."""
    ttl = dst = None
    for level, kind, data in ancdata:
        if level != socket.IPPROTO_IP:
            continue
        if kind in _TTL_TYPES:
            if len(data) >= 4:  # Linux: an int
                ttl = struct.unpack("=i", data[:4])[0]
            elif len(data) == 1:  # the BSDs: one byte
                ttl = data[0]
        elif kind == IP_PKTINFO and len(data) >= 12:
            dst = socket.inet_ntoa(data[8:12])
    if ttl != LINK_TTL:
        return "off_link"
    if dst != MDNS_GROUP:
        return "unicast"
    return ""


class MdnsConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="mdns", version="0.1.0", api_version=API_VERSION, produces=frozenset({"sighting"}),
        # a secondary source: the host never fails a poll or holds the baseline for it
        roles=frozenset({"names"}),
        settings=(
            Setting("interface", default="",
                    help="the address or name of the interface to listen on; empty = every non-loopback interface"),
            Setting("max_age_days", default="7", kind="int", min=1, max=90,
                    help="days a name heard is kept without being heard again"),
            Setting("max_entries", default="4096", kind="int", min=64, max=65536,
                    help="names kept at most; the oldest heard goes first"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None,
                 socket_factory: Callable[[], Any] | None = None) -> None:
        self._init_settings(name, settings, ctx)
        self.interface = self.settings["interface"].strip()
        self.max_age_days = _int(self.settings["max_age_days"], "7")
        self.max_entries = _int(self.settings["max_entries"], "4096")
        self._socket_factory = socket_factory or self._default_socket
        self._clock: Callable[[], float] = time.monotonic  # the rate budget and the warning interval
        self._lock = threading.Lock()  # the cache, its IP index and the counters
        self._cache: dict[str, _Entry] = {}  # mac -> entry, in the order last heard (oldest first)
        self._by_ip: dict[str, str] = {}  # ip -> the mac whose entry holds it
        self._counts = dict.fromkeys(("packets", "malformed", "unmapped", "wrong_port", "off_link", "unicast",
                                      "dropped_rate", "errors"), 0)
        self._joined = 0  # interfaces the group was joined on by the current socket
        self._window = -1  # the second the rate budget counts in
        self._in_window = 0
        self._warned: dict[str, float] = {}  # source ip -> clock of its last malformed-packet warning
        self._warn_since = -WARN_INTERVAL  # clock when the current window of WARN_BUDGET warnings started
        self._warn_count = 0  # warnings logged in that window
        self._link_warned = False  # the "cannot check the sender's link" warning was logged
        self._state = threading.Lock()  # starting and stopping the listener
        self._stop = threading.Event()
        self._sock: Any = None
        self._thread: threading.Thread | None = None

    # --- settings ----------------------------------------------------------------------------------------------

    def validate(self) -> list[str]:
        problems = self._generic_problems()
        if not hasattr(self.ctx, "device_ips"):
            problems.append(NEEDS_HOST)
        v = self.interface
        if v:
            try:
                addr = ipaddress.ip_address(v)
            except ValueError:
                addr = None
            if addr is not None:
                if addr.version != 4:
                    problems.append("interface must be an IPv4 address or an interface name")
            elif not _IFNAME_RE.fullmatch(v) or v in (".", "..") or re.fullmatch(r"[0-9.]+", v):
                problems.append("interface must be an IPv4 address or an interface name (at most 15 characters: "
                                "letters, digits, '_', '.', '-')")
        return problems

    # --- the socket --------------------------------------------------------------------------------------------

    def _default_socket(self) -> socket.socket:
        """A UDP socket on port 5353 that is a member of 224.0.0.251, on every interface or on the configured one.

        It binds to the wildcard address even when an interface is configured: on Linux a socket bound to a unicast
        address receives no multicast. The interface is chosen by the group membership instead. Without an
        interface the group is joined on each non-loopback interface by its index (one join with the address
        0.0.0.0 would join on the default-route interface only); an interface that refuses the join is skipped,
        and no join at all fails the start."""
        group = socket.inet_aton(MDNS_GROUP)
        any_addr = socket.inet_aton("0.0.0.0")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):  # another responder (avahi) may hold the port as well
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("", MDNS_PORT))
            if self.interface:
                try:  # hear only this interface, not the groups another socket joined elsewhere
                    sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)
                except OSError:  # not Linux
                    pass
                try:
                    mreq = group + socket.inet_aton(str(ipaddress.IPv4Address(self.interface)))
                except ValueError:  # a name: struct ip_mreqn (group, local address any, interface index)
                    try:
                        index = socket.if_nametoindex(self.interface)
                    except OSError:
                        raise ConnectorError(f"mdns: no interface named {self.interface}") from None
                    mreq = struct.pack("=4s4si", group, any_addr, index)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                joined = 1
            else:
                joined = failed = 0
                try:
                    interfaces = socket.if_nameindex()
                except OSError:
                    interfaces = []
                for index, ifname in interfaces:
                    if ifname == "lo":
                        continue
                    try:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                        struct.pack("=4s4si", group, any_addr, index))
                    except OSError as e:  # down, no IPv4, or no multicast: the others still count
                        failed += 1
                        log.debug("connector %s: cannot join %s on %s (%s)", self.name, MDNS_GROUP, ifname,
                                  _errno_text(e))
                        continue
                    joined += 1
                if not joined:
                    raise ConnectorError(f"mdns: cannot join {MDNS_GROUP} on any interface ({failed} refused)")
            sock.settimeout(RECV_TIMEOUT)
        except BaseException:
            sock.close()
            raise
        self._joined = joined
        log.info("mdns: listening on %d interfaces", joined)
        return sock

    def _start(self) -> None:
        with self._state:
            if self._thread is not None and self._thread.is_alive():
                return
            try:
                sock = self._socket_factory()
            except OSError as e:
                raise ConnectorError(f"mdns: cannot listen on {MDNS_PORT} ({_errno_text(e)})") from None
            checked = self._link_options(sock)
            # a new event per thread: a listener that outlived close()'s join must not be woken up again
            self._stop = threading.Event()
            self._sock = sock
            self._thread = threading.Thread(target=self._run, args=(sock, self._stop, checked),
                                            name=f"mdns-{self.name}", daemon=True)
            self._thread.start()

    def _link_options(self, sock: Any) -> bool:
        """Ask for each packet's TTL and destination address (RFC 6762 11). False when the OS refuses: the listener
        then uses recvfrom() and accepts any source, after one warning."""
        try:
            if IP_RECVTTL is None or IP_PKTINFO is None or not hasattr(sock, "recvmsg"):
                raise OSError("not supported on this system")
            sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
            sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
        except OSError as e:
            if not self._link_warned:
                self._link_warned = True
                log.warning("mdns: cannot check the sender's link; accepting any source")
            log.debug("connector %s: link checks unavailable (%s)", self.name, _errno_text(e))
            return False
        return True

    def _count(self, key: str) -> None:
        with self._lock:
            self._counts[key] += 1

    def _run(self, sock: Any, stop: threading.Event, checked: bool = False) -> None:
        """The listener: receive until stopped. No exception ends it; each one is counted in "errors". With
        `checked`, each packet comes with its TTL and destination, and one from off the link or sent unicast is
        rejected."""
        while not stop.is_set():
            try:
                if checked:
                    data, ancdata, _flags, addr = sock.recvmsg(RECV_SIZE, ANC_SIZE)
                    reject = _link_reject(ancdata)
                else:
                    data, addr = sock.recvfrom(RECV_SIZE)
                    reject = ""
            except TimeoutError:  # socket.timeout
                continue
            except Exception:  # noqa: BLE001 - a closed or broken socket; never let it end the thread unasked
                if stop.is_set():
                    break
                self._count("errors")
                log.debug("connector %s: receive failed", self.name, exc_info=True)
                stop.wait(RECV_TIMEOUT)  # a socket that fails at once every time must not spin
                continue
            if stop.is_set():
                break
            try:
                self._handle(data, addr, reject)
            except Exception:  # noqa: BLE001 - one bad packet or a failing device_ips() must not end the thread
                self._count("errors")
                log.debug("connector %s: packet not handled", self.name, exc_info=True)

    # --- what is heard -----------------------------------------------------------------------------------------

    def _handle(self, data: bytes, addr: Any, reject: str = "") -> None:
        """One received packet: the link checks (`reject` names the one it failed), the rate budget, the parse,
        then every name it carries."""
        second = int(self._clock())
        with self._lock:
            self._counts["packets"] += 1
            if reject:
                self._counts[reject] += 1
                return
            if not (isinstance(addr, tuple) and len(addr) > 1 and addr[1] == MDNS_PORT):
                self._counts["wrong_port"] += 1  # RFC 6762 6: a response not from port 5353 is not mDNS
                return
            if second != self._window:
                self._window, self._in_window = second, 0
            if self._in_window >= RATE_LIMIT:
                self._counts["dropped_rate"] += 1
                return
            self._in_window += 1
        packet = dns.parse_response(bytes(data))
        if packet.malformed:
            self._malformed(addr[0] if isinstance(addr, tuple) and addr else "?")
            return
        if not packet.names:
            return
        ips = self.ctx.device_ips()
        now = self.ctx.now()
        for hostname, ip, label in packet.names:
            self._hear(hostname, ip, label, now, ips)

    def _malformed(self, source: str) -> None:
        now = self._clock()
        with self._lock:
            self._counts["malformed"] += 1
            last = self._warned.get(source)
            if last is not None and now - last < WARN_INTERVAL:
                return
            if len(self._warned) >= MAX_WARNED:
                self._warned.clear()
            self._warned[source] = now
            # a budget for all sources together: many sources must not flood the log either
            if now - self._warn_since >= WARN_INTERVAL:
                self._warn_since, self._warn_count = now, 0
            self._warn_count += 1
            count = self._warn_count
        if count < WARN_BUDGET:
            log.warning("connector %s: malformed mDNS packet from %s (further ones from it are not logged for an "
                        "hour)", self.name, source)
        elif count == WARN_BUDGET:
            log.warning("connector %s: malformed mDNS packet from %s; further malformed packets are logged at DEBUG "
                        "for an hour", self.name, source)
        else:
            log.debug("connector %s: malformed mDNS packet from %s", self.name, source)

    def _drop(self, mac: str) -> None:
        """Remove one cache entry and its IP index. Called with the lock held."""
        entry = self._cache.pop(mac, None)
        if entry is not None and self._by_ip.get(entry.ip) == mac:
            del self._by_ip[entry.ip]

    def _hear(self, hostname: str, ip: str, label: str, now: int, ips: Mapping[str, str] | None = None) -> None:
        """Cache one (hostname, ip, label) heard at `now` (epoch seconds), under the MAC the host has for ip.

        The parser path calls it for every name in a packet; tests call it directly. An address the host does not
        know is counted as unmapped. An entry of another MAC that held the same address is dropped (the address
        was handed on). A field heard empty keeps the value heard before for that MAC with the same address (an A
        record and a model TXT record often come in separate packets). A goodbye (TTL 0) is heard like any other
        announcement: the name stays until it ages out."""
        mac = (self.ctx.device_ips() if ips is None else ips).get(ip)
        with self._lock:
            if not mac:
                self._counts["unmapped"] += 1
                return
            if not hostname and not label:
                return
            other = self._by_ip.get(ip)
            if other is not None and other != mac:
                self._drop(other)
            old = self._cache.get(mac)
            if old is not None and old.ip == ip:
                hostname, label = hostname or old.hostname, label or old.label
            self._drop(mac)  # re-inserted below: the dict stays in the order last heard
            self._cache[mac] = _Entry(ip=ip, hostname=hostname, label=label, heard_at=now)
            self._by_ip[ip] = mac
            while len(self._cache) > self.max_entries:
                self._drop(next(iter(self._cache)))

    # --- the lifecycle -----------------------------------------------------------------------------------------

    def check(self) -> None:
        if not hasattr(self.ctx, "device_ips"):
            raise ConnectorError(f"mdns: {NEEDS_HOST}")
        self._start()

    def collect(self) -> Batch:
        self._start()
        now = self.ctx.now()
        cutoff = now - self.max_age_days * DAY
        with self._lock:
            for mac in [m for m, e in self._cache.items() if e.heard_at < cutoff]:
                self._drop(mac)
            extra = len(self._cache) - self.max_entries
            if extra > 0:
                for mac, _ in sorted(self._cache.items(), key=lambda kv: kv[1].heard_at)[:extra]:
                    self._drop(mac)
            entries = list(self._cache.items())
            counts = self._counts
            self._counts = dict.fromkeys(counts, 0)
        sightings = [Sighting(mac=mac, source=self.name, kind="scan", presence=False, observed_at=now,
                              hostname=e.hostname, label=e.label) for mac, e in entries]
        # the counters cover the time since the previous collect()
        stats = {"names": len(sightings), "joined": self._joined, **counts}
        if not sightings:
            # an empty cache (just started, or nothing heard for MAX_AGE_DAYS) is no evidence that a label was
            # removed: the host keeps the stored labels
            stats["labels_unavailable"] = 1
        return Batch(sightings=sightings, stats=stats)

    def close(self) -> None:
        with self._state:
            self._stop.set()
            sock, self._sock = self._sock, None
            thread, self._thread = self._thread, None
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001 - close() never raises
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(JOIN_TIMEOUT)
