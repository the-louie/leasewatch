"""A dnsmasq leases file as a connector: one "dhcp" sighting per current DHCPv4 lease.

The file is what dnsmasq writes with `--dhcp-leasefile` (Pi-hole, OpenWrt, plain Linux). It lists leases only:
no ARP table, so it never says a device is online (presence False), and it does not say whether a lease came
from a `dhcp-host` entry or from a dynamic range. The connector only reads the file; it is mounted read-only.
"""
from __future__ import annotations

import errno
import ipaddress
import logging
import os
import stat
import time
from typing import Mapping

from leasewatch.connectors import (API_VERSION, Batch, ConnectorError, ConnectorInfo, HostContext, Setting,
                                   SettingsMixin, Sighting)

log = logging.getLogger("leasewatch.contrib.dnsmasq")

MAX_FILE_BYTES = 4 * 1024 * 1024
RETRY_DELAY = 0.05  # seconds between two reads that must agree; dnsmasq's rewrite takes far less
READ_ATTEMPTS = 3  # comparisons of a read with the one before it, so at most READ_ATTEMPTS + 1 reads per poll
# lines dnsmasq writes besides leases: the server DUID (before the DHCPv6 leases) and per-lease extra data
EXTRA_KEYWORDS = frozenset({"duid", "vendorclass", "agent-info"})


def parse_leases(text: str, now: int, network: str = "") -> tuple[list[Sighting], int]:
    """The current DHCPv4 leases in a dnsmasq leases file, and how many lines were dropped as unusable.

    A DHCPv4 line is `<expiry> <hwaddr> <ipv4> <hostname|*> <client-id|*>`. Skipped without counting: blank lines,
    `duid`/`vendorclass`/`agent-info` lines, DHCPv6 leases (an IPv6 address in the third field) and expired leases
    (expiry not 0 and not after `now`, the test dnsmasq's own prune uses). Dropped and counted: any other line
    that is not a DHCPv4 lease, and a lease whose hardware address carries a type prefix (`20-...`: not Ethernet,
    or no address at all), which is no MAC. Expiry 0 is an infinite lease and is kept. The MAC is passed as
    written; the host normalises it. Never raises."""
    out: list[Sighting] = []
    dropped = 0
    for line in text.split("\n"):
        tok = line.split()
        if not tok or tok[0] in EXTRA_KEYWORDS:
            continue
        if len(tok) < 5 or not (tok[0].isascii() and tok[0].isdigit()):
            dropped += 1
            continue
        expiry, hwaddr, ip, hostname, client_id = tok[:5]
        if ":" in ip:  # DHCPv6 lease: its second field is an IAID, not a MAC
            continue
        try:
            ip = str(ipaddress.IPv4Address(ip))
            expires = int(expiry)
        except ValueError:  # not an IPv4 address, or an expiry with more digits than int() converts
            dropped += 1
            continue
        if "-" in hwaddr:  # "<type>-<bytes>": a non-Ethernet or zero-length hardware address
            dropped += 1
            continue
        if expires and expires <= now:
            continue
        out.append(Sighting(mac=hwaddr, source="", kind="dhcp", presence=False, observed_at=now, ip=ip,
                            hostname="" if hostname == "*" else hostname, network=network,
                            lease_type="dynamic", client_id="" if client_id == "*" else client_id))
    return out, dropped


def _open(path: str) -> int:
    """A read-only fd on `path`, checked to be a regular file of at most MAX_FILE_BYTES. Errors name only the kind
    of problem, never the path or the content."""
    # O_NONBLOCK + fstat on the open fd: a FIFO would block a plain open() or read(), and a stat() of the path
    # followed by open() could be raced by a FIFO swapped in. O_NOCTTY: a tty given by mistake must not become
    # our controlling terminal before fstat rejects it
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
    except OSError as e:
        raise ConnectorError(f"PATH: {_os_problem(e)}") from None
    except ValueError:  # a NUL byte; validate() reports it too
        raise ConnectorError("PATH: not a valid path") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConnectorError("PATH: not a regular file")
        if st.st_size > MAX_FILE_BYTES:
            raise ConnectorError(f"PATH: larger than {MAX_FILE_BYTES // 1024} KiB")
    except OSError as e:
        os.close(fd)
        raise ConnectorError(f"PATH: {_os_problem(e)}") from None
    except ConnectorError:
        os.close(fd)
        raise
    return fd


def _os_problem(e: OSError) -> str:
    if e.errno in (errno.ENOENT, errno.ENOTDIR):
        return "not found"
    if e.errno in (errno.EACCES, errno.EPERM):
        return "permission denied"
    if e.errno == errno.ENXIO:  # a UNIX socket fails at open, before fstat could say what it is
        return "not a regular file"
    if e.errno == errno.ELOOP:
        return "symbolic link loop"
    if e.errno == errno.ENAMETOOLONG:
        return "path too long"
    # strerror never holds the path (the OSError's filename does); it says more than "OSError"
    return os.strerror(e.errno).lower() if e.errno else type(e).__name__


def _read_once(path: str) -> tuple[bytes, tuple[int, int, int] | None]:
    """The bytes of the file, and its (inode, size, mtime) after the read, or None when it changed while it was
    read: size or mtime differ before and after the read, or fewer bytes were read than its size.
    Raises ConnectorError."""
    fd = _open(path)
    try:
        before = os.fstat(fd)
        with open(fd, "rb", closefd=False) as f:
            raw = f.read(MAX_FILE_BYTES + 1)  # bounded again: the file may have grown since fstat()
        after = os.fstat(fd)
    except OSError as e:
        raise ConnectorError(f"PATH: {_os_problem(e)}") from None
    finally:
        os.close(fd)
    if len(raw) > MAX_FILE_BYTES:
        raise ConnectorError(f"PATH: larger than {MAX_FILE_BYTES // 1024} KiB")
    changed = ((before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
               or len(raw) != after.st_size)
    return raw, None if changed else (after.st_ino, after.st_size, after.st_mtime_ns)


def read_file(path: str) -> str:
    """The text of the leases file (bounded, regular files only). Raises ConnectorError.

    dnsmasq rewrites the file in place: ftruncate to 0, then buffered writes, then fflush (research: lease.c
    lease_update_file). A read in that window gets an empty text or a prefix that parses as a shorter but valid
    list, and on the first poll that list would become the baseline. A text is used only when it is stable: two
    reads RETRY_DELAY apart give the same bytes and the same inode, size and mtime, and neither changed while it
    was read. No size, mtime or final-newline heuristic decides alone: an empty read or a prefix that ends on a
    line end looks like a complete file. Up to READ_ATTEMPTS comparisons; then the poll fails for this instance
    instead of reporting a short list. Limit: a writer stalled for longer than RETRY_DELAY across both reads
    leaves a prefix that reads the same twice, and it is used."""
    prev = _read_once(path)
    for _ in range(READ_ATTEMPTS):
        time.sleep(RETRY_DELAY)
        cur = _read_once(path)
        if cur[1] is not None and cur == prev:
            raw = cur[0]
            break
        prev = cur
    else:
        raise ConnectorError("PATH: file changed while reading")
    # dnsmasq writes ASCII; a stray byte from a hand-edited file must not fail the whole poll
    return raw.decode("utf-8", errors="replace")


class DnsmasqLeasesConnector(SettingsMixin):
    INFO = ConnectorInfo(
        type="dnsmasq_leases", version="0.1", api_version=API_VERSION, produces=frozenset({"sighting"}),
        settings=(
            Setting("path", required=True, help="absolute path of the dnsmasq leases file (mounted read-only)"),
            Setting("network", default="", help="network name shown for these devices (e.g. LAN)"),
        ),
    )

    def __init__(self, name: str, settings: Mapping[str, str], ctx: HostContext | None = None) -> None:
        self._init_settings(name, settings, ctx)

    def validate(self) -> list[str]:
        problems = self._generic_problems()
        path = self.settings["path"]
        if path and ("\x00" in path or not os.path.isabs(path)):
            problems.append("path must be an absolute path")
        return problems

    def check(self) -> None:
        os.close(_open(self.settings["path"]))

    def collect(self) -> Batch:
        now = self.ctx.now()
        sightings, dropped = parse_leases(read_file(self.settings["path"]), now, self.settings["network"])
        if dropped:
            log.debug("connector %s: %d lines dropped", self.name, dropped)
        return Batch(sightings=sightings, stats={"leases": len(sightings), "dropped": dropped})

    def close(self) -> None:
        pass  # the file is opened and closed within each call
