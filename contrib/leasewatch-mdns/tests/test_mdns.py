"""Tests for the mdns connector: settings, the listener lifecycle against a fake socket, the cache rules, the rate
budget and that nothing is ever transmitted. Synthetic data only; no socket is opened and no multicast is needed."""
from __future__ import annotations

import errno
import os
import queue
import socket
import sys
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

from leasewatch.connectors import API_VERSION, Batch, ConnectorError, HostContext, Sighting  # noqa: E402
from leasewatch_mdns import connector as mc  # noqa: E402
from leasewatch_mdns import dns  # noqa: E402
from leasewatch_mdns.connector import MdnsConnector  # noqa: E402

NOW = 1_800_000_000
DAY = 86400
IP_A, MAC_A = "10.0.0.7", "02:00:00:00:00:07"
IP_B, MAC_B = "10.0.0.8", "02:00:00:00:00:08"
PACKAGE = os.path.join(os.path.dirname(HERE), "leasewatch_mdns")

_CLOSED = object()


class FakeSocket:
    """A listen-only stand-in for the multicast socket: recvfrom() blocks on a queue for at most `timeout` seconds
    and then raises socket.timeout, as the real one does after settimeout(1.0). Every transmitting or connecting
    call is recorded, so a test can assert there was none."""

    def __init__(self, timeout: float = mc.RECV_TIMEOUT) -> None:
        self.timeout = timeout
        self.inbox: queue.Queue = queue.Queue()
        self.closed = False
        self.sent: list[tuple[str, tuple]] = []
        self.received = 0

    def deliver(self, data: bytes = b"\x00" * 12, src: str = IP_A) -> None:
        self.inbox.put((data, (src, 5353)))

    def fail_next(self, exc: BaseException) -> None:
        self.inbox.put(exc)

    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple[str, int]]:
        if self.closed:
            raise OSError(errno.EBADF, "Bad file descriptor")
        try:
            item = self.inbox.get(timeout=self.timeout)
        except queue.Empty:
            raise socket.timeout("timed out") from None
        if item is _CLOSED:
            raise OSError(errno.EBADF, "Bad file descriptor")
        if isinstance(item, BaseException):
            raise item
        self.received += 1
        return item

    def close(self) -> None:
        self.closed = True
        self.inbox.put(_CLOSED)  # wakes a blocked recvfrom() at once, so the tests need not wait for the timeout

    def _record(self, what: str) -> object:
        def record(*args: object) -> int:
            self.sent.append((what, args))
            return 0
        return record

    def __getattr__(self, name: str) -> object:
        if name in ("sendto", "send", "sendall", "sendmsg", "connect", "connect_ex"):
            return self._record(name)
        raise AttributeError(name)


class FakeSocketFactory:
    """The injectable socket_factory: a new FakeSocket per call, or `error` raised as a failed bind would."""

    def __init__(self, error: OSError | None = None) -> None:
        self.error = error
        self.sockets: list[FakeSocket] = []

    def __call__(self) -> FakeSocket:
        if self.error is not None:
            raise self.error
        s = FakeSocket()
        self.sockets.append(s)
        return s


def wait_until(cond, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.005)
    return cond()


def packet(*names: tuple[str, str, str], malformed: bool = False) -> dns.ParsedPacket:
    return dns.ParsedPacket(names=list(names), malformed=malformed)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.now = NOW
        self.ips = {IP_A: MAC_A, IP_B: MAC_B}
        self.factory = FakeSocketFactory()

    def ctx(self) -> HostContext:
        return HostContext(now=lambda: self.now, device_ips=lambda: dict(self.ips))

    def conn(self, **settings: str) -> MdnsConnector:
        c = MdnsConnector("mdns1", settings, self.ctx(), socket_factory=self.factory)
        self.addCleanup(c.close)
        return c

    def tearDown(self) -> None:
        for s in self.factory.sockets:
            self.assertEqual(s.sent, [], "the connector transmitted on its socket")


class SettingsTest(Base):
    def test_describe(self) -> None:
        info = MdnsConnector.describe()
        self.assertEqual((info.type, info.version, info.api_version), ("mdns", "0.1.0", API_VERSION))
        self.assertEqual(info.produces, frozenset({"sighting"}))
        self.assertEqual({s.key: s.default for s in info.settings},
                         {"interface": "", "max_age_days": "7", "max_entries": "4096"})

    def test_defaults_valid(self) -> None:
        c = self.conn()
        self.assertEqual(c.validate(), [])
        self.assertEqual((c.interface, c.max_age_days, c.max_entries), ("", 7, 4096))

    def test_int_ranges(self) -> None:
        for key, bad, good in (("max_age_days", ("0", "91", "x"), ("1", "90")),
                               ("max_entries", ("63", "65537"), ("64", "65536"))):
            for v in bad:
                with self.subTest(key=key, value=v):
                    self.assertTrue(any(key.upper() in p for p in self.conn(**{key: v}).validate()))
            for v in good:
                with self.subTest(key=key, value=v):
                    self.assertEqual(self.conn(**{key: v}).validate(), [])

    def test_interface(self) -> None:
        for v in ("eth0", "br-lan", "enp3s0.20", "10.0.0.2", " eth0 "):
            with self.subTest(value=v):
                self.assertEqual(self.conn(interface=v).validate(), [])
        for v in ("fe80::1", "300.1.1.1", "10.0.0", "eth0:1", "a" * 16, "bad name", "..", "eth/0"):
            with self.subTest(value=v):
                problems = self.conn(interface=v).validate()
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("interface", problems[0])

    def test_validate_does_no_lookup(self) -> None:
        def no(*a: object) -> None:
            raise AssertionError("lookup in validate()")
        with mock.patch.object(socket, "if_nametoindex", no), mock.patch.object(socket, "getaddrinfo", no), \
                mock.patch.object(socket, "gethostbyname", no):
            self.assertEqual(self.conn(interface="eth0").validate(), [])
            self.assertEqual(self.factory.sockets, [])


class LifecycleTest(Base):
    def test_init_opens_nothing(self) -> None:
        self.conn()
        self.assertEqual(self.factory.sockets, [])

    def test_check_starts_close_stops(self) -> None:
        c = self.conn()
        self.assertIsNone(c.check())
        self.assertEqual(len(self.factory.sockets), 1)
        thread = c._thread
        self.assertTrue(thread is not None and thread.is_alive() and thread.daemon)
        c.check()  # running: no second socket
        self.assertEqual(len(self.factory.sockets), 1)
        c.close()
        self.assertFalse(thread.is_alive())
        self.assertTrue(self.factory.sockets[0].closed)
        c.close()

    def test_collect_starts_listener(self) -> None:
        c = self.conn()
        batch = c.collect()
        self.assertIsInstance(batch, Batch)
        self.assertEqual(len(self.factory.sockets), 1)
        self.assertEqual(batch.sightings, [])
        self.assertEqual(batch.stats, {"names": 0, "packets": 0, "malformed": 0, "unmapped": 0, "dropped_rate": 0,
                                       "errors": 0})

    def test_restart_after_close(self) -> None:
        c = self.conn()
        c.check()
        c.close()
        c.check()
        self.assertEqual(len(self.factory.sockets), 2)
        self.assertTrue(c._thread.is_alive())

    def test_bind_failure(self) -> None:
        self.factory.error = OSError(errno.EADDRINUSE, os.strerror(errno.EADDRINUSE))
        c = self.conn()
        with self.assertRaises(ConnectorError) as cm:
            c.check()
        self.assertEqual(str(cm.exception), f"mdns: cannot listen on 5353 ({os.strerror(errno.EADDRINUSE)})")
        with self.assertRaises(ConnectorError):
            c.collect()
        self.assertIsNone(c._thread)
        c.close()

    def test_close_without_start(self) -> None:
        self.conn().close()

    def test_close_waits_at_most_two_seconds(self) -> None:
        stuck = threading.Event()
        self.addCleanup(stuck.set)
        c = self.conn()
        c._thread = threading.Thread(target=stuck.wait, daemon=True)
        c._thread.start()
        t0 = time.monotonic()
        c.close()
        self.assertLess(time.monotonic() - t0, mc.JOIN_TIMEOUT + 1)


class PacketPathTest(Base):
    def test_heard_name_becomes_sighting(self) -> None:
        c = self.conn()
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "Synthetic P1"))):
            c.check()
            self.factory.sockets[0].deliver()
            self.assertTrue(wait_until(lambda: MAC_A in c._cache))
        batch = c.collect()
        self.assertEqual(batch.sightings, [Sighting(mac=MAC_A, source="mdns1", kind="scan", presence=False,
                                                    observed_at=NOW, hostname="printer-7", label="Synthetic P1")])
        self.assertEqual(batch.stats["names"], 1)
        self.assertEqual(batch.stats["packets"], 1)
        self.assertEqual(c.collect().stats["packets"], 0)  # counted per collect()

    def test_parser_exception_does_not_kill_thread(self) -> None:
        c = self.conn()
        side = [RuntimeError("synthetic"), packet(("tv", IP_B, ""))]
        with mock.patch.object(dns, "parse_response", side_effect=side):
            c.check()
            s = self.factory.sockets[0]
            s.deliver()
            s.deliver()
            self.assertTrue(wait_until(lambda: MAC_B in c._cache))
        self.assertTrue(c._thread.is_alive())
        self.assertEqual(c.collect().stats["errors"], 1)

    def test_receive_exception_does_not_kill_thread(self) -> None:
        c = self.conn()
        with mock.patch.object(mc, "RECV_TIMEOUT", 0.01), \
                mock.patch.object(dns, "parse_response", return_value=packet(("tv", IP_B, ""))):
            c.check()
            s = self.factory.sockets[0]
            s.fail_next(ValueError("synthetic"))
            s.deliver()
            self.assertTrue(wait_until(lambda: MAC_B in c._cache))
        self.assertTrue(c._thread.is_alive())
        self.assertEqual(c.collect().stats["errors"], 1)

    def test_malformed_warns_once_per_source_per_hour(self) -> None:
        c = self.conn()
        clock = [1000.0]
        c._clock = lambda: clock[0]
        with mock.patch.object(dns, "parse_response", return_value=packet(("x", IP_A, ""), malformed=True)):
            with self.assertLogs("leasewatch.contrib.mdns", "WARNING") as logs:
                c._handle(b"", ("10.0.0.50", 5353))
                c._handle(b"", ("10.0.0.50", 5353))
                c._handle(b"", ("10.0.0.51", 5353))
                clock[0] += mc.WARN_INTERVAL
                c._handle(b"", ("10.0.0.50", 5353))
        self.assertEqual([r.getMessage().split(" from ")[1].split()[0] for r in logs.records],
                         ["10.0.0.50", "10.0.0.51", "10.0.0.50"])
        stats = c.collect().stats
        self.assertEqual(stats["malformed"], 4)
        self.assertEqual(stats["names"], 0)  # a malformed packet's names are not used

    def test_rate_budget(self) -> None:
        c = self.conn()
        clock = [5000.2]
        c._clock = lambda: clock[0]
        with mock.patch.object(dns, "parse_response", return_value=packet()) as parse:
            for _ in range(250):
                c._handle(b"", (IP_A, 5353))
            self.assertEqual(parse.call_count, 200)
            clock[0] = 5001.0
            c._handle(b"", (IP_A, 5353))
            self.assertEqual(parse.call_count, 201)
        stats = c.collect().stats
        self.assertEqual((stats["packets"], stats["dropped_rate"]), (251, 50))

    def test_goodbye_keeps_name(self) -> None:
        # the parser returns a TTL-0 record like any other: the name is heard again, not removed
        c = self.conn()
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))):
            c._handle(b"announce", (IP_A, 5353))
            self.now += 60
            c._handle(b"goodbye", (IP_A, 5353))
        [s] = c.collect().sightings
        self.assertEqual((s.hostname, s.label), ("printer-7", "P1"))


class CacheTest(Base):
    def names(self, c: MdnsConnector) -> dict[str, tuple[str, str]]:
        return {s.mac: (s.hostname, s.label) for s in c.collect().sightings}

    def test_unmapped(self) -> None:
        c = self.conn()
        c._hear("ghost", "10.0.0.99", "", NOW)
        c._hear("ghost", "10.0.0.99", "", NOW)
        batch = c.collect()
        self.assertEqual((batch.sightings, batch.stats["unmapped"]), ([], 2))

    def test_expiry(self) -> None:
        c = self.conn(max_age_days="2")
        c._hear("kept", IP_A, "", NOW - 2 * DAY)
        c._hear("gone", IP_B, "", NOW - 2 * DAY - 1)
        self.assertEqual(self.names(c), {MAC_A: ("kept", "")})
        self.now += 1
        self.assertEqual(self.names(c), {})

    def test_max_entries_oldest_out(self) -> None:
        self.ips = {f"10.0.1.{i}": f"02:00:00:00:01:{i:02x}" for i in range(70)}
        c = self.conn(max_entries="64")
        for i in range(70):
            c._hear(f"host-{i}", f"10.0.1.{i}", "", NOW - 100 + i)
        names = self.names(c)
        self.assertEqual(len(names), 64)
        self.assertEqual(sorted(h for h, _ in names.values()), sorted(f"host-{i}" for i in range(6, 70)))

    def test_collect_trims_by_heard_at(self) -> None:
        self.ips = {f"10.0.1.{i}": f"02:00:00:00:01:{i:02x}" for i in range(64)}
        c = self.conn(max_entries="64")
        for i in range(64):
            c._hear(f"host-{i}", f"10.0.1.{i}", "", NOW - i)  # newest first
        c.max_entries = 60
        names = self.names(c)
        self.assertEqual(sorted(h for h, _ in names.values()), sorted(f"host-{i}" for i in range(60)))

    def test_ip_reuse_drops_old_mac(self) -> None:
        c = self.conn()
        c._hear("old-phone", IP_A, "", NOW)
        self.ips[IP_A] = MAC_B  # the address was handed on
        c._hear("new-laptop", IP_A, "", NOW)
        self.assertEqual(self.names(c), {MAC_B: ("new-laptop", "")})

    def test_moved_device_frees_old_ip(self) -> None:
        c = self.conn()
        c._hear("phone", IP_A, "", NOW)
        self.ips = {IP_B: MAC_A, IP_A: MAC_B}
        c._hear("phone", IP_B, "", NOW)  # MAC_A moved to IP_B
        c._hear("laptop", IP_A, "", NOW)  # IP_A now belongs to MAC_B; MAC_A keeps its entry
        self.assertEqual(self.names(c), {MAC_A: ("phone", ""), MAC_B: ("laptop", "")})

    def test_empty_field_keeps_earlier_value(self) -> None:
        c = self.conn()
        c._hear("printer-7", IP_A, "", NOW)
        c._hear("", IP_A, "Synthetic P1", NOW)
        self.assertEqual(self.names(c), {MAC_A: ("printer-7", "Synthetic P1")})
        c._hear("printer-7b", IP_A, "", NOW)
        self.assertEqual(self.names(c), {MAC_A: ("printer-7b", "Synthetic P1")})

    def test_nothing_to_say_is_skipped(self) -> None:
        c = self.conn()
        c._hear("", IP_A, "", NOW)
        self.assertEqual(self.names(c), {})


class ListenOnlyTest(unittest.TestCase):
    def test_package_has_no_transmit_or_connect_call(self) -> None:
        found = []
        for root, _dirs, files in os.walk(PACKAGE):
            for f in files:
                if not f.endswith(".py"):
                    continue
                with open(os.path.join(root, f), encoding="utf-8") as fh:
                    for n, line in enumerate(fh, 1):
                        if any(w in line for w in ("sendto", ".send(", "sendall", "sendmsg", ".connect(")):
                            found.append(f"{f}:{n}: {line.strip()}")
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
