"""Tests for the mdns connector: settings, the listener lifecycle against a fake socket, the cache rules, the rate
budget and that nothing is ever transmitted. Synthetic data only; no socket is opened and no multicast is needed."""
from __future__ import annotations

import errno
import os
import queue
import socket
import sys
import threading
import struct
import time
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

from leasewatch.connectors import API_VERSION, Batch, ConnectorError, HostContext, Sighting  # noqa: E402
from leasewatch_mdns import connector as mc  # noqa: E402
from leasewatch_mdns import dns  # noqa: E402
from leasewatch_mdns.connector import MdnsConnector  # noqa: E402

sys.path.insert(0, HERE)
import fixtures as fx  # noqa: E402

NOW = 1_800_000_000
DAY = 86400
IP_A, MAC_A = "10.0.0.7", "02:00:00:00:00:07"
IP_B, MAC_B = "10.0.0.8", "02:00:00:00:00:08"
PACKAGE = os.path.join(os.path.dirname(HERE), "leasewatch_mdns")

_CLOSED = object()


class FakeSocket:
    """A listen-only stand-in for the multicast socket: recvfrom() blocks on a queue for at most `timeout` seconds
    and then raises socket.timeout, as the real one does after settimeout(1.0). Every transmitting or connecting
    call is recorded, so a test can assert there was none. recvmsg() returns the packet's IP TTL and destination
    address as the kernel's control messages; with `link_options` False, setsockopt() refuses the options for them."""

    def __init__(self, timeout: float = mc.RECV_TIMEOUT, link_options: bool = True) -> None:
        self.timeout = timeout
        self.link_options = link_options
        self.options: list[tuple[int, int, object]] = []
        self.inbox: queue.Queue = queue.Queue()
        self.closed = False
        self.sent: list[tuple[str, tuple]] = []
        self.received = 0

    def deliver(self, data: bytes = b"\x00" * 12, src: str = IP_A, ttl: int = 255,
                dst: str = mc.MDNS_GROUP) -> None:
        self.inbox.put((data, (src, 5353), ttl, dst))

    def fail_next(self, exc: BaseException) -> None:
        self.inbox.put(exc)

    def setsockopt(self, level: int, option: int, value: object) -> None:
        if not self.link_options:
            raise OSError(errno.ENOPROTOOPT, os.strerror(errno.ENOPROTOOPT))
        self.options.append((level, option, value))

    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple[str, int]]:
        data, addr, _ttl, _dst = self._next()
        return data, addr

    def recvmsg(self, bufsize: int, ancbufsize: int = 0) -> tuple[bytes, list, int, tuple[str, int]]:
        data, addr, ttl, dst = self._next()
        pktinfo = struct.pack("=i4s4s", 2, socket.inet_aton("10.0.0.2"), socket.inet_aton(dst))
        ancdata = [(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("=i", ttl)),
                   (socket.IPPROTO_IP, mc.IP_PKTINFO, pktinfo)]
        return data, ancdata, 0, addr

    def _next(self) -> tuple[bytes, tuple[str, int], int, str]:
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

    def __init__(self, error: OSError | None = None, link_options: bool = True) -> None:
        self.error = error
        self.link_options = link_options
        self.sockets: list[FakeSocket] = []

    def __call__(self, group: str = mc.MDNS_GROUP, port: int = mc.MDNS_PORT) -> FakeSocket:
        if self.error is not None:
            raise self.error
        s = FakeSocket(link_options=self.link_options)
        s.group, s.port = group, port  # which group and port the connector asked for
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
        self.assertEqual(info.roles, frozenset({"names"}))
        self.assertEqual({s.key: s.default for s in info.settings},
                         {"interface": "", "max_age_days": "7", "max_entries": "4096", "relays": "", "ssdp": "0"})

    def test_needs_device_ips(self) -> None:
        old_host = types.SimpleNamespace(now=lambda: NOW)  # a host older than 1.5: no device_ips
        c = MdnsConnector("mdns1", {}, old_host, socket_factory=self.factory)  # type: ignore[arg-type]
        self.addCleanup(c.close)
        self.assertEqual(c.validate(), [mc.NEEDS_HOST])
        with self.assertRaises(ConnectorError) as cm:
            c.check()
        self.assertIn("needs leasewatch 1.5 or later", str(cm.exception))
        self.assertEqual(self.factory.sockets, [])

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

    def test_relays(self) -> None:
        for v in ("", "10.0.0.1", "10.0.0.1,", " 10.0.0.1 , 10.0.0.2,10.0.0.1"):
            with self.subTest(value=v):
                self.assertEqual(self.conn(relays=v).validate(), [])
        for v, pos in (("foo", "1"), ("10.0.0.1,foo,bar", "2"), ("fe80::1", "1"), ("10.0.0", "1")):
            with self.subTest(value=v):
                problems = self.conn(relays=v).validate()
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("relays entry " + pos, problems[0])

    def test_one_problem_each(self) -> None:
        for key, value in (("max_age_days", "0"), ("max_age_days", "91"), ("max_entries", "10"),
                           ("interface", "not an iface!")):
            with self.subTest(key=key, value=value):
                problems = self.conn(**{key: value}).validate()
                self.assertEqual(len(problems), 1, problems)
        self.assertEqual(self.conn(interface="eth0", max_age_days="30", max_entries="1024").validate(), [])

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
        self.assertEqual(batch.stats, {"names": 0, "joined": 0, "packets": 0, "malformed": 0, "unmapped": 0,
                                       "wrong_port": 0, "off_link": 0, "unicast": 0, "relayed": 0,
                                       "dropped_rate": 0, "errors": 0, "labels_unavailable": 1})

    def test_cold_cache_keeps_labels(self) -> None:
        c = self.conn()
        self.assertEqual(c.collect().stats["labels_unavailable"], 1)  # nothing heard since the start
        c._hear("printer-7", IP_A, "P1", NOW)
        self.assertNotIn("labels_unavailable", c.collect().stats)

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

    def test_close_while_blocked_in_recvmsg(self) -> None:
        # a real socket's close() does not wake a recvmsg() blocked in another thread; the receive timeout does
        entered = threading.Event()

        class BlockingSocket(FakeSocket):
            def recvmsg(self, bufsize: int, ancbufsize: int = 0) -> tuple[bytes, list, int, tuple[str, int]]:
                entered.set()
                return super().recvmsg(bufsize, ancbufsize)

            def close(self) -> None:
                self.closed = True

        sockets: list[FakeSocket] = []

        def factory() -> FakeSocket:
            sockets.append(BlockingSocket() if not sockets else FakeSocket())
            return sockets[-1]

        c = MdnsConnector("mdns1", {}, self.ctx(), socket_factory=factory)
        self.addCleanup(c.close)
        c.check()
        thread = c._thread
        self.assertTrue(entered.wait(2))
        t0 = time.monotonic()
        c.close()
        self.assertLess(time.monotonic() - t0, 2.5)
        self.assertTrue(sockets[0].closed)
        self.assertFalse(thread.is_alive())
        c.close()  # a second close() is a no-op
        self.assertEqual(len(sockets), 1)
        c.check()  # a fresh listener on a fresh socket
        self.assertEqual(len(sockets), 2)
        self.assertIsNot(c._thread, thread)
        self.assertTrue(c._thread.is_alive())
        for s in sockets:
            self.assertEqual(s.sent, [])

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

    def test_receive_oserror_counted_and_thread_continues(self) -> None:
        c = self.conn()
        with mock.patch.object(mc, "RECV_TIMEOUT", 0.01), \
                mock.patch.object(dns, "parse_response", return_value=packet(("tv", IP_B, ""))):
            c.check()
            s = self.factory.sockets[0]
            s.fail_next(OSError(errno.ENETDOWN, os.strerror(errno.ENETDOWN)))
            s.deliver()
            self.assertTrue(wait_until(lambda: MAC_B in c._cache))
        self.assertTrue(c._thread.is_alive())
        stats = c.collect().stats
        self.assertEqual((stats["errors"], stats["packets"], stats["names"]), (1, 1, 1))

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

    def test_malformed_global_budget(self) -> None:
        c = self.conn()
        clock = [1000.0]
        c._clock = lambda: clock[0]
        with mock.patch.object(dns, "parse_response", return_value=packet(malformed=True)):
            with self.assertLogs("leasewatch.contrib.mdns", "DEBUG") as logs:
                for i in range(50):
                    c._handle(b"", (f"10.0.2.{i}", 5353))
                clock[0] += mc.WARN_INTERVAL  # a new hour: a new budget
                c._handle(b"", ("10.0.3.1", 5353))
        warnings = [r.getMessage() for r in logs.records if r.levelname == "WARNING"]
        self.assertEqual(len(warnings), mc.WARN_BUDGET + 1)
        self.assertIn("further malformed packets are logged at DEBUG for an hour", warnings[mc.WARN_BUDGET - 1])
        self.assertEqual(sum("further malformed packets" in w for w in warnings), 1)
        self.assertIn("10.0.3.1", warnings[-1])
        self.assertEqual(sum(r.levelname == "DEBUG" for r in logs.records), 50 - mc.WARN_BUDGET)
        self.assertEqual(c.collect().stats["malformed"], 51)

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

    def test_wrong_source_port_not_parsed(self) -> None:
        c = self.conn()
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))) as parse:
            c._handle(b"announce", (IP_A, 40000))
        self.assertEqual(parse.call_count, 0)
        batch = c.collect()
        self.assertEqual(batch.sightings, [])
        self.assertEqual((batch.stats["packets"], batch.stats["wrong_port"]), (1, 1))

    def test_relayed_counted_only_when_handled(self) -> None:
        c = self.conn(relays="10.0.0.9")
        clock = [5000.2]
        c._clock = lambda: clock[0]
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))) as parse:
            c._handle(b"announce", ("10.0.0.9", 40000), "relayed")
            self.assertEqual(parse.call_count, 0)
            stats = c.collect().stats
            self.assertEqual((stats["packets"], stats["wrong_port"], stats["relayed"]), (1, 1, 0))
            for _ in range(200):
                c._handle(b"", ("10.0.0.9", 5353), "relayed")
            c._handle(b"", ("10.0.0.9", 5353), "relayed")
            self.assertEqual(parse.call_count, 200)
            stats = c.collect().stats
            self.assertEqual((stats["packets"], stats["dropped_rate"], stats["relayed"]), (201, 1, 200))
            clock[0] = 5001.0
            c._handle(b"", ("10.0.0.9", 5353), "relayed")
            self.assertIn(MAC_A, c._cache)
            self.assertEqual(c.collect().stats["relayed"], 1)

    def test_link_options_requested(self) -> None:
        c = self.conn()
        c.check()
        self.assertEqual(self.factory.sockets[0].options, [(socket.IPPROTO_IP, mc.IP_RECVTTL, 1),
                                                           (socket.IPPROTO_IP, mc.IP_PKTINFO, 1)])

    def test_off_link_and_unicast_rejected(self) -> None:
        c = self.conn()
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))) as parse:
            c.check()
            s = self.factory.sockets[0]
            s.deliver(ttl=64)  # routed: a router decremented the TTL
            s.deliver(dst="10.0.0.2")  # sent to this host's own address, not to the group
            self.assertTrue(wait_until(lambda: s.received == 2))
            self.assertTrue(wait_until(lambda: c._counts["unicast"] == 1))
            self.assertEqual(parse.call_count, 0)
            self.assertEqual(c._cache, {})
            s.deliver()  # TTL 255 to the group
            self.assertTrue(wait_until(lambda: MAC_A in c._cache))
        stats = c.collect().stats
        self.assertEqual((stats["packets"], stats["off_link"], stats["unicast"], stats["names"]), (3, 1, 1, 1))
        stats = c.collect().stats
        self.assertEqual((stats["off_link"], stats["unicast"]), (0, 0))  # reset per poll

    def test_link_reject(self) -> None:
        ttl = (socket.IPPROTO_IP, socket.IP_TTL, struct.pack("=i", 255))
        info = (socket.IPPROTO_IP, mc.IP_PKTINFO, struct.pack("=i4s4s", 2, socket.inet_aton("10.0.0.2"),
                                                              socket.inet_aton(mc.MDNS_GROUP)))
        self.assertEqual(mc._link_reject([ttl, info]), (True, True))
        self.assertEqual(mc._link_reject([info]), (False, True))  # no TTL: not ok
        self.assertEqual(mc._link_reject([ttl]), (True, False))  # no destination: not ok
        self.assertEqual(mc._link_reject([(socket.IPPROTO_IP, socket.IP_TTL, b"\xff"), info]), (True, True))  # 1 byte
        self.assertEqual(mc._link_reject([(socket.IPPROTO_IP, socket.IP_TTL, b"\x01"), info]), (False, True))

    def test_relay_accepted_at_any_ttl(self) -> None:
        c = self.conn(relays="10.0.0.9, 10.0.0.1,")
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))):
            c.check()
            s = self.factory.sockets[0]
            s.deliver(src="10.0.0.9", ttl=1)
            self.assertTrue(wait_until(lambda: MAC_A in c._cache))
        stats = c.collect().stats
        self.assertEqual((stats["packets"], stats["relayed"], stats["off_link"], stats["unicast"]), (1, 1, 0, 0))
        self.assertEqual(c.collect().stats["relayed"], 0)  # reset per poll

    def test_relay_unicast_still_rejected(self) -> None:
        c = self.conn(relays="10.0.0.9")
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))) as parse:
            c.check()
            s = self.factory.sockets[0]
            s.deliver(src="10.0.0.9", ttl=1, dst="10.0.0.2")
            s.deliver(src="10.0.0.9", ttl=255, dst="10.0.0.2")
            self.assertTrue(wait_until(lambda: c._counts["unicast"] == 2))
            self.assertEqual(parse.call_count, 0)
            self.assertEqual(c._cache, {})
        self.assertEqual(c.collect().stats["relayed"], 0)

    def test_unlisted_source_off_link(self) -> None:
        c = self.conn(relays="10.0.0.9")
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))) as parse:
            c.check()
            s = self.factory.sockets[0]
            s.deliver(src="10.0.0.8", ttl=1)
            self.assertTrue(wait_until(lambda: c._counts["off_link"] == 1))
            self.assertEqual(parse.call_count, 0)
            self.assertEqual(c._cache, {})
        self.assertEqual(c.collect().stats["relayed"], 0)

    def test_relay_at_ttl_255_not_counted(self) -> None:
        c = self.conn(relays="10.0.0.9")
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))):
            c.check()
            self.factory.sockets[0].deliver(src="10.0.0.9", ttl=255)
            self.assertTrue(wait_until(lambda: MAC_A in c._cache))
        stats = c.collect().stats
        self.assertEqual((stats["relayed"], stats["off_link"]), (0, 0))

    def test_link_options_refused_falls_back(self) -> None:
        self.factory.link_options = False
        c = self.conn()
        with mock.patch.object(dns, "parse_response", return_value=packet(("printer-7", IP_A, "P1"))):
            with self.assertLogs("leasewatch.contrib.mdns", "WARNING") as logs:
                c.check()
                c.close()
                c.check()  # a second start does not warn again
            s = self.factory.sockets[1]
            s.deliver(ttl=64, dst="10.0.0.2")  # nothing can be checked: accepted
            self.assertTrue(wait_until(lambda: MAC_A in c._cache))
        self.assertEqual([r.getMessage() for r in logs.records],
                         ["mdns: cannot check the sender's link; accepting any source"])
        stats = c.collect().stats
        self.assertEqual((stats["off_link"], stats["unicast"], stats["names"]), (0, 0, 1))

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


class RecordingSocket:
    """Stands in for socket.socket in _default_socket(): records the options set; opens nothing. A join on an
    interface index in `refuse` fails as the kernel's would; `no_multicast_all` makes IP_MULTICAST_ALL unknown."""

    refuse: set[int] = set()
    no_multicast_all = False
    made: list[RecordingSocket] = []

    def __init__(self, family: int, kind: int) -> None:
        self.options: list[tuple[int, int, object]] = []
        self.bound: tuple | None = None
        self.closed = False
        RecordingSocket.made.append(self)

    def setsockopt(self, level: int, option: int, value: object) -> None:
        if option == mc.IP_MULTICAST_ALL and self.no_multicast_all:
            raise OSError(errno.ENOPROTOOPT, os.strerror(errno.ENOPROTOOPT))
        if option == socket.IP_ADD_MEMBERSHIP and len(value) == 12 and struct.unpack("=4s4si", value)[2] in self.refuse:
            raise OSError(errno.ENODEV, os.strerror(errno.ENODEV))
        self.options.append((level, option, value))

    def bind(self, address: tuple) -> None:
        self.bound = address

    def settimeout(self, value: float) -> None:
        pass

    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple[str, int]]:
        time.sleep(0.01)  # nothing ever arrives
        raise socket.timeout("timed out")

    def recvmsg(self, bufsize: int, ancbufsize: int = 0) -> tuple[bytes, list, int, tuple[str, int]]:
        time.sleep(0.01)
        raise socket.timeout("timed out")

    def close(self) -> None:
        self.closed = True

    def joins(self) -> list[object]:
        return [v for level, opt, v in self.options if (level, opt) == (socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP)]

    def multicast_all(self) -> list[object]:
        return [v for level, opt, v in self.options if (level, opt) == (socket.IPPROTO_IP, mc.IP_MULTICAST_ALL)]


GROUP = socket.inet_aton("224.0.0.251")
ANY = socket.inet_aton("0.0.0.0")
INTERFACES = [(1, "lo"), (2, "d1"), (3, "d2")]


class JoinTest(unittest.TestCase):
    """_default_socket() against RecordingSocket: which group joins and options it asks the kernel for."""

    def setUp(self) -> None:
        RecordingSocket.refuse = set()
        RecordingSocket.no_multicast_all = False
        RecordingSocket.made = []
        self.patches = [mock.patch.object(socket, "socket", RecordingSocket),
                        mock.patch.object(socket, "if_nameindex", lambda: list(INTERFACES)),
                        mock.patch.object(socket, "if_nametoindex", lambda n: {v: k for k, v in INTERFACES}[n])]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def open(self, interface: str = "") -> tuple[MdnsConnector, RecordingSocket]:
        c = MdnsConnector("mdns1", {"interface": interface}, HostContext(now=lambda: NOW))
        sock = c._default_socket()
        return c, sock

    def test_every_interface_but_loopback(self) -> None:
        with self.assertLogs("leasewatch.contrib.mdns", "INFO") as logs:
            c, sock = self.open()
        self.assertEqual(sock.joins(), [struct.pack("=4s4si", GROUP, ANY, 2), struct.pack("=4s4si", GROUP, ANY, 3)])
        self.assertEqual(sock.multicast_all(), [])
        self.assertEqual(sock.bound, ("", 5353))
        self.assertEqual(c._joined, 2)
        self.assertIn("mdns: listening on 2 interfaces", [r.getMessage() for r in logs.records])

    def test_refused_interface_skipped(self) -> None:
        RecordingSocket.refuse = {2}
        with self.assertLogs("leasewatch.contrib.mdns", "DEBUG") as logs:
            c, sock = self.open()
        self.assertEqual(sock.joins(), [struct.pack("=4s4si", GROUP, ANY, 3)])
        self.assertEqual(c._joined, 1)
        self.assertEqual(sum("cannot join" in r.getMessage() for r in logs.records), 1)

    def test_no_join_fails_check(self) -> None:
        RecordingSocket.refuse = {2, 3}
        c = MdnsConnector("mdns1", {}, HostContext(now=lambda: NOW))
        self.addCleanup(c.close)
        with self.assertRaises(ConnectorError) as cm:
            c.check()
        self.assertIn("any interface", str(cm.exception))
        self.assertTrue(RecordingSocket.made[-1].closed)
        self.assertIsNone(c._thread)

    def test_named_interface(self) -> None:
        c, sock = self.open("d1")
        self.assertEqual(sock.joins(), [struct.pack("=4s4si", GROUP, ANY, 2)])
        self.assertEqual(sock.multicast_all(), [0])
        self.assertEqual(c._joined, 1)

    def test_unknown_interface_name(self) -> None:
        def no_such(name: str) -> int:
            raise OSError("no interface with this name")

        c = MdnsConnector("mdns1", {"interface": "eth9"}, HostContext(now=lambda: NOW))
        self.addCleanup(c.close)
        with mock.patch.object(socket, "if_nametoindex", no_such):
            with self.assertRaises(ConnectorError) as cm:
                c.check()
        self.assertEqual(str(cm.exception), "mdns: no interface named eth9")
        self.assertTrue(RecordingSocket.made[-1].closed)

    def test_errno_text_without_errno(self) -> None:
        self.assertEqual(mc._errno_text(OSError("no interface with this name")), "no interface with this name")
        self.assertEqual(mc._errno_text(OSError()), "OSError")

    def test_interface_address(self) -> None:
        _c, sock = self.open("10.0.0.2")
        self.assertEqual(sock.joins(), [GROUP + socket.inet_aton("10.0.0.2")])
        self.assertEqual(sock.multicast_all(), [0])

    def test_multicast_all_unknown_is_ignored(self) -> None:
        RecordingSocket.no_multicast_all = True
        _c, sock = self.open("d1")
        self.assertEqual((len(sock.joins()), sock.multicast_all()), (1, []))

    def test_joined_in_stats(self) -> None:
        c = MdnsConnector("mdns1", {}, HostContext(now=lambda: NOW))
        self.addCleanup(c.close)
        self.assertEqual(c.collect().stats["joined"], 2)


class SsdpSocketTest(Base):
    """SSDP=1: a second socket and listener on 239.255.255.250:1900, with its own counters and rate budget."""

    def test_ssdp_off_opens_one_socket(self) -> None:
        c = self.conn()
        self.assertFalse(c.ssdp)
        stats = c.collect().stats
        self.assertEqual([(s.group, s.port) for s in self.factory.sockets], [(mc.MDNS_GROUP, mc.MDNS_PORT)])
        self.assertIsNone(c._ssdp_thread)
        self.assertFalse(any(k.startswith("ssdp_") for k in stats))

    def test_ssdp_on_opens_two_sockets_close_closes_both(self) -> None:
        c = self.conn(ssdp="1")
        c.check()
        self.assertEqual([(s.group, s.port) for s in self.factory.sockets],
                         [("224.0.0.251", 5353), ("239.255.255.250", 1900)])
        threads = (c._thread, c._ssdp_thread)
        self.assertTrue(all(t is not None and t.is_alive() and t.daemon for t in threads))
        self.assertEqual(threads[1].name, "ssdp-mdns1")
        for s in self.factory.sockets:  # the link options are asked for on both
            self.assertEqual(s.options, [(socket.IPPROTO_IP, mc.IP_RECVTTL, 1), (socket.IPPROTO_IP, mc.IP_PKTINFO, 1)])
        c.check()  # running: no third socket
        self.assertEqual(len(self.factory.sockets), 2)
        c.close()
        self.assertTrue(all(s.closed for s in self.factory.sockets))
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertIsNone(c._ssdp_thread)

    def test_ssdp_bind_failure_leaves_nothing_open(self) -> None:
        sockets: list[FakeSocket] = []

        def factory(group: str = mc.MDNS_GROUP, port: int = mc.MDNS_PORT) -> FakeSocket:
            if port == mc.SSDP_PORT:
                raise OSError(errno.EADDRINUSE, os.strerror(errno.EADDRINUSE))
            sockets.append(FakeSocket())
            return sockets[-1]

        c = MdnsConnector("mdns1", {"ssdp": "1"}, self.ctx(), socket_factory=factory)
        self.addCleanup(c.close)
        with self.assertRaises(ConnectorError) as cm:
            c.check()
        self.assertEqual(str(cm.exception), f"mdns: cannot listen on 1900 ({os.strerror(errno.EADDRINUSE)})")
        self.assertEqual(len(sockets), 1)
        self.assertTrue(sockets[0].closed)
        self.assertIsNone(c._thread)
        self.assertIsNone(c._ssdp_thread)
        self.assertIsNone(c._sock)

    def test_ssdp_packet_counted_apart(self) -> None:
        c = self.conn(ssdp="true")
        with mock.patch.object(dns, "parse_response") as parse:
            c.check()
            s = self.factory.sockets[1]
            s.deliver(b"NOTIFY * HTTP/1.1\r\n\r\n", dst=mc.SSDP_GROUP)
            self.assertTrue(wait_until(lambda: s.received == 1 and c._counts["ssdp_packets"] == 1))
            self.assertEqual(parse.call_count, 0)  # never handed to the mDNS parser
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_packets"], stats["ssdp_dropped_rate"], stats["ssdp_errors"]), (1, 0, 0))
        self.assertEqual((stats["packets"], stats["unicast"], stats["off_link"], stats["errors"]), (0, 0, 0, 0))
        self.assertEqual(stats["ssdp_joined"], 0)  # the fake factory joins nothing
        self.assertEqual(c.collect().stats["ssdp_packets"], 0)  # counted per collect()

    def test_rate_windows_independent(self) -> None:
        c = self.conn(ssdp="1")
        clock = [5000.2]
        c._clock = lambda: clock[0]
        with mock.patch.object(dns, "parse_response", return_value=packet()) as parse:
            for _ in range(201):
                c._handle_ssdp(b"", ("10.0.0.40", 1900), None)
            for _ in range(200):
                c._handle(b"", (IP_A, 5353))
            self.assertEqual(parse.call_count, 200)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_packets"], stats["ssdp_dropped_rate"]), (201, 1))
        self.assertEqual((stats["packets"], stats["dropped_rate"]), (200, 0))

    def test_ssdp_receive_errors_counted_apart(self) -> None:
        c = self.conn(ssdp="1")
        with mock.patch.object(mc, "RECV_TIMEOUT", 0.01):
            c.check()
            s = self.factory.sockets[1]
            s.fail_next(OSError(errno.ENETDOWN, os.strerror(errno.ENETDOWN)))
            s.deliver(dst=mc.SSDP_GROUP)
            self.assertTrue(wait_until(lambda: c._counts["ssdp_packets"] == 1))
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_errors"], stats["errors"]), (1, 0))

    def test_validate_ssdp(self) -> None:
        for v in ("0", "1", "true", "false", "yes", "off", " TRUE "):
            with self.subTest(value=v):
                self.assertEqual(self.conn(ssdp=v).validate(), [])
        for v in ("maybe", "2", ""):
            with self.subTest(value=v):
                problems = self.conn(ssdp=v).validate()
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("SSDP", problems[0])
        self.assertEqual(self.factory.sockets, [])

    def test_link_info_ifindex(self) -> None:
        ttl = (socket.IPPROTO_IP, socket.IP_TTL, struct.pack("=i", 4))
        info = (socket.IPPROTO_IP, mc.IP_PKTINFO, struct.pack("=i4s4s", 7, socket.inet_aton("10.0.0.2"),
                                                              socket.inet_aton(mc.SSDP_GROUP)))
        self.assertEqual(mc._link_info([ttl, info]), (4, mc.SSDP_GROUP, 7))
        self.assertEqual(mc._link_info([info]).ifindex, 7)
        self.assertEqual(mc._link_info([]), (None, None, None))
        self.assertEqual(mc._link_reject([ttl, info]), (False, False))  # the mDNS rule: not the mDNS group


SONOS_IP, SONOS_MAC = "10.0.0.40", "02:00:00:00:00:40"


def anc(dst: str = mc.SSDP_GROUP, ttl: int = 2, ifindex: int = 2) -> list:
    """The control messages of a packet: its IP TTL and its in_pktinfo (interface index, local and destination)."""
    pktinfo = struct.pack("=i4s4s", ifindex, socket.inet_aton("10.0.0.2"), socket.inet_aton(dst))
    return [(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("=i", ttl)), (socket.IPPROTO_IP, mc.IP_PKTINFO, pktinfo)]


class SsdpPathTest(Base):
    """SSDP=1: a NOTIFY from a mapped source on the link becomes a product label for that source's MAC."""

    def setUp(self) -> None:
        super().setUp()
        self.ips[SONOS_IP] = SONOS_MAC
        self.clock = [1000.0]

    def ssdp(self, **settings: str) -> MdnsConnector:
        c = self.conn(ssdp="1", **settings)
        c._clock = lambda: self.clock[0]
        return c

    def send(self, c: MdnsConnector, data: bytes = fx.SONOS, src: str = SONOS_IP, ancdata="default") -> None:
        c._handle_ssdp(data, (src, 1900), anc() if ancdata == "default" else ancdata)

    def test_label_from_notify(self) -> None:
        c = self.ssdp()
        self.send(c)
        batch = c.collect()
        self.assertEqual([(s.mac, s.hostname, s.label, s.kind, s.presence) for s in batch.sightings],
                         [(SONOS_MAC, "", "Sonos/70.3-35220", "scan", False)])
        self.assertEqual((batch.stats["ssdp_labels"], batch.stats["names"]), (1, 1))
        self.assertNotIn("labels_unavailable", batch.stats)
        self.assertEqual(batch.stats["ssdp_generic"], 0)  # every counter is reported from the start

    def test_mdns_label_wins_hostname_kept(self) -> None:
        c = self.ssdp()
        c._hear("sonos-kitchen", SONOS_IP, "Sonos Play:1", NOW)
        self.send(c)
        batch = c.collect()
        self.assertEqual([(s.hostname, s.label) for s in batch.sightings], [("sonos-kitchen", "Sonos Play:1")])
        self.assertEqual((batch.stats["names"], batch.stats["ssdp_labels"]), (1, 1))

    def test_mdns_hostname_without_label_takes_ssdp_label(self) -> None:
        c = self.ssdp()
        c._hear("sonos-kitchen", SONOS_IP, "", NOW)
        self.send(c)
        self.assertEqual([(s.hostname, s.label) for s in c.collect().sightings],
                         [("sonos-kitchen", "Sonos/70.3-35220")])

    def test_unicast_dropped(self) -> None:
        c = self.ssdp()
        self.send(c, ancdata=anc(dst="10.0.0.25"))
        batch = c.collect()
        self.assertEqual((batch.stats["ssdp_unicast"], batch.stats["ssdp_labels"]), (1, 0))
        self.assertEqual(batch.sightings, [])
        self.assertEqual(batch.stats["labels_unavailable"], 1)

    def test_wrong_interface(self) -> None:
        c = self.ssdp(interface="eth0")
        c._ssdp_joined_idx = frozenset({2})
        self.send(c, ancdata=anc(ifindex=9))
        self.send(c, ancdata=anc(ifindex=2))
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_wrong_if"], stats["ssdp_labels"]), (1, 1))

    def test_interface_not_checked_without_setting_or_indexes(self) -> None:
        c = self.ssdp()
        c._ssdp_joined_idx = frozenset({2})  # no INTERFACE: every interface is listened on
        self.send(c, ancdata=anc(ifindex=9))
        c2 = self.ssdp(interface="eth0")  # INTERFACE set but no index known
        self.send(c2, ancdata=anc(ifindex=9))
        self.assertEqual((c.collect().stats["ssdp_wrong_if"], c2.collect().stats["ssdp_wrong_if"]), (0, 0))

    def test_ttl_counted_not_checked(self) -> None:
        c = self.ssdp()
        self.send(c, ancdata=anc(ttl=64))
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_ttl_gt4"], stats["ssdp_labels"]), (1, 1))

    def test_without_control_messages_link_rule_skipped(self) -> None:
        c = self.ssdp()
        self.send(c, ancdata=None)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_unicast"], stats["ssdp_labels"]), (0, 1))

    def test_mismatch(self) -> None:
        c = self.ssdp()
        self.send(c, fx.MISMATCH)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_mismatch"], stats["ssdp_labels"]), (1, 0))

    def test_location_name_passes(self) -> None:
        c = self.ssdp()
        self.send(c, fx.notify(fx.SONOS_SERVER, location="http://sonos-kitchen.local:1400/desc.xml"))
        self.assertEqual(c.collect().stats["ssdp_labels"], 1)

    def test_generic_and_parse_failures(self) -> None:
        c = self.ssdp()
        cases = [(fx.GENERIC_LIBUPNP, "ssdp_generic"), (fx.MSEARCH, "ssdp_not_notify"), (fx.BYEBYE, "ssdp_byebye"),
                 (fx.MALFORMED, "ssdp_malformed"), (fx.OVERSIZED, "ssdp_oversized")]
        for n, (data, _counter) in enumerate(cases):
            src = "10.0.0.42" if data is fx.GENERIC_LIBUPNP else f"10.0.0.{50 + n}"  # its LOCATION host
            self.ips[src] = f"02:00:00:00:00:{50 + n}"
            self.send(c, data, src=src)
        stats = c.collect().stats
        self.assertEqual(stats["ssdp_generic"], 1)
        for counter in ("ssdp_not_notify", "ssdp_byebye", "ssdp_malformed", "ssdp_oversized"):
            self.assertEqual(stats[counter], 1, counter)
        self.assertEqual((stats["ssdp_labels"], stats["ssdp_no_label"]), (0, 0))

    def test_no_label(self) -> None:
        c = self.ssdp()
        self.send(c, fx.notify("UPnP/1.0"))
        self.assertEqual(c.collect().stats["ssdp_labels"], 0)

    def test_repeat_within_window_then_parsed_again(self) -> None:
        c = self.ssdp()
        self.send(c)
        self.clock[0] += 599
        self.send(c)
        self.assertEqual(len(c._ssdp), 1)
        self.clock[0] += 2  # 601 s after the first
        self.send(c)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_repeat"], stats["ssdp_labels"], stats["ssdp_packets"]), (1, 1, 3))

    def test_repeat_memory_is_capped(self) -> None:
        c = self.ssdp()
        with mock.patch.object(mc, "MAX_WARNED", 3):
            for n in range(10):
                self.ips[f"10.0.1.{n}"] = f"02:00:00:00:01:{n:02x}"
                self.send(c, fx.notify(fx.SONOS_SERVER, location=f"http://10.0.1.{n}:1400/d.xml"), src=f"10.0.1.{n}")
        self.assertEqual(c.collect().stats["ssdp_labels"], 10)
        self.assertLessEqual(len(c._ssdp_seen), 3)

    def test_unicast_flood_does_not_use_the_budget(self) -> None:
        c = self.ssdp()
        for _ in range(300):
            self.send(c, ancdata=anc(dst="10.0.0.25"), src="10.9.9.9")
        self.send(c)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_unicast"], stats["ssdp_dropped_rate"], stats["ssdp_labels"]), (300, 0, 1))

    def test_wrong_interface_flood_does_not_use_the_budget(self) -> None:
        c = self.ssdp(interface="eth0")
        c._ssdp_joined_idx = frozenset({2})
        for _ in range(300):
            self.send(c, ancdata=anc(ifindex=9))
        self.send(c, ancdata=anc(ifindex=2))
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_wrong_if"], stats["ssdp_dropped_rate"], stats["ssdp_labels"]), (300, 0, 1))

    def test_generic_then_product_stack_from_one_source(self) -> None:
        c = self.ssdp()
        self.send(c, fx.notify("Linux/4.9 UPnP/1.0 Samsung UPnP SDK/1.0"))
        self.send(c)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_generic"], stats["ssdp_repeat"], stats["ssdp_labels"]), (1, 0, 1))

    def test_label_then_label_is_a_repeat(self) -> None:
        c = self.ssdp()
        self.send(c)
        self.send(c)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_repeat"], stats["ssdp_labels"]), (1, 1))

    def test_unmapped_does_not_start_the_window(self) -> None:
        c = self.ssdp()
        del self.ips[SONOS_IP]
        self.send(c)
        self.ips[SONOS_IP] = SONOS_MAC
        self.send(c)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_unmapped"], stats["ssdp_repeat"], stats["ssdp_labels"]), (1, 0, 1))

    def test_mismatch_does_not_start_the_window(self) -> None:
        c = self.ssdp()
        self.send(c, fx.MISMATCH)
        self.send(c)
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_mismatch"], stats["ssdp_repeat"], stats["ssdp_labels"]), (1, 0, 1))

    def test_unmapped(self) -> None:
        c = self.ssdp()
        self.send(c, fx.notify(fx.SONOS_SERVER, location="http://10.0.0.77:1400/d.xml"), src="10.0.0.77")
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_unmapped"], stats["ssdp_labels"]), (1, 0))

    def test_address_handed_on_drops_old_mac(self) -> None:
        c = self.ssdp()
        self.send(c)
        self.ips[SONOS_IP] = "02:00:00:00:00:41"
        self.clock[0] += 1000
        self.send(c)
        self.assertEqual([s.mac for s in c.collect().sightings], ["02:00:00:00:00:41"])

    def test_last_heard_order_and_cap(self) -> None:
        c = self.ssdp(max_entries="64")
        for n in range(70):
            self.ips[f"10.0.2.{n}"] = f"02:00:00:00:02:{n:02x}"
            self.send(c, fx.notify(fx.SONOS_SERVER, location=f"http://10.0.2.{n}:1400/d.xml"), src=f"10.0.2.{n}")
        batch = c.collect()
        self.assertEqual(batch.stats["ssdp_labels"], 64)
        self.assertNotIn("02:00:00:00:02:00", [s.mac for s in batch.sightings])

    def test_ageing(self) -> None:
        c = self.ssdp(max_age_days="1")
        self.send(c)
        self.now += DAY - 1
        self.assertEqual(c.collect().stats["ssdp_labels"], 1)
        self.now += 2
        batch = c.collect()
        self.assertEqual((batch.sightings, batch.stats["ssdp_labels"], batch.stats["labels_unavailable"]), ([], 0, 1))

    def test_ssdp_off_never_calls_handler(self) -> None:
        c = self.conn()
        with mock.patch.object(c, "_handle_ssdp") as handler:
            c.check()
            self.assertEqual(len(self.factory.sockets), 1)
        handler.assert_not_called()
        self.assertNotIn("ssdp_labels", c.collect().stats)


class SsdpMatrixTest(Base):
    """SSDP=1 seen through collect(): the whole path from a socket, the counters and the merge of the two caches."""

    def setUp(self) -> None:
        super().setUp()
        self.ips[SONOS_IP] = SONOS_MAC
        self.clock = [1000.0]

    def ssdp(self, **settings: str) -> MdnsConnector:
        c = self.conn(ssdp="1", **settings)
        c._clock = lambda: self.clock[0]
        return c

    def send(self, c: MdnsConnector, data: bytes = fx.SONOS, src: str = SONOS_IP) -> None:
        c._handle_ssdp(data, (src, 1900), anc())

    SSDP_KEYS = ["ssdp_byebye", "ssdp_dropped_rate", "ssdp_errors", "ssdp_generic", "ssdp_joined", "ssdp_labels",
                 "ssdp_malformed", "ssdp_mismatch", "ssdp_no_label", "ssdp_not_notify", "ssdp_oversized",
                 "ssdp_packets", "ssdp_repeat", "ssdp_ttl_gt4", "ssdp_unicast", "ssdp_unmapped", "ssdp_wrong_if"]
    MDNS_KEYS = ["dropped_rate", "errors", "joined", "labels_unavailable", "malformed", "names", "off_link",
                 "packets", "relayed", "unicast", "unmapped", "wrong_port"]

    def test_nothing_is_sent_on_either_socket(self) -> None:
        c = self.ssdp()
        c.check()
        mdns_sock, ssdp_sock = self.factory.sockets
        ssdp_sock.deliver(fx.SONOS, src=SONOS_IP, ttl=2, dst=mc.SSDP_GROUP)
        mdns_sock.deliver(src=IP_A)
        self.assertTrue(wait_until(lambda: c._counts["ssdp_packets"] == 1 and c._counts["packets"] == 1))
        batch = c.collect()
        self.assertEqual(batch.stats["ssdp_labels"], 1)
        c.close()
        self.assertEqual((mdns_sock.sent, ssdp_sock.sent), ([], []))

    def test_flood_from_many_sources(self) -> None:
        c = self.ssdp()
        for n in range(300):
            c._handle_ssdp(fx.SONOS, (f"10.1.{n // 250}.{n % 250}", 1900), anc())
        stats = c.collect().stats
        self.assertEqual((stats["ssdp_packets"], stats["ssdp_dropped_rate"]), (300, 100))
        self.assertEqual((stats["packets"], stats["dropped_rate"], stats["malformed"], stats["errors"]), (0, 0, 0, 0))

    def test_priority_through_collect(self) -> None:
        c = self.ssdp()
        c._hear("printer", SONOS_IP, "", NOW)
        self.send(c)
        self.assertEqual([(s.mac, s.hostname, s.label) for s in c.collect().sightings],
                         [(SONOS_MAC, "printer", "Sonos/70.3-35220")])
        c._hear("printer", SONOS_IP, "Brother HL", NOW)
        self.assertEqual([(s.hostname, s.label) for s in c.collect().sightings], [("printer", "Brother HL")])

    def test_ssdp_only_mac_disappears_when_mdns_has_it(self) -> None:
        c = self.ssdp()
        self.send(c)
        self.assertEqual([s.mac for s in c.collect().sightings], [SONOS_MAC])
        c._hear("sonos-kitchen", SONOS_IP, "Sonos Play:1", NOW)
        batch = c.collect()
        self.assertEqual([(s.mac, s.label) for s in batch.sightings], [(SONOS_MAC, "Sonos Play:1")])
        self.assertEqual((batch.stats["names"], batch.stats["ssdp_labels"]), (1, 1))

    def test_stats_keys_with_ssdp_on(self) -> None:
        c = self.ssdp()
        stats = c.collect().stats
        self.assertEqual(sorted(stats), sorted(self.MDNS_KEYS + self.SSDP_KEYS))
        self.assertEqual([k for k in self.SSDP_KEYS if stats[k] != 0], [])

    def test_stats_keys_with_ssdp_off_after_a_packet(self) -> None:
        c = self.conn()
        c.check()
        self.factory.sockets[0].deliver(src=IP_A)
        self.assertTrue(wait_until(lambda: c._counts["packets"] == 1))
        stats = c.collect().stats
        self.assertEqual(sorted(stats), sorted(self.MDNS_KEYS))
        self.assertEqual(stats["packets"], 1)

    def test_ssdp_cache_ages_and_caps_on_its_own(self) -> None:
        c = self.ssdp(max_entries="64", max_age_days="1")
        self.now = NOW - 2 * DAY
        c._hear("printer-7", IP_A, "P1", self.now)  # aged out by the time of the collect()
        c._hear("printer-8", IP_B, "P2", self.now)
        self.now = NOW
        for n in range(65):
            self.ips[f"10.0.3.{n}"] = f"02:00:00:00:03:{n:02x}"
            self.send(c, fx.notify(fx.SONOS_SERVER, location=f"http://10.0.3.{n}:1400/d.xml"), src=f"10.0.3.{n}")
        batch = c.collect()
        self.assertEqual((len(batch.sightings), batch.stats["names"], batch.stats["ssdp_labels"]), (64, 64, 64))
        self.assertNotIn(MAC_A, [s.mac for s in batch.sightings])

    def test_location_rule(self) -> None:
        cases = [("a name", fx.LOCATION_NAME, 1), ("the source's own IPv4", fx.SONOS, 1),
                 ("another IPv4", fx.MISMATCH, 0), ("an IPv6 literal", fx.LOCATION_V6, 1)]
        for what, data, labels in cases:
            with self.subTest(location=what):
                c = self.ssdp()
                self.send(c, data)
                stats = c.collect().stats
                self.assertEqual((stats["ssdp_labels"], stats["ssdp_mismatch"]), (labels, 1 - labels))

    def test_close_then_collect_restarts_both_listeners(self) -> None:
        c = self.ssdp()
        c.collect()
        c.close()
        self.assertEqual(len(self.factory.sockets), 2)
        c.collect()
        self.assertEqual(len(self.factory.sockets), 4)
        self.assertEqual([(s.group, s.port) for s in self.factory.sockets[2:]],
                         [(mc.MDNS_GROUP, mc.MDNS_PORT), (mc.SSDP_GROUP, mc.SSDP_PORT)])
        self.assertTrue(c._thread.is_alive() and c._ssdp_thread.is_alive())
        self.assertFalse(any(s.closed for s in self.factory.sockets[2:]))


class SsdpJoinTest(unittest.TestCase):
    """_default_socket(group, port) for SSDP: the same joins, on port 1900 and 239.255.255.250."""

    setUp = JoinTest.setUp
    open = JoinTest.open

    def test_ssdp_group_and_port(self) -> None:
        c = MdnsConnector("mdns1", {"ssdp": "1"}, HostContext(now=lambda: NOW))
        with self.assertLogs("leasewatch.contrib.mdns", "INFO") as logs:
            sock = c._default_socket(group=mc.SSDP_GROUP, port=mc.SSDP_PORT)
        ssdp = socket.inet_aton(mc.SSDP_GROUP)
        self.assertEqual(sock.bound, ("", 1900))
        self.assertEqual(sock.joins(), [struct.pack("=4s4si", ssdp, ANY, 2), struct.pack("=4s4si", ssdp, ANY, 3)])
        self.assertEqual((c._ssdp_joined, c._ssdp_joined_idx), (2, frozenset({2, 3})))
        self.assertEqual((c._joined, c._joined_idx), (0, frozenset()))  # the mDNS figures are untouched
        self.assertIn("mdns: listening for SSDP on 2 interfaces", [r.getMessage() for r in logs.records])

    def test_joined_indexes(self) -> None:
        c, _sock = self.open()
        self.assertEqual(c._joined_idx, frozenset({2, 3}))
        c, _sock = self.open("d2")
        self.assertEqual(c._joined_idx, frozenset({3}))
        c, _sock = self.open("10.0.0.2")  # joined by address: the kernel picks the interface, no index is known
        self.assertEqual(c._joined_idx, frozenset())

    def test_ssdp_joined_in_stats(self) -> None:
        c = MdnsConnector("mdns1", {"ssdp": "1"}, HostContext(now=lambda: NOW))
        self.addCleanup(c.close)
        stats = c.collect().stats
        self.assertEqual((stats["joined"], stats["ssdp_joined"]), (2, 2))
        self.assertEqual([s.bound for s in RecordingSocket.made], [("", 5353), ("", 1900)])
        c.close()
        self.assertTrue(all(s.closed for s in RecordingSocket.made))


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
