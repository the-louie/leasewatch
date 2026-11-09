"""Tests for the mDNS response parser: the handcrafted packets of fixtures.py, the limits, a fuzz run that must never
raise, and one packet through the connector to a sighting. Synthetic data only; no socket is opened."""
from __future__ import annotations

import os
import random
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # fixtures and test_mdns, when not started from here
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

import fixtures as fx  # noqa: E402
from leasewatch.connectors import HostContext, Sighting  # noqa: E402
from leasewatch_mdns import dns  # noqa: E402
from leasewatch_mdns.connector import MdnsConnector  # noqa: E402
from test_mdns import NOW, FakeSocketFactory, wait_until  # noqa: E402


class FixtureTest(unittest.TestCase):
    def parse(self, data: bytes, malformed: bool = False) -> list[tuple[str, str, str]]:
        p = dns.parse_response(data)
        self.assertEqual(p.malformed, malformed)
        return p.names

    def test_apple(self) -> None:
        self.assertEqual(self.parse(fx.APPLE), [("Alex-iPad", "10.0.0.21", "iPad13,1")])

    def test_apple_without_srv(self) -> None:
        self.assertEqual(self.parse(fx.APPLE_NO_SRV), [("Alex-iPad", "10.0.0.21", "iPad13,1")])

    def test_printer(self) -> None:
        self.assertEqual(self.parse(fx.PRINTER), [("BRW020000000030", "10.0.0.30", "Brother HL-L2350DW series")])

    def test_chromecast_fn_wins(self) -> None:
        self.assertEqual(self.parse(fx.CHROMECAST), [("0a1b-cast", "10.0.0.40", "Living Room TV")])

    def test_goodbye(self) -> None:
        self.assertEqual(self.parse(fx.GOODBYE), [("printer", "10.0.0.50", "")])

    def test_query_is_empty_not_malformed(self) -> None:
        self.assertEqual(self.parse(fx.QUERY), [])

    def test_truncated_keeps_earlier_records(self) -> None:
        self.assertEqual(self.parse(fx.TRUNCATED, malformed=True), [("printer", "10.0.0.50", "")])

    def test_pointer_loop(self) -> None:
        self.assertEqual(self.parse(fx.POINTER_LOOP, malformed=True), [])

    def test_two_ips(self) -> None:
        self.assertEqual(self.parse(fx.TWO_IPS), [("nas", "10.0.0.70", ""), ("nas", "10.0.0.71", "")])

    def test_too_many(self) -> None:
        p = dns.parse_response(fx.TOO_MANY)
        self.assertFalse(p.malformed)
        self.assertTrue(p.truncated)
        self.assertEqual(len(p.names), 64)
        self.assertEqual(p.names[-1], ("host-63", "10.0.1.63", ""))


class RuleTest(unittest.TestCase):
    def test_short(self) -> None:
        for data in (b"", b"\x00" * 11):
            self.assertEqual(dns.parse_response(data), dns.ParsedPacket(malformed=True))

    def test_header_only_response(self) -> None:
        self.assertEqual(dns.parse_response(fx.packet()), dns.ParsedPacket())

    def test_forward_pointer(self) -> None:
        data = fx.packet([fx.rr(fx.name(pointer=fx.HEADER + 2), fx.A, fx.a("10.0.0.60"))])
        self.assertTrue(dns.parse_response(data).malformed)

    def test_pointer_out_of_range(self) -> None:
        data = fx.packet([fx.rr(fx.name("x", pointer=0x3FFF), fx.A, fx.a("10.0.0.60"))])
        self.assertTrue(dns.parse_response(data).malformed)

    def test_name_too_long(self) -> None:
        long = ".".join(["a" * 63] * 4) + ".local"  # 4 * 64 + 6 + 1 > 255 bytes
        self.assertTrue(dns.parse_response(fx.packet([fx.rr(long, fx.A, fx.a("10.0.0.60"))])).malformed)

    def test_a_with_wrong_length(self) -> None:
        self.assertTrue(dns.parse_response(fx.packet([fx.rr("p.local", fx.A, b"\x0a\x00\x00")])).malformed)

    def test_other_class_and_type_skipped(self) -> None:
        data = fx.packet([fx.rr("p.local", 28, b"\x00" * 16),  # AAAA
                          fx.rr("q.local", fx.A, fx.a("10.0.0.61"), rclass=3),  # CH
                          fx.rr("r.local", fx.A, fx.a("10.0.0.62"), rclass=fx.IN)])  # no flush bit
        self.assertEqual(dns.parse_response(data), dns.ParsedPacket(names=[("r", "10.0.0.62", "")]))

    def test_product_and_cut(self) -> None:
        def label(*items: str | bytes) -> str:
            rdata = b"".join(bytes([len(i)]) + i if isinstance(i, bytes) else fx.txt(i) for i in items)
            data = fx.packet([fx.rr("i._ipp._tcp.local", fx.SRV, fx.srv("p.local", 631)),
                              fx.rr("i._ipp._tcp.local", fx.TXT, rdata),
                              fx.rr("p.local", fx.A, fx.a("10.0.0.63"))])
            return dns.parse_response(data).names[0][2]

        self.assertEqual(label("product=(Synthetic P2)"), "Synthetic P2")
        self.assertEqual(label("MD=Synthetic\x01 P3", "md=second"), "Synthetic P3")  # key case, first wins
        self.assertEqual(label("fn=" + "x" * 100), "x" * 64)
        self.assertEqual(label(b"ty=P\xff4"), "P�4")  # not UTF-8: replaced
        self.assertEqual(label("model", "=v", "rp=ipp"), "")

    def test_opcode_or_rcode_not_zero_ignored(self) -> None:
        for flags in (0xAC00, 0x8403):  # OPCODE 5 (update), RCODE 3 (NXDOMAIN)
            with self.subTest(flags=hex(flags)):
                data = bytearray(fx.GOODBYE)
                data[2:4] = flags.to_bytes(2, "big")
                self.assertEqual(dns.parse_response(bytes(data)), dns.ParsedPacket())


class CostTest(unittest.TestCase):
    """A hostile packet costs little to read: the question, pointer and expansion caps."""

    def test_pointer_chains_in_questions(self) -> None:
        self.assertGreater(len(fx.QUADRATIC), 8900)
        t0 = time.perf_counter()
        p = dns.parse_response(fx.QUADRATIC)
        self.assertLess(time.perf_counter() - t0, 0.01)
        self.assertEqual((p.malformed, p.names), (True, []))

    def test_question_cap(self) -> None:
        def with_questions(n: int) -> bytes:
            return fx.packet([rr_a("p.local", "10.0.0.64")], questions=[fx.question("_ipp._tcp.local")] * n)
        self.assertEqual(dns.parse_response(with_questions(dns.MAX_QUESTIONS)).names, [("p", "10.0.0.64", "")])
        self.assertTrue(dns.parse_response(with_questions(dns.MAX_QUESTIONS + 1)).malformed)

    def test_hop_cap(self) -> None:
        self.assertEqual(dns.parse_response(fx.chain(dns.MAX_HOPS)),
                         dns.ParsedPacket(names=[("host", "10.0.0.80", "")]))
        self.assertEqual(dns.parse_response(fx.chain(dns.MAX_HOPS + 1)), dns.ParsedPacket(malformed=True))

    def test_expansion_cap(self) -> None:
        self.assertFalse(dns.parse_response(fx.expansion(25)).malformed)  # 25 * 2 * 254 bytes
        self.assertTrue(dns.parse_response(fx.expansion(40)).malformed)  # 40 * 2 * 254 > MAX_EXPANSION

    def test_real_fixtures_within_caps(self) -> None:
        for key, data in fx.ALL.items():
            with self.subTest(fixture=key):
                self.assertEqual(dns.parse_response(data).malformed, key in ("TRUNCATED", "POINTER_LOOP"))


class FirstLabelLinkTest(unittest.TestCase):
    """An instance without SRV is tied to the A record's host by its first label."""

    def names(self, *records: bytes) -> list[tuple[str, str, str]]:
        p = dns.parse_response(fx.packet(list(records)))
        self.assertFalse(p.malformed)
        return p.names

    def test_case_insensitive(self) -> None:
        self.assertEqual(self.names(rr_a("ALEX-IPAD.local", "10.0.0.21"),
                                    fx.rr("alex-ipad._device-info._tcp.local", fx.TXT, fx.txt("model=iPad13,1"))),
                         [("ALEX-IPAD", "10.0.0.21", "iPad13,1")])

    def test_srv_wins(self) -> None:
        instance = "Alex-iPad._device-info._tcp.local"
        self.assertEqual(self.names(rr_a("Alex-iPad.local", "10.0.0.21"), rr_a("tablet-2.local", "10.0.0.22"),
                                    fx.rr(instance, fx.SRV, fx.srv("tablet-2.local", 0)),
                                    fx.rr(instance, fx.TXT, fx.txt("model=iPad13,1"))),
                         [("Alex-iPad", "10.0.0.21", ""), ("tablet-2", "10.0.0.22", "iPad13,1")])

    def test_other_first_label_not_linked(self) -> None:
        self.assertEqual(self.names(rr_a("Alex-iPad.local", "10.0.0.21"),
                                    fx.rr("Sam-iPad._device-info._tcp.local", fx.TXT, fx.txt("model=iPad13,1"))),
                         [("Alex-iPad", "10.0.0.21", "")])

    def test_host_txt_is_not_an_instance(self) -> None:
        # a TXT record on the host name itself is no DNS-SD instance and gives no label
        self.assertEqual(self.names(rr_a("Alex-iPad.local", "10.0.0.21"),
                                    fx.rr("Alex-iPad.local", fx.TXT, fx.txt("model=iPad13,1"))),
                         [("Alex-iPad", "10.0.0.21", "")])


def rr_a(owner: str, ip: str) -> bytes:
    return fx.rr(owner, fx.A, fx.a(ip))


class FuzzTest(unittest.TestCase):
    def check(self, data: bytes) -> None:
        try:
            p = dns.parse_response(data)
        except Exception as e:  # noqa: BLE001
            self.fail(f"raised {e!r} on {data.hex()}")
        self.assertIsInstance(p.names, list)

    def test_random_bytes(self) -> None:
        rnd = random.Random(5353)
        for _ in range(300):
            self.check(rnd.randbytes(rnd.randint(0, 600)))

    def test_mutated_fixtures(self) -> None:
        rnd = random.Random(6762)
        sources = list(fx.ALL.values())
        for _ in range(100):
            data = bytearray(rnd.choice(sources))
            for _ in range(rnd.randint(1, 8)):
                data[rnd.randrange(len(data))] = rnd.randrange(256)
            self.check(bytes(data))


class ConnectorEndToEndTest(unittest.TestCase):
    def test_printer_becomes_sighting(self) -> None:
        mac = "02:00:00:00:00:30"
        factory = FakeSocketFactory()
        ctx = HostContext(now=lambda: NOW, device_ips=lambda: {"10.0.0.30": mac})
        c = MdnsConnector("mdns1", {}, ctx, socket_factory=factory)
        self.addCleanup(c.close)
        c.check()
        factory.sockets[0].deliver(fx.PRINTER, src="10.0.0.30")
        self.assertTrue(wait_until(lambda: mac in c._cache))
        batch = c.collect()
        self.assertEqual(batch.sightings, [Sighting(mac=mac, source="mdns1", kind="scan", presence=False,
                                                    observed_at=NOW, hostname="BRW020000000030",
                                                    label="Brother HL-L2350DW series")])
        self.assertEqual(batch.stats["malformed"], 0)
        self.assertEqual(factory.sockets[0].sent, [])


MAC_PRINTER, MAC_IPAD = "02:00:00:00:00:30", "02:00:00:00:00:21"


class ListenerPathTest(unittest.TestCase):
    """The fixture packets through the fake socket and the listener thread, as the network would hand them over."""

    def setUp(self) -> None:
        self.ips = {"10.0.0.30": MAC_PRINTER, "10.0.0.21": MAC_IPAD}
        self.factory = FakeSocketFactory()
        ctx = HostContext(now=lambda: NOW, device_ips=lambda: dict(self.ips))
        self.c = MdnsConnector("mdns1", {}, ctx, socket_factory=self.factory)
        self.addCleanup(self.c.close)
        self.handled = 0
        handle = self.c._handle

        def counting_handle(data: bytes, addr: object, reject: str = "") -> None:  # counts finished packets
            try:
                handle(data, addr, reject)
            finally:
                self.handled += 1
        self.c._handle = counting_handle

    def tearDown(self) -> None:
        for s in self.factory.sockets:
            self.assertEqual(s.sent, [], "the connector transmitted on its socket")

    def feed(self, *packets: tuple[bytes, str]) -> None:
        """Start the listener, deliver the packets and wait until it has handled every one."""
        self.c.check()
        sock = self.factory.sockets[-1]
        target = self.handled + len(packets)
        for data, src in packets:
            sock.deliver(data, src=src)
        self.assertTrue(wait_until(lambda: self.handled == target))
        self.assertTrue(self.c._thread.is_alive())

    def test_printer_and_ipad(self) -> None:
        self.feed((fx.PRINTER, "10.0.0.30"), (fx.APPLE_NO_SRV, "10.0.0.21"))
        batch = self.c.collect()
        self.assertEqual(sorted(batch.sightings, key=lambda s: s.mac), [
            Sighting(mac=MAC_IPAD, source="mdns1", kind="scan", presence=False, observed_at=NOW,
                     hostname="Alex-iPad", label="iPad13,1"),
            Sighting(mac=MAC_PRINTER, source="mdns1", kind="scan", presence=False, observed_at=NOW,
                     hostname="BRW020000000030", label="Brother HL-L2350DW series")])
        self.assertEqual(batch.stats, {"names": 2, "joined": 0, "packets": 2, "malformed": 0, "unmapped": 0,
                                       "wrong_port": 0, "off_link": 0, "unicast": 0, "dropped_rate": 0, "errors": 0})

    def test_unmapped_address(self) -> None:
        self.feed((fx.GOODBYE, "10.0.0.50"))  # 10.0.0.50 is not in device_ips
        batch = self.c.collect()
        self.assertEqual(batch.sightings, [])
        self.assertEqual((batch.stats["unmapped"], batch.stats["malformed"]), (1, 0))

    def test_query_is_not_malformed(self) -> None:
        self.feed((fx.QUERY, "10.0.0.50"))
        batch = self.c.collect()
        self.assertEqual(batch.sightings, [])
        self.assertEqual({k: batch.stats[k] for k in ("packets", "malformed", "unmapped", "errors")},
                         {"packets": 1, "malformed": 0, "unmapped": 0, "errors": 0})

    def test_malformed_packets_warn_once_per_source_per_hour(self) -> None:
        clock = [1000.0]
        self.c._clock = lambda: clock[0]
        with self.assertLogs("leasewatch.contrib.mdns", "WARNING") as logs:
            self.feed((fx.TRUNCATED, "10.0.0.50"), (fx.POINTER_LOOP, "10.0.0.50"), (fx.POINTER_LOOP, "10.0.0.51"))
            clock[0] += 3599
            self.feed((fx.TRUNCATED, "10.0.0.50"))
            clock[0] += 1
            self.feed((fx.POINTER_LOOP, "10.0.0.50"))
        self.assertEqual([r.getMessage().split(" from ")[1].split()[0] for r in logs.records],
                         ["10.0.0.50", "10.0.0.51", "10.0.0.50"])
        self.feed((fx.PRINTER, "10.0.0.30"))  # the thread lives on and still hears names
        batch = self.c.collect()
        self.assertEqual((batch.stats["malformed"], batch.stats["errors"]), (5, 0))
        self.assertEqual([s.mac for s in batch.sightings], [MAC_PRINTER])

    def test_rate_cap_keeps_the_first_200(self) -> None:
        self.ips = {f"10.0.{i // 256}.{i % 256}": f"02:00:00:00:{i // 256:02x}:{i % 256:02x}" for i in range(250)}
        self.c._clock = lambda: 7000.5  # all 250 within one second
        self.feed(*((fx.packet([rr_a(f"host-{i}.local", f"10.0.{i // 256}.{i % 256}")]), "10.0.0.1")
                    for i in range(250)))
        batch = self.c.collect()
        self.assertGreaterEqual(batch.stats["dropped_rate"], 50)
        self.assertEqual(batch.stats["packets"], 250)
        self.assertEqual(sorted(s.hostname for s in batch.sightings), sorted(f"host-{i}" for i in range(200)))


class ConnectorFuzzTest(unittest.TestCase):
    def test_handle_random_bytes(self) -> None:
        factory = FakeSocketFactory()
        ctx = HostContext(now=lambda: NOW, device_ips=lambda: {"10.0.0.30": MAC_PRINTER, "10.0.0.21": MAC_IPAD})
        c = MdnsConnector("mdns1", {}, ctx, socket_factory=factory)
        self.addCleanup(c.close)
        c.check()
        rnd = random.Random(1035)
        sources = list(fx.ALL.values())
        with self.assertLogs("leasewatch.contrib.mdns", "WARNING"):  # the malformed ones; keeps the output quiet
            self._fuzz(c, rnd, sources)
        self.assertEqual(c.collect().stats["packets"], 100)
        self.assertEqual(factory.sockets[0].sent, [])

    def _fuzz(self, c: MdnsConnector, rnd: random.Random, sources: list[bytes]) -> None:
        for i in range(100):
            if i % 2:
                data = rnd.randbytes(rnd.randint(0, 600))
            else:
                buf = bytearray(rnd.choice(sources))
                for _ in range(rnd.randint(1, 8)):
                    buf[rnd.randrange(len(buf))] = rnd.randrange(256)
                data = bytes(buf)
            try:
                c._handle(data, ("10.0.0.99", 5353))
            except Exception as e:  # noqa: BLE001
                self.fail(f"raised {e!r} on {data.hex()}")


if __name__ == "__main__":
    unittest.main()
