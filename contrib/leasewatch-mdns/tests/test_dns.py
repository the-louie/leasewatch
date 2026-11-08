"""Tests for the mDNS response parser: the handcrafted packets of fixtures.py, the limits, a fuzz run that must never
raise, and one packet through the connector to a sighting. Synthetic data only; no socket is opened."""
from __future__ import annotations

import os
import random
import sys
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


if __name__ == "__main__":
    unittest.main()
