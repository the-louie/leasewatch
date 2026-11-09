"""Tests for the SSDP announcement parser: the handcrafted texts of fixtures.py, the product label rule, a fuzz run
that must never raise, and a check that the module holds no network code. Synthetic data only."""
from __future__ import annotations

import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # fixtures, when not started from here
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

import fixtures as fx  # noqa: E402
from leasewatch_mdns import ssdp  # noqa: E402

USN = "uuid:0000-0000::upnp:rootdevice"


class FixtureTest(unittest.TestCase):
    def alive(self, data: bytes) -> ssdp.Notify:
        notify, reason = ssdp.parse_notify(data)
        self.assertEqual(reason, "")
        self.assertIsNotNone(notify)
        self.assertEqual(notify.nts, "ssdp:alive")
        self.assertEqual(notify.usn, USN)
        return notify

    def refused(self, data: bytes, reason: str) -> None:
        self.assertEqual(ssdp.parse_notify(data), (None, reason))

    def test_sonos(self) -> None:
        n = self.alive(fx.SONOS)
        self.assertEqual((n.server, n.location_host), (fx.SONOS_SERVER, "10.0.0.40"))
        self.assertEqual(ssdp.product_label(n.server), "Sonos/70.3-35220")

    def test_hue(self) -> None:
        n = self.alive(fx.HUE)
        self.assertEqual((n.server, n.location_host), ("FreeRTOS/10.4.3, UPnP/1.0, IpBridge/1.65.0", "10.0.0.41"))
        self.assertEqual(ssdp.product_label(n.server), "IpBridge/1.65.0")

    def test_generic_libupnp(self) -> None:
        n = self.alive(fx.GENERIC_LIBUPNP)
        self.assertEqual(n.location_host, "10.0.0.42")
        self.assertEqual(ssdp.product_label(n.server), "")
        self.assertTrue(ssdp.is_generic(n.server))

    def test_portable_sdk(self) -> None:
        n = self.alive(fx.PORTABLE_SDK)
        self.assertEqual(ssdp.product_label(n.server), "")
        self.assertTrue(ssdp.is_generic(n.server))

    def test_byebye(self) -> None:
        self.refused(fx.BYEBYE, "byebye")

    def test_msearch(self) -> None:
        self.refused(fx.MSEARCH, "not_notify")

    def test_http_response(self) -> None:
        self.refused(fx.HTTP_RESPONSE, "not_notify")

    def test_malformed(self) -> None:
        self.refused(fx.MALFORMED, "malformed")

    def test_oversized(self) -> None:
        self.assertGreater(len(fx.OVERSIZED), ssdp.MAX_BYTES)
        self.refused(fx.OVERSIZED, "oversized")

    def test_mismatch(self) -> None:
        self.assertEqual(self.alive(fx.MISMATCH).location_host, "10.0.0.99")

    def test_location_name(self) -> None:
        self.assertEqual(self.alive(fx.LOCATION_NAME).location_host, "sonos-kitchen.example.lan")

    def test_location_v6(self) -> None:
        self.assertEqual(self.alive(fx.LOCATION_V6).location_host, "2001:db8::40")

    def test_lf_only(self) -> None:
        self.assertEqual(ssdp.parse_notify(fx.LF_ONLY), ssdp.parse_notify(fx.SONOS))

    def test_case(self) -> None:
        n = self.alive(fx.CASE)
        self.assertEqual((n.server, n.location_host), (fx.SONOS_SERVER, "10.0.0.40"))


class RuleTest(unittest.TestCase):
    def test_no_line_end(self) -> None:
        self.assertEqual(ssdp.parse_notify(b"NOTIFY * HTTP/1.1"), (None, "malformed"))
        self.assertEqual(ssdp.parse_notify(b""), (None, "malformed"))

    def test_request_line_is_case_sensitive(self) -> None:
        self.assertEqual(ssdp.parse_notify(fx.SONOS.replace(b"NOTIFY", b"notify", 1)), (None, "not_notify"))
        self.assertEqual(ssdp.parse_notify(fx.SONOS.replace(b"HTTP/1.1", b"HTTP/2.0", 1)), (None, "not_notify"))

    def test_too_many_lines(self) -> None:
        extra = tuple(f"X-{i}: {i}" for i in range(ssdp.MAX_LINES))
        self.assertEqual(ssdp.parse_notify(fx.notify(fx.SONOS_SERVER, extra=extra)), (None, "malformed"))
        fits = fx.notify(fx.SONOS_SERVER, extra=extra[:ssdp.MAX_LINES - 7])  # notify() writes 7 header lines
        self.assertEqual(ssdp.parse_notify(fits)[1], "")

    def test_exactly_max_bytes(self) -> None:
        base = fx.notify(fx.SONOS_SERVER, extra=("X-PAD: ",))
        data = fx.notify(fx.SONOS_SERVER, extra=("X-PAD: " + "a" * (ssdp.MAX_BYTES - len(base)),))
        self.assertEqual(len(data), ssdp.MAX_BYTES)
        self.assertEqual(ssdp.parse_notify(data)[1], "")
        self.assertEqual(ssdp.parse_notify(data[:-4] + b"a\r\n\r\n")[1], "oversized")

    def test_first_header_wins_and_body_ignored(self) -> None:
        data = fx.notify("Linux UPnP/1.0 First/1", extra=("SERVER: Linux UPnP/1.0 Second/2",)) + b"no colon\r\n"
        n, reason = ssdp.parse_notify(data)
        self.assertEqual((n.server, reason), ("Linux UPnP/1.0 First/1", ""))

    def test_other_nts_and_missing_nts(self) -> None:
        self.assertEqual(ssdp.parse_notify(fx.notify(fx.SONOS_SERVER, nts="ssdp:update")), (None, "not_notify"))
        data = b"NOTIFY * HTTP/1.1\r\nSERVER: x\r\n\r\n"
        self.assertEqual(ssdp.parse_notify(data), (None, "not_notify"))

    def test_absent_fields_are_empty(self) -> None:
        n, _ = ssdp.parse_notify(b"NOTIFY * HTTP/1.1\nNTS: ssdp:alive\n")
        self.assertEqual(n, ssdp.Notify(server="", location_host="", nts="ssdp:alive", usn=""))

    def test_non_utf8_is_text(self) -> None:
        n, reason = ssdp.parse_notify(fx.notify("Linux UPnP/1.0 Caf\xe9/1").replace(b"\xc3\xa9", b"\xe9"))
        self.assertEqual(reason, "")
        self.assertEqual(ssdp.product_label(n.server), "Caf�/1")

    def test_location_hosts(self) -> None:
        cases = {
            "http://10.0.0.40:1400/xml/device_description.xml": "10.0.0.40",
            "http://10.0.0.40/desc.xml": "10.0.0.40",
            "http://10.0.0.40": "10.0.0.40",
            "http://user@10.0.0.40:80/": "10.0.0.40",
            "http://sonos-kitchen.example.lan:1400/desc.xml": "sonos-kitchen.example.lan",
            "http://[2001:db8::40]:1400/desc.xml": "2001:db8::40",
            "http://[2001:db8::40]/": "2001:db8::40",
            "http://[not-v6]:1400/": "",
            "http://[2001:db8::40:1400/": "",
            "http://10.0.0.40:port/": "",
            "http://bad host/": "",
            "http:///desc.xml": "",
            "10.0.0.40:1400/desc.xml": "",
            "": "",
        }
        for location, host in cases.items():
            with self.subTest(location=location):
                n, _ = ssdp.parse_notify(fx.notify(fx.SONOS_SERVER, location=location))
                self.assertEqual(n.location_host, host)


class LabelTest(unittest.TestCase):
    def test_examples(self) -> None:
        cases = {
            "Linux/4.9 UPnP/1.0 Sonos/70.3-35220": "Sonos/70.3-35220",
            "FreeRTOS/10.4.3, UPnP/1.0, IpBridge/1.65.0": "IpBridge/1.65.0",
            "Linux/3.14 UPnP/1.0 libupnp/1.6.18": "",
            "Windows/10.0 UPnP/1.0 Portable SDK for UPnP devices/1.6.18": "",
            "Sonos/70.3": "",
            "Linux/4.9 UPnP/1.0": "",
            "Linux/4.9 upnp/1.1 Roku/9.4  Tv/1": "Roku/9.4 Tv/1",
            "Linux UPnP/1.0 DLNADOC/1.50 Platinum/1.0.5.13": "",
            "Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0": "",
            "Linux UPnP/1.0 Sonos/70.3 UPnP/2.0 Extra/1": "Sonos/70.3 UPnP/2.0 Extra/1",
            "": "",
        }
        for server, label in cases.items():
            with self.subTest(server=server):
                self.assertEqual(ssdp.product_label(server), label)

    def test_generic_by_name_part(self) -> None:
        for product in ("libupnp/1.6.18", "LIBUPNP", "DLNADOC/1.50", "miniupnpd/2.1", "Cling/2.0", "IntelUPnP/1",
                        "WindowsMediaPlayer/12", "Samsung UPnP SDK/1.0", "Portable SDK for UPnP devices"):
            with self.subTest(product=product):
                self.assertTrue(ssdp.is_generic("Linux UPnP/1.0 " + product))
                self.assertEqual(ssdp.product_label("Linux UPnP/1.0 " + product), "")

    def test_not_generic(self) -> None:
        for server in ("Linux UPnP/1.0 Sonos/70.3", "Linux UPnP/1.0 libupnpx/1", "Linux UPnP/1.0 Portable/1",
                       "Linux UPnP/1.0 Samsung TV/1", "Sonos/70.3", "Linux UPnP/1.0", ""):
            with self.subTest(server=server):
                self.assertFalse(ssdp.is_generic(server))

    def test_control_characters(self) -> None:
        self.assertEqual(ssdp.product_label("Linux UPnP/1.0 So\x00nos\x1b/70\x7f.3\x85"), "Sonos/70.3")
        self.assertEqual(ssdp.product_label("Linux UPnP/1.0 \x01\x02"), "")

    def test_cut_to_64(self) -> None:
        label = ssdp.product_label("Linux UPnP/1.0 " + "P" * 100)
        self.assertEqual(label, "P" * 64)


class FuzzTest(unittest.TestCase):
    def check(self, data: bytes) -> None:
        try:
            result = ssdp.parse_notify(data)
        except Exception as e:  # noqa: BLE001
            self.fail(f"raised {e!r} on {data.hex()}")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        if result[0] is not None:
            ssdp.product_label(result[0].server)
            ssdp.is_generic(result[0].server)

    def test_truncations(self) -> None:
        for i in range(len(fx.SONOS) + 1):
            self.check(fx.SONOS[:i])

    def test_random_bytes(self) -> None:
        rnd = random.Random(7)
        for _ in range(200):
            self.check(rnd.randbytes(rnd.randint(0, 600)))

    def test_one_byte_flips(self) -> None:
        rnd = random.Random(1900)
        sources = list(fx.SSDP_ALL.values())
        for _ in range(500):
            data = bytearray(rnd.choice(sources))
            data[rnd.randrange(len(data))] ^= 1 << rnd.randrange(8)
            self.check(bytes(data))

    def test_random_server_text(self) -> None:
        rnd = random.Random(1901)
        alphabet = "UPnP/1.0 ,\t\x00\x85/ab" + "".join(sorted(ssdp.GENERIC))
        for _ in range(300):
            server = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 80)))
            self.assertIsInstance(ssdp.product_label(server), str)
            self.assertIsInstance(ssdp.is_generic(server), bool)


class NoNetworkTest(unittest.TestCase):
    def test_module_has_no_network_code(self) -> None:
        with open(ssdp.__file__, encoding="utf-8") as f:
            source = f.read()
        for word in ("socket", "urllib", "http.client", "sendto", "sendmsg", "send(", "import http"):
            with self.subTest(word=word):
                self.assertNotIn(word, source)


if __name__ == "__main__":
    unittest.main()
