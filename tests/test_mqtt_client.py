"""leasewatch.mqtt.Client against the fake broker in _mqttfake (loopback, port 0), and the Remaining Length codec.
Synthetic data only."""
from __future__ import annotations

import socket
import ssl
import tempfile
import time
import unittest

import _env  # noqa: F401  # the repo root on the path and the network guard, also when this module runs on its own
from _mqttfake import FakeBroker
from _smtpfake import make_cert, server_tls
from leasewatch.mqtt import (MAX_REMAINING, Client, MqttError, _decode_remaining_length,
                             _encode_remaining_length)
from leasewatch.notify import _tls_context

USER = "synthetic-operator"
PASSWORD = "synthetic-secret-value"
WILL = ("leasewatch/status", b"offline", 1, True)


class CodecTests(unittest.TestCase):
    CASES = [(0, b"\x00"), (127, b"\x7f"), (128, b"\x80\x01"), (16383, b"\xff\x7f"), (16384, b"\x80\x80\x01"),
             (2097151, b"\xff\xff\x7f"), (2097152, b"\x80\x80\x80\x01"), (268435455, b"\xff\xff\xff\x7f")]

    def test_round_trip(self) -> None:
        for n, raw in self.CASES:
            with self.subTest(n=n):
                self.assertEqual(_encode_remaining_length(n), raw)
                self.assertEqual(_decode_remaining_length(b"\x30" + raw + b"rest", 1), (n, len(raw)))

    def test_partial_is_none(self) -> None:
        for raw in (b"", b"\x80", b"\xff\xff", b"\xff\xff\xff"):
            with self.subTest(raw=raw):
                self.assertIsNone(_decode_remaining_length(b"\x30" + raw, 1))

    def test_five_bytes_refused(self) -> None:
        with self.assertRaises(ValueError):
            _decode_remaining_length(b"\x30\x80\x80\x80\x80\x01", 1)

    def test_too_large_refused(self) -> None:
        for n in (MAX_REMAINING + 1, -1):
            with self.subTest(n=n), self.assertRaises(ValueError):
                _encode_remaining_length(n)


class BrokerCase(unittest.TestCase):
    split = False  # the split-writes subclasses set this

    def broker(self, **kw: object) -> FakeBroker:
        kw.setdefault("split_writes", self.split)
        b = FakeBroker(**kw)
        self.addCleanup(b.close)
        return b

    def client(self, broker: FakeBroker, **kw: object) -> Client:
        kw.setdefault("client_id", "lw-test")
        kw.setdefault("timeout", 2.0)
        c = Client(broker.host, broker.port, **kw)
        self.addCleanup(c.close)
        return c

    def connected(self, **kw: object) -> tuple[FakeBroker, Client]:
        b = self.broker(**{k: kw.pop(k) for k in ("withhold_puback", "refuse_subscribe") if k in kw})
        c = self.client(b, **kw)
        c.connect()
        return b, c

    def err(self, fn, *args, **kw) -> str:
        with self.assertRaises(MqttError) as cm:
            fn(*args, **kw)
        return str(cm.exception)

    def poll_until(self, c: Client, timeout: float = 5.0) -> list[tuple[str, bytes]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            got = c.poll_incoming()
            if got:
                return got
            time.sleep(0.01)
        return []


class ConnectTests(BrokerCase):
    def test_connect_fields_seen_by_broker(self) -> None:
        b, c = self.connected(user=USER, password=PASSWORD, will=WILL, keepalive=45, client_id="lw-abc")
        self.assertTrue(c.connected)
        self.assertEqual(b.protocol, ("MQTT", 4))
        self.assertEqual(b.client_id, "lw-abc")
        self.assertEqual(b.user, USER)
        self.assertTrue(b.password_given)
        self.assertEqual(b.password, PASSWORD)
        self.assertEqual(b.will, WILL)
        self.assertEqual(b.keepalive, 45)
        self.assertTrue(b.clean_session)
        self.assertEqual(b.connections, 1)

    def test_connect_without_credentials_or_will(self) -> None:
        b, c = self.connected()
        self.assertIsNone(b.user)
        self.assertFalse(b.password_given)
        self.assertIsNone(b.will)

    def test_refusal_codes(self) -> None:
        texts = {1: "bad protocol", 2: "id rejected", 3: "unavailable", 4: "bad user or password", 5: "not authorised"}
        for code, text in texts.items():
            with self.subTest(code=code):
                b = self.broker(connack_code=code)
                c = self.client(b, user=USER, password=PASSWORD)
                msg = self.err(c.connect)
                self.assertEqual(msg, f"mqtt: refused ({code} {text})")
                self.assertNotIn(USER, msg)
                self.assertNotIn(PASSWORD, msg)
                self.assertFalse(c.connected)
                self.assertTrue(b.wait_gone())


class PublishTests(BrokerCase):
    def test_qos0_no_packet_id_retain_carried(self) -> None:
        b, c = self.connected()
        c.publish("lw/a", b"one")
        c.publish("lw/b", "two", retain=True)
        self.assertTrue(b.wait_published(2))
        self.assertEqual(b.published, [("lw/a", b"one", 0, False, None), ("lw/b", b"two", 0, True, None)])

    def test_qos1_puback_matched(self) -> None:
        b, c = self.connected()
        c.publish("lw/a", b"x", qos=1)
        c.publish("lw/a", b"y", qos=1)
        self.assertEqual([(p[2], p[4]) for p in b.published], [(1, 1), (1, 2)])
        self.assertTrue(c.connected)

    def test_withheld_puback_times_out(self) -> None:
        b, c = self.connected(withhold_puback=True, timeout=0.3)
        start = time.monotonic()
        self.assertEqual(self.err(c.publish, "lw/a", b"x", qos=1), "mqtt: timeout waiting for PUBACK")
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertFalse(c.connected)
        self.assertTrue(b.wait_gone())

    def test_retained_empty_payload(self) -> None:
        b, c = self.connected()
        c.publish("lw/a", b"", qos=1, retain=True)
        self.assertEqual(b.published, [("lw/a", b"", 1, True, 1)])

    def test_qos2_refused(self) -> None:
        b, c = self.connected()
        with self.assertRaises(ValueError):
            c.publish("lw/a", b"x", qos=2)
        self.assertTrue(c.connected)


class SubscribeTests(BrokerCase):
    def test_suback(self) -> None:
        b, c = self.connected()
        c.subscribe("lw/cmd/#", qos=1)
        self.assertEqual(b.subscriptions, [("lw/cmd/#", 1, 0b0010)])
        self.assertTrue(c.connected)

    def test_refused_stays_connected(self) -> None:
        b, c = self.connected(refuse_subscribe=True)
        self.assertEqual(self.err(c.subscribe, "lw/cmd/#"), "mqtt: subscription refused")
        self.assertTrue(c.connected)
        c.ping()  # the connection still works


class IncomingTests(BrokerCase):
    def test_inject_returned_once(self) -> None:
        b, c = self.connected()
        b.inject("lw/cmd", b"hello")
        self.assertEqual(self.poll_until(c), [("lw/cmd", b"hello")])
        self.assertEqual(c.poll_incoming(), [])

    def test_qos1_inject_acknowledged(self) -> None:
        b, c = self.connected()
        pid = b.inject("lw/cmd", b"hello", qos=1)
        self.assertEqual(self.poll_until(c), [("lw/cmd", b"hello")])
        self.assertTrue(b.wait_for(lambda: b.client_pubacks == [pid]))

    def test_publish_during_puback_wait_buffered(self) -> None:
        b, c = self.connected()
        pid = b.inject("lw/cmd", b"early", qos=1)  # queued before the PUBACK on the same stream
        time.sleep(0.1)
        c.publish("lw/a", b"x", qos=1)
        self.assertTrue(b.wait_for(lambda: b.client_pubacks == [pid]))
        self.assertEqual(c.poll_incoming(), [("lw/cmd", b"early")])

    def test_poll_without_connection(self) -> None:
        b = self.broker()
        c = self.client(b)
        self.assertEqual(c.poll_incoming(), [])


class PingTests(BrokerCase):
    def test_ping_and_last_sent(self) -> None:
        now = [100.0]
        b, c = self.connected(clock=lambda: now[0])
        self.assertEqual(c.last_sent, 100.0)
        now[0] = 250.0
        c.ping()
        self.assertEqual(b.pings, 1)
        self.assertEqual(c.last_sent, 250.0)


class DropTests(BrokerCase):
    def test_dropped_connection(self) -> None:
        b, c = self.connected()
        b.drop()
        self.assertEqual(self.err(c.publish, "lw/a", b"x"), "mqtt: connection closed")
        self.assertFalse(c.connected)
        self.assertEqual(self.err(c.publish, "lw/a", b"x"), "mqtt: not connected")

    def test_dropped_connection_seen_by_poll(self) -> None:
        b, c = self.connected()
        b.drop()
        self.assertEqual(self.err(c.poll_incoming), "mqtt: connection closed")
        self.assertFalse(c.connected)


class DisconnectTests(BrokerCase):
    def test_disconnect(self) -> None:
        b, c = self.connected()
        c.disconnect()
        self.assertFalse(c.connected)
        self.assertTrue(b.wait_gone())
        self.assertTrue(b.disconnected)
        c.disconnect()
        c.close()

    def test_close_sends_no_disconnect(self) -> None:
        b, c = self.connected(will=WILL)
        c.close()
        self.assertFalse(c.connected)
        self.assertTrue(b.wait_gone())
        self.assertFalse(b.disconnected)


class ConnectSplitTests(ConnectTests):
    split = True


class PublishSplitTests(PublishTests):
    split = True


class SubscribeSplitTests(SubscribeTests):
    split = True


class IncomingSplitTests(IncomingTests):
    split = True


class PingSplitTests(PingTests):
    split = True


class TlsTests(BrokerCase):
    """Real TLS on the wire, with a certificate made now (skipped without the openssl command)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pair = make_cert(cls.tmp.name)
        if not cls.pair:
            cls.tmp.cleanup()
            raise unittest.SkipTest("openssl not available")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_unverified_tls_connects(self) -> None:
        b = self.broker(tls=server_tls(*self.pair))
        c = self.client(b, tls=_tls_context(False), user=USER, password=PASSWORD)
        c.connect()
        c.publish("lw/a", b"x", qos=1)
        b.inject("lw/cmd", b"over tls")
        self.assertEqual(self.poll_until(c), [("lw/cmd", b"over tls")])
        self.assertEqual(b.password, PASSWORD)

    def test_self_signed_refused_by_verifying_context(self) -> None:
        b = self.broker(tls=server_tls(*self.pair))
        c = self.client(b, tls=_tls_context(True))
        self.assertEqual(self.err(c.connect), "mqtt: certificate verification failed")
        self.assertFalse(c.connected)
        self.assertTrue(b.wait_for(lambda: b.connections == 0 and not b.active))
        self.assertIsNone(b.client_id)

    def test_trusted_cert_verifies(self) -> None:
        b = self.broker(tls=server_tls(*self.pair))
        ctx = ssl.create_default_context(cafile=self.pair[0])
        c = self.client(b, tls=ctx)
        c.connect()
        self.assertTrue(c.connected)


def _ipv6_loopback() -> bool:
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


@unittest.skipUnless(_ipv6_loopback(), "no IPv6 loopback")
class Ipv6Tests(BrokerCase):
    def test_connect_over_ipv6(self) -> None:
        b = self.broker(host="::1")
        c = self.client(b)
        c.connect()
        c.publish("lw/a", b"v6", qos=1)
        self.assertEqual(b.published[0][:2], ("lw/a", b"v6"))


if __name__ == "__main__":
    unittest.main()
