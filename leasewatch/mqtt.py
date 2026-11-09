"""Publish to (and read back from) an MQTT 3.1.1 broker over one TCP or TLS connection.

A deliberately small subset of OASIS MQTT 3.1.1, enough for a publisher: CONNECT (with an optional Will, user and
password), PUBLISH at QoS 0 and 1, SUBSCRIBE at QoS 0 and 1, PINGREQ and DISCONNECT. Not supported: QoS 2, DUP resends,
persistent sessions (every CONNECT asks for a clean session, so the broker keeps no state between connections and
nothing is resent after a reconnect). Any timeout or protocol error closes the connection; the caller reconnects.

The module only ever speaks to the broker the operator configured; TLS goes through the context the caller passes.
"""
from __future__ import annotations

import logging
import select
import socket
import ssl
import time
from collections.abc import Callable

log = logging.getLogger("leasewatch.mqtt")

CONNECT = 1
CONNACK = 2
PUBLISH = 3
PUBACK = 4
PUBREC = 5
PUBREL = 6
PUBCOMP = 7
SUBSCRIBE = 8
SUBACK = 9
UNSUBSCRIBE = 10
UNSUBACK = 11
PINGREQ = 12
PINGRESP = 13
DISCONNECT = 14

CONNACK_CODES = {
    0: "accepted",
    1: "bad protocol",
    2: "id rejected",
    3: "unavailable",
    4: "bad user or password",
    5: "not authorised",
}
SUBACK_FAILURE = 0x80
MAX_REMAINING = 268_435_455  # the largest Remaining Length four bytes can carry
# bytes of one incoming packet: the broker only sends back what was subscribed to (small status messages); a larger
# announced length is refused instead of buffering up to 256 MB
MAX_INCOMING = 1024 * 1024
# PUBLISHes kept for poll_incoming(): beyond either limit the oldest is dropped (Client.dropped_incoming counts them)
MAX_KEPT = 64
MAX_KEPT_BYTES = 1024 * 1024
_RECV_SIZE = 65536
_POLL_READS = 64  # recv calls per poll_incoming(): a busy subscription cannot keep the caller in there for ever
_TYPES_IN = {CONNACK, PUBLISH, PUBACK, SUBACK, UNSUBACK, PINGRESP}  # what a broker may send a client that never uses QoS 2
_BODY_LEN = {CONNACK: 2, PUBACK: 2, UNSUBACK: 2, PINGRESP: 0}  # fixed body sizes; SUBACK and PUBLISH vary


class MqttError(Exception):
    pass


def _encode_remaining_length(n: int) -> bytes:
    """7 bits per byte, least significant first; the high bit says another byte follows."""
    if not 0 <= n <= MAX_REMAINING:
        raise ValueError("mqtt: packet too large")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _decode_remaining_length(data: bytes | bytearray, pos: int) -> tuple[int, int] | None:
    """(value, bytes used) of the Remaining Length at data[pos:], or None when it has not fully arrived yet.

    A fourth byte with the continuation bit set would make a fifth: ValueError, the packet is malformed.
    """
    value = 0
    for i in range(4):
        if pos + i >= len(data):
            return None
        b = data[pos + i]
        value |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return value, i + 1
    raise ValueError("remaining length over 4 bytes")


def _string(text: str, what: str) -> bytes:
    raw = text.encode("utf-8")
    if len(raw) > 0xFFFF:
        raise ValueError(f"mqtt: {what} too long")
    return len(raw).to_bytes(2, "big") + raw


def _binary(data: bytes, what: str) -> bytes:
    if len(data) > 0xFFFF:
        raise ValueError(f"mqtt: {what} too long")
    return len(data).to_bytes(2, "big") + data


def _check_topic(topic: str, *, filter_: bool) -> None:
    """A topic name to publish to holds no wildcard; a filter may. Neither is empty or carries U+0000."""
    if not topic or "\0" in topic:
        raise ValueError("mqtt: bad topic")
    if not filter_ and ("+" in topic or "#" in topic):
        raise ValueError("mqtt: wildcard in a topic to publish to")


def _check_qos(qos: int) -> None:
    if qos not in (0, 1):
        raise ValueError("mqtt: only QoS 0 and 1 are supported")


def _packet(ptype: int, flags: int, body: bytes) -> bytes:
    return bytes([ptype << 4 | flags]) + _encode_remaining_length(len(body)) + body


def _parse_publish(flags: int, body: bytes) -> tuple[str, bytes, int, int]:
    """(topic, payload, qos, packet id) of an incoming PUBLISH; ValueError when it is malformed."""
    qos = flags >> 1 & 0x03
    if qos not in (0, 1):  # never granted: every subscription asks for at most QoS 1
        raise ValueError(f"PUBLISH with QoS {qos}")
    if len(body) < 2:
        raise ValueError("short PUBLISH")
    n = int.from_bytes(body[:2], "big")
    pos = 2 + n
    if len(body) < pos + (2 if qos else 0):
        raise ValueError("short PUBLISH")
    try:
        topic = body[2:pos].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("topic not UTF-8") from None
    pid = 0
    if qos:
        pid = int.from_bytes(body[pos:pos + 2], "big")
        if pid == 0:
            raise ValueError("PUBLISH with packet id 0")
        pos += 2
    return topic, bytes(body[pos:]), qos, pid


def _kept_size(topic: str, payload: bytes) -> int:
    """The bytes one kept PUBLISH counts toward MAX_KEPT_BYTES: its topic (UTF-8) and payload."""
    return len(topic.encode("utf-8")) + len(payload)


class Client:
    """One connection to one broker. Not thread-safe: the caller serialises calls."""

    def __init__(self, host: str, port: int, *, tls: ssl.SSLContext | None = None, client_id: str,
                 user: str = "", password: str = "", keepalive: int = 120,
                 will: tuple[str, bytes, int, bool] | None = None,
                 timeout: float = 5.0, clock: Callable[[], float] = time.monotonic) -> None:
        if password and not user:  # 3.1.1 forbids the password flag without the user flag
            raise ValueError("mqtt: password without user")
        if not 0 <= keepalive <= 0xFFFF:
            raise ValueError("mqtt: keepalive out of range")
        if will is not None:
            _check_topic(will[0], filter_=False)
            _check_qos(will[2])
        self.host = host
        self.port = port
        self.tls = tls
        self.client_id = client_id
        self.keepalive = keepalive
        self.will = will
        self.timeout = timeout
        self._user = user
        self._password = password
        self._clock = clock
        self._sock: socket.socket | None = None
        self._rbuf = bytearray()
        self._incoming: list[tuple[str, bytes]] = []
        self._incoming_bytes = 0  # topic and payload bytes in _incoming
        self.dropped_incoming = 0  # PUBLISHes dropped (oldest first) beyond MAX_KEPT / MAX_KEPT_BYTES
        self._pid = 0
        self._last_sent = 0.0

    @property
    def connected(self) -> bool:
        return self._sock is not None

    @property
    def last_sent(self) -> float:
        return self._last_sent

    # --- connection ----------------------------------------------------------
    def connect(self) -> None:
        self.close()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except TimeoutError as e:
            raise MqttError("mqtt: timeout connecting") from e
        except OSError as e:
            raise MqttError(f"mqtt: {e.strerror or type(e).__name__}") from e
        if self.tls is not None:
            try:
                sock = self.tls.wrap_socket(sock, server_hostname=self.host)
            except ssl.SSLCertVerificationError as e:
                sock.close()
                raise MqttError("mqtt: certificate verification failed") from e
            except TimeoutError as e:
                sock.close()
                raise MqttError("mqtt: timeout in the TLS handshake") from e
            except ssl.SSLError as e:
                sock.close()
                raise MqttError(f"mqtt: TLS error ({e.reason or type(e).__name__})") from e
            except OSError as e:
                sock.close()
                raise MqttError(f"mqtt: {e.strerror or type(e).__name__}") from e
        self._sock = sock
        self._send(_packet(CONNECT, 0, self._connect_body()))
        body = self._wait(CONNACK, "CONNACK", strict=True)
        code = body[1]
        if code != 0:
            self.close()
            raise MqttError(f"mqtt: refused ({code} {CONNACK_CODES.get(code, 'unknown')})")
        log.debug("mqtt: connected to %s:%d", self.host, self.port)

    def _connect_body(self) -> bytes:
        flags = 0x02  # clean session
        payload = _string(self.client_id, "client id")
        if self.will is not None:
            topic, message, qos, retain = self.will
            flags |= 0x04 | qos << 3 | (0x20 if retain else 0)
            payload += _string(topic, "will topic") + _binary(message, "will message")
        if self._user:
            flags |= 0x80
            payload += _string(self._user, "user")
        if self._password:
            flags |= 0x40
            payload += _binary(self._password.encode("utf-8"), "password")
        return _string("MQTT", "protocol") + bytes([4, flags]) + self.keepalive.to_bytes(2, "big") + payload

    def disconnect(self) -> None:
        """DISCONNECT tells the broker to discard the Will; then close. Never raises: the caller is going away."""
        sock = self._sock
        if sock is not None:
            try:
                sock.settimeout(self.timeout)
                sock.sendall(_packet(DISCONNECT, 0, b""))
            except OSError:
                pass
        self.close()

    def close(self) -> None:
        """Close without DISCONNECT, so the broker publishes the Will. Never raises."""
        sock, self._sock = self._sock, None
        self._rbuf.clear()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # --- operations ----------------------------------------------------------
    def publish(self, topic: str, payload: bytes | str, qos: int = 0, retain: bool = False) -> None:
        """Send one message; at QoS 1 wait for its PUBACK. A retained empty payload clears the retained message."""
        _check_topic(topic, filter_=False)
        _check_qos(qos)
        data = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        self._require()
        body = _string(topic, "topic")
        pid = 0
        if qos:
            pid = self._next_pid()
            body += pid.to_bytes(2, "big")
        self._send(_packet(PUBLISH, qos << 1 | (1 if retain else 0), body + data))
        if qos:
            self._wait(PUBACK, "PUBACK", pid=pid)

    def subscribe(self, topic: str, qos: int = 0) -> None:
        _check_topic(topic, filter_=True)
        _check_qos(qos)
        self._require()
        pid = self._next_pid()
        body = pid.to_bytes(2, "big") + _string(topic, "topic") + bytes([qos])
        self._send(_packet(SUBSCRIBE, 0b0010, body))
        code = self._wait(SUBACK, "SUBACK", pid=pid)[2]
        if code == SUBACK_FAILURE:
            raise MqttError("mqtt: subscription refused")

    def ping(self) -> None:
        self._require()
        self._send(_packet(PINGREQ, 0, b""))
        self._wait(PINGRESP, "PINGRESP")

    def poll_incoming(self) -> list[tuple[str, bytes]]:
        """The PUBLISHes received since the last call, (topic, payload), without blocking.

        Reads only what has already arrived; a packet still partly on the wire stays buffered for the next call.
        """
        sock = self._sock
        if sock is not None:
            sock.settimeout(0.0)
            try:
                for _ in range(_POLL_READS):
                    # TLS may hold decrypted bytes that select() cannot see
                    if not (isinstance(sock, ssl.SSLSocket) and sock.pending()):
                        if not select.select([sock], [], [], 0)[0]:
                            break
                    try:
                        data = sock.recv(_RECV_SIZE)
                    except (ssl.SSLWantReadError, BlockingIOError):
                        break  # only part of a TLS record so far
                    except OSError as e:
                        raise self._fail(self._os_reason(e)) from e
                    if not data:
                        raise self._fail("mqtt: connection closed")
                    self._rbuf += data
            finally:
                if self._sock is not None:
                    sock.settimeout(self.timeout)
            while (pkt := self._take_packet()) is not None:
                self._dispatch(*pkt)
        out, self._incoming, self._incoming_bytes = self._incoming, [], 0
        return out

    # --- internals -----------------------------------------------------------
    def _require(self) -> None:
        if self._sock is None:
            raise MqttError("mqtt: not connected")

    def _next_pid(self) -> int:
        """1..65535 and round again; 0 is not a valid packet id."""
        self._pid = self._pid % 0xFFFF + 1
        return self._pid

    def _fail(self, msg: str) -> MqttError:
        """Close (the connection is unusable after a timeout or a protocol error) and return the error to raise."""
        log.debug("%s", msg)
        self.close()
        return MqttError(msg)

    @staticmethod
    def _os_reason(e: OSError) -> str:
        if isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return "mqtt: connection closed"
        return f"mqtt: {e.strerror or type(e).__name__}"

    def _send(self, data: bytes) -> None:
        sock = self._sock
        assert sock is not None
        try:
            sock.settimeout(self.timeout)
            sock.sendall(data)
        except TimeoutError as e:
            raise self._fail("mqtt: timeout sending") from e
        except OSError as e:
            raise self._fail(self._os_reason(e)) from e
        self._last_sent = self._clock()

    def _recv(self, timeout: float, what: str) -> None:
        sock = self._sock
        assert sock is not None
        try:
            sock.settimeout(timeout)
            data = sock.recv(_RECV_SIZE)
        except TimeoutError as e:
            raise self._fail(f"mqtt: timeout waiting for {what}") from e
        except OSError as e:
            raise self._fail(self._os_reason(e)) from e
        if not data:
            raise self._fail("mqtt: connection closed")
        self._rbuf += data

    def _take_packet(self) -> tuple[int, int, bytes] | None:
        """(type, flags, body) of the first complete packet in the buffer, or None until all of it has arrived."""
        buf = self._rbuf
        if len(buf) < 2:
            return None
        try:
            got = _decode_remaining_length(buf, 1)
        except ValueError as e:
            raise self._fail(f"mqtt: bad packet ({e})") from None
        if got is None:
            return None
        length, used = got
        ptype, flags = buf[0] >> 4, buf[0] & 0x0F
        if ptype not in _TYPES_IN:
            raise self._fail(f"mqtt: bad packet (unexpected type {ptype})")
        if ptype != PUBLISH and flags:
            raise self._fail(f"mqtt: bad packet (flags {flags:#x} on type {ptype})")
        if length > MAX_INCOMING:
            raise self._fail("mqtt: bad packet (too large)")
        start = 1 + used
        if len(buf) < start + length:
            return None
        body = bytes(buf[start:start + length])
        del buf[:start + length]
        want = _BODY_LEN.get(ptype)
        if (want is not None and length != want) or (ptype == SUBACK and length < 3):
            raise self._fail(f"mqtt: bad packet (length {length} for type {ptype})")
        return ptype, flags, body

    def _wait(self, ptype: int, what: str, *, pid: int | None = None, strict: bool = False) -> bytes:
        """The body of the next `ptype` packet (with packet id `pid` when given), within `timeout` in total.

        Anything else that arrives meanwhile is handled as poll_incoming() would: PUBLISHes are kept for it. With
        `strict` the first packet must be the one waited for (CONNACK).
        """
        deadline = time.monotonic() + self.timeout
        while True:
            pkt = self._take_packet()
            if pkt is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise self._fail(f"mqtt: timeout waiting for {what}")
                self._recv(remaining, what)
                continue
            t, flags, body = pkt
            if t == ptype and (pid is None or int.from_bytes(body[:2], "big") == pid):
                if ptype == SUBACK and body[2] not in (0, 1, 2, SUBACK_FAILURE):
                    raise self._fail(f"mqtt: bad packet (SUBACK code {body[2]})")
                return body
            if strict:
                raise self._fail(f"mqtt: bad packet (expected {what}, got type {t})")
            self._dispatch(t, flags, body)

    def _dispatch(self, ptype: int, flags: int, body: bytes) -> None:
        if ptype == PUBLISH:
            try:
                topic, payload, qos, pid = _parse_publish(flags, body)
            except ValueError as e:
                raise self._fail(f"mqtt: bad packet ({e})") from None
            if qos:
                self._send(_packet(PUBACK, 0, pid.to_bytes(2, "big")))
            self._incoming.append((topic, payload))
            self._incoming_bytes += _kept_size(topic, payload)
            # a flood while the caller waits for an ack (or between two polls) must not grow the buffer without end
            while len(self._incoming) > MAX_KEPT or self._incoming_bytes > MAX_KEPT_BYTES:
                t, p = self._incoming.pop(0)
                self._incoming_bytes -= _kept_size(t, p)
                self.dropped_incoming += 1
        elif ptype == CONNACK:
            raise self._fail("mqtt: bad packet (unexpected CONNACK)")
        # PINGRESP, and a PUBACK/SUBACK/UNSUBACK nobody waits for: consumed
