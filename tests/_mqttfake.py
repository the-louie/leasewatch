"""A small MQTT 3.1.1 broker for the tests: a test double for one client at a time, on loopback port 0.

It records what the client sent (CONNECT fields, PUBLISHes, SUBSCRIBEs, PINGREQs, DISCONNECT) and answers with
scripted replies. Optional TLS with a certificate made at test time (see _smtpfake.make_cert). The packet codec here is
written separately from leasewatch.mqtt on purpose, so a codec bug in the client is not hidden by sharing it.

Only the handler thread touches the client socket (TLS objects are not safe for a read and a write from two threads):
inject() and drop() leave a request that the handler picks up within its short read timeout.
"""
from __future__ import annotations

import socket
import socketserver
import ssl
import struct
import threading
import time
from collections.abc import Callable

_TICK = 0.02  # handler read timeout: how soon an inject(), a drop() or close() is seen


def _remaining(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _packet(ptype: int, flags: int, body: bytes) -> bytes:
    return bytes([ptype << 4 | flags]) + _remaining(len(body)) + body


def _take(buf: bytearray) -> tuple[int, int, bytes] | None:
    """(type, flags, body) of the first complete packet in buf (removed from it), or None until it has arrived."""
    value = 0
    for i in range(4):
        if 1 + i >= len(buf):
            return None
        value |= (buf[1 + i] & 0x7F) << (7 * i)
        if not buf[1 + i] & 0x80:
            start = 2 + i
            break
    else:
        raise ValueError("remaining length over 4 bytes")
    if len(buf) < start + value:
        return None
    first, body = buf[0], bytes(buf[start:start + value])
    del buf[:start + value]
    return first >> 4, first & 0x0F, body


def _field(body: bytes, pos: int) -> tuple[bytes, int]:
    n = struct.unpack_from(">H", body, pos)[0]
    return body[pos + 2:pos + 2 + n], pos + 2 + n


class _Handler(socketserver.BaseRequestHandler):
    server: FakeBroker

    def handle(self) -> None:
        srv, sock = self.server, self.request
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            if srv.tls is not None:
                sock.settimeout(5)
                sock = srv.tls.wrap_socket(sock, server_side=True)
            srv._set(active=True, connections=srv.connections + 1)
            self.session(sock)
        except (OSError, ValueError, struct.error):
            pass  # the client gave up (e.g. it refused the certificate) or sent garbage
        finally:
            sock.close()  # also the TLS socket: the server would only close the plain one it accepted
            srv._set(active=False, _drop=False)

    def send(self, sock: socket.socket, data: bytes) -> None:
        if self.server.split_writes and len(data) > 1:
            sock.sendall(data[:1])
            time.sleep(0.05)
            data = data[1:]
        sock.sendall(data)

    def session(self, sock: socket.socket) -> None:
        srv, buf = self.server, bytearray()
        sock.settimeout(_TICK)
        while not srv._stopping:
            with srv._cond:
                out, srv._outbox = srv._outbox, []
                drop = srv._drop
            for data in out:
                self.send(sock, data)
            if drop:  # RST instead of FIN: the client's next send or recv fails at once
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                return
            pkt = _take(buf)
            if pkt is not None:
                if not self.packet(sock, *pkt):
                    return
                continue
            try:
                data = sock.recv(65536)
            except (TimeoutError, ssl.SSLWantReadError):
                continue
            if not data:
                return
            buf += data

    def packet(self, sock: socket.socket, ptype: int, flags: int, body: bytes) -> bool:
        """Record and answer one packet; False ends the session."""
        srv = self.server
        if ptype == 1:  # CONNECT
            proto, pos = _field(body, 0)
            level, cflags, keepalive = body[pos], body[pos + 1], struct.unpack_from(">H", body, pos + 2)[0]
            cid, pos = _field(body, pos + 4)
            will = user = password = None
            if cflags & 0x04:
                topic, pos = _field(body, pos)
                msg, pos = _field(body, pos)
                will = (topic.decode(), msg, cflags >> 3 & 0x03, bool(cflags & 0x20))
            if cflags & 0x80:
                raw, pos = _field(body, pos)
                user = raw.decode()
            if cflags & 0x40:
                raw, pos = _field(body, pos)
                password = raw.decode()
            srv._set(protocol=(proto.decode(), level),client_id=cid.decode(), user=user,
                     password=password, password_given=password is not None, will=will, keepalive=keepalive,
                     clean_session=bool(cflags & 0x02))
            self.send(sock, _packet(2, 0, bytes([0, srv.connack_code])))
        elif ptype == 3:  # PUBLISH
            qos, retain = flags >> 1 & 0x03, bool(flags & 0x01)
            topic, pos = _field(body, 0)
            pid = None
            if qos:
                pid, pos = struct.unpack_from(">H", body, pos)[0], pos + 2
            with srv._cond:
                srv.published.append((topic.decode(), body[pos:], qos, retain, pid))
                srv._cond.notify_all()
            if qos == 1 and not srv.withhold_puback:
                self.send(sock, _packet(4, 0, struct.pack(">H", pid)))
        elif ptype == 4:  # PUBACK for an inject()ed QoS 1 message
            with srv._cond:
                srv.client_pubacks.append(struct.unpack(">H", body)[0])
                srv._cond.notify_all()
        elif ptype == 8:  # SUBSCRIBE
            pid, pos, codes = struct.unpack_from(">H", body)[0], 2, bytearray()
            while pos < len(body):
                topic, pos = _field(body, pos)
                qos, pos = body[pos], pos + 1
                with srv._cond:
                    srv.subscriptions.append((topic.decode(), qos, flags))
                    srv._cond.notify_all()
                codes.append(0x80 if srv.refuse_subscribe else qos)
            self.send(sock, _packet(9, 0, struct.pack(">H", pid) + bytes(codes)))
        elif ptype == 12:  # PINGREQ
            srv._set(pings=srv.pings + 1)
            self.send(sock, _packet(13, 0, b""))
        elif ptype == 14:  # DISCONNECT
            srv._set(disconnected=True)
            return False
        else:
            srv._set(unexpected=srv.unexpected + [(ptype, flags, body)])
        return True


class FakeBroker(socketserver.ThreadingTCPServer):
    """Scripted replies: connack_code, withhold_puback, refuse_subscribe, split_writes (set before the client acts).

    Recorded: connections, active, the last CONNECT (protocol, client_id, user, password, password_given, will,
    keepalive, clean_session), published [(topic, payload, qos, retain, packet id)], subscriptions [(filter, qos,
    fixed-header flags)], client_pubacks [packet id], pings, disconnected, unexpected [(type, flags, body)].
    """
    allow_reuse_address = True
    daemon_threads = False  # server_close() joins the handler threads, so no socket outlives a test

    def __init__(self, host: str = "127.0.0.1", tls: ssl.SSLContext | None = None, *, connack_code: int = 0,
                 withhold_puback: bool = False, refuse_subscribe: bool = False, split_writes: bool = False) -> None:
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.tls, self.connack_code, self.split_writes = tls, connack_code, split_writes
        self.withhold_puback, self.refuse_subscribe = withhold_puback, refuse_subscribe
        self._cond = threading.Condition()
        self._outbox: list[bytes] = []
        self._drop = self._stopping = False
        self._pid = 0
        self.connections, self.active, self.pings, self.disconnected = 0, False, 0, False
        self.protocol = self.client_id = self.user = self.password = self.will = self.keepalive = None
        self.password_given = self.clean_session = None
        self.published: list[tuple[str, bytes, int, bool, int | None]] = []
        self.subscriptions: list[tuple[str, int, int]] = []
        self.client_pubacks: list[int] = []
        self.unexpected: list[tuple[int, int, bytes]] = []
        super().__init__((host, 0), _Handler)
        self.host, self.port = host, self.server_address[1]
        self._t = threading.Thread(target=self.serve_forever, args=(_TICK,), daemon=True)  # a quick shutdown()
        self._t.start()

    def _set(self, **kw: object) -> None:
        with self._cond:
            for k, v in kw.items():
                setattr(self, k, v)
            self._cond.notify_all()

    def wait_for(self, pred: Callable[[], bool], timeout: float = 5.0) -> bool:
        with self._cond:
            return self._cond.wait_for(pred, timeout)

    def wait_published(self, n: int, timeout: float = 5.0) -> bool:
        return self.wait_for(lambda: len(self.published) >= n, timeout)

    def wait_gone(self, timeout: float = 5.0) -> bool:
        """True once no client connection is open (the client closed it, or drop() did)."""
        return self.wait_for(lambda: not self.active, timeout)

    def inject(self, topic: str, payload: bytes, qos: int = 0, retain: bool = False) -> int | None:
        """Send a PUBLISH to the connected client; its packet id at QoS 1 (its PUBACK lands in client_pubacks)."""
        if not self.wait_for(lambda: self.active):
            raise AssertionError("inject: no client connected")
        body = struct.pack(">H", len(topic.encode())) + topic.encode()
        pid = None
        with self._cond:
            if qos:
                self._pid = self._pid % 0xFFFF + 1
                pid = self._pid
                body += struct.pack(">H", pid)
            self._outbox.append(_packet(3, qos << 1 | int(retain), body + payload))
        return pid

    def drop(self) -> None:
        """Reset the client connection (RST, no DISCONNECT), and wait until it is gone."""
        self._set(_drop=True)
        if not self.wait_gone():
            raise AssertionError("drop: the connection did not close")

    def close(self) -> None:
        self._set(_stopping=True)
        self.shutdown()
        self.server_close()
        self._t.join(5)
