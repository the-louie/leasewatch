"""Network guard for the test suite: a test that tries to reach a non-loopback address fails.

Tests must never talk to a real firewall, controller, switch or Mailgun. A stale mock (one that patches a name the
code no longer calls) used to let a test send a real request without failing, because the client wrapped the
connection error into its own exception. The guard closes that hole twice:

- socket.socket.connect / connect_ex, socket.create_connection and socket.getaddrinfo raise NetworkBlocked for any
  host that is not loopback (127.0.0.0/8, ::1, "localhost"), not the unspecified address (this host) and not a unix
  socket. NetworkBlocked is an OSError, so the code under test takes its normal failure path.
- every blocked attempt is recorded, and a cleanup that every TestCase gets fails the test that made it, even when
  the code under test swallowed the error.

install() is called by tests/test_netguard.py at import (unittest discover imports every test module before it runs
any test, so the whole suite is guarded) and by _env.py (a single module run on its own). Child processes are not
guarded; child_argv() starts a guarded `unittest discover` for the contrib package suites.
"""
from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import sys
import threading
import unittest
from collections.abc import Iterator

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


class NetworkBlocked(OSError):
    """A test tried to reach a non-loopback address."""


# process globals, written only by the patched functions below and by expect_blocked()
_violations: list[str] = []
_lock = threading.Lock()
_orig: dict[str, object] = {}


def host_allowed(host: object) -> bool:
    """True for loopback, "localhost", the unspecified address and None/"" (a passive lookup or bind to any)."""
    if host is None:
        return True
    if isinstance(host, (bytes, bytearray)):
        host = bytes(host).decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    host = host.strip().lower().rstrip(".")
    if host in ("", "localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False  # any other name: resolving it already reaches a DNS server
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def _block(what: str, host: object, port: object = None) -> None:
    where = f"{host!r}" + (f" port {port}" if port not in (None, 0) else "")
    msg = (f"network guard: a test tried to {what} {where}. Tests must not reach the network: "
           f"fake or stub the client (only loopback is allowed)")
    with _lock:
        _violations.append(msg)
    raise NetworkBlocked(msg)


def _check_address(sock: socket.socket, address: object, what: str) -> None:
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return  # unix sockets (and netlink etc.) never leave the host
    if isinstance(address, tuple) and address:
        if not host_allowed(address[0]):
            _block(what, address[0], address[1] if len(address) > 1 else None)
    else:
        _block(what, address)


def _connect(self: socket.socket, address: object) -> None:
    _check_address(self, address, "connect to")
    return _orig["connect"](self, address)  # type: ignore[operator]


def _connect_ex(self: socket.socket, address: object) -> int:
    _check_address(self, address, "connect to")
    return _orig["connect_ex"](self, address)  # type: ignore[operator]


def _create_connection(address: tuple, *args: object, **kwargs: object) -> socket.socket:
    if not host_allowed(address[0]):
        _block("connect to", address[0], address[1])
    return _orig["create_connection"](address, *args, **kwargs)  # type: ignore[operator]


def _getaddrinfo(host: object, *args: object, **kwargs: object) -> list:
    if not host_allowed(host):
        _block("resolve", host, args[0] if args else kwargs.get("port"))
    return _orig["getaddrinfo"](host, *args, **kwargs)  # type: ignore[operator]


def _run(self: unittest.TestCase, result: unittest.TestResult | None = None) -> unittest.TestResult | None:
    with _lock:
        start = len(_violations)

    def check() -> None:
        with _lock:
            new = _violations[start:]
        if new:
            raise self.failureException("\n".join(dict.fromkeys(new)))

    # registered first, so it runs last: after tearDown and the test's own cleanups (servers stopped, threads joined)
    self.addCleanup(check)
    return _orig["run"](self, result)  # type: ignore[operator]


def install() -> None:
    """Patch socket and unittest for this process. Idempotent; never undone (the guard is meant to stay on)."""
    if _orig:
        return
    _orig.update(connect=socket.socket.connect, connect_ex=socket.socket.connect_ex,
                 create_connection=socket.create_connection, getaddrinfo=socket.getaddrinfo,
                 run=unittest.TestCase.run)
    # process-wide patches: socket.socket is the Python class every socket (ssl.SSLSocket too) derives from, and
    # create_connection looks getaddrinfo up in the socket module at call time
    socket.socket.connect = _connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _connect_ex  # type: ignore[method-assign]
    socket.create_connection = _create_connection  # type: ignore[assignment]
    socket.getaddrinfo = _getaddrinfo  # type: ignore[assignment]
    unittest.TestCase.run = _run  # type: ignore[method-assign]


def installed() -> bool:
    return socket.socket.connect is _connect and socket.getaddrinfo is _getaddrinfo


@contextlib.contextmanager
def expect_blocked() -> Iterator[list[str]]:
    """For the guard's own tests: the attempts made inside the block are returned and do not fail the test."""
    with _lock:
        start = len(_violations)
    caught: list[str] = []
    try:
        yield caught
    finally:
        with _lock:
            caught.extend(_violations[start:])
            del _violations[start:]


def child_argv(*unittest_args: str) -> list[str]:
    """argv for a child `python -m unittest <args>` that installs the guard first (for the contrib suites)."""
    code = ("import sys, unittest; sys.path.insert(0, %r); import _netguard; _netguard.install(); sys.path.remove(%r); "
            "unittest.main(module=None, argv=['python -m unittest', *sys.argv[1:]])") % (TESTS_DIR, TESTS_DIR)
    return [sys.executable, "-W", "error::ResourceWarning", "-c", code, *unittest_args]
