"""Tests for the dnsmasq_leases connector: the pure parser, the bounded file read, settings and the Batch shape."""
from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # the package directory, when not started from it

from leasewatch.connectors import API_VERSION, Batch, ConnectorError, HostContext, Sighting  # noqa: E402
from leasewatch_dnsmasq import connector as dc  # noqa: E402
from leasewatch_dnsmasq.connector import DnsmasqLeasesConnector, parse_leases  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")
NOW = 1_800_000_000


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def text(name: str) -> str:
    with open(fixture(name), encoding="utf-8") as f:
        return f.read()


def make(path: str, network: str = "") -> DnsmasqLeasesConnector:
    settings = {"path": path}
    if network:
        settings["network"] = network
    return DnsmasqLeasesConnector("dhcp1", settings, HostContext(now=lambda: NOW))


class ParseTest(unittest.TestCase):
    def test_v4_lines(self) -> None:
        sightings, dropped = parse_leases(text("v4.leases"), NOW, "LAN")
        self.assertEqual(dropped, 0)
        self.assertEqual(sightings[0], Sighting(mac="02:00:00:00:00:01", source="", kind="dhcp", presence=False,
                                                observed_at=NOW, ip="10.0.0.10", hostname="alex-ipad", network="LAN",
                                                lease_type="dynamic", client_id="01:02:00:00:00:00:01"))
        self.assertEqual(len(sightings), 2)

    def test_star_fields_are_empty(self) -> None:
        s = parse_leases(text("v4.leases"), NOW)[0][1]
        self.assertEqual((s.hostname, s.client_id, s.network), ("", "", ""))

    def test_mixed_file(self) -> None:
        sightings, dropped = parse_leases(text("mixed.leases"), NOW)
        self.assertEqual([s.ip for s in sightings], ["10.0.0.10", "10.0.0.12"])
        # 20- (InfiniBand, no bytes), 06-... (token ring), a 3-part address, a garbage line, a short line
        self.assertEqual(dropped, 5)

    def test_duid_ipv6_and_extra_lines_skipped_uncounted(self) -> None:
        t = ("duid 00:01:00:01:aa:bb:cc:dd:02:00:00:00:00:01\n"
             "1900000000 12345 fd00::10 alex-ipad 00:01\n1900000000 T678 fd00::11 * *\n"
             "vendorclass 10.0.0.10 01:02\nagent-info 10.0.0.10 01:02\n\n   \n")
        self.assertEqual(parse_leases(t, NOW), ([], 0))

    def test_non_ethernet_hwaddr_dropped(self) -> None:
        t = "1900000000 20- 10.0.0.14 ib * \n1900000000 06-02:00:00:00:00:05 10.0.0.15 tr *\n"
        self.assertEqual(parse_leases(t, NOW), ([], 2))

    def test_expired_lease_skipped(self) -> None:
        self.assertEqual(parse_leases(f"{NOW - 1} 02:00:00:00:00:04 10.0.0.13 old *\n", NOW), ([], 0))
        self.assertEqual(parse_leases(f"{NOW} 02:00:00:00:00:04 10.0.0.13 old *\n", NOW), ([], 0))  # dnsmasq: >= 0
        self.assertEqual(len(parse_leases(f"{NOW + 1} 02:00:00:00:00:04 10.0.0.13 old *\n", NOW)[0]), 1)

    def test_expiry_zero_is_infinite_and_kept(self) -> None:
        (s,), dropped = parse_leases("0 02:00:00:00:00:03 10.0.0.12 printer *\n", NOW)
        self.assertEqual((s.ip, s.lease_type, dropped), ("10.0.0.12", "dynamic", 0))

    def test_malformed_lines_dropped_never_raise(self) -> None:
        bad = ["garbage", "1900000000 02:00:00:00:00:07", "1900000000 02:00:00:00:00:06 10.0.0 x *",
               "1900000000 02:00:00:00:00:06 010.0.0.1 x *", "-5 02:00:00:00:00:06 10.0.0.1 x *",
               "١٢ 02:00:00:00:00:06 10.0.0.1 x *", "9" * 5000 + " 02:00:00:00:00:06 10.0.0.1 x *",
               "1900000000 02:00:00:00:00:06 10.0.0.256 x *"]
        self.assertEqual(parse_leases("\n".join(bad), NOW), ([], len(bad)))

    def test_crlf_and_extra_fields(self) -> None:
        sightings, dropped = parse_leases("1900000000 02:00:00:00:00:01 10.0.0.10 a * extra\r\n", NOW)
        self.assertEqual((len(sightings), sightings[0].client_id, dropped), (1, "", 0))


class FileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def assert_problem(self, conn: DnsmasqLeasesConnector, problem: str) -> None:
        for call in (conn.check, conn.collect):
            with self.assertRaises(ConnectorError) as cm:
                call()
            self.assertEqual(str(cm.exception), f"PATH: {problem}")
            self.assertNotIn(self.dir, str(cm.exception))

    def test_collect_reads_file(self) -> None:
        conn = make(fixture("mixed.leases"), "LAN")
        conn.check()
        b = conn.collect()
        self.assertEqual(b.stats, {"leases": 2, "dropped": 5})
        self.assertEqual({s.network for s in b.sightings}, {"LAN"})
        self.assertEqual({s.observed_at for s in b.sightings}, {NOW})

    def test_missing_file(self) -> None:
        self.assert_problem(make(os.path.join(self.dir, "nope.leases")), "not found")

    def test_directory(self) -> None:
        self.assert_problem(make(self.dir), "not a regular file")

    def test_fifo_does_not_block(self) -> None:
        path = os.path.join(self.dir, "fifo")
        os.mkfifo(path)
        self.assert_problem(make(path), "not a regular file")

    def test_unix_socket(self) -> None:
        path = os.path.join(self.dir, "sock")
        with socket.socket(socket.AF_UNIX) as s:
            s.bind(path)
            self.assert_problem(make(path), "not a regular file")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads any file")
    def test_permission_denied(self) -> None:
        path = os.path.join(self.dir, "locked.leases")
        shutil.copy(fixture("v4.leases"), path)
        os.chmod(path, 0)
        self.assert_problem(make(path), "permission denied")

    def test_oversize_file(self) -> None:
        path = os.path.join(self.dir, "big.leases")
        with open(path, "wb") as f:
            f.truncate(dc.MAX_FILE_BYTES + 1)
        self.assert_problem(make(path), "larger than 4096 KiB")

    def test_file_at_the_cap_is_read(self) -> None:
        path = os.path.join(self.dir, "full.leases")
        line = b"1900000000 02:00:00:00:00:01 10.0.0.10 a *\n"
        with open(path, "wb") as f:
            f.write(line + b" " * (dc.MAX_FILE_BYTES - len(line)))
        self.assertEqual(make(path).collect().stats, {"leases": 1, "dropped": 0})

    def test_bad_bytes_do_not_fail(self) -> None:
        path = os.path.join(self.dir, "bytes.leases")
        with open(path, "wb") as f:
            f.write(b"1900000000 02:00:00:00:00:01 10.0.0.10 caf\xe9 *\n\xff\xfe\n")
        self.assertEqual(make(path).collect().stats, {"leases": 1, "dropped": 1})


class SettingsTest(unittest.TestCase):
    def test_describe(self) -> None:
        info = DnsmasqLeasesConnector.describe()
        self.assertEqual((info.type, info.api_version, info.produces), ("dnsmasq_leases", API_VERSION,
                                                                        frozenset({"sighting"})))
        self.assertEqual([s.key for s in info.settings], ["path", "network"])

    def test_path_required(self) -> None:
        self.assertEqual(DnsmasqLeasesConnector("dhcp1", {}).validate(),
                         ["connector dhcp1 (dnsmasq_leases): PATH is required"])

    def test_path_must_be_absolute(self) -> None:
        for path in ("dnsmasq.leases", "./x", "/var/lib/misc/\x00x"):
            self.assertEqual(make(path).validate(), ["path must be an absolute path"])
        self.assertEqual(make("/var/lib/misc/dnsmasq.leases").validate(), [])

    def test_no_io_before_check(self) -> None:
        conn = make("/nonexistent/dnsmasq.leases")  # constructing and validating must not touch the file
        self.assertEqual(conn.validate(), [])
        conn.close()

    def test_batch_type(self) -> None:
        self.assertIsInstance(make(fixture("v4.leases")).collect(), Batch)


if __name__ == "__main__":
    unittest.main()
