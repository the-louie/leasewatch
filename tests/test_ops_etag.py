"""ETag / 304 on /api/devices and /api/events: a weak tag from the start id, the database version, three bits and the query hash."""
from __future__ import annotations

import gzip
import json
import os
import re
import sys
import time
import unittest
from unittest import mock

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_web_edge_cases as QW  # noqa: E402
from leasewatch import web  # noqa: E402
from leasewatch.collector import Collector  # noqa: E402
from leasewatch.fw1 import Sighting  # noqa: E402

TAG = re.compile(r'^W/"[0-9a-f]{8}\.\d+\.[01][01][01]\.[0-9a-f]{1,8}"$')


class _Client:
    def __init__(self, sightings: list) -> None:
        self.data = sightings

    def arp_raw(self) -> list:
        return []

    def sightings(self, ignore: tuple = ()) -> tuple:
        return list(self.data), {"leases": len(self.data), "arp": 0}


class EtagTests(QW.Base):
    def setUp(self) -> None:
        super().setUp()
        self.db.set_meta("last_poll_ts", str(int(time.time())))  # fresh data: meta.stale is false
        self.add_device(hostname="laptop")

    def get(self, path: str = "/api/devices", inm: str | None = None, enc: str | None = None,
            command: str = "GET", H: type | None = None, client: str = "127.0.0.1") -> tuple[int, dict, bytes]:
        hdr = b"Host: 127.0.0.1\r\n"
        if inm is not None:
            hdr += b"If-None-Match: " + inm.encode() + b"\r\n"
        if enc is not None:
            hdr += b"Accept-Encoding: " + enc.encode() + b"\r\n"
        h = self.handler(command=command, path=path, headers=hdr)
        h.client_address = (client, 40000)
        if H is not None:
            h.__class__ = H
        h.do_GET()
        head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        return int(lines[0].split()[1]), {k.lower(): v for k, _, v in (ln.partition(": ") for ln in lines[1:])}, body

    def test_200_has_weak_etag(self) -> None:
        for path in ("/api/devices", "/api/events"):
            st, h, body = self.get(path)
            self.assertEqual(st, 200, path)
            self.assertRegex(h["etag"], TAG)
            self.assertTrue(h["etag"].endswith('.100.0"'), h["etag"])  # may write, not stale
            json.loads(body)

    def test_same_tag_gives_exact_304(self) -> None:
        for path in ("/api/devices", "/api/events"):
            _, h200, _ = self.get(path)
            st, h, body = self.get(path, h200["etag"])
            self.assertEqual(st, 304, path)
            self.assertEqual(body, b"")
            self.assertEqual(set(h), {"server", "date", "etag", "vary", *(k.lower() for k in web._SECURITY_HEADERS)}, path)
            self.assertEqual(h["etag"], h200["etag"])
            self.assertEqual(h["vary"], "Accept-Encoding")
            self.assertEqual(h["cache-control"], "no-store")
            self.assertEqual(h["content-security-policy"], web.CSP)

    def test_list_strong_form_and_star(self) -> None:
        _, h, _ = self.get()
        tag = h["etag"]
        for inm in (f'"x", {tag}', tag[2:], f'W/"a,b", {tag[2:]}', "*", '"x", *'):
            self.assertEqual(self.get(inm=inm)[0], 304, inm)
        for inm in ('"x"', 'W/"x"', "", tag[:-2] + '"'):
            self.assertEqual(self.get(inm=inm)[0], 200, inm)

    def test_user_write_changes_tag(self) -> None:
        _, h, _ = self.get()
        self.db.update_user_fields(QW.MAC, True, "renamed", None)
        st, h2, body = self.get(inm=h["etag"])
        self.assertEqual(st, 200)
        self.assertNotEqual(h2["etag"], h["etag"])
        self.assertEqual(json.loads(body)["devices"][0]["name"], "renamed")
        self.assertEqual(self.get(inm=h2["etag"])[0], 304)

    def test_poll_changes_tag(self) -> None:
        tags = {p: self.get(p)[1]["etag"] for p in ("/api/devices", "/api/events")}
        s = Sighting(mac="02:00:00:00:00:09", ip="10.0.1.9", hostname="phone", vendor="Acme", vlan="lan", iface="lan",
                     source="dhcp", lease_type="dynamic", online=True)
        Collector(self.cfg, self.db, _Client([s])).run_once()
        for p, tag in tags.items():
            st, h, _ = self.get(p, tag)
            self.assertEqual(st, 200, p)
            self.assertNotEqual(h["etag"], tag, p)

    def test_stale_flip_changes_tag(self) -> None:
        _, h, _ = self.get()
        # no write: only time passes, so the last poll gets old and meta.stale flips
        later = time.time() + self.cfg.poll_seconds * 10
        with mock.patch.object(web.time, "time", return_value=later):
            st, h2, body = self.get(inm=h["etag"])
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["meta"]["stale"])
        self.assertEqual((h["etag"][-6:], h2["etag"][-6:]), ('100.0"', '111.0"'))
        self.assertEqual(h2["etag"][:-6], h["etag"][:-6])

    def test_collector_stale_flip_changes_tag(self) -> None:
        self.db.set_meta("last_attempt_ts", str(int(time.time())))
        _, h, _ = self.get()
        self.assertTrue(h["etag"].endswith('.100.0"'), h["etag"])
        self.db.set_meta("last_attempt_ts", "1")  # far back, no other change to the tag's inputs
        st, h2, body = self.get(inm=h["etag"])
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["meta"]["collector_stale"])
        self.assertTrue(h2["etag"].endswith('.101.0"') or h2["etag"].endswith('.111.0"'), h2["etag"])

    def test_write_between_version_and_body_gives_200_next(self) -> None:
        _, h0, _ = self.get()
        orig = self.db.devices

        def devices() -> list:
            self.db.set_meta("late", "1")  # a write after the version was read
            return orig()

        with mock.patch.object(self.db, "devices", devices):
            st, h1, _ = self.get()
        self.assertEqual(st, 200)
        self.assertEqual(h1["etag"], h0["etag"])  # the tag is the older version
        st, h2, _ = self.get(inm=h1["etag"])
        self.assertEqual(st, 200)
        self.assertNotEqual(h2["etag"], h1["etag"])

    def test_304_never_reads_the_devices(self) -> None:
        _, h, _ = self.get()
        with mock.patch.object(self.db, "devices", wraps=self.db.devices) as dev, \
                mock.patch.object(self.db, "events", wraps=self.db.events) as ev:
            self.assertEqual(self.get(inm=h["etag"])[0], 304)
            _, he, _ = self.get("/api/events")
            self.assertEqual(self.get("/api/events", he["etag"])[0], 304)
        self.assertEqual(dev.call_count, 0)
        self.assertEqual(ev.call_count, 1)  # only the 200 above

    def test_failed_poll_and_set_meta_change_tag(self) -> None:
        _, h, _ = self.get()
        Collector(self.cfg, self.db, _Client([]))._fail("fw1 down")
        st, h2, _ = self.get(inm=h["etag"])
        self.assertEqual(st, 200)
        self.assertNotEqual(h2["etag"], h["etag"])
        self.db.set_meta("anything", "x")
        st, h3, _ = self.get(inm=h2["etag"])
        self.assertEqual(st, 200)
        self.assertNotEqual(h3["etag"], h2["etag"])

    def test_gzip_and_identity_share_tag(self) -> None:
        self.db._conn.executemany("INSERT INTO devices(mac,first_seen,last_seen) VALUES(?,1,1)",
                                  [(f"02:00:00:01:{i >> 8:02x}:{i & 255:02x}",) for i in range(500)])
        st, gz, gbody = self.get(enc="gzip")
        _, plain, _ = self.get()
        self.assertEqual((st, gz["content-encoding"]), (200, "gzip"))
        self.assertEqual(len(json.loads(gzip.decompress(gbody))["devices"]), 501)
        self.assertEqual(gz["etag"], plain["etag"])
        st, h, body = self.get(inm=gz["etag"], enc="gzip")
        self.assertEqual((st, body), (304, b""))
        self.assertNotIn("content-encoding", h)
        self.assertNotIn("content-length", h)
        self.assertNotIn("content-type", h)

    def test_head_gets_tag(self) -> None:
        _, g, _ = self.get()
        st, h, body = self.get(command="HEAD")
        self.assertEqual((st, body, h["etag"]), (200, b"", g["etag"]))
        st, h, body = self.get(inm=g["etag"], command="HEAD")
        self.assertEqual((st, body, h["etag"]), (304, b"", g["etag"]))

    def test_new_start_never_matches_old_tag(self) -> None:
        _, h, _ = self.get()
        H2 = web.make_handler(self.cfg, self.db, "9.9.9")
        self.assertNotEqual(H2.boot, self.H.boot)
        st, h2, _ = self.get(inm=h["etag"], H=H2)
        self.assertEqual(st, 200)
        self.assertNotEqual(h2["etag"], h["etag"])
        self.assertEqual(h2["etag"].split(".", 1)[1], h["etag"].split(".", 1)[1])  # only the start id differs

    def test_other_routes_have_no_tag(self) -> None:
        for path in ("/api/status", "/api/stats", "/api/devices.csv", f"/api/devices/{QW.MAC}", "/static/app.js"):
            st, h, _ = self.get(path, "*")
            self.assertEqual(st, 200, path)
            self.assertNotIn("etag", h, path)


class WriteBitTests(QW.Base):
    """The w bit is meta.can_write of the asking client: two clients with a different right never share a tag."""
    env = {"WRITE_ALLOW": "10.0.1.0/24"}
    get = EtagTests.get

    def setUp(self) -> None:
        super().setUp()
        self.db.set_meta("last_poll_ts", str(int(time.time())))
        self.add_device(hostname="laptop")

    def test_tag_differs_per_write_right_and_no_304_across(self) -> None:
        for path in ("/api/devices", "/api/events"):
            _, ok, _ = self.get(path, client="10.0.1.7")
            _, no, _ = self.get(path, client="10.0.9.9")
            self.assertTrue(ok["etag"].endswith('.100.0"'), ok["etag"])
            self.assertTrue(no["etag"].endswith('.000.0"'), no["etag"])
            self.assertEqual(self.get(path, ok["etag"], client="10.0.9.9")[0], 200, path)
            self.assertEqual(self.get(path, no["etag"], client="10.0.1.7")[0], 200, path)
            self.assertEqual(self.get(path, ok["etag"], client="10.0.1.8")[0], 304, path)  # same right, same tag

    def test_read_only_clears_the_bit(self) -> None:
        with mock.patch.object(self.cfg, "read_only", "1"):
            _, h, _ = self.get(client="10.0.1.7")
        self.assertTrue(h["etag"].endswith('.000.0"'), h["etag"])


if __name__ == "__main__":
    unittest.main()
