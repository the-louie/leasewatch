"""/api/events filters, paging and CSV, and the ETag rules that go with them."""
from __future__ import annotations

import csv
import gzip
import json
import os
import sys
import unittest
from unittest import mock

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_qa11_web as QW  # noqa: E402
from leasewatch import web  # noqa: E402

KINDS = ["new", "ip", "back", "source_down"]
T0 = 1_700_000_000
N = 700


class Base(QW.Base):
    def setUp(self) -> None:
        super().setUp()
        rows = []
        for i in range(N):  # 3 days; several rows share a ts
            kind = KINDS[i % 4]
            rows.append((T0 + (i * 3 * 86400) // N // 2 * 2, "" if kind == "source_down" else QW.MAC, kind, f"d{i}"))
        self.db.q("INSERT INTO devices(mac,first_seen,last_seen,name) VALUES(?,1,1,'box')", (QW.MAC,))
        with self.db.tx() as c:
            c.executemany("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", rows)

    def get(self, path: str, headers: bytes = b"") -> tuple[int, dict, bytes]:
        h = self.handler(path=path, headers=b"Host: 127.0.0.1\r\n" + headers)
        h.do_GET()
        head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        hd = {k.lower(): v for k, v in (ln.split(": ", 1) for ln in lines[1:])}
        if hd.get("content-encoding") == "gzip":
            body = gzip.decompress(body)
        return int(lines[0].split()[1]), hd, body

    def js(self, path: str) -> dict:
        st, _, body = self.get(path)
        self.assertEqual(st, 200, body)
        return json.loads(body)


class ApiTests(Base):
    def test_default_is_300_newest(self) -> None:
        d = self.js("/api/events")
        ev = d["events"]
        self.assertEqual(len(ev), 300)
        self.assertEqual(ev[0]["id"], N)
        self.assertEqual([(e["ts"], e["id"]) for e in ev], sorted([(e["ts"], e["id"]) for e in ev], reverse=True))
        self.assertEqual(d["next"], ev[-1]["id"])
        self.assertEqual(set(ev[0]), {"id", "ts", "mac", "kind", "detail", "name", "hostname", "vlan"})
        self.assertEqual(self.js("/api/events?")["events"], ev)

    def test_paging_has_no_gap_or_repeat(self) -> None:
        seen, before = [], None
        for _ in range(20):
            d = self.js("/api/events?limit=100" + (f"&before={before}" if before else ""))
            seen += [e["id"] for e in d["events"]]
            before = d["next"]
            if before is None:
                break
        self.assertEqual(seen, list(range(N, 0, -1)))
        self.assertEqual(len(d["events"]), 100)  # the last page is exactly full and has no next
        self.assertIsNone(d["next"])

    def test_before_unknown_id_is_empty(self) -> None:
        d = self.js("/api/events?before=99999")
        self.assertEqual(d, {"events": [], "next": None})

    def test_kind_filter_and_unknown_kind(self) -> None:
        d = self.js("/api/events?kind=ip,new&limit=500")
        self.assertEqual({e["kind"] for e in d["events"]}, {"ip", "new"})
        self.assertEqual(len(d["events"]), 350)
        self.assertIsNone(d["next"])
        self.assertEqual(self.js("/api/events?kind=nope"), {"events": [], "next": None})
        src = self.js("/api/events?kind=source_down&limit=5")["events"]
        self.assertEqual([e["mac"] for e in src], [""] * 5)
        self.assertIsNone(src[0]["name"])

    def test_since_inclusive_until_exclusive(self) -> None:
        ts = sorted({r["ts"] for r in self.db.q("SELECT ts FROM events")})
        a, b = ts[10], ts[20]
        ev = self.js(f"/api/events?since={a}&until={b}&limit=500")["events"]
        self.assertEqual(min(e["ts"] for e in ev), a)
        self.assertEqual(max(e["ts"] for e in ev), ts[19])
        self.assertEqual(len(ev), self.db.q("SELECT COUNT(*) n FROM events WHERE ts>=? AND ts<?", (a, b))[0]["n"])
        self.assertEqual(self.js(f"/api/events?since={a}&until={a}")["events"], [])

    def test_bad_parameters_are_400(self) -> None:
        for q in ("limit=0", "limit=501", "limit=x", "before=abc", "before=0", "since=-1", "until=1.5", "kind=",
                  "kind=A", "kind=a,,b", "kind=" + ",".join(["a"] * 21),
                  "since=10&until=5", "limit=1&limit=2", "kind=ip&kind=new", "limit=%EF%BC%91"):
            st, _, body = self.get("/api/events?" + q)
            self.assertEqual(st, 400, q)
            self.assertIn("error", json.loads(body))

    def test_index_is_used(self) -> None:
        plan = " ".join(r["detail"] for r in self.db.q(
            "EXPLAIN QUERY PLAN SELECT e.id FROM events e WHERE e.kind IN ('ip') AND e.ts >= 5 AND e.ts < 9 "
            "ORDER BY e.ts DESC, e.id DESC LIMIT 10"))
        self.assertIn("events_kind_ts", plan)
        self.assertNotIn("SCAN e", plan)


class EtagTests(Base):
    def test_plain_request_keeps_its_etag(self) -> None:
        st, hd, _ = self.get("/api/events")
        self.assertEqual(st, 200)
        self.assertIn("etag", hd)
        st2, _, _ = self.get("/api/events", b"If-None-Match: " + hd["etag"].encode() + b"\r\n")
        self.assertEqual(st2, 304)

    def test_filtered_answer_has_no_etag_and_is_never_304(self) -> None:
        _, hd, _ = self.get("/api/events?kind=new")
        self.assertNotIn("etag", hd)
        tag = self.get("/api/events")[1]["etag"].encode()
        for q in ("?kind=ip", "?limit=60", "?since=0"):
            st, hd, body = self.get("/api/events" + q, b"If-None-Match: " + tag + b"\r\nIf-None-Match: *\r\n")
            self.assertEqual(st, 200, q)
            self.assertNotIn("etag", hd)
            self.assertTrue(json.loads(body)["events"])


class CsvTests(Base):
    def rows(self, q: str = "") -> tuple[dict, list[list[str]]]:
        st, hd, body = self.get("/api/events.csv" + q)
        self.assertEqual(st, 200, body)
        return hd, list(csv.reader(body.decode("utf-8-sig").splitlines()))

    def test_header_rows_and_disposition(self) -> None:
        hd, rows = self.rows()
        self.assertEqual(rows[0], ["id", "time", "mac", "kind", "detail", "name", "hostname", "vlan"])
        self.assertEqual(len(rows), N + 1)
        self.assertEqual(rows[1][0], str(N))
        self.assertEqual(rows[1][3], KINDS[(N - 1) % 4])
        self.assertEqual(hd["content-disposition"], 'attachment; filename="leasewatch-events.csv"')
        self.assertTrue(hd["content-type"].startswith("text/csv"))
        self.assertNotIn("etag", hd)

    def test_default_cap_and_limit(self) -> None:
        with mock.patch.object(web, "_event_filters", wraps=web._event_filters) as m:
            self.rows()
            self.assertEqual(m.call_args.args[1:3], (10000, 50000))
        _, rows = self.rows("?limit=50")
        self.assertEqual(len(rows), 51)
        st, _, _ = self.get("/api/events.csv?limit=50001")
        self.assertEqual(st, 400)
        real = web._event_filters
        with mock.patch.object(web, "_event_filters", lambda q, d, m, p: real(q, 120, m, p)):
            _, rows = self.rows()
        self.assertEqual(len(rows), 121)

    def test_filters_and_formula_guard(self) -> None:
        self.db.q("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (T0 + 10**6, QW.MAC, "ip", "=cmd|' /C calc'!A0"))
        _, rows = self.rows("?kind=ip&limit=3")
        self.assertEqual({r[3] for r in rows[1:]}, {"ip"})
        self.assertTrue(rows[1][4].startswith("'="), rows[1][4])
        self.assertEqual(rows[1][5], "box")
        _, rows = self.rows("?kind=ip&since=%d" % (T0 + 10**6))
        self.assertEqual(len(rows), 2)

    def test_name_is_guarded_too(self) -> None:
        self.db.update_user_fields(QW.MAC, None, "=1+1", None)
        _, rows = self.rows("?kind=new&limit=1")
        self.assertEqual(rows[1][5], "'=1+1")

    def test_bad_parameter_is_400(self) -> None:
        st, _, body = self.get("/api/events.csv?kind=A")
        self.assertEqual(st, 400)
        self.assertIn("error", json.loads(body))


if __name__ == "__main__":
    unittest.main()
