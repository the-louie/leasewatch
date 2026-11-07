"""Browser tests for the web UI: headless Chrome (puppeteer, via tests/browser/run.js) against a real server.

Skipped as a whole when node, puppeteer or Chrome is missing, so a CI runner without a browser stays green.
One server and one browser serve the whole module: setUpClass runs every scenario in one node process, and each
test asserts on its scenario's JSON result line.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from _env import FW1_ENV, clean_env, restore  # noqa: E402
from leasewatch.collector import Collector  # noqa: E402
from leasewatch.config import Config  # noqa: E402
from leasewatch.db import Database  # noqa: E402
from leasewatch.fw1 import Sighting  # noqa: E402
from leasewatch.web import serve  # noqa: E402

RUN_JS = os.path.join(HERE, "browser", "run.js")
TIMEOUT = 60
ENV = {**FW1_ENV, "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "0", "SITE_NAME": "HomeNet Test",
       "MAILGUN_KEY": "", "MAILGUN_DOMAIN": "", "MAIL_TO": "", "POLL_SECONDS": "120"}

# 16 synthetic devices on 3 networks: (n, hostname, network, online, new). n gives MAC 02:00:00:00:00:<n> and
# IP 10.0.<net>.<n+10>.
NETS = {"HomeNet": (1, "lan"), "IOT": (2, "opt1"), "Guest": (3, "opt2")}
DEVICES = [
    (1, "alex-laptop", "HomeNet", True, False), (2, "Alex's iPad", "HomeNet", True, False),
    (3, "printer", "HomeNet", False, False), (4, "nas", "HomeNet", True, False),
    (5, "kitchen-tv", "HomeNet", False, False), (6, "sam-phone", "HomeNet", True, True),
    (7, "desktop", "HomeNet", True, False), (8, "Sam's iPad", "HomeNet", False, True),
    (9, "thermostat", "IOT", True, False), (10, "doorbell", "IOT", True, False),
    (11, "plug-1", "IOT", False, False), (12, "plug-2", "IOT", True, True), (13, "camera", "IOT", True, True),
    (14, "guest-phone", "Guest", True, False), (15, "guest-laptop", "Guest", False, True),
    (16, "visitor-ipad", "Guest", True, True),
]
NAMES = {d[1] for d in DEVICES}
NEW = {d[1] for d in DEVICES if d[4]}
SCENARIOS = ("load", "rows", "status", "chips", "search", "csv", "trap", "columns", "dirty", "drawer")  # the ones that change server state last


def mac(n: int) -> str:
    return f"02:00:00:00:00:{n:02x}"


def sighting(n: int, host: str, net: str, online: bool) -> Sighting:
    sub, iface = NETS[net]
    return Sighting(mac=mac(n), ip=f"10.0.{sub}.{n + 10}", hostname=host, vendor="Acme", vlan=net, iface=iface,
                    source="dhcp", lease_type="dynamic", online=online)


class FakeClient:
    def __init__(self, sightings: list) -> None:
        self.data = sightings

    def arp_raw(self) -> list:
        return []

    def sightings(self, ignore: tuple = ()) -> tuple:
        return list(self.data), {"leases": len(self.data), "arp": 0}


def setUpModule() -> None:
    if not shutil.which("node"):
        raise unittest.SkipTest("browser tests need node (not on PATH)")
    try:
        r = subprocess.run(["node", RUN_JS, "--probe"], capture_output=True, text=True, timeout=TIMEOUT)
        probe = json.loads(r.stdout.strip().splitlines()[-1])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as e:
        raise unittest.SkipTest(f"browser probe failed: {e}") from None
    if not probe.get("ok"):
        raise unittest.SkipTest(f"browser tests need puppeteer and Chrome: {probe.get('reason')}")


def start(case: type, *polls: list) -> tuple[str, Database]:
    """Serve a fresh DB, after one collector poll per sighting list, until the class cleanups of `case` run."""
    tmp = tempfile.TemporaryDirectory()
    case.addClassCleanup(tmp.cleanup)
    saved = clean_env(dict(ENV, DATA_DIR=tmp.name))
    case.addClassCleanup(restore, saved)
    cfg = Config()
    db = Database(cfg.db_path)
    case.addClassCleanup(db._conn.close)
    client = FakeClient([])
    collector = Collector(cfg, db, client)
    for sightings in polls:  # the first poll is the baseline
        client.data += sightings
        collector.run_once()
    srv = serve(cfg, db, "9.9.9-test")
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    # cleanups run last-in first-out: the server stops before the DB closes
    case.addClassCleanup(thread.join, 5)
    case.addClassCleanup(srv.server_close)
    case.addClassCleanup(srv.shutdown)
    return f"http://127.0.0.1:{srv.server_address[1]}/", db


class _BrowserCase(unittest.TestCase):
    results: dict = {}
    stderr = ""

    @classmethod
    def run_scenarios(cls, base: str, scenarios: tuple) -> None:
        r = subprocess.run(["node", RUN_JS, base, *scenarios], capture_output=True, text=True, timeout=TIMEOUT)
        cls.stderr = r.stderr[-2000:]
        cls.results = {}
        for line in r.stdout.splitlines():
            if line.startswith("{"):
                res = json.loads(line)
                cls.results[res["scenario"]] = res

    def result(self, name: str) -> dict:
        res = self.results.get(name)
        self.assertIsNotNone(res, f"no result for {name}; node stderr: {self.stderr}")
        self.assertIsNone(res["error"], res["error"])
        self.assertEqual(res["console_errors"], [])
        self.assertEqual(res["failed_requests"], [])
        self.assertTrue(res["pass"])
        return res["details"]


class BrowserUITest(_BrowserCase):
    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        base, db = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new],
                         [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if new])  # then the 6 newcomers
        # both polls fall in the same second: backdate the baseline 10 days so "newest first" is deterministic
        db.q("UPDATE devices SET first_seen=first_seen-864000 WHERE baseline=1")
        cls.run_scenarios(base, SCENARIOS)

    def test_page_loads_clean(self) -> None:
        d = self.result("load")
        self.assertEqual(d["title"], "HomeNet Test")
        self.assertEqual(d["rows"], 16)
        self.assertTrue(d["banner_hidden"])

    def test_rows_render_all_devices(self) -> None:
        d = self.result("rows")
        self.assertEqual(len(d["names"]), 16)
        self.assertEqual(set(d["names"]), NAMES)
        self.assertEqual(set(d["names"][:6]), NEW)  # newest first: the newcomers lead, the baseline follows
        self.assertEqual(d["total_card"], "16")

    def test_status_shows_firewall_ok(self) -> None:
        d = self.result("status")
        self.assertIn("ok", d["dot"].split())
        self.assertEqual(len(d["sources"]), 1)
        src = d["sources"][0]
        self.assertEqual(src["title"], "fw1: OK")
        self.assertIn("ok", src["dot"].split())

    def test_network_chips_filter(self) -> None:
        d = self.result("chips")
        want = {}
        for _, h, net, on, _ in DEVICES:
            want.setdefault(net, set()).add(h)
        self.assertEqual({c["vlan"] for c in d["chips"]}, set(NETS))
        for c in d["chips"]:
            net = c["vlan"]
            online = sum(1 for x in DEVICES if x[2] == net and x[3])
            self.assertEqual(c["n"], f"{online}/{len(want[net])}")
            per = d["per"][net]
            self.assertEqual({r["name"] for r in per["rows"]}, want[net])
            self.assertEqual({r["vlan"] for r in per["rows"]}, {net})
            self.assertEqual(per["pressed"], "true")
            self.assertIn(f"vlan={net}", per["url"])
        self.assertEqual(d["rows_after"], 16)

    def test_search_filters(self) -> None:
        d = self.result("search")
        self.assertEqual(set(d["ipad"]["names"]), {"Alex's iPad", "Sam's iPad", "visitor-ipad"})
        self.assertEqual(set(d["10.0.2."]["names"]), {h for _, h, net, _, _ in DEVICES if net == "IOT"})
        self.assertEqual(d["02:00:00:00:00:0c"]["names"], ["plug-2"])
        self.assertEqual(d["zzz-nothing"]["names"], [])
        self.assertTrue(d["zzz-nothing"]["empty_shown"])
        self.assertEqual(d["cleared"], 16)

    def test_csv_export(self) -> None:
        d = self.result("csv")
        self.assertTrue(d["href"].endswith("/api/devices.csv"))
        self.assertEqual(d["status"], 200)
        self.assertTrue(d["type"].startswith("text/csv"), d["type"])
        self.assertIn("attachment", d["disposition"])
        self.assertTrue(d["header"].startswith("mac,ip,name,hostname,vendor,vlan,"), d["header"])
        self.assertEqual(d["data_lines"], 16)

    def test_drawer_traps_focus(self) -> None:
        d = self.result("trap")
        self.assertEqual(d["bg_before"], [False, False, False])
        self.assertEqual(d["bg_open"], [True, True, True])  # header, main, footer
        # Tab from Name: Note, Save, the ack button, then around to Close and Name again
        self.assertEqual([t["id"] for t in d["tab"]], ["fNote", "fSave", "fAck", "dClose", "fName", "fNote"])
        self.assertEqual([t["id"] for t in d["shift_tab"]], ["fAck", "fSave", "fNote", "fName", "dClose", "fAck"])
        self.assertTrue(all(t["in_drawer"] for t in d["tab"] + d["shift_tab"]))
        self.assertTrue(d["q_focus"]["in_drawer"], d["q_focus"])
        self.assertEqual(d["bg_closed"], [False, False, False])
        self.assertEqual(d["closed_focus"], {"id": None, "tag": "tr", "mac": mac(1)})

    def test_type_column_on_laptop_widths(self) -> None:
        d = self.result("columns")
        every = ["c-dot", "c-dev", "c-ip", "c-mac", "c-vlan", "c-type", "c-where", "c-first", "c-last", "c-act"]
        for width in ("1280", "1366", "1440", "1920"):
            with self.subTest(width=width):
                self.assertEqual(d[width]["shown"], every)
                self.assertEqual(d[width]["table_scroll"], 0, d[width])
                self.assertEqual(d[width]["page_scroll"], 0, d[width])

    def test_sr_labels_visually_hidden(self) -> None:
        d = self.result("columns")
        self.assertEqual([e["text"] for e in d["sr"]], ["online", "actions"])
        for e in d["sr"]:
            with self.subTest(text=e["text"]):
                self.assertEqual((e["w"], e["h"]), (1, 1))
                self.assertEqual(e["overflow"], "hidden")
                self.assertTrue(e["clip"])
                self.assertTrue(e["nowrap"])
                self.assertGreaterEqual(e["left"], 0)  # not parked off-screen (which can scroll an RTL page)

    def test_unsaved_edits_ask_before_discard(self) -> None:
        d = self.result("dirty")
        self.assertEqual(d["clean_close"], {"open": False, "mac": mac(4), "name": "", "dialogs": 0})  # the body stays behind
        # Cancel: the drawer stays on the edited device with the typed name, one confirm per attempt
        for n, way in enumerate(("escape", "scrim", "close", "click_other", "enter_other"), 1):
            with self.subTest(way=way):
                self.assertEqual(d["cancel"][way], {"open": True, "mac": mac(2), "name": "Alex printer", "dialogs": n})
        # OK: the other device opens with its own clean form; an edited close goes through
        self.assertEqual(d["ok_other"], {"open": True, "mac": mac(3), "name": "", "dialogs": 6})
        self.assertEqual(d["ok_close"], {"open": False, "mac": mac(3), "name": "Sam printer", "dialogs": 7})
        self.assertEqual(d["server"], {mac(2): "", mac(3): ""})  # discarded, not saved
        self.assertEqual({(x["type"], x["message"]) for x in d["dialog_log"]}, {("confirm", "Discard unsaved changes?")})

    def test_drawer_flows(self) -> None:
        d = self.result("drawer")
        # click opens the drawer on the device with Name focused; Escape closes it and focuses the row again
        self.assertTrue(d["click"]["open"])
        self.assertEqual(d["click"]["title"], "sam-phone")
        self.assertEqual(d["click"]["focus"]["id"], "fName")
        self.assertFalse(d["click_closed"]["open"])
        self.assertEqual(d["click_closed"]["focus"], {"id": None, "tag": "tr", "mac": mac(6)})
        # Enter on a focused row opens it too
        self.assertTrue(d["key"]["open"])
        self.assertEqual(d["key"]["focus"]["id"], "fName")
        self.assertEqual(d["key"]["ack_label"], "Save & mark known")
        # "Save & mark known" stores the name and the ack on the server, and the page shows both
        srv = d["saved"]["server"]
        self.assertEqual(srv["name"], "Alex's camera")
        self.assertTrue(srv["acked"])
        self.assertEqual(d["saved"]["title"], "Alex's camera")
        self.assertEqual(d["saved"]["ack_label"], "Mark unknown")
        self.assertEqual(d["saved"]["row_name"], "Alex's camera")
        self.assertFalse(d["saved"]["row_ack"])
        # the save rebuilt the table: Escape focuses the device's new row
        self.assertFalse(d["key_closed"]["open"])
        self.assertEqual(d["key_closed"]["focus"], {"id": None, "tag": "tr", "mac": mac(13)})
        # the row's "Mark known" acks without opening the drawer
        self.assertFalse(d["rowack_before"])
        self.assertTrue(d["rowack"]["server"])
        self.assertFalse(d["rowack"]["open"])
        self.assertEqual(d["rowack"]["unacked_card"], str(len(NEW) - 2))


class BrowserPerfTest(_BrowserCase):
    """Search on 2000 devices (hostnames dev-0000 .. dev-1999, all on HomeNet)."""
    N = 2000

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        many = [Sighting(mac=f"02:00:00:01:{i // 256:02x}:{i % 256:02x}", ip=f"10.0.{1 + i // 250}.{1 + i % 250}",
                         hostname=f"dev-{i:04d}", vendor="Acme", vlan="HomeNet", iface="lan", source="dhcp",
                         lease_type="dynamic", online=i % 3 == 0) for i in range(cls.N)]
        base, _ = start(cls, many)
        cls.run_scenarios(base, ("perf",))

    def test_search_debounced_on_2000_devices(self) -> None:
        d = self.result("perf")
        self.assertEqual(d["rows0"], self.N)
        # no dropped characters: box, URL and table all show the whole query
        self.assertEqual(d["value"], "dev-12")
        self.assertEqual(d["url_q"], "dev-12")
        self.assertEqual(sorted(d["names"]), [f"dev-12{i:02d}" for i in range(100)])
        self.assertEqual(d["keys"], 6)
        self.assertLessEqual(d["renders"], 2, d)  # one per pause in typing, not one per key
        self.assertLess(d["last_render_ms"], 1000, d)  # last key to the final table, debounce included
        # Enter and Escape do not wait for the debounce
        self.assertEqual(d["enter"]["rows"], 1000)
        self.assertEqual(d["enter"]["url_q"], "dev-1")
        self.assertEqual(d["escape"]["rows"], self.N)
        self.assertEqual(d["escape"]["value"], "")


if __name__ == "__main__":
    unittest.main()
