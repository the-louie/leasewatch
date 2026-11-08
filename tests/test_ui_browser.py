"""Browser tests for the web UI: headless Chrome (puppeteer, via tests/browser/run.js) against a real server.

Skipped as a whole when node, puppeteer or Chrome is missing, so a CI runner without a browser stays green.
One server and one browser serve the whole module: setUpClass runs every scenario in one node process, and each
test asserts on its scenario's JSON result line.
"""
from __future__ import annotations

import csv
import datetime
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.parse

from _env import FW1_ENV, clean_env, restore, sources, swap_client
from _fixtures import FakeClient
from leasewatch.collector import Collector
from leasewatch.config import Config
from leasewatch.db import Database
from leasewatch.fw1 import Sighting
from leasewatch.unifi import WifiInfo
from leasewatch.web import serve

HERE = os.path.dirname(os.path.abspath(__file__))

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
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SCENARIOS = ("load", "nossid", "rows", "status", "chips", "search", "lang_apply", "lang_param", "csv", "trap", "columns", "baseline", "etag", "dirty", "saving", "drawer")  # the ones that change server state last


def mac(n: int) -> str:
    return f"02:00:00:00:00:{n:02x}"


def sighting(n: int, host: str, net: str, online: bool) -> Sighting:
    sub, iface = NETS[net]
    return Sighting(mac=mac(n), ip=f"10.0.{sub}.{n + 10}", hostname=host, vendor="Acme", vlan=net, iface=iface,
                    source="dhcp", lease_type="dynamic", online=online)


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


def start(case: type, *polls: list, env: dict | None = None) -> tuple[str, Database]:
    """Serve a fresh DB, after one collector poll per sighting list, until the class cleanups of `case` run. `env`:
    settings on top of ENV."""
    tmp = tempfile.TemporaryDirectory()
    case.addClassCleanup(tmp.cleanup)
    saved = clean_env(dict(ENV, DATA_DIR=tmp.name, **(env or {})))
    case.addClassCleanup(restore, saved)
    cfg = Config()
    db = Database(cfg.db_path)
    case.addClassCleanup(db._conn.close)
    client = FakeClient([])
    collector = Collector(cfg, db, client)
    for sightings in polls:  # the first poll is the baseline
        client.sightings_data += sightings
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
    def run_scenarios(cls, base: str, scenarios: tuple, creds: str = "") -> None:
        env = {**os.environ, "LW_TEST_AUTH": creds} if creds else {k: v for k, v in os.environ.items() if k != "LW_TEST_AUTH"}
        r = subprocess.run(["node", RUN_JS, base, *scenarios], capture_output=True, text=True, timeout=TIMEOUT, env=env)
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
        self.assertEqual(res["csp_violations"], [])
        self.assertEqual(res["csp"], CSP)  # every scenario runs under the policy the server sends
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
        # the network colours survive the CSP: a swatch per network and a colour on every event badge
        self.assertEqual(len(d["swatches"]), len(NETS))
        for bg in d["swatches"]:
            self.assertNotIn(bg, ("", "rgba(0, 0, 0, 0)", "transparent"), d["swatches"])
        self.assertTrue(d["event_badges"]); self.assertNotIn("", d["event_badges"])
        self.assertEqual(d["favicon"], {"status": 200, "type": "image/svg+xml"})

    def test_no_ssid_chip_row_without_wifi_presence(self) -> None:
        d = self.result("nossid")
        self.assertEqual((d["hidden"], d["chips"], d["heads"]), (True, 0, ["First seen", "Last online"]))

    def test_rows_render_all_devices(self) -> None:
        d = self.result("rows")
        self.assertEqual(len(d["names"]), 16)
        self.assertEqual(set(d["names"]), NAMES)
        self.assertEqual(set(d["names"][:6]), NEW)  # newest first: the newcomers lead, the baseline follows
        self.assertEqual(d["total_card"], "16")

    def test_reload_revalidates_with_304(self) -> None:
        d = self.result("etag")
        devices = [r for r in d["responses"] if r["path"] == "/api/devices"]
        events = [r for r in d["responses"] if r["path"] == "/api/events"]
        self.assertEqual(len(devices), 1, d["responses"])
        # the page sent the tag of its first load itself and got a 304 with the same tag
        self.assertRegex(devices[0]["sent"] or "", r'^W/"[0-9a-f]{8}\.\d+\.\d+\.100\.[0-9a-f]+"$')
        self.assertEqual((devices[0]["status"], devices[0]["etag"]), (304, devices[0]["sent"]))
        self.assertEqual(len(events), 1, d["responses"])  # the query hash is in the tag: the events request revalidates too
        self.assertRegex(events[0]["sent"] or "", r'^W/"[0-9a-f]{8}\.\d+\.\d+\.100\.[0-9a-f]+"$')
        self.assertEqual((events[0]["status"], events[0]["etag"]), (304, events[0]["sent"]))
        self.assertEqual((d["rows_before"], d["rows_after"]), (16, 16))
        self.assertTrue(d["status_after"].startswith("polled"), d["status_after"])
        self.assertTrue(d["banner_hidden"])

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
        for _, h, net, _on, _ in DEVICES:
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

    def test_english_marks_are_left_alone(self) -> None:
        d = self.result("lang_apply")
        self.assertEqual(d, {"html_lang": "en", "sub": "Who is on the network, newest first", "refresh": "refreshes every minute",
                             "option": "Offline", "tpl_title": "Click to copy", "row_title": "Click to copy"})

    def test_lang_param_survives_filters(self) -> None:
        d = self.result("lang_param")
        self.assertEqual((d["html_lang"], d["data_lang"], d["strings"]), ("en", "auto", "object"))
        self.assertEqual(d["filtered"], "?filter=new&lang=en")
        self.assertEqual(d["cleared"], "?lang=en")

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
        # Tab from Name: Note, Tags, Save, the ack, archive and watch buttons, then around to Close and Name again
        self.assertEqual([t["id"] for t in d["tab"]], ["fNote", "fTags", "fSave", "fAck", "fArch", "fWatch", "dClose", "fName"])
        self.assertEqual([t["id"] for t in d["shift_tab"]], ["fWatch", "fArch", "fAck", "fSave", "fTags", "fNote", "fName", "dClose"])
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

    def test_close_during_save_asks_only_for_new_text(self) -> None:
        d = self.result("saving")
        # nothing typed after Save: the close goes through without a prompt and the save still lands
        self.assertEqual(d["plain"], {"dialogs": 0, "open": False, "server": "Kitchen TV"})
        # text typed after Save: the close asks (Cancel keeps the drawer); after the save only that text is unsaved
        self.assertEqual(d["typed"]["dialogs"], 1)
        self.assertTrue(d["typed"]["open"])
        self.assertEqual(d["typed"]["after"], {"dialogs": 2, "open": False, "server": "Desk"})
        self.assertEqual(set(d["dialog_log"]), {"Discard unsaved changes?"})

    def test_drawer_flows(self) -> None:
        d = self.result("drawer")
        # click opens the drawer on the device with Name focused; Escape closes it and focuses the row again
        self.assertTrue(d["click"]["open"])
        self.assertEqual(d["click"]["title"], "sam-phone")
        self.assertEqual(d["click"]["focus"]["id"], "fName")
        self.assertTrue(d["click"]["badges"]); self.assertNotIn("", d["click"]["badges"])  # network + history badges
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
        # Watch posts only {"watch": true}; the row shows the watch badge and the button turns into Unwatch
        self.assertEqual(d["watch_label"], "Watch")
        self.assertEqual(json.loads(d["watched"]["body"]), {"watch": True})
        self.assertEqual(d["watched"]["badge"], "watch")
        self.assertEqual(d["watched"]["server"], 1)
        # the row's "Mark known" acks without opening the drawer
        self.assertFalse(d["rowack_before"])
        self.assertTrue(d["rowack"]["server"])
        self.assertFalse(d["rowack"]["open"])
        self.assertEqual(d["rowack"]["unacked_card"], str(len(NEW) - 2))


class BrowserBaselineTest(_BrowserCase):
    """The seed's 10 baseline devices are all unchecked: the fifth card shows 10 and ?filter=baseline lists them."""

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        base, _ = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new],
                        [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if new])
        cls.run_scenarios(base, ("baseline",))

    def test_filter_and_card(self) -> None:
        d = self.result("baseline")
        want = {h for _, h, _, _, new in DEVICES if not new}
        self.assertIn(["baseline", "Baseline, not checked"], d["option"])
        self.assertEqual(d["card"], {"hidden": False, "num": str(len(want)), "five": True, "pressed": "false"})
        self.assertEqual(d["restored"], "baseline")
        self.assertEqual(set(d["names"]), want)
        self.assertEqual(len(d["names"]), len(want))
        self.assertEqual(d["card_filtered"]["num"], str(len(d["names"])))
        self.assertEqual(d["card_filtered"]["pressed"], "true")
        self.assertEqual(d["after_click_filter"], "all")  # the card toggles its filter off

    def test_no_horizontal_scroll_at_1280(self) -> None:
        d = self.result("baseline")
        self.assertLessEqual(d["scroll_1280"], 0)
        self.assertLessEqual(d["scroll_filtered"], 0)
        self.assertGreaterEqual(d["card_box"]["w"], 110)


class BrowserBaselineDoneTest(_BrowserCase):
    """Every baseline device is marked known: the card is hidden and the filter, if opened by URL, is empty."""

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        base, db = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new],
                         [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if new])
        db.q("UPDATE devices SET acked=1 WHERE baseline=1")
        cls.run_scenarios(base, ("baseline",))

    def test_card_hidden_at_zero(self) -> None:
        d = self.result("baseline")
        self.assertTrue(d["card"]["hidden"])
        self.assertFalse(d["card"]["five"])
        self.assertEqual(d["names"], [])
        self.assertEqual(d["empty"], "Every baseline device is checked.")
        self.assertFalse(d["card_filtered"]["hidden"])  # shown while its filter is on, so the click can be undone
        self.assertEqual(d["card_filtered"]["num"], "0")


class BrowserPrivateTest(_BrowserCase):
    """Private (locally administered) MACs, the merged-MAC list and click-to-copy. A hardware MAC from the RFC 7042
    documentation range, a private device that sends a client-id, and a new private MAC merged into it by that id."""
    UA, DEV, NEWP, OTHER = "00:00:5e:00:53:01", "02:00:00:00:10:01", "06:00:00:00:10:02", "0a:00:00:00:10:03"
    CID = "ff00000000000001"

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(m: str, n: int, host: str, cid: str = "") -> Sighting:
            # OTHER is alone on a network that sorts before HomeNet: archiving it must not recolour HomeNet
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=host, vendor="Acme", vlan="Aaa" if m == cls.OTHER else "HomeNet", iface="lan",
                            source="dhcp", lease_type="dynamic", online=True, client_id=cid)
        first = [s(cls.UA, 20, "printer"), s(cls.DEV, 21, "tablet", cls.CID), s(cls.OTHER, 23, "laptop")]
        base, db = start(cls, first, [s(cls.NEWP, 22, "tablet", cls.CID)])
        assert [r["mac"] for r in db.q("SELECT mac FROM aliases")] == [cls.NEWP], "the seed did not merge"
        # the tablet is online on "Home" and was seen before on a hostile SSID; the older row's first sighting is the day counting began
        now = int(time.time())
        db.q("UPDATE devices SET online=1, wifi_ssid='Home' WHERE mac=?", (cls.DEV,))
        db.q("INSERT INTO events (mac, kind, detail, ts) VALUES (?, 'offline', 'no sighting for 10 minutes', ?)", (cls.DEV, int(time.time())))
        for ssid, first, last, secs, polls, ap in (("Home", now - 7200, now, 5400, 45, "ap-<b>1"), ("Guest <i>x</i>", now - 86400, now - 80000, 600, 5, "ap-2")):
            db.q("INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) VALUES(?,?,?,?,?,?,?)",
                 (cls.DEV, ssid, first, last, secs, polls, ap))
        cls.run_scenarios(base, ("private", "copy", "aliassearch", "deeplink", "deeplinkretry", "wifihistory", "archive", "vlancolor", "presencekinds", "split"))  # archive and split change server state: last

    def test_private_rows_are_marked(self) -> None:
        rows = {r["mac"]: r for r in self.result("private")["rows"]}
        self.assertEqual(set(rows), {self.UA, self.DEV, self.OTHER})
        for m in (self.DEV, self.OTHER):
            with self.subTest(mac=m):
                r = rows[m]
                self.assertTrue(r["cls"])
                self.assertNotEqual(r["shadow"], "none")  # the tinted border
                self.assertTrue(r["shown"])
                self.assertTrue(r["emoji"])
                self.assertEqual(r["title"], "private address")
                self.assertEqual(r["hint"], "private address")  # in words, at 1400 px
                self.assertTrue(r["hint_shown"])
                self.assertEqual(r["ico_in_mac"], True)  # the sleuth stays next to the MAC at 1400 px
                self.assertEqual(r["ico_in_hint"], False)
                self.assertEqual(r["copy_text"], m)  # the sleuth is not part of the copied text
        self.assertEqual(rows[self.DEV]["sub_start"], "private address")
        ua = rows[self.UA]
        self.assertIsNone(ua["hint"])
        self.assertFalse(ua["cls"])
        self.assertEqual(ua["shadow"], "none")
        self.assertFalse(ua["shown"])
        self.assertEqual(ua["copy_text"], self.UA)

    def test_private_hint_at_800_px_has_the_sleuth_and_no_scroll(self) -> None:
        d = self.result("private")["narrow"]
        self.assertLessEqual(d["scroll"], 0)
        for m in (self.DEV, self.OTHER):
            with self.subTest(mac=m):
                r = d["rows"][m]
                self.assertEqual(r["hint"], "private address")
                self.assertTrue(r["hint_shown"])
                self.assertFalse(r["mac_shown"])  # .c-mac is hidden here
                self.assertTrue(r["ico_in_hint"])
        self.assertIsNone(d["rows"][self.UA]["hint"])

    def test_network_colour_survives_archiving_an_earlier_networks_last_device(self) -> None:
        d = self.result("vlancolor")
        self.assertEqual(d["before"]["chips"].keys(), {"Aaa", "HomeNet"})
        self.assertEqual(d["after"]["chips"].keys(), {"HomeNet"})  # the chip of the emptied network is gone
        self.assertTrue(d["before"]["chips"]["HomeNet"])
        self.assertEqual(d["after"]["chips"]["HomeNet"], d["before"]["chips"]["HomeNet"])
        self.assertEqual(d["after"]["row"], d["before"]["row"])
        self.assertEqual(d["before"]["chips"]["HomeNet"], d["before"]["row"])
        self.assertNotEqual(d["before"]["chips"]["Aaa"], d["before"]["chips"]["HomeNet"])

    def test_deep_link_opens_after_a_failed_first_load(self) -> None:
        d = self.result("deeplinkretry")
        self.assertEqual(d["refused"], 1)
        self.assertIn("Cannot reach", d["banner"])
        self.assertFalse(d["open_before"])
        self.assertIn(self.DEV, d["url_before"])  # the key waits in the address
        self.assertTrue(d["open_after"])
        self.assertIn(self.DEV, d["url_after"])
        self.assertTrue(d["banner_hidden"])

    def test_drawer_lists_merged_macs(self) -> None:
        d = self.result("private")
        self.assertIn("Merged addresses", d["drawer"]["heading"])
        self.assertIn("client-id", d["drawer"]["why"])
        self.assertEqual(d["drawer"]["head"], ["MAC", "Matched by", "Merged", "Last seen", "Action"])
        self.assertEqual(len(d["drawer"]["rows"]), 1)
        mac_cell, why, merged, seen, action = d["drawer"]["rows"][0]
        self.assertEqual(action, "Split")
        self.assertEqual(mac_cell, self.NEWP)
        self.assertEqual(why, f"client-id {self.CID}")
        self.assertRegex(merged, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
        self.assertEqual(seen, "just now")
        self.assertFalse(d["plain"]["table"])
        self.assertNotIn("Merged addresses", d["plain"]["heading"])

    def test_offline_event_in_the_drawer_history(self) -> None:
        self.assertEqual(self.result("presencekinds"), {"cls": "k offline", "text": "offline"})

    def test_split_off_a_merged_address(self) -> None:
        d = self.result("split")
        b = d["before"]
        self.assertEqual(b["aliases"], [self.NEWP])
        self.assertEqual(b["buttons"], [[self.NEWP, "Split"]])
        self.assertEqual(b["head"][-1], "Action")
        self.assertTrue(b["note"].endswith("Split one if it is not this device."))
        self.assertTrue(b["visible"])  # no hover reveal
        c = d["cancelled"]  # the first dialog was dismissed
        self.assertEqual((c["dialogs"], c["aliases"], c["server"], c["open"], c["new_row"]), (1, [self.NEWP], [self.NEWP], True, False))
        done = d["done"]
        self.assertEqual(done["dialogs"][0], f"Split {self.NEWP} off tablet? It becomes its own device. What it recorded here stays here, "
                                             "and it is never merged back into this device automatically.")
        self.assertEqual(len(done["dialogs"]), 2)
        self.assertEqual((done["aliases"], done["server"], done["open"], done["title"]), ([], [], True, "tablet"))
        self.assertNotIn("Merged addresses", done["headings"])
        self.assertIn(self.DEV, done["mac"])
        self.assertEqual(done["row_private"], "private address")
        # Name held unsaved text: the table still drops the address, the text and the focus stay
        self.assertEqual((done["buttons"], done["name"], done["focus"]), (0, " typed", "fName"))
        a = d["again"]  # the button from before the split, clicked again
        self.assertTrue(a["banner"].startswith("Split failed: "), a["banner"])
        self.assertEqual((a["dialogs"], a["name"]), (3, " typed"))
        self.assertEqual(d["events"], ["split address", "split address"])
        self.assertEqual(d["ev_filter"]["kinds"], ["split address", "split address"])
        self.assertIn("ek=split", d["ev_filter"]["url"])
        self.assertEqual(d["ek_url"], {"select": "split", "url": "?ek=split", "kinds": ["split address", "split address"]})
        r = d["split_row"]
        self.assertEqual(r["split_from"], ["tablet", self.DEV])
        self.assertEqual(r["status"], "offline · split off; waiting for its first poll")
        self.assertFalse(r["aliases_table"])
        self.assertEqual(r["kinds"], ["split address"])
        self.assertEqual(d["back"], {"title": "tablet", "open": True})

    def test_drawer_shows_wifi_history(self) -> None:
        d = self.result("wifihistory")
        s = d["shown"]
        self.assertIn("Wi-Fi history", s["headings"])
        self.assertEqual(s["head"], ["SSID", "First", "Last", "Time", "Last AP"])
        self.assertEqual(len(s["rows"]), 2)
        (ssid1, first1, last1, time1, ap1), (ssid2, first2, last2, time2, ap2) = s["rows"]
        self.assertEqual((ssid1, last1, time1, ap1), ("Home", "now", "1.5 h", "ap-<b>1"))
        self.assertRegex(first1, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
        self.assertEqual((ssid2, time2, ap2), ("Guest <i>x</i>", "10 min", "ap-2"))  # the text, not an element
        self.assertRegex(last2, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
        self.assertRegex(first2, r"^since \d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
        self.assertEqual(s["titles"], ["1.50 h in 45 polls", "0.17 h in 5 polls"])
        self.assertEqual(s["italics"], 0)
        self.assertNotIn("Wi-Fi history", d["none"]["headings"])  # no rows: no block
        self.assertIsNone(d["none"]["rows"])

    def test_search_by_merged_mac_lists_only_its_device(self) -> None:
        rows = self.result("aliassearch")["rows"]
        self.assertEqual([r["mac"] for r in rows], [self.DEV])

    def test_device_link_opens_the_drawer(self) -> None:
        r = self.result("deeplink")
        self.assertTrue(r["direct"]["open"])
        self.assertEqual(r["direct"]["title"], "tablet")
        self.assertEqual(r["direct"]["search"], f"?device={self.DEV}")
        self.assertIn(self.DEV, r["direct"]["shown"])
        self.assertEqual(r["upper"]["search"], f"?device={self.DEV}")  # the key is lower case
        self.assertTrue(r["upper"]["open"])

    def test_device_link_with_a_merged_mac_opens_its_device(self) -> None:
        r = self.result("deeplink")["alias"]
        self.assertTrue(r["open"])
        self.assertEqual(r["title"], "tablet")
        self.assertIn(self.DEV, r["shown"])
        self.assertNotIn(self.NEWP, r["shown"])
        self.assertEqual(r["search"], f"?device={self.DEV}")  # the address names the device

    def test_closing_the_drawer_removes_the_key(self) -> None:
        d = self.result("deeplink")
        for k in ("closed", "alias_closed"):
            with self.subTest(k=k):
                self.assertFalse(d[k]["open"])
                self.assertEqual(d[k]["search"], "")

    def test_unknown_device_link_opens_nothing(self) -> None:
        d = self.result("deeplink")
        for k in ("unknown", "junk"):
            with self.subTest(k=k):
                self.assertFalse(d[k]["open"])
                self.assertFalse(d[k]["banner"])
                self.assertEqual(d[k]["search"], "")

    def test_merged_event_has_a_label(self) -> None:
        d = self.result("private")
        self.assertEqual(d["merged_event"], [{"label": "merged address", "detail": f"{self.NEWP} (client-id)"}])

    def test_click_and_keys_copy_mac_and_ip(self) -> None:
        d = self.result("copy")
        self.assertEqual(d["mac_title"], "Click to copy")
        self.assertEqual(d["ip_title"], "Click to copy")
        self.assertEqual(d["after_click"]["copied"], [self.UA])
        self.assertFalse(d["after_click"]["open"])  # copying does not open the drawer
        fb = d["after_click"]["feedback"]
        self.assertTrue(fb["cls"])
        self.assertEqual(fb["title"], "Copied")
        self.assertEqual(fb["bubble"], '"Copied"')
        self.assertEqual(fb["position"], "absolute")  # over the text, not in the flow
        self.assertEqual(d["keys"]["copied"], [self.UA, "10.0.1.20", "10.0.1.20", self.UA])
        self.assertFalse(d["keys"]["open"])
        self.assertEqual(d["tab_to"], "c-mac mono")
        self.assertEqual(d["keys"]["role"], ["button", 0])

    def test_archive_hides_the_row_and_restore_brings_it_back(self) -> None:
        d = self.result("archive")
        self.assertEqual(d["before"]["label"], "Archive")
        self.assertIn(self.OTHER, d["before"]["rows"])
        # archived: the row leaves the list (the drawer stays open on it), the total card no longer counts it
        self.assertNotIn(self.OTHER, d["archived"]["rows"])
        self.assertEqual(d["archived"]["label"], "Restore to list")
        self.assertIsInstance(d["archived"]["server"], int)
        self.assertEqual(int(d["archived"]["total"]), int(d["before"]["total"]) - 1)
        # the "Archived" status filter shows only archived devices
        self.assertEqual(d["filter"]["rows"], [self.OTHER])
        # restore from the drawer: back in the list
        self.assertIsNone(d["restored"]["server"])
        self.assertEqual(d["restored"]["label"], "Archive")
        self.assertEqual(d["restored"]["filter_rows"], [])
        self.assertIn(self.OTHER, d["restored"]["rows"])
        self.assertEqual(d["restored"]["total"], d["before"]["total"])

    def test_hover_and_copy_keep_the_table_width(self) -> None:
        d = self.result("copy")
        for when in ("hover_mac", "hover_ip", "end"):
            with self.subTest(when=when):
                self.assertEqual(d[when], d["before"])
        self.assertEqual(d["after_click"]["widths"], d["before"])


class BrowserLongTextTest(_BrowserCase):
    """Long Type and "Connected via" text: neither the table nor the page scrolls sideways at laptop and desktop
    widths, and a cell that is cut short still offers its full text as a title."""
    WIFI, WIFI2, PORT, PLAIN = "02:00:00:00:20:01", "02:00:00:00:20:02", "02:00:00:00:20:03", "02:00:00:00:20:04"
    WHERE = {WIFI: ("HomeNet-Upstairs-Guest-5GHz-Extended", "ap-upstairs-hallway-ceiling-east", -67, "", ""),
             WIFI2: ("HomeNet-Downstairs-IoT-2GHz-Legacy", "ap-basement-workshop-wall-north", -81, "", ""),
             PORT: ("", "", None, "GigabitEthernet1/0/24", "sw-garage-poe-16-port-desk"),
             PLAIN: ("", "", None, "", "")}

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(m: str, n: int, lease_type: str) -> Sighting:
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=f"alex-workstation-upstairs-{n}", vendor="Acme Networks",
                            vlan="HomeNet", iface="lan", source="dhcp" if lease_type else "arp", lease_type=lease_type,
                            online=True)
        # "fixed address" is the longest Type text
        base, db = start(cls, [s(cls.WIFI, 20, ""), s(cls.WIFI2, 21, "static"), s(cls.PORT, 22, ""),
                               s(cls.PLAIN, 23, "dynamic")])
        for m, (ssid, ap, sig, port, via) in cls.WHERE.items():
            db.q("UPDATE devices SET wifi_ssid=?, wifi_ap=?, wifi_signal=?, sw_port=?, sw_via=? WHERE mac=?",
                 (ssid, ap, sig, port, via, m))
        cls.run_scenarios(base, ("longtext",))

    def test_no_horizontal_scroll(self) -> None:
        d = self.result("longtext")
        for width in ("1280", "1366", "1440", "1920"):
            with self.subTest(width=width):
                self.assertLessEqual(d[width]["table_scroll"], 0, d[width])
                self.assertLessEqual(d[width]["page_scroll"], 0, d[width])

    def test_full_text_in_title(self) -> None:
        cells = self.result("longtext")["cells"]
        self.assertEqual(set(cells), set(self.WHERE))
        for m, (ssid, ap, sig, port, via) in self.WHERE.items():
            with self.subTest(mac=m):
                c = cells[m]
                self.assertEqual(c["type"]["title"], c["type"]["text"])
                self.assertEqual(c["where"]["title"], " ".join(c["where"]["text"].split()))  # the signal too
                for part in (ssid, ap, port, via) + ((f"{sig} dBm",) if sig is not None else ()):
                    self.assertIn(part, c["where"]["title"])
        self.assertEqual(cells[self.WIFI]["type"]["title"], "fixed address")
        self.assertEqual(cells[self.PLAIN]["where"]["title"], "")


class BrowserSsidWidthTest(_BrowserCase):
    """Long SSID names, a NEW private-MAC row and a NEW watched row with a 19-character name (two badges beside it):
    no sideways scroll at phone widths, filtered or not."""
    S32, S40 = "Guest-Network-Long-SSID-Name-32c", "VeryLongNetworkNameWithoutAnyBreaksAtAll"
    MACS = ("02:00:00:00:31:01", "02:00:00:00:31:02", "02:00:00:00:31:03", "02:00:00:00:31:04")

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(m: str, n: int, host: str) -> Sighting:
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan",
                            source="dhcp", lease_type="dynamic", online=True)
        a, b, c, w = cls.MACS
        # c and w appear after the baseline: NEW
        base, db = start(cls, [s(a, 40, "laptop"), s(b, 41, "phone")],
                         [s(c, 42, "newcomer"), s(w, 43, "living-room-speaker")])
        db.q("UPDATE devices SET watch=1 WHERE mac=?", (w,))
        now = int(time.time())
        for m, ssid in ((a, cls.S32), (b, cls.S40), (c, cls.S32)):
            db.q("INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) VALUES(?,?,?,?,?,?,?)",
                 (m, ssid, now - 86400, now, 3600, 1, "ap-1"))
            db.q("UPDATE devices SET wifi_ssid=?, online=1 WHERE mac=?", (ssid, m))
        cls.run_scenarios(base, ("ssidwidth",))

    def test_no_horizontal_scroll_at_400_and_360_px(self) -> None:
        d = self.result("ssidwidth")
        for name in ("none", "ever32", "now32", "ever40"):
            for width in (400, 360):
                with self.subTest(case=name, width=width):
                    r = d[f"{name}_{width}"]
                    self.assertGreater(r["rows"], 0, r)
                    if name == "none":
                        self.assertEqual(r["watched_new"], ["living-room-speaker"], r)
                    self.assertLessEqual(r["table_scroll"], 0, r)
                    self.assertLessEqual(r["page_scroll"], 0, r)
                    self.assertEqual(r["over"], [], r)


class BrowserTagsTest(_BrowserCase):
    """Tags: typed in the drawer and normalised by the server, badges in the row, the chip row and its ?tag= filter, a
    refused tag, and a row with eight long tags at phone widths."""
    A, B, W = "02:00:00:00:50:01", "02:00:00:00:50:02", "02:00:00:00:50:03"

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(m: str, n: int, host: str, online: bool) -> Sighting:
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan",
                            source="dhcp", lease_type="dynamic", online=online)
        base, _db = start(cls, [s(cls.A, 50, "thermostat", True), s(cls.B, 51, "printer", False),
                                s(cls.W, 52, "living-room-speaker", True)])
        cls.run_scenarios(base, ("tags",))

    def test_no_chip_row_without_tags(self) -> None:
        d = self.result("tags")["before"]
        self.assertEqual((d["hidden"], d["chips"], d["tag"]), (True, [], None))
        self.assertEqual(d["badges"], {self.A: [], self.B: [], self.W: []})

    def test_save_posts_tags_and_server_normalises(self) -> None:
        d = self.result("tags")["saved"]
        self.assertEqual(d["body"], {"name": "", "note": "", "tags": "IoT, owner:alex"})
        self.assertEqual(d["server"], "iot,owner:alex")
        self.assertEqual(d["input"], "iot, owner:alex")  # the drawer shows what was stored

    def test_row_badges_and_chips(self) -> None:
        d = self.result("tags")["after"]
        self.assertEqual(d["badges"][self.A], [{"tag": "iot", "text": "iot", "owner": False},
                                               {"tag": "owner:alex", "text": "\U0001F464alex", "owner": True}])
        self.assertEqual(d["badges"][self.B], [])
        self.assertFalse(d["hidden"])
        # the owner chip shows the name only, under its own heading; data-tag and the title keep the full tag
        self.assertEqual([(c["tag"], c["text"], c["n"], c["pressed"]) for c in d["chips"]],
                         [("iot", "iot", "1/1", "false"), ("owner:alex", "alex", "1/1", "false")])
        self.assertEqual(d["chips"][1]["title"], "1 online of 1 device tagged owner:alex")
        self.assertEqual(d["grp"], [{"text": "Tags", "tag": "span", "tabindex": None},
                                    {"text": "Owner", "tag": "span", "tabindex": None}])

    def test_owner_chip_filters_on_the_full_tag(self) -> None:
        r = self.result("tags")
        self.assertEqual((r["owner"]["rows"], r["owner"]["tag"]), ([self.A], "owner:alex"))
        self.assertEqual([c["tag"] for c in r["owner"]["chips"] if c["pressed"] == "true"], ["owner:alex"])
        self.assertIn("tag=owner%3Aalex", r["owner_url"])

    def test_no_headings_with_plain_tags_only(self) -> None:
        d = self.result("tags")["plain"]
        self.assertEqual([c["text"] for c in d["chips"]], ["iot", "speaker"])
        self.assertEqual(d["grp"], [])

    # 14 tags on one device each rank by name: the 12 first as chips, then "+2 more"
    TAGS14 = sorted(["living-room-speaker-01", "owner:alexandra-long", "upstairs-hallway-ceil", "media-streaming-box",
                     "firmware-pinned-v2", "kids-bedtime-schedule", "guest-network-allowed", "energy-monitoring-on"]
                    + [f"printer-{c}" for c in "abcdef"])

    @staticmethod
    def _plain_first(tags: list[str]) -> list[str]:  # the row order: plain tags, then the owners
        return [t for t in tags if not t.startswith("owner:")] + [t for t in tags if t.startswith("owner:")]

    def test_twelve_chips_then_more(self) -> None:
        r = self.result("tags")
        self.assertEqual(r["capped"]["chips"], self._plain_first(self.TAGS14[:12]))
        self.assertEqual(r["capped"]["more"], "+2 more")
        # "+2 more" shows all 14 and goes away; the focus moves to the first chip it brought in
        self.assertEqual((r["all"]["chips"], r["all"]["more"]), (self._plain_first(self.TAGS14), None))
        self.assertEqual(r["all"]["focus"], "printer-f")

    def test_active_tag_beyond_the_cap(self) -> None:
        r = self.result("tags")
        self.assertEqual(r["far"]["chips"], self._plain_first(self.TAGS14[:12] + ["upstairs-hallway-ceil"]))
        self.assertEqual(r["far"]["more"], "+1 more")
        # "+1 more" focuses the one tag it brought in, not the one already shown
        self.assertEqual((len(r["far_more"]["chips"]), r["far_more"]["more"], r["far_more"]["focus"]), (14, None, "printer-f"))

    def test_clicking_off_a_chip_beyond_the_cap_keeps_the_focus_in_the_row(self) -> None:
        d = self.result("tags")["far_off"]
        self.assertEqual((d["chips"], d["more"]), (self._plain_first(self.TAGS14[:12]), "+2 more"))
        self.assertEqual(d["focus"], "tagMore")

    def test_chip_filters_and_reload_keeps_it(self) -> None:
        r = self.result("tags")
        for name in ("filtered", "reloaded"):
            with self.subTest(step=name):
                d = r[name]
                self.assertEqual((d["rows"], d["tag"]), ([self.A], "iot"))
                self.assertEqual([c["tag"] for c in d["chips"] if c["pressed"] == "true"], ["iot"])

    def test_clear_filters_resets_the_tag(self) -> None:
        d = self.result("tags")["cleared"]
        self.assertEqual((d["tag"], d["rows"]), (None, sorted([self.A, self.B, self.W])))
        self.assertEqual([c for c in d["chips"] if c["pressed"] == "true"], [])

    def test_refused_tag_shows_the_reason_and_keeps_the_input(self) -> None:
        d = self.result("tags")["refused"]
        self.assertTrue(d["banner"].startswith("Save failed: "), d["banner"])
        self.assertIn("tag!", d["banner"])
        self.assertEqual((d["input"], d["open"], d["server"]), ("tag!", True, ""))

    def test_many_badges_wrap_without_sideways_scroll(self) -> None:
        r = self.result("tags")
        for width in ("400", "360"):
            with self.subTest(width=width):
                d = r[width]
                self.assertGreater(d["lines"], 1, d)
                self.assertLessEqual(d["table_scroll"], 0, d)
                self.assertLessEqual(d["page_scroll"], 0, d)
                self.assertEqual(d["over"], [], d)


class BrowserIp6Test(_BrowserCase):
    """The IPv6 line: under the IPv4 text in the IP column and in the phone meta line, in the drawer and in the search,
    for one device with an address and one without."""
    A, B = "02:00:00:00:60:01", "02:00:00:00:60:02"
    V6 = "2001:db8:1234:5600:211:22ff:fe33:4455"  # a real-length address: 37 characters

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(m: str, n: int, host: str) -> Sighting:
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan",
                            source="dhcp", lease_type="dynamic", online=True)
        base, db = start(cls, [s(cls.A, 60, "thermostat"), s(cls.B, 61, "printer")])
        db.q("UPDATE devices SET ip6=? WHERE mac=?", (cls.V6, cls.A))
        cls.run_scenarios(base, ("ipv6",))

    def test_row_shows_the_v6_line_under_the_v4_text(self) -> None:
        a = self.result("ipv6")["a"]
        self.assertEqual((a["v4"], a["v4_title"]), ("10.0.1.60", "Click to copy"))
        self.assertEqual((a["v6"], a["v6_title"], a["v6_visible"], a["v6_below"]), (self.V6, self.V6, True, True))
        self.assertEqual((a["v6_role"], a["v6_tab"], a["meta_v6"]), ("button", 0, self.V6))

    def test_no_v6_element_without_an_address(self) -> None:
        b = self.result("ipv6")["b"]
        self.assertEqual((b["v4"], b["v6"], b["v6_visible"], b["meta_v6"]), ("10.0.1.61", None, False, None))
        self.assertEqual((b["focusable"], b["meta_focusable"]), (1, 0))  # the IPv4 text only
        self.assertEqual(self.result("ipv6")["a"]["focusable"], 2)

    def test_drawer_row_for_the_device_with_an_address_only(self) -> None:
        r = self.result("ipv6")
        self.assertEqual(r["drawer_a"], [["IPv6", self.V6, "mono"]])
        self.assertEqual(r["drawer_b"], [])

    def test_search_finds_the_address(self) -> None:
        self.assertEqual(self.result("ipv6")["search"], ["thermostat"])

    def test_click_copies_the_address(self) -> None:
        r = self.result("ipv6")
        self.assertEqual((r["copied"], r["open_after_copy"], r["copied_cls"]), ([self.V6], False, True))
        self.assertEqual(r["title_after"], self.V6)

    def test_phone_layout_keeps_two_lines_and_no_sideways_scroll(self) -> None:
        r = self.result("ipv6")
        for width in ("400", "360"):
            with self.subTest(width=width):
                d = r[width]
                self.assertEqual((d["meta_v6"], d["meta_v6_title"], d["meta_v6_visible"], d["col_v6_visible"]),
                                 (self.V6, self.V6, True, False), d)
                self.assertLessEqual(d["lines_a"], 2, d)
                self.assertLessEqual(d["table_scroll"], 0, d)
                self.assertLessEqual(d["page_scroll"], 0, d)
                self.assertEqual(d["over"], [], d)

    def test_focused_meta_address_survives_a_rebuild_and_enter_copies(self) -> None:
        r = self.result("ipv6")
        self.assertTrue(r["meta_focus"]["restored"], r["meta_focus"])
        self.assertEqual(r["meta_enter"], {"copied": [self.V6], "open": False, "cls": True, "title": "Copied"}, r["meta_enter"])


class BrowserLangSvTest(_BrowserCase):
    """?lang=sv: the texts come from the Swedish table (read in the browser, so a new wording does not break the test),
    the server's event text stays English, and the table fits at 800, 1024 and 1280 px. A browser that prefers
    Swedish gets it with no parameter, and ?lang=en overrides that."""
    A, B = "02:00:00:00:70:01", "02:00:00:00:70:02"

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(m: str, n: int, host: str) -> Sighting:
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan",
                            source="dhcp", lease_type="dynamic", online=True)
        # B is there at the start, A comes later: A is new
        base, db = start(cls, [s(cls.B, 71, "printer")], [s(cls.A, 70, "thermostat")])
        db.q("UPDATE devices SET tags=? WHERE mac=?", ("iot,owner:alex", cls.A))
        db.q("INSERT INTO events(ts,mac,kind,detail) VALUES(?,?,?,?)", (int(time.time()), cls.A, "renamed", "(none) -> Hall sensor"))
        cls.run_scenarios(base, ("lang_sv", "lang_auto"))

    def test_texts_come_from_the_swedish_table(self) -> None:
        d = self.result("lang_sv")
        self.assertEqual(d["html_lang"], "sv")
        self.assertEqual(d["sub"]["shown"], d["sub"]["table"])
        self.assertEqual(d["sub"]["shown"], "Vem finns på nätverket, nyast först")  # the owner-facing sample
        for part in (d["new_badge"], d["kind_option"], d["headings"], *d["headers"].values(), *d["drawer"].values()):
            self.assertEqual(part["shown"], part["table"], part)
        self.assertEqual(sorted(d["headers"]), ["th.device", "th.first", "th.last"])
        self.assertEqual(sorted(d["drawer"]), ["drawer.archive", "drawer.save", "drawer.watch"])

    def test_event_kind_is_swedish_and_its_detail_stays_english(self) -> None:
        e = self.result("lang_sv")["event"]
        self.assertEqual(e["kind"], e["table"])
        self.assertEqual(e["detail"], "(none) → Hall sensor")

    def test_tag_headings_and_the_param_survives_a_filter(self) -> None:
        d = self.result("lang_sv")
        self.assertEqual(d["headings"]["shown"], d["headings"]["table"])
        self.assertEqual(d["filtered"], "?filter=new&lang=sv")

    def test_tables_fit_at_desktop_widths(self) -> None:
        for width, d in self.result("lang_sv")["widths"].items():
            with self.subTest(width=width):
                self.assertLessEqual(d["page_scroll"], 0, d)
                self.assertLessEqual(d["table_scroll"], 0, d)
                self.assertEqual(d["th_over"], [], d)

    def test_browser_language_picks_swedish_and_the_param_overrides(self) -> None:
        d = self.result("lang_auto")
        self.assertEqual((d["auto"]["html_lang"], d["auto"]["data_lang"], d["auto"]["sub"]), ("sv", "auto", "Vem finns på nätverket, nyast först"))
        self.assertEqual((d["en"]["html_lang"], d["en"]["sub"], d["en"]["search"]), ("en", "Who is on the network, newest first", "?lang=en"))
        self.assertEqual(d["plain"]["html_lang"], "en")  # the override stayed on its own page


class BrowserSsidTest(_BrowserCase):
    """The Wi-Fi network chips and the SSID filter, on presence rows seeded straight into the DB. One SSID name carries
    markup and quotes, as anyone in radio range can name a network that way."""
    GUEST, HOME = 'Guest <b>&"x</b>', "HomeNet"
    A, B, C, D = "02:00:00:00:30:01", "02:00:00:00:30:02", "02:00:00:00:30:03", "02:00:00:00:30:04"
    SINCE = 1767268800  # 2026-01-01 12:00 UTC: the same calendar day in every time zone a CI runner has

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(m: str, n: int, host: str) -> Sighting:
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan",
                            source="dhcp", lease_type="dynamic", online=True)
        base, db = start(cls, [s(cls.A, 30, "laptop"), s(cls.B, 31, "phone"), s(cls.C, 32, "tablet"), s(cls.D, 33, "desktop")])
        now = cls.now = int(time.time())
        # A: on the guest network now (3.5 h there), earlier on HomeNet; B: was on the guest network, offline now;
        # C: on HomeNet now; D: wired, never on Wi-Fi
        for m, ssid, first, last, secs in ((cls.A, cls.HOME, now - 864000, now - 3600, 7200),
                                           (cls.A, cls.GUEST, now - 172800, now, 12600),
                                           (cls.B, cls.GUEST, now - 86400, now - 10800, 1800),
                                           (cls.C, cls.HOME, now - 3 * 86400, now, 600)):
            db.q("INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) VALUES(?,?,?,?,?,?,?)",
                 (m, ssid, first, last, secs, 1, "ap-1"))
        for m, ssid, online in ((cls.A, cls.GUEST, 1), (cls.B, "", 0), (cls.C, cls.HOME, 1), (cls.D, "", 1)):
            db.q("UPDATE devices SET wifi_ssid=?, online=? WHERE mac=?", (ssid, online, m))
        db.q("INSERT OR REPLACE INTO meta(key, value) VALUES('wifi_presence_since', ?)", (str(cls.SINCE),))
        cls.run_scenarios(base, ("ssids",))

    def test_chip_row_counts_and_titles(self) -> None:
        d = self.result("ssids")
        self.assertFalse(d["hidden"])
        day = datetime.datetime.fromtimestamp(self.SINCE).strftime("%Y-%m-%d")
        self.assertEqual([(c["ssid"], c["text"], c["n"], c["tag"], c["b"]) for c in d["chips"]],
                         [(self.GUEST, self.GUEST, "1/2", "button", 0), (self.HOME, self.HOME, "1/2", "button", 0)])
        self.assertEqual(d["chips"][0]["title"], f"1 online now on {self.GUEST}, 2 devices seen on it since {day}")
        self.assertEqual(d["before"]["heads"], ["First seen", "Last online"])
        self.assertFalse(d["before"]["now_shown"])
        self.assertEqual(d["before"]["markup"], 0)

    def test_chip_filters_to_devices_ever_on_it(self) -> None:
        d = self.result("ssids")["ever"]
        self.assertEqual([r["mac"] for r in d["rows"]], [self.B, self.A])  # newest on the SSID first
        self.assertEqual(d["pressed"], [self.GUEST])
        self.assertEqual((d["ssid"], d["ssidnow"]), (self.GUEST, None))
        self.assertTrue(d["now_shown"])
        self.assertEqual(d["now_pressed"], "false")
        self.assertEqual(d["markup"], 0)

    def test_ssid_times_in_the_rows(self) -> None:
        d = self.result("ssids")["ever"]
        self.assertEqual(d["heads"], ["First on SSID", "Last on SSID"])
        rows = {r["mac"]: r for r in d["rows"]}
        self.assertEqual((rows[self.A]["first"], rows[self.A]["last"]), ("2 d ago", "now"))
        self.assertEqual((rows[self.B]["first"], rows[self.B]["last"]), ("24 h ago", "3 h ago"))
        self.assertTrue(rows[self.A]["meta"].endswith(f" · 3.5 h on {self.GUEST}"), rows[self.A]["meta"])
        self.assertTrue(rows[self.B]["meta"].endswith(f" · 30 min on {self.GUEST}"), rows[self.B]["meta"])

    def test_now_only_narrows_to_online_on_it(self) -> None:
        d = self.result("ssids")["now"]
        self.assertEqual([r["mac"] for r in d["rows"]], [self.A])
        self.assertEqual((d["ssid"], d["ssidnow"], d["now_pressed"]), (self.GUEST, "1", "true"))

    def test_reload_restores_the_filter(self) -> None:
        d = self.result("ssids")["reloaded"]
        self.assertEqual([r["mac"] for r in d["rows"]], [self.A])
        self.assertEqual((d["pressed"], d["now_pressed"]), ([self.GUEST], "true"))
        self.assertEqual(d["heads"], ["First on SSID", "Last on SSID"])

    def test_chip_works_from_the_keyboard(self) -> None:
        d = self.result("ssids")
        off, on = d["key_off"], d["key_on"]
        self.assertEqual((off["ssid"], off["ssidnow"], off["focus"], len(off["rows"])), (None, None, self.GUEST, 4))
        self.assertFalse(off["now_shown"])
        self.assertEqual(off["heads"], ["First seen", "Last online"])
        self.assertEqual([r["mac"] for r in on["rows"]], [self.B, self.A])  # "now only" went with the filter

    def test_clear_filters_resets_the_ssid(self) -> None:
        d = self.result("ssids")["cleared"]
        self.assertEqual((d["ssid"], d["ssidnow"], d["pressed"], len(d["rows"])), (None, None, [], 4))
        self.assertFalse(d["now_shown"])
        self.assertEqual(d["heads"], ["First seen", "Last online"])

    def test_no_horizontal_scroll_with_the_filter_on(self) -> None:
        d = self.result("ssids")
        for width in ("1280", "800", "600"):
            with self.subTest(width=width):
                self.assertLessEqual(d[width]["table_scroll"], 0, d[width])
                self.assertLessEqual(d[width]["page_scroll"], 0, d[width])

    def test_last_on_ssid_is_visible_between_561_and_900_px(self) -> None:
        d = self.result("ssids")
        for width in ("800", "600"):
            with self.subTest(width=width):
                self.assertEqual(d[width]["last_col"], "none")  # the column is gone: the sub line carries its value
                sub = {r["mac"]: r for r in d[width]["sub"]}
                self.assertTrue(all(r["shown"] for r in sub.values()), sub)
                self.assertEqual(sub[self.A]["text"], f"on {self.GUEST} now · 3.5 h")
                self.assertEqual(sub[self.B]["text"], f"last on {self.GUEST} 3 h ago · 30 min")
        for width in ("1280", "400"):  # the column, or the meta line, shows it there
            with self.subTest(width=width):
                self.assertFalse(any(r["shown"] for r in d[width]["sub"]), d[width]["sub"])


class BrowserSsidArchivedTest(_BrowserCase):
    """A device archived after it was on the guest network: out of the Guest list and the chip's count, in the list under
    the Archived filter."""
    A, B, E = "02:00:00:00:31:01", "02:00:00:00:31:02", "02:00:00:00:31:03"

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(m: str, n: int, host: str) -> Sighting:
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan",
                            source="dhcp", lease_type="dynamic", online=True)
        base, db = start(cls, [s(cls.A, 50, "phone"), s(cls.B, 51, "tablet"), s(cls.E, 52, "camera")])
        now = int(time.time())
        for m in (cls.A, cls.B, cls.E):
            db.q("INSERT INTO wifi_presence(mac, ssid, first_seen, last_seen, seconds_seen, polls_seen, last_ap) VALUES(?,?,?,?,?,?,?)",
                 (m, "Guest", now - 86400, now - 600, 1800, 1, "ap-1"))
        db.q("UPDATE devices SET wifi_ssid='Guest', online=1 WHERE mac=?", (cls.A,))
        db.q("UPDATE devices SET online=0 WHERE mac IN (?, ?)", (cls.B, cls.E))
        db.q("UPDATE devices SET archived_ts=? WHERE mac=?", (now - 300, cls.E))
        cls.run_scenarios(base, ("ssidarchived",))

    def test_archived_guest_device_by_status_filter(self) -> None:
        d = self.result("ssidarchived")
        self.assertEqual(d["default_rows"], [self.A, self.B])  # hidden under the default status filter
        self.assertEqual(d["archived_rows"], [self.E])  # shown under Archived

    def test_archived_guest_device_is_not_counted_in_the_chip(self) -> None:
        d = self.result("ssidarchived")
        self.assertEqual((d["chip_before"], d["chip_filtered"], d["chip_archived"]), ("1/2", "1/2", "1/2"))


class BrowserGuestFlowTest(_BrowserCase):
    """Who was on the Guest network: presence written by the real collector, four polls 120 s apart, a fake controller.
    X is on HomeNet, then from poll 3 on Guest under a private MAC (merged into X). Y is on Guest in polls 2 and 3 and
    back on HomeNet in poll 4. Z stays on HomeNet."""
    X, ALIAS, Y, Z = "02:00:00:00:40:01", "06:00:00:00:40:09", "02:00:00:00:40:02", "02:00:00:00:40:03"

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        saved = clean_env(dict(sources("unifi"), **{k: v for k, v in ENV.items() if k not in FW1_ENV}, DATA_DIR=tmp.name))
        cls.addClassCleanup(restore, saved)
        cfg = Config()
        db = Database(cfg.db_path)
        cls.addClassCleanup(db._conn.close)
        client = FakeClient([])
        collector = Collector(cfg, db, client)
        wifi: dict = {}
        swap_client(collector, "unifi", type("U", (), {"clients": lambda s: wifi})())

        def s(m: str, n: int, host: str, online: bool = True) -> Sighting:
            return Sighting(mac=m, ip=f"10.0.1.{n}", hostname=host, vendor="Acme", vlan="HomeNet", iface="lan",
                            source="dhcp", lease_type="dynamic", online=online)
        home, guest = WifiInfo(ssid="HomeNet", ap="ap-hall"), WifiInfo(ssid="Guest", ap="ap-attic")
        t0 = int(time.time()) - 360  # the last poll is now: the page shows no stale banner
        # (what the firewall lists, what the controller lists) per poll
        x, y, z = s(cls.X, 41, "phone"), s(cls.Y, 42, "laptop"), s(cls.Z, 43, "tv")
        xa = s(cls.ALIAS, 41, "phone")
        polls = [([x, y, z], {cls.X: home, cls.Y: home, cls.Z: home}),
                 ([x, y, z], {cls.X: home, cls.Y: guest, cls.Z: home}),
                 ([xa, y, z], {cls.ALIAS: guest, cls.Y: guest, cls.Z: home}),
                 ([xa, y, z], {cls.ALIAS: guest, cls.Y: home, cls.Z: home})]
        for i, (sightings, wifi_now) in enumerate(polls):
            if i == 2:  # the private MAC is merged into X (the merge rules have their own tests)
                db.q("INSERT INTO aliases(mac,device,reason,detail,merged_ts,last_seen) VALUES(?,?,?,?,?,?)",
                     (cls.ALIAS, cls.X, "client-id", "", t0, t0))
            client.sightings_data = sightings
            wifi.clear(); wifi.update(wifi_now)
            with mock.patch("leasewatch.collector.time.time", lambda: t0 + 120 * i):
                collector.run_once()
        srv = serve(cfg, db, "9.9.9-test")
        thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        cls.addClassCleanup(thread.join, 5)
        cls.addClassCleanup(srv.server_close)
        cls.addClassCleanup(srv.shutdown)
        cls.run_scenarios(f"http://127.0.0.1:{srv.server_address[1]}/", ("guestflow",))

    def test_chips_count_now_and_ever(self) -> None:
        d = self.result("guestflow")
        self.assertEqual(sorted((c["ssid"], c["n"]) for c in d["chips"]), [("Guest", "1/2"), ("HomeNet", "2/3")])

    def test_guest_lists_the_devices_ever_on_it(self) -> None:
        d = self.result("guestflow")["list"]
        self.assertEqual(d["heads"], ["First on SSID", "Last on SSID"])
        rows = {r["mac"]: r for r in d["rows"]}
        self.assertEqual(set(rows), {self.X, self.Y})  # the private MAC is no row of its own
        self.assertEqual(rows[self.X]["last"], "now")  # X is on Guest now; Y left
        self.assertNotEqual(rows[self.X]["first"], rows[self.Y]["first"])  # Y joined at poll 2, X at poll 3
        self.assertEqual([r["mac"] for r in d["rows"]], [self.X, self.Y])  # newest on the SSID first

    def test_drawer_of_the_merged_device_has_its_history(self) -> None:
        d = self.result("guestflow")["drawer"]
        self.assertEqual({r[0] for r in d}, {"Guest", "HomeNet"})
        self.assertEqual(len(d), 2)

    def test_guest_csv_has_one_row_per_device(self) -> None:
        d = self.result("guestflow")["csv"]
        self.assertEqual((d["status"], d["type"].split(";")[0]), (200, "text/csv"))
        lines = d["text"].lstrip("﻿").splitlines()
        head = lines[0].split(",")
        self.assertEqual(len(lines) - 1, 2)
        got = {}
        for line in lines[1:]:
            rec = dict(zip(head, next(csv.reader([line]))))
            got[rec["mac"]] = rec
        self.assertEqual(set(got), {self.X, self.Y})
        self.assertTrue(all(float(r["hours_seen"]) > 0 for r in got.values()), got)
        self.assertEqual({r["last_ap"] for r in got.values()}, {"ap-attic"})

    def test_no_horizontal_scroll_at_1280(self) -> None:
        d = self.result("guestflow")["scroll"]
        self.assertLessEqual(d["page"], 0, d)
        self.assertLessEqual(d["table"], 0, d)


class BrowserLabelTest(_BrowserCase):
    """A reservation description (Sighting.label) is the display name of a device with no name, Wi-Fi alias or hostname."""

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        s = Sighting(mac="00:00:5e:00:53:31", ip="10.0.1.31", hostname="", vendor="Acme", vlan="HomeNet", iface="lan",
                     source="dhcp", lease_type="static", online=True, label="Kitchen shelf plug")
        other = Sighting(mac="00:00:5e:00:53:32", ip="10.0.1.32", hostname="laptop", vendor="Acme", vlan="HomeNet", iface="lan",
                         source="dhcp", lease_type="dynamic", online=True, label="Spare")
        base, _db = start(cls, [s, other])
        cls.run_scenarios(base, ("labelsearch",))

    def test_label_is_name_and_searchable(self) -> None:
        d = self.result("labelsearch")
        self.assertEqual(sorted(d["names"]), ["Kitchen shelf plug", "laptop"])  # the hostname outranks the label
        self.assertEqual(d["found"], ["Kitchen shelf plug"])
        self.assertIn("Label", d["dts"])
        self.assertEqual(d["dd"], ["Kitchen shelf plug"])


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
        self.assertEqual(d["idle_enter_renders"], 0)  # Enter with no search pending does not rebuild


class BrowserCollectorStaleTest(_BrowserCase):
    """No poll attempt for longer than the attempt limit: the banner tells to restart, not "Data is stale"."""

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        import leasewatch.web as web
        real = web.make_handler

        def old_process(*a: object) -> type:  # an attempt from before the start counts as none: judged by process age
            h = real(*a)
            h.started -= 7200
            return h

        with mock.patch.object(web, "make_handler", old_process):
            base, db = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new])
        db.set_meta("last_attempt_ts", str(int(time.time()) - 7200))
        cls.run_scenarios(base, ("collector",))

    def test_banner_says_restart(self) -> None:
        text = self.result("collector")["banner"]
        self.assertTrue(text.startswith("Collector has not run a poll since "), text)
        self.assertTrue(text.endswith("restart the service"), text)
        self.assertNotIn("Data is stale", text)


class BrowserSourceEventsTest(_BrowserCase):
    """source_down / source_up events name a connector as plain text: no who button, no drawer."""

    @classmethod
    def setUpClass(cls) -> None:
        base, db = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new])
        with db.tx() as c:
            now = int(time.time())
            c.execute("INSERT INTO events (mac, kind, detail, ts) VALUES ('', 'source_down', 'fw1: boom', ?)", (now,))
            c.execute("INSERT INTO events (mac, kind, detail, ts) VALUES ('', 'source_up', 'fw1: up after 12m', ?)", (now + 1,))
        cls.run_scenarios(base, ("sourceevents",))

    def test_source_events_are_plain_text(self) -> None:
        d = self.result("sourceevents")
        self.assertEqual(d["count"], 2)
        self.assertEqual(sorted("boom" in t for t in d["texts"]), [False, True])
        self.assertTrue(any("up after 12m" in t for t in d["texts"]), d["texts"])
        self.assertEqual(sorted(d["kinds"]), ["k source_down", "k source_up"])
        self.assertFalse(d["who"])
        self.assertFalse(d["drawer_open_after_click"])


class BrowserEventsViewTest(_BrowserCase):
    """The events list: 60 per page with "Load more", a kind select, a date range and the export link."""

    KINDS = ("ip", "hostname", "vlan")

    @classmethod
    def setUpClass(cls) -> None:
        base, db = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new])
        # 150 events, 50 on each of the three days before today (local noon + i seconds), kinds in turn
        noon = datetime.datetime.now().replace(hour=12, minute=0, second=0, microsecond=0)
        with db.tx() as c:
            for i in range(150):
                ts = int((noon - datetime.timedelta(days=3 - i // 50)).timestamp()) + i
                c.execute("INSERT INTO events (mac, kind, detail, ts) VALUES (?, ?, ?, ?)", (mac(1), cls.KINDS[i % 3], f"n{i}", ts))
        cls.run_scenarios(base, ("eventsview", "evinvalid", "evbadday"))

    @staticmethod
    def params(href: str) -> dict:
        parts = urllib.parse.urlsplit(href)
        return {"path": parts.path, **{k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}}

    @staticmethod
    def midnight(day: str, plus: int = 0) -> int:
        y, m, d = map(int, day.split("-"))
        return int((datetime.datetime(y, m, d) + datetime.timedelta(days=plus)).timestamp())

    def test_paging_by_sixty(self) -> None:
        d = self.result("eventsview")
        self.assertEqual((d["first"], d["second"], d["third"]), (60, 120, 150))
        self.assertFalse(d["more_hidden_first"])
        self.assertTrue(d["more_hidden_end"])
        self.assertEqual(d["unique_after_paging"], 150)
        self.assertEqual(d["csv_plain"], "/api/events.csv")

    def test_kind_select_offers_every_kind(self) -> None:
        d = self.result("eventsview")
        values = [o["value"] for o in d["kind_options"]]
        self.assertEqual(values[0], "")
        self.assertEqual(len(values), 24)  # "All" and the 23 kinds the server writes
        for k in ("source_down", "source_up", "lease_type", "merged", "split", "offline", "online", "renamed", "note", "tags", "watched", "unwatched"):
            self.assertIn(k, values)
        self.assertIn({"value": "tags", "text": "tags changed"}, d["kind_options"])
        self.assertIn({"value": "source_down", "text": "source down"}, d["kind_options"])
        self.assertIn({"value": "split", "text": "split address"}, d["kind_options"])

    def test_kind_filter(self) -> None:
        d = self.result("eventsview")
        self.assertEqual(d["kind_rows"], 50)
        self.assertTrue(d["kind_more_hidden"])
        self.assertEqual(self.params(d["kind_csv"]), {"path": "/api/events.csv", "kind": "ip"})
        self.assertEqual(d["kind_url"], "?ek=ip")

    def test_date_range_is_one_local_day(self) -> None:
        d = self.result("eventsview")
        self.assertEqual(d["day_rows"], 50)
        p = self.params(d["day_csv"])
        self.assertEqual(p, {"path": "/api/events.csv", "since": str(self.midnight(d["day"])), "until": str(self.midnight(d["day"], 1))})
        self.assertEqual(d["kind_day_rows"], 16)  # a changed filter starts again at the first page

    def test_from_after_to_shows_no_events_and_asks_for_none(self) -> None:
        d = self.result("evinvalid")
        self.assertEqual(d["asked_on_load"], 0)
        self.assertEqual(d["asked_after_reload"], 0)
        for when in ("loaded", "reloaded"):
            with self.subTest(when=when):
                self.assertEqual(d[when]["items"], 0)
                self.assertTrue(d[when]["empty"])
                self.assertFalse(d[when]["note_hidden"])
                self.assertEqual(d[when]["note"], "From is after To.")
                self.assertTrue(d[when]["csv_hidden"])
                self.assertTrue(d[when]["more_hidden"])
        self.assertGreater(d["fixed"]["items"], 0)  # a valid range brings the list back
        self.assertTrue(d["fixed"]["note_hidden"])

    def test_impossible_day_in_the_address_is_dropped(self) -> None:
        d = self.result("evbadday")
        self.assertEqual(d, {"search": "", "csv": "/api/events.csv", "from": "", "to": ""})

    def test_no_horizontal_scroll(self) -> None:
        d = self.result("eventsview")
        self.assertEqual((d["scroll_1400"], d["scroll_1280"], d["scroll_800"]), (0, 0, 0))


class BrowserReadOnlyTest(_BrowserCase):
    """READ_ONLY=1: the page leaves out every edit control and says why."""

    @classmethod
    def setUpClass(cls) -> None:
        base, db = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new],
                         [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if new], env={"READ_ONLY": "1"})
        db.q("INSERT INTO aliases(mac,device,reason,detail,merged_ts,last_seen) VALUES(?,?,?,?,?,?)",
             ("06:00:00:00:00:99", mac(1), "hostname", "alex-laptop", int(time.time()), int(time.time())))
        cls.run_scenarios(base, ("readonly", "bulkro", "splitro"))

    def test_no_select_mode(self) -> None:
        self.assertEqual(self.result("bulkro"), {"button": "none", "column": "none"})

    def test_merged_addresses_have_no_split_button(self) -> None:
        self.assertEqual(self.result("splitro"), {"table": True, "buttons": 0, "head": ["MAC", "Matched by", "Merged", "Last seen"]})

    def test_drawer_and_rows_are_read_only(self) -> None:
        d = self.result("readonly")
        self.assertFalse(d["can_write"])
        self.assertEqual(d["row_acks"], 0)
        self.assertEqual(d["line"], "Read-only: changes are off on this server")
        self.assertEqual(d["buttons"], [])
        self.assertTrue(d["name_readonly"])
        self.assertTrue(d["note_readonly"])


class BrowserBulkTest(_BrowserCase):
    """The Select mode and the selection bar: a server of its own, as Mark known changes its data."""

    PICK = [mac(6), mac(8), mac(12)]

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        base, db = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new],
                         [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if new])
        db.q("UPDATE devices SET first_seen=first_seen-864000 WHERE baseline=1")
        cls.run_scenarios(base, ("bulk",))

    def test_select_mode_swaps_type_for_checkboxes(self) -> None:
        d = self.result("bulk")
        self.assertIn("c-type", d["before"]["shown"])
        self.assertNotIn("c-sel", d["before"]["shown"])
        self.assertEqual(d["selecting"]["shown"][0], "c-sel")
        self.assertNotIn("c-type", d["selecting"]["shown"])
        self.assertLessEqual(d["selecting"]["sel_width"], 25)
        self.assertLessEqual(d["selecting"]["table_scroll"], 0, d["selecting"])
        self.assertLessEqual(d["selecting"]["page_scroll"], 0, d["selecting"])
        self.assertFalse(d["bar_empty"]["shown"])  # nothing ticked: no bar
        self.assertEqual(d["bar_empty"]["pressed"], "true")
        # leaving the mode restores Type and drops the selection; coming back starts empty
        self.assertEqual(d["left"]["cols"]["shown"], d["before"]["shown"])
        self.assertEqual(d["left"]["sel"], 0)
        self.assertFalse(d["left"]["bar"]["shown"])
        self.assertEqual(d["left"]["bar"]["pressed"], "false")
        self.assertFalse(d["reentered"]["shown"])

    def test_three_rows_marked_known(self) -> None:
        d = self.result("bulk")
        self.assertFalse(d["space_drawer"])  # Space on the box toggles it, no drawer
        self.assertEqual(sorted(d["ticked"]), self.PICK)
        self.assertEqual(d["labels"], ["Select sam-phone", "Select Sam's iPad", "Select plug-2"])
        b = d["bar3"]
        self.assertEqual((b["shown"], b["count"], b["ack"], b["archive"], b["restore"]), (True, "3 selected", True, True, False))
        self.assertTrue(b["some"])
        a = d["after"]
        self.assertFalse(a["bar"]["shown"])
        self.assertEqual(a["new_badges"], 0)
        self.assertEqual(a["server"], [1, 1, 1])
        self.assertEqual(a["acked_events"], 3)
        self.assertEqual(a["ticked"], 0)
        self.assertTrue(a["still_selecting"])

    def test_select_all_visible(self) -> None:
        d = self.result("bulk")
        self.assertEqual(d["all"]["rows"], 8)
        self.assertEqual((d["all"]["bar"]["count"], d["all"]["bar"]["all"], d["all"]["bar"]["some"]), ("8 selected", True, False))
        self.assertFalse(d["none"]["shown"])
        self.assertFalse(d["none"]["all"])
        self.assertEqual((d["one"]["count"], d["one"]["all"], d["one"]["some"]), ("1 selected", False, True))
        self.assertFalse(d["one"]["ack"])  # the one ticked row is known now: no Mark known


class BrowserSelectNarrowTest(_BrowserCase):
    """Select mode below 1280 px with unacked rows and 28-character names: no sideways scroll in the table or the page."""

    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        def s(n: int) -> Sighting:
            return Sighting(mac=f"00:00:5e:00:53:{n:02x}", ip=f"10.0.1.{n}", hostname=f"alex-workstation-upstairs-{n:02d}",
                            vendor="Acme", vlan="HomeNet", iface="lan", source="dhcp", lease_type="dynamic", online=True)
        base, _ = start(cls, [s(1)], [s(n) for n in range(10, 15)])  # five newcomers: unacked
        cls.run_scenarios(base, ("selectnarrow",))

    def test_no_sideways_scroll_in_select_mode(self) -> None:
        d = self.result("selectnarrow")
        for width in ("1280", "1024", "800"):
            with self.subTest(width=width):
                self.assertEqual(d[width]["shown"][0], "c-sel")
                self.assertLessEqual(d[width]["table_scroll"], 0, d[width])
                self.assertLessEqual(d[width]["page_scroll"], 0, d[width])
        self.assertNotIn("c-first", d["1024"]["shown"])


class BrowserAuthTest(_BrowserCase):
    """Basic auth on: the page sends the credentials (page.authenticate) and loads under the same CSP."""

    @classmethod
    def setUpClass(cls) -> None:
        from leasewatch import auth
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        pw = "correct horse battery"
        cls.base, _ = start(cls, [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if not new],
                            [sighting(n, h, net, on) for n, h, net, on, new in DEVICES if new],  # events for "load"
                            env={"AUTH_USER": "alex", "AUTH_PASSWORD_HASH": auth.make_hash(pw, 100_000)})
        cls.run_scenarios(cls.base, ("load", "rows"), creds=f"alex:{pw}")

    def test_without_credentials_401(self) -> None:
        import urllib.error
        import urllib.request
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.base, timeout=10).close()
        cm.exception.close()
        self.assertEqual(cm.exception.code, 401)

    def test_page_loads_with_credentials(self) -> None:
        d = self.result("load")  # zero console errors, failed requests and CSP violations, as every scenario
        self.assertEqual(d["rows"], len(DEVICES))
        self.assertEqual(d["favicon"], {"status": 200, "type": "image/svg+xml"})  # a static file fetched by the page
        self.assertEqual(set(self.result("rows")["names"]), NAMES)


if __name__ == "__main__":
    unittest.main()
