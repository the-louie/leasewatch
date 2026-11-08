"""Regression tests for the UI: the README must describe the status dots the page draws, and app.js behaviour.

The app.js tests cut the named functions out of leasewatch/static/app.js and run them under node with a small stub
DOM (the frontend has no build step and no npm, so there is no jsdom). They are skipped where node is not installed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
NODE = shutil.which("node")


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class ReadmeStatusDotTests(unittest.TestCase):
    # a failing instance gets class "dot bad" (red, var(--danger)), not a grey dot
    def test_readme_failed_dot_is_red_not_grey(self) -> None:
        readme = _read("README.md")
        self.assertNotRegex(readme, r"fail\w*[^.]*\bgreys\b")
        self.assertIn("turns its status dot red", readme)
        self.assertIn("turns its dot in the status pill red", readme)
        self.assertRegex(_read("leasewatch", "static", "style.css"), r"\.dot\.bad\s*\{[^}]*var\(--danger\)")

    # the grey dot the page now draws (an instance not read while polls fail) is documented
    def test_readme_documents_grey_dot_for_unread_instance(self) -> None:
        readme = _read("README.md")
        self.assertTrue(re.search(r"grey dot", readme), "README does not say when a dot is grey")


# ---------- app.js under node ----------

def _statement_end(src: str, i: int, stop_at_semicolon: bool) -> int:
    """Index just past the statement that starts at i: a function body's closing brace, or a ';' at depth 0.

    Skips strings, template literals (with ${} nesting), regex literals and comments, as app.js has quotes inside
    regexes ("esc") and apostrophes inside comments."""
    depth, n = 0, len(src)
    modes: list[tuple[str, int]] = []  # ("`", _) inside a template literal; ("${", depth) inside its expression
    prev = ""  # last significant code character, to tell a regex literal from a division
    while i < n:
        c = src[i]
        if modes and modes[-1][0] == "`":
            if c == "\\":
                i += 2
                continue
            if c == "`":
                modes.pop()
                prev = "`"
            elif c == "$" and src[i + 1:i + 2] == "{":
                modes.append(("${", depth))
                i += 1
            i += 1
            continue
        if c in "\"'":
            j = i + 1
            while src[j] != c:
                j += 2 if src[j] == "\\" else 1
            i, prev = j + 1, c
            continue
        if c == "`":
            modes.append(("`", depth))
            i += 1
            continue
        if c == "/" and src[i + 1:i + 2] == "/":
            i = src.index("\n", i)
            continue
        if c == "/" and src[i + 1:i + 2] == "*":
            i = src.index("*/", i) + 2
            continue
        if c == "/" and (prev == "" or prev in "(,=:[!&|?{};"):
            j, cls = i + 1, False
            while cls or src[j] != "/":
                if src[j] == "\\":
                    j += 1
                elif src[j] == "[":
                    cls = True
                elif src[j] == "]":
                    cls = False
                j += 1
            i = j + 1
            while src[i].isalpha():
                i += 1
            prev = "/"
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if c == "}" and modes and modes[-1] == ("${", depth):
                modes.pop()
                i += 1
                continue
            depth -= 1
            if c == "}" and depth == 0 and not stop_at_semicolon:
                return i + 1
        elif c == ";" and depth == 0 and stop_at_semicolon:
            return i + 1
        if not c.isspace():
            prev = c
        i += 1
    raise ValueError("unterminated statement")


def _extract(src: str, name: str) -> str:
    m = re.search(rf"^[ \t]*(?:async )?function {re.escape(name)}\(", src, re.M)
    if m:
        return src[m.start():_statement_end(src, src.index("{", m.end()), False)]
    m = re.search(rf"^[ \t]*(?:const|let) {re.escape(name)} = ", src, re.M)
    if not m:
        raise LookupError(name)
    return src[m.start():_statement_end(src, m.end(), True)]


# helpers most tests need; each test adds the functions it exercises
BASE = ["state", "esc", "pad", "abs", "rel", "pad3", "ipKey", "ipCmp", "isNew", "label", "typeText", "sourcesText",
        "onWifi", "connLabel", "whereHtml", "whereText", "vlanColor", "VLAN_COLORS", "kindText", "FORM_FIELDS", "formValues", "applyForm", "formEdited", "copyable",
        "aliasesHtml", "wifiHtml", "paintVc", "durText", "ssidRow", "onSsidNow", "tagsOf", "T", "pickLang", "lang", "langParam", "t"]

# the page globals the language code reads, a block outside the rest: a test's own "const location" or
# "const navigator" shadows them instead of clashing. Mutable, so a test can change them and call pickLang() again
PAGE = r"""
const window = { LW_STRINGS: { en: { "app.copied": "Copied", "app.click_to_copy": "Click to copy",
  "app.copy_hint": "selected: press Ctrl+C to copy", "count.devices": { one: "{n} device", other: "{n} devices" } }, sv: {} } };
const location = { pathname: "/", search: "" };
const navigator = { languages: ["en-US"] };
"""

# a stub DOM: enough of Element for renderTable, renderStatus and the drawer. Elements are made on first lookup.
DOM = r"""
const focusLog = [];
const document = { activeElement: null, getElementById: id => byId[id] || null, documentElement: { lang: "en", dataset: { lang: "" } },
  createDocumentFragment: () => ({ kids: [], appendChild(x) { this.kids.push(x); } }),
  createRange: () => ({ selectNodeContents() {} }), execCommand: () => { calls.exec = (calls.exec || 0) + 1; return false; } };
const calls = {};
const getSelection = () => ({ removeAllRanges() {}, addRange() { calls.selected = true; } });
class El {
  constructor(tag) {
    this.tagName = tag || "DIV"; this.kids = {}; this.dataset = {}; this.style = { setProperty() {} }; this.title = "";
    this.textContent = ""; this._html = ""; this.className = ""; this.value = ""; this.parent = null; this.isConnected = true;
    const set = new Set(); this.classList = { add: (...a) => a.forEach(x => set.add(x)), remove: (...a) => a.forEach(x => set.delete(x)),
      toggle: (x, on) => { if (on === undefined) on = !set.has(x); on ? set.add(x) : set.delete(x); return on; }, contains: x => set.has(x) };
  }
  get innerHTML() { return this._html; } set innerHTML(h) { this._html = h; if (this.onHtml) this.onHtml(h); }
  q(sel) { if (!(sel in this.kids)) { const k = new El(); k.parent = this; this.kids[sel] = k; } return this.kids[sel]; }
  insertAdjacentHTML(_, h) { this._html += h; }
  remove() { this.removed = true; }
  closest(t) { let e = this; while (e && e.tagName !== t.toUpperCase()) e = e.parent; return e; }
  contains(x) { while (x) { if (x === this) return true; x = x.parent; } return false; }
  focus(opts) { focusLog.push(opts || null); document.activeElement = this; }
  setSelectionRange() {}
  setAttribute() {}
  querySelectorAll() { return []; }
}
const byId = {};
const rows = new El("TBODY"); rows.list = [];
rows.onHtml = () => { rows.list.forEach(r => { r.parent = null; }); rows.list = []; };
rows.appendChild = f => { for (const k of f.kids) { k.parent = rows; rows.list.push(k); } };
const tpl = { content: { cloneNode: () => ({ firstElementChild: new El("TR") }) } };
const body = new El(); body.parent = null;
// the drawer body: pick the controls out of the HTML the code writes, as a browser would build them
body.onHtml = h => {
  for (const id of ["fName", "fNote", "fTags", "fSave", "fAck", "fArch", "fWatch", "fSaved"]) delete byId[id];
  const kv = /<dl class="kv">([\s\S]*?)<\/dl>/.exec(h);
  body.kv = new El("DL"); body.kv.parent = body; body.kv._html = kv ? kv[1] : "";
  const name = /id="fName"[^>]*value="([^"]*)"/.exec(h);
  if (name) { byId.fName = new El("INPUT"); byId.fName.value = name[1]; }
  const note = /<textarea id="fNote"[^>]*>([^<]*)<\/textarea>/.exec(h);
  if (note) { byId.fNote = new El("TEXTAREA"); byId.fNote.value = note[1]; }
  const tags = /id="fTags"[^>]*value="([^"]*)"/.exec(h);
  if (tags) { byId.fTags = new El("INPUT"); byId.fTags.value = tags[1]; }
  for (const id of ["fSave", "fAck", "fArch", "fWatch"]) { const m = new RegExp(`<button class="([^"]*)" id="${id}">([^<]*)<`).exec(h); if (m) { byId[id] = new El("BUTTON"); byId[id].className = m[1]; byId[id].textContent = m[2]; } }
  if (/id="fSaved"/.test(h)) byId.fSaved = new El("SPAN");
  for (const id of ["fName", "fNote", "fTags", "fSave", "fAck", "fArch", "fWatch", "fSaved"]) if (byId[id]) byId[id].parent = body;
};
const els = { "#rows": rows, "#rowTpl": tpl, "#dBody": body };
const $ = (s, el) => {
  if (el && el !== body) return el.kids[s]?.removed ? null : el.q(s);
  if (el === body || s.startsWith("#f")) { if (s === "dl.kv") return body.kv; return byId[s.slice(1)] || null; }
  return els[s] ??= new El();
};
const $$ = s => s === "#rows tr" ? rows.list.slice() : [];
"""


def _run(names: list[str], script: str) -> dict:
    src = _read("leasewatch", "static", "app.js")
    code = "\n".join(_extract(src, n) for n in dict.fromkeys(BASE + names))
    # wrapped in a function: the stubs (navigator, setTimeout, location, ...) shadow node's own globals
    prog = f"(async () => {{\n'use strict';\nconst out = {{}};\n{PAGE}\n{{\n{DOM}\n{script.split('//--')[0]}\n{code}\n" \
           f"{script.split('//--')[1] if '//--' in script else script}\nconsole.log(JSON.stringify(out));\n}}\n}})()" \
           ".catch(e => { console.error(e); process.exit(3); });"
    p = subprocess.run([NODE, "-e", prog], capture_output=True, text=True, timeout=30)
    if p.returncode:
        raise AssertionError(f"node failed: {p.stderr[-2000:]}")
    return json.loads(p.stdout.strip().splitlines()[-1])


@unittest.skipUnless(NODE, "node is not installed")
class AppJsTests(unittest.TestCase):
    def test_extractor_finds_every_helper(self) -> None:
        src = _read("leasewatch", "static", "app.js")
        for n in BASE + ["renderStatus", "renderTable", "refreshDrawer", "setFields", "seenHtml", "syncUrl", "filtered"]:
            self.assertTrue(_extract(src, n).rstrip().endswith((";", "}")), n)

    # every kind the events filter offers has a label (no raw kind name falls through) and a colour
    def test_kind_text_knows_every_filter_kind(self) -> None:
        out = _run(["EV_KINDS"], "//--\nout.kinds = EV_KINDS.flatMap(g => g[1]);")
        self.assertEqual(len(out["kinds"]), 23)
        css, src = _read("leasewatch", "static", "style.css"), _extract(_read("leasewatch", "static", "app.js"), "kindText")
        for k in out["kinds"]:
            with self.subTest(kind=k):
                self.assertRegex(src, rf"\b{k}: \"")  # a label entry, not the fallback to the raw kind
                self.assertRegex(css, rf"\.k\.{k}\b")

    # an SSID-less Wi-Fi row that a switch has since placed on a port is wired, as before;
    # a live SSID-less client (no stored port) still shows as Wi-Fi
    def test_stale_ssidless_wifi_with_switch_port_is_wired(self) -> None:
        out = _run(["filtered"], r"""//--
const stale = { mac: "02:00:00:00:00:01", wifi_ssid: "", wifi_ap: "ap-hall", link: "wifi", sw_port: "GE1/0/5", sw_via: "", loc_source: "sw1", vlan: "LAN", ip: "10.0.0.5" };
const live = { mac: "02:00:00:00:00:02", wifi_ssid: "", wifi_ap: "ap-hall", link: "wifi", sw_port: "", sw_via: "", loc_source: "unifi", vlan: "LAN", ip: "10.0.0.6" };
state.devices = [stale, live];
out.where = whereText(stale); out.html = whereHtml(stale, false); out.live = whereHtml(live, false);
state.status = "wired"; out.wired = filtered().map(d => d.mac);
state.status = "wifi"; out.wifi = filtered().map(d => d.mac);
state.status = "all"; state.q = "ge1/0/5"; out.search = filtered().map(d => d.mac);
""")
        self.assertEqual(out["where"].strip(), "GE1/0/5")
        self.assertNotIn("ap-hall", out["html"])
        self.assertEqual(out["wired"], ["02:00:00:00:00:01"])
        self.assertEqual(out["wifi"], ["02:00:00:00:00:02"])
        self.assertEqual(out["search"], ["02:00:00:00:00:01"])
        self.assertIn("ap-hall", out["live"])

    # a controller never places a switch port, so it is not named after one; a switch still is
    def test_port_not_labelled_with_controller(self) -> None:
        out = _run([], r"""//--
state.meta = { connectors: [{ name: "sw1", label: "sw-rack", type: "snmp_switch" }, { name: "unifi", label: "Wi-Fi", type: "unifi" }] };
out.ctl = whereHtml({ link: "wired", sw_port: "GE1/0/5", sw_via: "", loc_source: "unifi" }, true);
out.sw = whereHtml({ link: "wired", sw_port: "GE1/0/5", sw_via: "", loc_source: "sw1" }, true);
""")
        self.assertNotIn("Wi-Fi", out["ctl"])
        self.assertIn("GE1/0/5", out["ctl"])
        self.assertIn("on sw-rack", out["sw"])

    # a last good poll in the future (clock stepped back) proves nothing: the instance that just failed is red
    def test_failed_instance_red_when_last_poll_in_future(self) -> None:
        out = _run(["renderStatus"], r"""const showBanner = () => {};
//--
const now = Math.round(Date.now() / 1000);
const conns = [{ name: "fw1", label: "fw1", ok: false, error: "boom", ts: now }, { name: "sw1", label: "sw", ok: true, error: "", ts: now - 700 }];
state.meta = { now, stale: true, last_poll_ts: now + 86400, last_poll_ok: false, last_error: "boom", poll_seconds: 60, last_raw: "", new_days: 7, connectors: conns };
renderStatus(); out.future = $("#statusText").innerHTML;
state.meta = { ...state.meta, stale: false, last_poll_ts: now - 600 };
renderStatus(); out.normal = $("#statusText").innerHTML;
""")
        self.assertIn('title="fw1: boom"><span class="dot bad">', out["future"])
        # with a sane clock an instance not read since the last good poll is grey
        self.assertIn('title="fw1: boom"><span class="dot bad">', out["normal"])
        self.assertIn('<span class="dot "></span>sw', out["normal"])

    # restoring focus after a re-render must not scroll the focused row back into view
    def test_focus_restore_does_not_scroll(self) -> None:
        out = _run(["renderTable", "filtered"], r"""const setFields = () => {}, openDrawer = () => {};
//--
state.meta = { now: 2000000000, new_days: 7, baseline_ts: 1 };
state.devices = [1, 2].map(i => ({ mac: `02:00:00:00:00:0${i}`, ip: `10.0.0.${i}`, vlan: "LAN", baseline: 1, acked: 0, first_seen: 1, last_seen: 1 }));
renderTable();
const tr = rows.list.find(t => t.dataset.mac === "02:00:00:00:00:02"); document.activeElement = tr;
renderTable();
out.focused = document.activeElement.dataset.mac; out.opts = focusLog[focusLog.length - 1];
""")
        self.assertEqual(out["focused"], "02:00:00:00:00:02")
        self.assertEqual(out["opts"], {"preventScroll": True})

    # the age in a Seen-by line uses the same (server) clock as its "on the wire" badge
    def test_seen_line_age_uses_server_clock(self) -> None:
        out = _run(["seenHtml"], r"""//--
const srv = 2000000000; Date.now = () => (srv + 660) * 1000; state.skew = -660;
state.meta = { grace_minutes: 10, connectors: [{ name: "fw1", label: "fw1" }] };
out.ahead = seenHtml([{ source: "fw1", last_seen: srv - 30, last_present: srv - 30 }]);
Date.now = () => (srv - 660) * 1000; state.skew = 660;
out.behind = seenHtml([{ source: "fw1", last_seen: srv - 700, last_present: srv - 500 }]);
""")
        self.assertIn("fw1 · just now · ", out["ahead"])
        self.assertIn("on the wire", out["ahead"])
        self.assertIn("fw1 · 12 min ago · ", out["behind"])

    DRAWER = r"""const history = { replaceState() {} }, location = { pathname: "/" };
const server = { mac: "02:00:00:00:00:01", name: "", note: "", acked: 0, baseline: 0, vlan: "LAN", ip: "10.0.0.5", first_seen: 1, last_seen: 1, sources: "arp" };
let typing = null, failGet = false, posts = [];
const api = async (path, opts) => {
  if (opts?.method) { posts.push(JSON.parse(opts.body)); await null; if (typing) await typing(); Object.assign(server, JSON.parse(opts.body)); server.acked = server.acked ? 1 : 0; return { ok: true }; }
  if (failGet) throw new Error("timeout");
  return { device: { ...server }, history: [], events: [], seen: [] };
};
const showBanner = m => { out.banner = m; };
const setTimeout = () => 0;
const confirm = () => true; // "Discard unsaved changes?" answered OK
//--
const load = async () => { if (state.open) await refreshDrawer(state.open, false); };
state.meta = { now: 2000000000, new_days: 7, baseline_ts: 1, connectors: [] };
const known = () => /<dt>Known<\/dt><dd>([^<]*)/.exec(body.kv.innerHTML)[1];
"""

    # an ack saved while the user types shows the new Known state and toggle, and keeps the typed text
    def test_ack_with_typing_in_flight_updates_known_and_toggle(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], self.DRAWER + r"""
state.open = server.mac; await refreshDrawer(server.mac, true);
typing = () => { byId.fNote.value = "typed"; typing = null; };
await byId.fAck.onclick();
out.known = known(); out.label = byId.fAck.textContent; out.note = byId.fNote.value; out.acked = server.acked;
await byId.fAck.onclick(); out.second = posts[posts.length - 1].acked;
""")
        self.assertEqual(out["acked"], 1)
        self.assertTrue(out["known"].startswith("yes, marked"), out["known"])
        self.assertEqual(out["label"], "Mark unknown")
        self.assertEqual(out["note"], "typed")
        self.assertIs(out["second"], False)

    # Tags is a form field: Save posts it with Name and Note, and a typed tag is an unsaved edit until then
    def test_tags_are_a_form_field(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], self.DRAWER + r"""
out.fields = FORM_FIELDS;
server.tags = "iot,owner:alex";
state.open = server.mac; await refreshDrawer(server.mac, true);
out.shown = byId.fTags.value; out.clean = formEdited(server.mac);
byId.fTags.value = "iot, printer"; out.dirty = formEdited(server.mac);
await byId.fSave.onclick();
out.body = posts[posts.length - 1]; out.after = formEdited(server.mac);
""")
        self.assertEqual(out["fields"], {"name": "#fName", "note": "#fNote", "tags": "#fTags"})
        self.assertEqual(out["shown"], "iot, owner:alex")
        self.assertEqual((out["clean"], out["dirty"], out["after"]), (False, True, False))
        self.assertEqual(out["body"], {"name": "", "note": "", "tags": "iot, printer"})

    # the tag chips: archived devices left out, most used first, then by name
    def test_tag_counts_sorted_by_use_then_name(self) -> None:
        out = _run(["tagCounts"], r"""//--
const d = (tags, online, archived) => ({ tags, online, archived_ts: archived ? 1 : null });
out.list = tagCounts([d("iot,owner:alex", 1), d("iot", 0), d("printer,owner:alex", 0), d("", 1), d("tv", 1, true), d("b", 1), d("a", 0)]);
out.none = tagCounts([d("", 1), {}]);
""")
        self.assertEqual(out["list"], [{"tag": "iot", "online": 1, "n": 2}, {"tag": "owner:alex", "online": 1, "n": 2},
                                       {"tag": "a", "online": 0, "n": 1}, {"tag": "b", "online": 1, "n": 1},
                                       {"tag": "printer", "online": 0, "n": 1}])
        self.assertEqual(out["none"], [])

    # an owner tag is "owner:" and at least one character; anything else is a plain tag
    def test_owner_of_splits_the_prefix(self) -> None:
        out = _run(["ownerOf"], r"""//--
out.r = ["owner:alex", "owner:a b", "owner:", "owner", "Owner:alex", "my-owner:alex", "iot"].map(ownerOf);
""")
        self.assertEqual(out["r"], ["alex", "a b", None, None, None, None, None])

    # the tag filter matches whole tags; the search box matches tag text too
    def test_tag_filter_and_search(self) -> None:
        out = _run(["filtered"], r"""//--
state.devices = [{ mac: "a", ip: "10.0.0.1", tags: "iot,owner:alex", baseline: 1 }, { mac: "b", ip: "10.0.0.2", tags: "iot-hub", baseline: 1 },
                 { mac: "c", ip: "10.0.0.3", tags: "", baseline: 1 }];
state.tag = "iot"; out.tag = filtered().map(d => d.mac);
state.tag = null; state.q = "alex"; out.q = filtered().map(d => d.mac);
""")
        self.assertEqual(out["tag"], ["a"])
        self.assertEqual(out["q"], ["a"])

    # a failed refresh after a save does not wipe text typed while the save ran
    def test_failed_refresh_after_save_keeps_typed_text(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], self.DRAWER + r"""
state.open = server.mac; await refreshDrawer(server.mac, true);
byId.fName.value = "Alex's iPad";
typing = () => { byId.fNote.value = "typed"; failGet = true; typing = null; };
await byId.fSave.onclick();
out.body = body.innerHTML.slice(0, 40); out.note = byId.fNote?.value ?? null; out.saved = server.name;
""")
        self.assertEqual(out["saved"], "Alex's iPad")
        self.assertNotEqual(out["body"], "<p>timeout</p>")
        self.assertEqual(out["note"], "typed")

    # a baseline device is already known: "Save & mark known" is not the primary action
    def test_baseline_device_ack_button_not_primary(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], self.DRAWER + r"""
server.baseline = 1; state.open = server.mac; await refreshDrawer(server.mac, true);
out.known = known(); out.ack = byId.fAck.className; out.save = byId.fSave.className;
""")
        self.assertEqual(out["known"], "yes, present at the start")
        self.assertNotIn("primary", out["ack"])
        self.assertIn("primary", out["save"])

    COPY = r"""const setFields = () => {}, openDrawer = () => {};
//--
state.meta = { now: 2000000000, new_days: 7, baseline_ts: 1 };
state.devices = [{ mac: "02:00:00:00:00:01", ip: "10.0.0.1", vlan: "LAN", baseline: 1, acked: 0, first_seen: 1, last_seen: 1 }];
renderTable();
const mac = rows.list[0].kids[".c-mac .cp"]; mac.title = "Click to copy";
"""

    # a refused clipboard write falls back to selecting the MAC, as plain HTTP does
    def test_rejected_clipboard_write_falls_back(self) -> None:
        out = _run(["renderTable", "filtered"], "const navigator = { clipboard: { writeText: () => Promise.reject(new Error('NotAllowedError')) } };\n"
                   + self.COPY + r"""
mac.onclick({ stopPropagation() {} }); await new Promise(r => globalThis.setTimeout(r, 10));
out.title = mac.title; out.selected = !!calls.selected; out.exec = calls.exec || 0;
""")
        self.assertTrue(out["selected"])
        self.assertEqual(out["exec"], 1)
        self.assertEqual(out["title"], "selected: press Ctrl+C to copy")

    # the "press Ctrl+C" hint belongs to that click: it is gone once the pointer leaves the cell
    def test_copy_hint_reset_after_leaving(self) -> None:
        out = _run(["renderTable", "filtered"], "const navigator = {};\n" + self.COPY + r"""
mac.onclick({ stopPropagation() {} }); out.hint = mac.title;
mac.onmouseleave?.(); out.after = mac.title;
""")
        self.assertEqual(out["hint"], "selected: press Ctrl+C to copy")
        self.assertEqual(out["after"], "Click to copy")

    # the language: ?lang= first, then the server's data-lang (auto and junk go on), then the browser's first language
    def test_pick_lang_order(self) -> None:
        out = _run([], r"""//--
const el = document.documentElement, pick = (search, data, langs) => {
  location.search = search; el.dataset.lang = data; navigator.languages = langs; return pickLang(); };
out.v = [
  pick("", "", ["en-US"]), pick("", "", ["sv-SE", "en"]), pick("", "", ["SV"]), pick("", "", ["en", "sv"]), pick("", "", []),
  pick("", "sv", ["en-US"]), pick("", "en", ["sv-SE"]), pick("", "auto", ["sv-SE"]), pick("", "xx", ["sv"]),
  pick("?lang=sv", "en", ["en-US"]), pick("?q=a&lang=en", "sv", ["sv-SE"]), pick("?lang=de", "sv", ["en"]), pick("?lang=", "", ["sv"]),
];
navigator.languages = undefined; navigator.language = "sv-FI"; location.search = ""; el.dataset.lang = ""; out.single = pickLang();
navigator.language = undefined; out.none = pickLang();
out.lang = lang; out.param = langParam;
""")
        self.assertEqual(out["v"], ["en", "sv", "sv", "en", "en", "sv", "en", "sv", "sv", "sv", "en", "sv", "sv"])
        self.assertEqual((out["single"], out["none"]), ("sv", "en"))
        self.assertEqual((out["lang"], out["param"]), ("en", None))  # no ?lang= in the address: nothing to keep

    def test_t_fallbacks_plurals_and_params(self) -> None:
        out = _run([], r"""location.search = "?lang=sv";
window.LW_STRINGS.sv = { "a.only_sv": "bara {name}", "count.devices": { one: "{n} enhet", other: "{n} enheter" } };
window.LW_STRINGS.en["a.params"] = "{a} and {b}";
//--
out.lang = lang; out.param = langParam;
out.v = [t("a.only_sv", { name: "x<y" }), t("app.copied"), t("no.such_key"), t("count.devices", { n: 1 }), t("count.devices", { n: 3 }),
         t("count.devices"), t("a.params", { a: 1 }), t("a.params", { a: 0, b: "" }), t("a.only_sv")];
""")
        self.assertEqual((out["lang"], out["param"]), ("sv", "sv"))
        self.assertEqual(out["v"], ["bara x<y", "Copied", "no.such_key", "1 enhet", "3 enheter", "{n} enheter",
                                    "1 and {b}", "0 and ", "bara {name}"])

    def test_t_english_plural_and_no_strings_file(self) -> None:
        out = _run([], r"""//--
out.v = [t("count.devices", { n: 1 }), t("count.devices", { n: 0 }), t("count.devices", { n: 2 })];
""")
        self.assertEqual(out["v"], ["1 device", "0 devices", "2 devices"])
        # i18n.js failed to load: every text is its key, nothing throws
        out = _run([], r"""window.LW_STRINGS = undefined;
//--
out.v = [t("app.copied"), t("count.devices", { n: 2 })];
""")
        self.assertEqual(out["v"], ["app.copied", "count.devices"])

    # a ?lang= from the address stays through a filter change and a clear; it is not a filter
    def test_lang_param_survives_url_writes(self) -> None:
        out = _run(["urlRetry", "syncUrl"], r"""location.search = "?lang=en&q=old"; let url = null;
const history = { replaceState: (_, __, u) => { url = u; } };
//--
state.q = "ap"; syncUrl(); out.filtered = url;
state.q = ""; syncUrl(); out.cleared = url;
""")
        self.assertEqual(out["filtered"], "?q=ap&lang=en")
        self.assertEqual(out["cleared"], "?lang=en")

    # a replaceState the browser throttles is written once the throttle ends, so the URL is not left stale
    def test_throttled_url_write_is_retried(self) -> None:
        out = _run(["urlRetry", "syncUrl"], r"""const timers = []; const setTimeout = f => timers.push(f); const clearTimeout = id => { if (id) timers[id - 1] = null; };
const location = { pathname: "/" }; let throttled = true, url = null;
const history = { replaceState: (_, __, u) => { if (throttled) throw new Error("SecurityError"); url = u; } };
//--
state.q = "ap-h"; syncUrl(); state.q = "ap-hall"; syncUrl();
throttled = false; for (const f of timers.splice(0)) if (f) f();
out.url = url;
""")
        self.assertEqual(out["url"], "?q=ap-hall")

    # an unnamed network sorts after the named ones, as an empty IP or vendor does
    def test_unnamed_network_sorts_last(self) -> None:
        out = _run(["filtered"], r"""//--
state.sort = "vlan";
state.devices = [{ mac: "02:00:00:00:00:01", vlan: "", ip: "10.0.0.1" }, { mac: "02:00:00:00:00:02", vlan: "iot", ip: "10.0.0.2" }];
out.order = filtered().map(d => d.vlan);
""")
        self.assertEqual(out["order"], ["iot", ""])


    def test_dur_text_picks_the_unit_after_rounding(self) -> None:
        out = _run([], r"""//--
out.v = [0, 20, 59, 59.4, 60, 89, 90, 3569, 3570, 3599, 3600, 12600, 172619, 172620, 172799, 172800, 4 * 86400 + 7200].map(durText);
""")
        self.assertEqual(out["v"], ["< 1 min", "< 1 min", "< 1 min", "< 1 min", "1 min", "1 min", "2 min", "59 min", "1.0 h",
                                    "1.0 h", "1.0 h", "3.5 h", "47.9 h",
                                    "2 d 0 h", "2 d 0 h", "2 d 0 h", "4 d 2 h"])

    def test_last_sort_under_an_ssid_filter_follows_the_ssid_column(self) -> None:
        out = _run(["filtered"], r"""//--
const mk = (mac, online, ssid, last, lastOnline) => ({ mac, vlan: "v", ip: "10.0.0." + mac, online, wifi_ssid: ssid, last_online: lastOnline, wifi_presence: [{ ssid: "Guest", first_seen: 1, last_seen: last }] });
// A left Guest 3 days ago and is online on HomeNet now; B was on Guest an hour ago and is offline; C is on Guest now
state.devices = [mk("1", 1, "HomeNet", 1000, 9000), mk("2", 0, "", 9000, 5000), mk("3", 1, "Guest", 9500, 9500)];
state.status = "all"; state.sort = "last_desc";
state.ssid = "Guest"; out.on = filtered().map(d => d.mac);
state.ssid = null; out.off = filtered().map(d => d.mac);
""")
        self.assertEqual(out["on"], ["3", "2", "1"])
        self.assertEqual(out["off"], ["3", "1", "2"])  # without the filter: online first, then the last time online

    # the 60 s refresh that puts focus back in the drawer form must not scroll the drawer body to it
    def test_drawer_poll_refocus_does_not_scroll(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], self.DRAWER + r"""
state.open = server.mac; await refreshDrawer(server.mac, true);
byId.fName.id = "fName"; // the stub sets no ids; refreshDrawer finds the control to refocus by its id
await refreshDrawer(server.mac, false);
out.focused = document.activeElement === byId.fName; out.opts = focusLog[focusLog.length - 1];
""")
        self.assertTrue(out["focused"])
        self.assertEqual(out["opts"], {"preventScroll": True})

    # a baseline device is shown as known already, so its ack button does not offer to "mark known"
    def test_baseline_device_ack_label_not_mark_known(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], self.DRAWER + r"""
server.baseline = 1; state.open = server.mac; await refreshDrawer(server.mac, true);
out.label = byId.fAck.textContent;
""")
        self.assertNotIn("mark known", out["label"])

    # an alias (or name) equal to the hostname is not repeated on the sub-line
    def test_hostname_equal_to_label_not_repeated(self) -> None:
        out = _run(["renderTable", "filtered"], r"""const setFields = () => {}, openDrawer = () => {};
//--
state.meta = { now: 2000000000, new_days: 7, baseline_ts: 1 };
state.devices = [{ mac: "02:00:00:00:00:01", ip: "10.0.0.1", vlan: "LAN", baseline: 1, acked: 0, first_seen: 1, last_seen: 1, name: "", wifi_alias: "ipad", hostname: "ipad", vendor: "Apple" },
  { mac: "02:00:00:00:00:02", ip: "10.0.0.2", vlan: "LAN", baseline: 1, acked: 0, first_seen: 1, last_seen: 1, name: "", wifi_alias: "Alex", hostname: "ipad", vendor: "Apple" }];
renderTable();
out.subs = rows.list.map(t => t.kids[".dev-sub"].innerHTML);
""")
        self.assertEqual(out["subs"], ["Apple", '<span class="host">ipad</span> · Apple'])

    # the status line does not name a firewall "fw1" that the configuration may not have
    def test_status_line_does_not_hardcode_fw1(self) -> None:
        out = _run(["renderStatus"], r"""const showBanner = () => {};
//--
const now = Math.round(Date.now() / 1000);
state.meta = { now, stale: false, last_poll_ts: now, last_poll_ok: true, last_error: "", poll_seconds: 60, last_raw: "arp 5", new_days: 7,
  connectors: [{ name: "gw", label: "gw", ok: true, error: "", ts: now }] };
renderStatus(); out.txt = $("#statusText").innerHTML;
""")
        self.assertNotIn("fw1", out["txt"])
        self.assertTrue(out["txt"].startswith("polled just now"), out["txt"])

    # a slow poll refresh whose GET was served before a save must not rebuild the drawer with the pre-save state
    def test_late_poll_refresh_does_not_overwrite_saved_drawer(self) -> None:
        pre = self.DRAWER.split("//--")[0].replace(
            'if (failGet) throw new Error("timeout");',
            'if (failGet) throw new Error("timeout"); const snap = { ...server }; '
            'if (hold) { const h = hold; hold = null; await h; } return { device: snap, history: [], events: [], seen: [] };')
        pre = pre.replace("let typing = null", "let hold = null, release; let typing = null")
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], pre + "//--" + self.DRAWER.split("//--")[1] + r"""
state.open = server.mac; await refreshDrawer(server.mac, true);
hold = new Promise(r => release = r);
const poll = refreshDrawer(server.mac, false);
await byId.fAck.onclick();
release(); await poll;
out.known = known(); out.label = byId.fAck.textContent; out.acked = server.acked;
""")
        self.assertEqual(out["acked"], 1)
        self.assertTrue(out["known"].startswith("yes, marked"), out["known"])
        self.assertEqual(out["label"], "Mark unknown")


    # a poll refresh that answers before the open's slow refresh still moves focus to Name
    def test_open_focus_survives_an_overtaking_poll_refresh(self) -> None:
        pre = self.DRAWER.split("//--")[0].replace(
            'if (failGet) throw new Error("timeout");',
            'if (failGet) throw new Error("timeout"); const snap = { ...server }; '
            'if (hold) { const h = hold; hold = null; await h; } return { device: snap, history: [], events: [], seen: [] };')
        pre = pre.replace("let typing = null", "let hold = null, release; let typing = null")
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], pre + "//--" + self.DRAWER.split("//--")[1] + r"""
const row = new El("TR"); row.focus(); state.open = server.mac;
hold = new Promise(r => release = r);
const open = refreshDrawer(server.mac, true);
await refreshDrawer(server.mac, false);
release(); await open;
out.focusedIsName = document.activeElement === byId.fName;
""")
        self.assertTrue(out["focusedIsName"])

    # a poll refresh that fails before the open's slow but successful refresh does not leave the error text
    def test_open_success_renders_after_an_overtaking_failed_poll(self) -> None:
        pre = self.DRAWER.split("//--")[0].replace(
            'if (failGet) throw new Error("timeout");',
            'if (failGet) throw new Error("timeout"); const snap = { ...server }; '
            'if (hold) { const h = hold; hold = null; await h; } return { device: snap, history: [], events: [], seen: [] };')
        pre = pre.replace("let typing = null", "let hold = null, release; let typing = null")
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], pre + "//--" + self.DRAWER.split("//--")[1] + r"""
const row = new El("TR"); row.focus(); state.open = server.mac;
hold = new Promise(r => release = r);
const open = refreshDrawer(server.mac, true);
failGet = true; await refreshDrawer(server.mac, false); failGet = false;
release(); await open;
out.hasForm = !!byId.fName; out.focusedIsName = !!byId.fName && document.activeElement === byId.fName;
""")
        self.assertTrue(out["hasForm"])
        self.assertTrue(out["focusedIsName"])

    # text typed during a save and then reverted: the next poll rebuild puts the caret back, not on Name
    def test_poll_rebuild_after_edited_refresh_restores_caret(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], self.DRAWER + r"""
state.open = server.mac; await refreshDrawer(server.mac, true);
byId.fNote.id = "fNote"; byId.fNote.focus(); // the stub sets no ids; refreshDrawer finds the control to refocus by its id
typing = () => { byId.fNote.value = "x"; typing = null; };
await byId.fSave.onclick();
byId.fNote.value = "";
await refreshDrawer(server.mac, false);
out.focusedIsNote = document.activeElement === byId.fNote; out.focusedIsName = document.activeElement === byId.fName;
""")
        self.assertTrue(out["focusedIsNote"])
        self.assertFalse(out["focusedIsName"])

    # a poll reply issued before a save, released after the save's own refresh failed, does not rebuild the
    # form with the pre-save name (the next Save or Ack would post it back)
    def test_stale_poll_reply_after_failed_save_refresh_keeps_saved_name(self) -> None:
        pre = self.DRAWER.split("//--")[0].replace(
            'if (failGet) throw new Error("timeout");',
            'if (failGet) throw new Error("timeout"); const snap = { ...server }; '
            'if (hold) { const h = hold; hold = null; await h; } return { device: snap, history: [], events: [], seen: [] };')
        pre = pre.replace("let typing = null", "let hold = null, release; let typing = null")
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], pre + "//--" + self.DRAWER.split("//--")[1] + r"""
state.open = server.mac; await refreshDrawer(server.mac, true);
hold = new Promise(r => release = r);
const poll = refreshDrawer(server.mac, false); // answered with the pre-save row, reply held
byId.fName.value = "Printer";
typing = () => { failGet = true; typing = null; }; // the save's own refresh fails
await byId.fSave.onclick();
failGet = false; release(); await poll;
out.body = body.innerHTML.slice(0, 40); out.form = state.form; out.server = server.name;
""")
        self.assertEqual(out["server"], "Printer")
        self.assertEqual(out["body"], "<p>timeout</p>")
        self.assertEqual(out["form"]["name"], "Printer")

    # a save on A does not drop the open refresh of B, opened while A's POST ran and answered after it, when
    # load() then fails and no other refresh redraws B
    def test_save_does_not_drop_open_refresh_of_other_device(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], r"""
const devs = { "02:00:00:00:00:01": { mac: "02:00:00:00:00:01", name: "A", note: "", acked: 0, baseline: 0, vlan: "LAN", ip: "10.0.0.5", first_seen: 1, last_seen: 1, sources: "arp" },
  "02:00:00:00:00:02": { mac: "02:00:00:00:00:02", name: "B", note: "", acked: 0, baseline: 0, vlan: "LAN", ip: "10.0.0.6", first_seen: 1, last_seen: 1, sources: "arp" } };
let gate = null, hold = null, release = null;
const api = async (path, opts) => {
  const mac = path.split("/").pop();
  if (opts?.method) { await new Promise(r => { gate = r; }); Object.assign(devs[mac], JSON.parse(opts.body)); return { ok: true }; }
  if (hold) { const h = hold; hold = null; await h; }
  return { device: { ...devs[mac] }, history: [], events: [], seen: [] };
};
const showBanner = m => { out.banner = m; };
const setTimeout = () => 0;
//--
const load = async () => {}; // its Promise.all failed: load() catches that itself and refreshes no drawer
state.meta = { now: 2000000000, new_days: 7, baseline_ts: 1, connectors: [] };
const A = "02:00:00:00:00:01", B = "02:00:00:00:00:02";
state.open = A; await refreshDrawer(A, true);
const save = byId.fSave.onclick(); // A's POST in flight
hold = new Promise(r => { release = r; });
state.open = B; body.innerHTML = '<p class="muted">loading…</p>'; state.form = null;
const openB = refreshDrawer(B, true); // B's GET, issued before A's POST returns
await null; gate(); await save;
release(); await openB; // B's reply arrives after the save
out.hasForm = !!byId.fName; out.name = byId.fName ? byId.fName.value : null; out.banner = out.banner || null;
""")
        self.assertTrue(out["hasForm"], out)
        self.assertEqual(out["name"], "B")
        self.assertIsNone(out["banner"])

    # an older failed open of the same row does not cancel a newer open's Name focus, also when a poll refresh
    # comes between them
    def test_older_failed_open_keeps_newer_open_focus(self) -> None:
        pre = self.DRAWER.split("//--")[0].replace(
            'if (failGet) throw new Error("timeout");',
            'const g = {}; g.p = new Promise((ok, fail) => { g.ok = ok; g.fail = fail; }); gets.push(g); '
            'opts?.signal?.addEventListener("abort", () => g.fail(new Error("aborted"))); await g.p;')
        pre = pre.replace("let typing = null", "const gets = []; let typing = null")
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml", "openDrawer", "closeDrawer", "discardOk", "syncUrl", "urlRetry"],
                   pre + "//--" + self.DRAWER.split("//--")[1] + r"""
const row = new El("TR"); row.focus();
const o1 = openDrawer(server.mac); // the older open: its GET will fail
const o2 = openDrawer(server.mac); // the same row opened again
gets[0].fail(new Error("timeout")); await o1;
const poll = refreshDrawer(server.mac, false); if (gets[2]) gets[2].ok(); await poll;
gets[1].ok(); await o2;
out.hasForm = !!byId.fName; out.focusedIsName = !!byId.fName && document.activeElement === byId.fName;
""")
        self.assertTrue(out["hasForm"])
        self.assertTrue(out["focusedIsName"])

    # close and reopen of the same drawer while a save's POST runs: after the save's refresh the inputs show the
    # saved values, and a later Save does not post the pre-save ones back
    def test_close_reopen_during_save_shows_saved_values(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml", "openDrawer", "closeDrawer", "discardOk", "syncUrl", "urlRetry"], self.DRAWER + r"""
await openDrawer(server.mac);
byId.fName.value = "Printer";
typing = async () => { typing = null; closeDrawer(); await openDrawer(server.mac); }; // the reopen is served the pre-save row
await byId.fSave.onclick();
out.input = byId.fName.value; out.form = state.form.name;
await byId.fSave.onclick(); out.posted = posts[posts.length - 1].name; out.server = server.name;
""")
        self.assertEqual(out["input"], "Printer")
        self.assertEqual(out["form"], "Printer")
        self.assertEqual(out["posted"], "Printer")
        self.assertEqual(out["server"], "Printer")

    # a close while a save's POST runs asks only about text typed after Save
    def test_close_during_save_asks_only_for_text_typed_after_save(self) -> None:
        pre = self.DRAWER.replace('const confirm = () => true;', 'const asked = []; const confirm = m => { asked.push(m); return true; };')
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml", "openDrawer", "closeDrawer", "discardOk", "syncUrl", "urlRetry"], pre + r"""
await openDrawer(server.mac);
byId.fName.value = "Printer";
typing = () => { typing = null; closeDrawer(); out.openAfterClose = state.open; };
await byId.fSave.onclick();
out.askedPlain = asked.length; out.server = server.name;
await openDrawer(server.mac);
byId.fName.value = "Printer 2";
typing = () => { typing = null; byId.fName.value = "Printer 2 hall"; closeDrawer(); };
await byId.fSave.onclick();
out.askedTyped = asked.length - out.askedPlain; out.saving = state.saving;
""")
        self.assertEqual(out["askedPlain"], 0)
        self.assertIsNone(out["openAfterClose"])
        self.assertEqual(out["server"], "Printer")
        self.assertEqual(out["askedTyped"], 1)
        self.assertIsNone(out["saving"])

    # after a failed save the posted text counts as unsaved again
    def test_close_after_failed_save_asks(self) -> None:
        pre = self.DRAWER.replace('const confirm = () => true;', 'const asked = []; const confirm = m => { asked.push(m); return false; };')
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml", "openDrawer", "closeDrawer", "discardOk", "syncUrl", "urlRetry"], pre + r"""
await openDrawer(server.mac);
byId.fName.value = "Printer";
typing = () => { typing = null; throw new Error("HTTP 500"); };
await byId.fSave.onclick();
closeDrawer();
out.asked = asked.length; out.open = state.open;
""")
        self.assertEqual(out["asked"], 1)
        self.assertEqual(out["open"], "02:00:00:00:00:01")

    # the discard prompt and the refresh guard share one "edited" test
    def test_discard_and_refresh_share_formEdited(self) -> None:
        src = _read("leasewatch", "static", "app.js")
        self.assertIn("formEdited(state.open)", _extract(src, "discardOk"))
        self.assertIn("formEdited(mac)", _extract(src, "refreshDrawer"))
        self.assertEqual(src.count("v[k] !== ref[k]"), 1)  # every form field compared once, in formEdited
        self.assertIn("v[k] !== ref[k]", _extract(src, "formEdited"))

    # opening another device from a drawer control keeps the control outside the drawer to return to
    def test_switch_from_drawer_control_keeps_return_target(self) -> None:
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml", "openDrawer", "closeDrawer", "discardOk", "syncUrl", "urlRetry"], self.DRAWER + r"""
const drawer = $("#drawer"); body.parent = drawer; $("#dClose").parent = drawer;
const rowA = new El("TR"); rowA.focus();
await openDrawer(server.mac);
$("#dClose").focus();
await openDrawer("02:00:00:00:00:02");
out.kept = state.returnTo === rowA;
closeDrawer(); out.back = document.activeElement === rowA;
""")
        self.assertTrue(out["kept"])
        self.assertTrue(out["back"])

    # where AbortSignal.any is missing (Chrome < 116, Firefox < 124, Safari < 17.4) the drawer GET, which passes its
    # own signal, still times out after 30 s, and its timer is cleared once the request settles
    def test_drawer_get_keeps_timeout_without_abort_signal_any(self) -> None:
        out = _run(["api"], r"""
const timers = []; const setTimeout = (f, ms) => timers.push({ f, ms, st: true }); const clearTimeout = id => { if (id) timers[id - 1].f = null; };
// timeout() exists but any() does not; its timer is one the test fires, like setTimeout's
const AbortSignal = { timeout: ms => { const c = new AbortController(); timers.push({ f: () => c.abort(new Error("timeout")), ms }); return c.signal; } };
let answer = null;
const fetch = (path, o) => new Promise((ok, fail) => {
  if (answer) return ok(answer);
  o.signal?.addEventListener("abort", () => fail(o.signal.reason || new Error("aborted")));
});
//--
const own = new AbortController();
const p = api("/api/devices/02:00:00:00:00:01", { signal: own.signal }).then(() => "resolved", e => "rejected: " + e.message);
for (const t of timers.filter(t => t.ms === 30000)) t.f?.();
out.stalled = await Promise.race([p, new Promise(r => globalThis.setTimeout(() => r("hung"), 50))]); // node's own timer
// the caller's own abort still cancels it
const own2 = new AbortController();
const p2 = api("/api/devices/02:00:00:00:00:01", { signal: own2.signal }).then(() => "resolved", () => "rejected");
own2.abort(); out.aborted = await p2;
// a reply that arrives in time clears its timer: no late abort fires afterwards
timers.length = 0; answer = { ok: true, json: async () => ({ device: {} }) };
await api("/api/devices/02:00:00:00:00:01", { signal: new AbortController().signal });
out.live = timers.filter(t => t.st && t.f).length;
""")
        self.assertTrue(out["stalled"].startswith("rejected: "), out["stalled"])  # "hung" before the fix
        self.assertEqual(out["aborted"], "rejected")
        self.assertEqual(out["live"], 0)

    # where AbortSignal.timeout is missing (Chrome < 103, Firefox < 100, Safari < 16) a load or a save, which pass no
    # signal of their own, still time out after 30 s
    def test_load_and_save_keep_timeout_without_abort_signal_timeout(self) -> None:
        out = _run(["api"], r"""
const timers = []; const setTimeout = (f, ms) => timers.push({ f, ms }); const clearTimeout = id => { if (id) timers[id - 1].f = null; };
const AbortSignal = {};
const fetch = (path, o) => new Promise((ok, fail) => { o.signal?.addEventListener("abort", () => fail(o.signal.reason || new Error("aborted"))); });
//--
const hung = () => new Promise(r => globalThis.setTimeout(() => r("hung"), 50)); // node's own timer
const p = api("/api/devices").then(() => "resolved", e => "rejected: " + e.name);
const p2 = api("/api/devices/02:00:00:00:00:01", { method: "POST" }).then(() => "resolved", e => "rejected: " + e.name);
for (const t of timers.filter(t => t.ms === 30000)) t.f?.();
out.load = await Promise.race([p, hung()]);
out.save = await Promise.race([p2, hung()]);
""")
        self.assertEqual(out["load"], "rejected: TimeoutError")  # "hung" before the fix
        self.assertEqual(out["save"], "rejected: TimeoutError")

    # a re-render while a MAC or IP copy target has keyboard focus keeps focus on that target
    def test_refresh_keeps_focus_on_copy_target(self) -> None:
        for sel in (".c-mac .cp", ".c-ip .cp"):
            with self.subTest(sel=sel):
                out = _run(["renderTable", "filtered"], r"""const setFields = () => {}, openDrawer = () => {};
//--
state.meta = { now: 2000000000, new_days: 7, baseline_ts: 1 };
state.devices = [1, 2].map(i => ({ mac: `02:00:00:00:00:0${i}`, ip: `10.0.0.${i}`, vlan: "LAN", baseline: 1, acked: 0, first_seen: 1, last_seen: 1 }));
renderTable();
const tr = rows.list.find(t => t.dataset.mac === "02:00:00:00:00:02"); document.activeElement = tr.kids[SEL];
renderTable();
const nt = rows.list.find(t => t.dataset.mac === "02:00:00:00:00:02");
out.same = document.activeElement === nt.kids[SEL]; out.tag = document.activeElement.tagName;
""".replace("SEL", json.dumps(sel)))
                self.assertTrue(out["same"], out["tag"])  # "TR" before the fix

    # the row count leaves archived devices out of the total, as the cards do
    def test_count_total_leaves_archived_out(self) -> None:
        out = _run(["renderTable", "filtered"], r"""const setFields = () => {}, openDrawer = () => {};
//--
state.meta = { now: 2000000000, new_days: 7, baseline_ts: 1 };
state.devices = [1, 2, 3].map(i => ({ mac: `02:00:00:00:00:0${i}`, ip: `10.0.0.${i}`, vlan: "LAN", baseline: 1, acked: 0, first_seen: 1, last_seen: 1, archived_ts: i === 3 ? 123 : null }));
renderTable(); out.all = $("#count").textContent;
state.status = "archived"; renderTable(); out.archived = $("#count").textContent;
""")
        self.assertEqual(out["all"], "2 of 2")  # "2 of 3" before the fix
        self.assertEqual(out["archived"], "1 of 1")

    # the "press Ctrl+C" hint of a keyboard copy goes when focus leaves, as a mouse leave clears it
    def test_copy_hint_reset_after_blur(self) -> None:
        out = _run(["renderTable", "filtered"], "const navigator = {};\n" + self.COPY + r"""
mac.onkeydown({ key: "Enter", preventDefault() {}, stopPropagation() {} }); out.hint = mac.title;
mac.onblur?.(); out.after = mac.title;
""")
        self.assertEqual(out["hint"], "selected: press Ctrl+C to copy")
        self.assertEqual(out["after"], "Click to copy")

    # a second copy keeps its own "Copied" time; the first copy's timer does not end it early
    def test_second_copy_feedback_not_cut_short(self) -> None:
        out = _run(["renderTable", "filtered"], r"""const navigator = { clipboard: { writeText: () => Promise.resolve() } };
const timers = []; const setTimeout = f => timers.push(f); const clearTimeout = id => { if (id) timers[id - 1] = null; };
""" + self.COPY + r"""
mac.onclick({ stopPropagation() {} }); await null; await null;
mac.onclick({ stopPropagation() {} }); await null; await null;
if (timers[0]) timers[0](); // the first copy's 900 ms are up
out.copied = mac.classList.contains("copied"); out.title = mac.title;
""")
        self.assertTrue(out["copied"])  # false before the fix
        self.assertEqual(out["title"], "Copied")

    # Archive posts only the archive state, so it does not flash "saved" over a typed, unsaved Name
    def test_archive_does_not_say_saved(self) -> None:
        pre = self.DRAWER.replace("server.acked = server.acked ? 1 : 0;",
                                  "server.acked = server.acked ? 1 : 0; if ('archived' in server) server.archived_ts = server.archived ? 123 : null;")
        out = _run(["refreshDrawer", "drawerActions", "setFields", "seenHtml"], pre + r"""
state.open = server.mac; await refreshDrawer(server.mac, true);
byId.fName.value = "typed name";
await byId.fArch.onclick();
out.post = posts[posts.length - 1]; out.saved = byId.fSaved?.textContent ?? null; out.label = byId.fArch.textContent;
out.name = byId.fName.value; out.server = server.name; out.edited = formEdited(server.mac);
""")
        self.assertEqual(out["post"], {"archived": True})
        self.assertEqual(out["label"], "Restore to list")
        self.assertEqual(out["saved"], "")  # "saved" before the fix
        self.assertEqual(out["name"], "typed name")
        self.assertEqual(out["server"], "")
        self.assertTrue(out["edited"])

    # an impossible day (2026-02-31 rolls over to March 3 in Date) is no day: it must not become a hidden filter
    def test_impossible_day_is_not_a_day(self) -> None:
        out = _run(["isDay"], r"""//--
out.res = ["2026-02-28", "2026-02-31", "2026-04-31", "2026-02-29", "2028-02-29", "2026-13-01", "2026-00-10", "2026-1-01", "x"].map(isDay);
""")
        self.assertEqual(out["res"], [True, False, False, False, True, False, False, False, False])

    # a 60 s refresh that replaces the list while the first "Load more" is pending: that reply is for the old list
    # (appended after the old cursor it would leave the events between the two first pages out for good)
    def test_refresh_while_load_more_is_pending_drops_the_reply(self) -> None:
        out = _run(["EV_PAGE", "isDay", "dayTs", "eventsFilter", "eventsPath", "clearEvents", "mergeFirstPage", "loadMoreEvents"], r"""
const renderEvents = () => {}; const showBanner = () => {};
let release = null, asked = null;
const api = path => { asked = path; return new Promise(r => { release = () => r({ events: [{ id: 30 }, { id: 29 }], next: 29 }); }); };
//--
state.events = [{ id: 60 }, { id: 59 }]; state.evNext = 59; state.evPaged = false;
const more = loadMoreEvents();
out.asked = asked;
mergeFirstPage({ events: [{ id: 62 }, { id: 61 }, { id: 60 }], next: 60 }); // the refresh lands first
release(); await more;
out.ids = state.events.map(x => x.id); out.next = state.evNext; out.paged = state.evPaged;
// without a refresh in between the page is appended
state.events = [{ id: 60 }, { id: 59 }]; state.evNext = 59; state.evPaged = false;
const again = loadMoreEvents(); release(); await again;
out.ids2 = state.events.map(x => x.id); out.paged2 = state.evPaged;
""")
        self.assertEqual(out["asked"], "/api/events?limit=60&before=59")
        self.assertEqual(out["ids"], [62, 61, 60])
        self.assertEqual((out["next"], out["paged"]), (60, False))
        self.assertEqual(out["ids2"], [60, 59, 30, 29])
        self.assertTrue(out["paged2"])

    # every event kind the server writes has a colour rule, like the older kinds
    def test_new_event_kinds_have_a_colour(self) -> None:
        css = _read("leasewatch", "static", "style.css")
        for kind in ("archived", "restored", "merged"):
            self.assertTrue(re.search(rf"\.k\.{kind}\b[^{{]*\{{[^}}]*color:", css), kind)

    # a read-only login is worded apart from a blocked address; the generic .note rule leaves the event label alone
    def test_read_only_login_line_and_note_scope(self) -> None:
        src, css = _read("leasewatch", "static", "app.js"), _read("leasewatch", "static", "style.css")
        self.assertIn('state.meta.role === "ro" ? "Read-only login: this user can look but not change anything"', src)
        self.assertIn("Read-only: changes are off for this address", src)
        self.assertNotRegex(css, r"(^|[},\s])\.note\s*[,{]")  # a bare .note would style <span class="k note"> too
        self.assertRegex(css, r"\.k\.renamed, \.k\.note, \.k\.tags\s*\{[^}]*color:")

if __name__ == "__main__":
    unittest.main()
