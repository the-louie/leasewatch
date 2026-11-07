#!/usr/bin/env node
/**
 * Browser checks for the leasewatch UI, driven by tests/test_ui_browser.py.
 *
 *   node run.js --probe                          prints {"ok": true} when puppeteer and Chrome are usable
 *   node run.js <base-url> <scenario> [...]      one browser, one fresh page per scenario, one JSON line each
 *
 * Each result line: {"scenario", "pass", "details", "console_errors", "failed_requests", "error"}.
 * "pass" covers what the page itself can tell (no exception, no console error, no failed request); the
 * expected device names and counts are asserted on "details" by the Python test.
 * Chrome: $LW_TEST_CHROME, else $PUPPETEER_EXECUTABLE_PATH, else the first of google-chrome / chromium found.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function loadPuppeteer() {
  try { return require('puppeteer'); } catch (e) { /* not next to this file: try the global root */ }
  try {
    const root = execSync('npm root -g', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (root) return require(path.join(root, 'puppeteer'));
  } catch (e) { /* not installed */ }
  return null;
}

function findChrome() {
  const env = process.env.LW_TEST_CHROME || process.env.PUPPETEER_EXECUTABLE_PATH;
  const list = env ? [env] : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  return list.find(p => { try { fs.accessSync(p, fs.constants.X_OK); return true; } catch (e) { return false; } }) || null;
}

const out = obj => process.stdout.write(JSON.stringify(obj) + '\n');

// ---------- scenarios: (page, base) -> details; throw to fail ----------
const rowNames = page => page.$$eval('#rows tr', trs => trs.map(t => t.querySelector('.nm').textContent));
const visibleRows = page => page.$$eval('#rows tr', trs => trs.map(t => ({
  mac: t.dataset.mac, name: t.querySelector('.nm').textContent, vlan: t.querySelector('.c-vlan .badge').textContent })));

// drawer helpers: what the page shows, and the device as the server has it now
const row = mac => `#rows tr[data-mac="${mac}"]`;
const focused = page => page.evaluate(() => {
  const a = document.activeElement;
  return { id: a.id || null, tag: a.tagName.toLowerCase(), mac: a.closest('tr') ? a.closest('tr').dataset.mac : null };
});
const drawerOpen = page => page.$eval('#drawer', d => d.classList.contains('open') && !d.inert);
const serverDevice = (page, mac) => page.evaluate(async m => (await (await fetch(`/api/devices/${m}`)).json()).device, mac);
// open = the device's form is rendered, Name has the focus and the drawer has slid in (a click during the slide can miss)
const waitOpen = (page, mac) => page.waitForFunction(m => document.activeElement && document.activeElement.id === 'fName'
  && getComputedStyle(document.querySelector('#drawer')).transform === 'none'
  && [...document.querySelectorAll('#dBody dd.mono')].some(d => d.textContent === m), {}, mac);
const waitClosed = page => page.waitForFunction(() => !document.querySelector('#drawer').classList.contains('open'));

const scenarios = {
  async load(page) {
    return { title: await page.title(), rows: (await rowNames(page)).length,
             banner_hidden: await page.$eval('#banner', b => b.classList.contains('hidden')) };
  },
  async rows(page) {
    return { names: await rowNames(page), count_text: await page.$eval('#count', e => e.textContent),
             total_card: await page.$eval('#cTotal', e => e.textContent) };
  },
  async status(page) {
    await page.waitForSelector('#statusText .src');
    return {
      dot: await page.$eval('#statusDot', e => e.className),
      sources: await page.$$eval('#statusText .src', ss => ss.map(s => ({
        label: s.textContent, title: s.getAttribute('title'), dot: s.querySelector('.dot').className }))),
    };
  },
  async chips(page) {
    const chips = await page.$$eval('#vlans .chip', cs => cs.map(c => ({ vlan: c.dataset.vlan, n: c.querySelector('.n').textContent })));
    const per = {};
    for (const c of chips) {
      await page.click(`#vlans .chip[data-vlan="${c.vlan}"]`);
      await page.waitForFunction(v => [...document.querySelectorAll('#rows tr .c-vlan .badge')].every(b => b.textContent === v), {}, c.vlan);
      per[c.vlan] = { rows: await visibleRows(page), pressed: await page.$eval(`#vlans .chip[data-vlan="${c.vlan}"]`, e => e.getAttribute('aria-pressed')),
                      url: page.url() };
      await page.click(`#vlans .chip[data-vlan="${c.vlan}"]`); // same chip again: filter off
    }
    return { chips, per, rows_after: (await rowNames(page)).length };
  },
  async search(page) {
    const res = {};
    for (const q of ['ipad', '10.0.2.', '02:00:00:00:00:0c', 'zzz-nothing']) {
      await page.click('#q', { clickCount: 3 });
      await page.type('#q', q);
      await page.waitForFunction(v => new URLSearchParams(location.search).get('q') === v, {}, q);
      res[q] = { names: await rowNames(page), empty_shown: await page.$eval('#empty', e => !e.classList.contains('hidden')) };
    }
    await page.click('#q', { clickCount: 3 });
    await page.keyboard.press('Escape'); // Escape in the box clears the search
    res.cleared = (await rowNames(page)).length;
    return res;
  },
  async csv(page) {
    const href = await page.$eval('a[href$=".csv"]', a => a.href);
    const r = await page.evaluate(async u => {
      const resp = await fetch(u);
      return { status: resp.status, type: resp.headers.get('content-type'), disposition: resp.headers.get('content-disposition'), text: await resp.text() };
    }, href);
    const lines = r.text.replace(/^﻿/, '').split(/\r?\n/).filter(Boolean);
    return { href, status: r.status, type: r.type, disposition: r.disposition, header: lines[0], data_lines: lines.length - 1 };
  },
  // Tab and Shift+Tab stay inside the open drawer; the page behind it is inert until it closes
  async trap(page) {
    const MAC = '02:00:00:00:00:01';
    const where = () => page.evaluate(() => {
      const a = document.activeElement;
      return { id: a.id || a.tagName.toLowerCase(), in_drawer: document.querySelector('#drawer').contains(a) };
    });
    const bg = () => page.$$eval('body > header, body > main, body > footer', es => es.map(e => e.inert));
    const res = { bg_before: await bg() };
    await page.click(`${row(MAC)} .c-dev`);
    await waitOpen(page, MAC);
    res.bg_open = await bg();
    res.tab = [];
    for (let i = 0; i < 6; i++) { await page.keyboard.press('Tab'); res.tab.push(await where()); }
    await page.focus('#dClose');
    res.shift_tab = [];
    for (let i = 0; i < 6; i++) {
      await page.keyboard.down('Shift'); await page.keyboard.press('Tab'); await page.keyboard.up('Shift');
      res.shift_tab.push(await where());
    }
    // a script or a click cannot put the focus behind the drawer either
    await page.evaluate(() => document.querySelector('#q').focus());
    res.q_focus = await where();
    await page.keyboard.press('Escape');
    await waitClosed(page);
    res.bg_closed = await bg();
    res.closed_focus = await focused(page);
    return res;
  },
  // per laptop/desktop width: which columns show, and whether the table or the page needs a horizontal scroll
  async columns(page) {
    const res = {};
    for (const width of [1280, 1366, 1440, 1920]) {
      await page.setViewport({ width, height: 900 });
      res[width] = await page.evaluate(() => {
        const wrap = document.querySelector('.table-wrap'), th = [...document.querySelectorAll('#tbl thead th')];
        return { shown: th.filter(t => getComputedStyle(t).display !== 'none').map(t => t.className),
                 table_scroll: wrap.scrollWidth - wrap.clientWidth,
                 page_scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                 table_width: document.querySelector('#tbl').offsetWidth, wrap_width: wrap.clientWidth,
                 col_widths: Object.fromEntries(th.filter(t => t.offsetWidth).map(t => [t.className, t.offsetWidth])) };
      });
    }
    // the visually hidden header labels: in the accessibility tree, but 1 px and clipped
    res.sr = await page.$$eval('#tbl thead .sr', es => es.map(e => {
      const s = getComputedStyle(e), r = e.getBoundingClientRect();
      return { text: e.textContent, w: r.width, h: r.height, overflow: s.overflow, clip: s.clipPath !== 'none' || s.clip !== 'auto',
               nowrap: s.whiteSpace === 'nowrap', left: r.left };
    }));
    return res;
  },
  // against the 2000-device server: type a query at a fast typist's pace, count the table renders, time the last one
  async perf(page) {
    const Q = 'dev-12';
    await page.evaluate(() => {
      // a renderTable() rebuilds #rows in one task: one observer callback per render, run when it has finished
      window.__renders = [];
      new MutationObserver(() => window.__renders.push(performance.now())).observe(document.querySelector('#rows'), { childList: true });
      window.__keys = [];
      document.addEventListener('keydown', () => window.__keys.push(performance.now()), true);
    });
    const rows0 = await page.$$eval('#rows tr', t => t.length);
    await page.focus('#q');
    await page.type('#q', Q, { delay: 30 });
    await page.waitForFunction(q => new URLSearchParams(location.search).get('q') === q, {}, Q);
    await new Promise(r => setTimeout(r, 400)); // a late render would still be counted
    const typed = await page.evaluate(() => ({ renders: window.__renders.length, keys: window.__keys.length,
      last_render_ms: window.__renders.length ? window.__renders[window.__renders.length - 1] - window.__keys[window.__keys.length - 1] : null }));
    const names = await rowNames(page), value = await page.$eval('#q', e => e.value), url_q = new URL(page.url()).searchParams.get('q');
    // Enter and Escape in the box act at once: the table is right when the key event returns
    const now = await page.evaluate(() => {
      const q = document.querySelector('#q'), key = k => q.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true }));
      q.value = 'dev-1'; q.dispatchEvent(new Event('input', { bubbles: true }));
      const t0 = performance.now(); key('Enter');
      const enter = { ms: performance.now() - t0, rows: document.querySelectorAll('#rows tr').length, url_q: new URLSearchParams(location.search).get('q') };
      const t1 = performance.now(); key('Escape');
      const escape = { ms: performance.now() - t1, rows: document.querySelectorAll('#rows tr').length, value: q.value };
      return { enter, escape };
    });
    // Enter with no search pending does not rebuild the table
    const idle_enter_renders = await page.evaluate(async () => {
      const q = document.querySelector('#q'), n = window.__renders.length; q.focus();
      for (let i = 0; i < 3; i++) q.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
      await new Promise(r => setTimeout(r, 300));
      return window.__renders.length - n;
    });
    return { rows0, value, url_q, names, ...typed, ...now, idle_enter_renders };
  },
  // unsaved form edits: closing the drawer or opening another device asks first; Cancel keeps both, OK goes on
  async dirty(page) {
    const A = '02:00:00:00:00:02', B = '02:00:00:00:00:03', C = '02:00:00:00:00:04';
    let answer = false; const dialogs = [];
    page.on('dialog', async d => { dialogs.push({ type: d.type(), message: d.message(), answer }); await (answer ? d.accept() : d.dismiss()); });
    const shown = async () => ({ open: await drawerOpen(page), mac: await page.$$eval('#dBody dd.mono', ds => ds.length > 1 ? ds[1].textContent : null),
                                 name: await page.$eval('#fName', e => e.value).catch(() => null), dialogs: dialogs.length });
    // the rows are inert behind the open drawer: a script click or Enter is the only way left to open another device
    const openOther = (how, mac) => page.evaluate((h, m) => {
      const tr = document.querySelector(`#rows tr[data-mac="${m}"]`);
      if (h === 'click') tr.click(); else tr.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    }, how, mac);
    const res = {};
    // a clean form closes without asking
    await page.click(`${row(C)} .c-dev`); await waitOpen(page, C);
    await page.keyboard.press('Escape'); await waitClosed(page);
    res.clean_close = await shown();
    // edit A's name, then try every way out with Cancel
    await page.click(`${row(A)} .c-dev`); await waitOpen(page, A);
    await page.type('#fName', 'Alex printer');
    res.cancel = {};
    await page.keyboard.press('Escape'); res.cancel.escape = await shown();
    await page.mouse.click(20, 400); res.cancel.scrim = await shown(); // left of the drawer: the scrim
    await page.click('#dClose'); res.cancel.close = await shown();
    await openOther('click', B); res.cancel.click_other = await shown();
    await openOther('enter', B); res.cancel.enter_other = await shown();
    // OK: another device opens, its form is clean; then an edited close with OK closes and saves nothing
    answer = true;
    await openOther('enter', B); await waitOpen(page, B); res.ok_other = await shown();
    await page.type('#fName', 'Sam printer');
    await page.keyboard.press('Escape'); await waitClosed(page); res.ok_close = await shown();
    res.server = { [A]: (await serverDevice(page, A)).name, [B]: (await serverDevice(page, B)).name };
    res.dialog_log = dialogs;
    return res;
  },
  // a close while Save's POST is held: no prompt for the text being saved, a prompt for text typed after Save
  async saving(page) {
    const A = '02:00:00:00:00:05', B = '02:00:00:00:00:07';
    let answer = false; const dialogs = [];
    page.on('dialog', async d => { dialogs.push(d.message()); await (answer ? d.accept() : d.dismiss()); });
    let held = null;
    await page.setRequestInterception(true);
    page.on('request', r => { if (r.method() === 'POST') held = r; else r.continue(); });
    const saveHeld = async () => { held = null; await page.click("#fSave"); while (!held) await new Promise(r => setTimeout(r, 10)); };
    const release = async (mac, name) => { const r = held; held = null; await r.continue();
      await page.waitForFunction(m => [...document.querySelectorAll('#rows tr')].some(t => t.dataset.mac === m[0] && t.querySelector('.nm').textContent === m[1]), {}, [mac, name]); }; // the save's table render is done
    const res = {};
    await page.click(`${row(A)} .c-dev`); await waitOpen(page, A);
    await page.type('#fName', 'Kitchen TV');
    await saveHeld();
    await page.keyboard.press('Escape');
    res.plain = { dialogs: dialogs.length, open: await drawerOpen(page) };
    await release(A, 'Kitchen TV');
    res.plain.server = (await serverDevice(page, A)).name;
    await page.click(`${row(B)} .c-dev`); await waitOpen(page, B);
    await page.type('#fName', 'Desk');
    await saveHeld();
    await page.type('#fName', ' PC');
    await page.keyboard.press('Escape');
    res.typed = { dialogs: dialogs.length, open: await drawerOpen(page) };
    await release(B, 'Desk');
    await page.waitForFunction(() => document.querySelector('#fSaved').textContent === 'saved');
    answer = true; await page.keyboard.press('Escape'); await waitClosed(page);
    res.typed.after = { dialogs: dialogs.length, open: await drawerOpen(page), server: (await serverDevice(page, B)).name };
    res.dialog_log = dialogs;
    return res;
  },
  // private (locally administered) MACs: the row's border class, the sleuth and its hint; a hardware MAC has none
  async private(page) {
    const rows = await page.$$eval('#rows tr', trs => trs.map(t => {
      const p = t.querySelector('.c-mac .priv'), s = p && getComputedStyle(p);
      return { mac: t.dataset.mac, cls: t.classList.contains('is-private'), shadow: getComputedStyle(t.querySelector('td')).boxShadow,
               shown: !!p && s.display !== 'none' && p.offsetWidth > 0, emoji: p ? p.textContent.includes('\u{1F575}\u{FE0F}') : false,
               title: p ? p.getAttribute('title') : null, sr: p && p.querySelector('.sr') ? p.querySelector('.sr').textContent : null,
               copy_text: t.querySelector('.c-mac .cp') ? t.querySelector('.c-mac .cp').textContent : null };
    }));
    // the merged device's drawer lists the MAC merged into it and why
    const DEV = '02:00:00:00:10:01';
    await page.click(`${row(DEV)} .c-dev`);
    await waitOpen(page, DEV);
    const drawer = await page.evaluate(() => {
      const t = document.querySelector('#dBody table.aliases');
      return { heading: [...document.querySelectorAll('#dBody h3')].map(h => h.textContent),
               why: t && t.previousElementSibling ? t.previousElementSibling.textContent : null,
               head: t ? [...t.querySelectorAll('thead th')].map(th => th.textContent) : null,
               rows: t ? [...t.querySelectorAll('tbody tr')].map(r => [...r.querySelectorAll('td')].map(td => td.textContent)) : null };
    });
    await page.keyboard.press('Escape');
    await waitClosed(page);
    const UA = '00:00:5e:00:53:01';
    await page.click(`${row(UA)} .c-dev`);
    await waitOpen(page, UA);
    const plain = await page.evaluate(() => ({ table: !!document.querySelector('#dBody table.aliases'),
      heading: [...document.querySelectorAll('#dBody h3')].map(h => h.textContent) }));
    return { rows, drawer, plain };
  },
  // MAC and IP text copy on click, Enter and Space; hovering or copying does not change any column width
  async copy(page) {
    await page.evaluate(() => {
      window.__copied = [];
      Object.defineProperty(navigator, 'clipboard', { configurable: true,
        value: { writeText: t => { window.__copied.push(t); return Promise.resolve(); } } });
    });
    const MAC = '00:00:5e:00:53:01';
    const widths = () => page.evaluate(() => ({ table: document.querySelector('#tbl').offsetWidth,
      cols: [...document.querySelectorAll('#tbl thead th')].map(t => t.offsetWidth) }));
    const copied = () => page.evaluate(() => window.__copied.slice());
    const res = { before: await widths() };
    // a private row: its sleuth already makes it the widest MAC cell, so anything added on hover widens the column
    await page.hover(`${row('02:00:00:00:10:01')} td.c-mac`);
    res.hover_mac = await widths();
    res.mac_title = await page.$eval(`${row(MAC)} .c-mac .cp`, e => e.getAttribute('title'));
    await page.hover(`${row(MAC)} td.c-ip`);
    res.hover_ip = await widths();
    res.ip_title = await page.$eval(`${row(MAC)} .c-ip .cp`, e => e.getAttribute('title'));
    await page.click(`${row(MAC)} .c-mac .cp`);
    await page.waitForFunction(() => window.__copied.length === 1);
    res.after_click = { copied: await copied(), open: await drawerOpen(page), widths: await widths(),
      feedback: await page.$eval(`${row(MAC)} .c-mac .cp`, e => ({ cls: e.classList.contains('copied'), title: e.getAttribute('title'),
        bubble: getComputedStyle(e, '::after').content, position: getComputedStyle(e, '::after').position })) };
    await page.click(`${row(MAC)} .c-ip .cp`);
    await page.waitForFunction(() => window.__copied.length === 2);
    // keyboard: Tab reaches the IP and the MAC text; Enter and Space copy without opening the drawer
    await page.focus(`${row(MAC)} .c-ip .cp`);
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => window.__copied.length === 3);
    await page.keyboard.press('Tab');
    res.tab_to = await page.evaluate(() => document.activeElement.closest('td') ? document.activeElement.closest('td').className : null);
    await page.keyboard.press('Space');
    await page.waitForFunction(() => window.__copied.length === 4);
    res.keys = { copied: await copied(), open: await drawerOpen(page), role: await page.$eval(`${row(MAC)} .c-ip .cp`, e => [e.getAttribute('role'), e.tabIndex]) };
    res.end = await widths();
    return res;
  },
  // archive from the drawer hides the row; the "Archived" filter shows it; restore brings it back (changes server state)
  async archive(page) {
    const M = '0a:00:00:00:10:03';
    const macs = () => page.$$eval('#rows tr', trs => trs.map(t => t.dataset.mac));
    const total = () => page.$eval('#cTotal', e => e.textContent);
    const label = () => page.$eval('#fArch', e => e.textContent);
    const filter = v => page.evaluate(x => { const s = document.querySelector('#fStatus'); s.value = x; s.dispatchEvent(new Event('change')); }, v);
    const res = {};
    await page.click(`${row(M)} .c-dev`); await waitOpen(page, M);
    res.before = { rows: await macs(), label: await label(), total: await total() };
    await page.click('#fArch');
    await page.waitForFunction(s => !document.querySelector(s) && document.querySelector('#fArch').textContent === 'Restore to list', {}, row(M));
    res.archived = { rows: await macs(), label: await label(), total: await total(), server: (await serverDevice(page, M)).archived_ts };
    await page.keyboard.press('Escape'); await waitClosed(page);
    await filter('archived');
    res.filter = { rows: await macs() };
    await page.click(`${row(M)} .c-dev`); await waitOpen(page, M);
    await page.click('#fArch');
    await page.waitForFunction(s => !document.querySelector(s) && document.querySelector('#fArch').textContent === 'Archive', {}, row(M));
    res.restored = { label: await label(), filter_rows: await macs(), server: (await serverDevice(page, M)).archived_ts };
    await page.keyboard.press('Escape'); await waitClosed(page);
    await filter('all');
    res.restored.rows = await macs(); res.restored.total = await total();
    return res;
  },
  // changes server state (a name, two acks): runs after the read-only scenarios
  async drawer(page) {
    const res = {};
    const CLICK = '02:00:00:00:00:06', KEY = '02:00:00:00:00:0d', ROWACK = '02:00:00:00:00:0c';
    // open by click, close with Escape: focus goes back to the row
    await page.click(`${row(CLICK)} .c-dev`);
    await waitOpen(page, CLICK);
    res.click = { open: await drawerOpen(page), title: await page.$eval('#dTitle', e => e.textContent), focus: await focused(page) };
    await page.keyboard.press('Escape');
    await waitClosed(page);
    res.click_closed = { open: await drawerOpen(page), focus: await focused(page) };
    // open by Enter on a focused row, rename, "Save & mark known"
    await page.focus(row(KEY));
    await page.keyboard.press('Enter');
    await waitOpen(page, KEY);
    res.key = { open: await drawerOpen(page), focus: await focused(page), ack_label: await page.$eval('#fAck', e => e.textContent) };
    await page.click('#fName', { clickCount: 3 });
    await page.type('#fName', "Alex's camera");
    await page.click('#fAck');
    await page.waitForFunction(() => document.querySelector('#fSaved') && document.querySelector('#fSaved').textContent === 'saved');
    res.saved = { server: await serverDevice(page, KEY), title: await page.$eval('#dTitle', e => e.textContent),
                  ack_label: await page.$eval('#fAck', e => e.textContent), row_name: await page.$eval(`${row(KEY)} .nm`, e => e.textContent),
                  row_ack: await page.$(`${row(KEY)} .ack`) !== null };
    // the save re-rendered the table: Escape focuses the new row of the device
    await page.keyboard.press('Escape');
    await waitClosed(page);
    res.key_closed = { open: await drawerOpen(page), focus: await focused(page) };
    // ack from the row button: no drawer, the button goes away
    res.rowack_before = (await serverDevice(page, ROWACK)).acked;
    await page.click(`${row(ROWACK)} .ack`);
    await page.waitForFunction(s => !document.querySelector(s), {}, `${row(ROWACK)} .ack`);
    res.rowack = { server: (await serverDevice(page, ROWACK)).acked, open: await drawerOpen(page),
                   unacked_card: await page.$eval('#cUnacked', e => e.textContent) };
    return res;
  },
};

async function runScenario(browser, base, name) {
  const res = { scenario: name, pass: false, details: null, console_errors: [], failed_requests: [], error: null };
  const page = await browser.newPage();
  try {
    // listeners before goto, or the first load's errors are missed
    page.on('console', m => { if (m.type() === 'error') res.console_errors.push(m.text()); });
    page.on('pageerror', e => res.console_errors.push(`pageerror: ${e.message}`));
    page.on('requestfailed', r => res.failed_requests.push(`${r.failure() ? r.failure().errorText : 'failed'} ${r.url()}`));
    page.on('response', r => { if (r.status() >= 400) res.failed_requests.push(`http ${r.status()} ${r.url()}`); });
    if (!scenarios[name]) throw new Error(`unknown scenario ${name}`);
    await page.setViewport({ width: 1400, height: 900 });
    await page.goto(base, { waitUntil: 'domcontentloaded', timeout: 15000 });
    await page.waitForSelector('#rows tr', { timeout: 15000 }); // the first load() has rendered
    res.details = await scenarios[name](page, base);
    res.pass = !res.console_errors.length && !res.failed_requests.length;
  } catch (e) {
    res.error = String(e && e.message || e);
  } finally {
    await page.close().catch(() => {});
  }
  return res;
}

(async () => {
  const argv = process.argv.slice(2);
  const puppeteer = loadPuppeteer();
  const chrome = findChrome();
  if (argv[0] === '--probe') {
    out(!puppeteer ? { ok: false, reason: 'puppeteer not found (local require or `npm root -g`)' }
      : !chrome ? { ok: false, reason: 'no Chrome/Chromium binary (set LW_TEST_CHROME)' } : { ok: true, chrome });
    return;
  }
  if (argv.length < 2 || !puppeteer || !chrome) {
    console.error('usage: node run.js <base-url> <scenario> [...]   (needs puppeteer and Chrome; see --probe)');
    process.exitCode = 2;
    return;
  }
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const browser = await puppeteer.launch({ executablePath: chrome, headless: true,
    args: isRoot ? ['--no-sandbox', '--disable-dev-shm-usage'] : ['--disable-dev-shm-usage'] }); // the sandbox needs a non-root user
  try {
    for (const name of argv.slice(1)) out(await runScenario(browser, argv[0], name));
  } finally {
    await browser.close(); // a throw without this leaves a Chrome process behind
  }
})().catch(e => { console.error(String(e && e.stack || e)); process.exitCode = 1; });
