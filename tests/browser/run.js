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
    await page.click(`${row(MAC)} .c-ip`);
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
    res.sr = await page.$$eval('#tbl .sr', es => es.map(e => {
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
    return { rows0, value, url_q, names, ...typed, ...now };
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
    await page.click(`${row(C)} .c-ip`); await waitOpen(page, C);
    await page.keyboard.press('Escape'); await waitClosed(page);
    res.clean_close = await shown();
    // edit A's name, then try every way out with Cancel
    await page.click(`${row(A)} .c-ip`); await waitOpen(page, A);
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
  // changes server state (a name, two acks): runs after the read-only scenarios
  async drawer(page) {
    const res = {};
    const CLICK = '02:00:00:00:00:06', KEY = '02:00:00:00:00:0d', ROWACK = '02:00:00:00:00:0c';
    // open by click, close with Escape: focus goes back to the row
    await page.click(`${row(CLICK)} .c-ip`);
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
