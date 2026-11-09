#!/usr/bin/env node
/**
 * Browser checks for the leasewatch UI, driven by tests/test_ui_browser.py.
 *
 *   node run.js --probe                          prints {"ok": true} when puppeteer and Chrome are usable
 *   node run.js <base-url> <scenario> [...]      one browser, one fresh page per scenario, one JSON line each
 *   LW_TEST_AUTH=user:password                   basic-auth credentials the pages send (server with auth on)
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
    await page.waitForSelector('#vlans .chip .sw');
    await page.waitForSelector('#events .badge.vlan');
    return { title: await page.title(), rows: (await rowNames(page)).length,
             banner_hidden: await page.$eval('#banner', b => b.classList.contains('hidden')),
             // the network colours come from data-vc, not from a style attribute the CSP would block
             swatches: await page.$$eval('#vlans .chip .sw', ss => ss.map(s => getComputedStyle(s).backgroundColor)),
             event_badges: await page.$$eval('#events .badge.vlan', bs => bs.map(b => getComputedStyle(b).getPropertyValue('--vc').trim())),
             favicon: await page.evaluate(async () => { const l = document.querySelector('link[rel~="icon"]');
               const r = l && await fetch(l.href); return r ? { status: r.status, type: r.headers.get('content-type') } : null; }) };
  },
  async collector(page) {
    await page.waitForFunction(() => !document.querySelector('#banner').classList.contains('hidden'));
    return { banner: await page.$eval('#banner', b => b.textContent) };
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
  // English is already in the HTML: the applier changes nothing there
  async lang_apply(page, base) {
    await page.goto(`${base}?lang=en`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#rows tr');
    return await page.evaluate(() => ({ html_lang: document.documentElement.lang,
      sub: document.querySelector('[data-i18n="nav.sub"]').textContent,
      refresh: document.querySelector('[data-i18n="foot.refresh"]').textContent,
      option: document.querySelector('#fStatus [data-i18n="opt.offline"]').textContent,
      tpl_title: document.querySelector('#rowTpl').content.querySelector('.c-mac .cp').title,
      row_title: document.querySelector('#rows .c-mac .cp').title }));
  },
  // ?lang= is not a filter: a filter click and Clear filters keep it in the address
  async lang_param(page, base) {
    await page.goto(`${base}?lang=en`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#rows tr');
    const res = await page.evaluate(() => ({ html_lang: document.documentElement.lang, data_lang: document.documentElement.dataset.lang,
      strings: typeof window.LW_STRINGS?.en }));
    await page.click('.card[data-filter="new"]');
    await page.waitForFunction(() => new URLSearchParams(location.search).get('filter') === 'new');
    res.filtered = await page.evaluate(() => location.search);
    await page.type('#q', 'zzz-nothing');
    await page.waitForSelector('#empty:not(.hidden) #emptyClear:not(.hidden)');
    await page.click('#emptyClear');
    await page.waitForFunction(() => !new URLSearchParams(location.search).has('filter'));
    res.cleared = await page.evaluate(() => location.search);
    return res;
  },
  // ?lang=sv: the static texts, the rows, the drawer, the event kinds and the tag headings come from the Swedish table;
  // the server's event detail stays English; the tables fit at 800, 1024 and 1280 px
  async lang_sv(page, base) {
    const A = '02:00:00:00:70:01';
    await page.goto(`${base}?lang=sv`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector(`${row(A)}`);
    await page.waitForSelector('#tags .grp');
    await page.waitForSelector('#events .k.renamed');
    const sv = k => page.evaluate(key => window.LW_STRINGS.sv[key], k);
    const res = { html_lang: await page.evaluate(() => document.documentElement.lang) };
    res.sub = { shown: await page.$eval('[data-i18n="nav.sub"]', e => e.textContent), table: await sv('nav.sub') };
    res.new_badge = { shown: await page.$eval(`${row(A)} .badge.new`, e => e.textContent), table: await sv('row.new') };
    res.headers = {};
    for (const [cls, key] of [['c-dev', 'th.device'], ['c-first', 'th.first'], ['c-last', 'th.last']])
      res.headers[key] = { shown: await page.$eval(`thead th.${cls}`, e => e.textContent.trim()), table: await sv(key) };
    res.row_ack = { shown: await page.$eval(`${row(A)} button.ack`, e => e.textContent.trim()), table: await sv('row.mark_known') };
    res.new_label = { shown: await page.$eval('.card[data-filter="new"] .lbl', e => e.textContent), table: await sv('card.new_default') };
    res.kind_option = { shown: await page.$eval('#evKind option[value="renamed"]', e => e.textContent), table: await sv('kind.renamed') };
    res.event = await page.$eval('#events li:has(.k.renamed)', li => ({ kind: li.querySelector('.k').textContent, detail: li.querySelector('.muted').textContent }));
    res.event.table = await sv('kind.renamed');
    res.headings = { shown: await page.$$eval('#tags .grp', gs => gs.map(g => g.textContent)), table: [await sv('chip.tags'), await sv('chip.owner')] };
    await page.click(`${row(A)} .nm`); await waitOpen(page, A);
    res.drawer = {};
    for (const [id, key] of [['#fSave', 'drawer.save'], ['#fArch', 'drawer.archive'], ['#fWatch', 'drawer.watch']])
      res.drawer[key] = { shown: await page.$eval(id, e => e.textContent), table: await sv(key) };
    await page.keyboard.press('Escape'); await waitClosed(page);
    await page.click('.card[data-filter="new"]');
    await page.waitForFunction(() => new URLSearchParams(location.search).get('filter') === 'new');
    res.filtered = await page.evaluate(() => location.search);
    await page.click('.card[data-filter="new"]'); // filter off again: all rows back for the width checks
    await page.waitForFunction(() => !new URLSearchParams(location.search).has('filter'));
    // widths: nothing scrolls sideways and no header text is cut by its cell
    res.widths = {};
    for (const width of [800, 1024, 1280]) {
      await page.setViewport({ width, height: 900 });
      res.widths[width] = await page.evaluate(() => {
        const wrap = document.querySelector('.table-wrap'), de = document.documentElement;
        return { page_scroll: de.scrollWidth - innerWidth, table_scroll: wrap.scrollWidth - wrap.clientWidth,
          th_over: [...document.querySelectorAll('thead th')].filter(th => th.scrollWidth > th.clientWidth)
            .map(th => `${th.className}: ${th.scrollWidth}>${th.clientWidth}`) };
      });
    }
    return res;
  },
  // the browser's own language (sv-SE) picks Swedish with no parameter; ?lang=en overrides it. A fresh page with
  // the override, so the other scenarios keep en-US
  async lang_auto(page, base) {
    const p2 = await page.browser().newPage();
    try {
      await p2.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'languages', { get: () => ['sv-SE', 'sv'] });
        Object.defineProperty(navigator, 'language', { get: () => 'sv-SE' });
      });
      const read = () => p2.evaluate(() => ({ html_lang: document.documentElement.lang, data_lang: document.documentElement.dataset.lang,
        sub: document.querySelector('[data-i18n="nav.sub"]').textContent, search: location.search }));
      const res = {};
      await p2.goto(base, { waitUntil: 'domcontentloaded' });
      await p2.waitForSelector('#rows tr');
      res.auto = await read();
      await p2.goto(`${base}?lang=en`, { waitUntil: 'domcontentloaded' });
      await p2.waitForSelector('#rows tr');
      res.en = await read();
      res.plain = await page.evaluate(() => ({ html_lang: document.documentElement.lang, languages: navigator.languages.slice() }));
      return res;
    } finally {
      await p2.close().catch(() => {});
    }
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
    for (let i = 0; i < 8; i++) { await page.keyboard.press('Tab'); res.tab.push(await where()); }
    await page.focus('#dClose');
    res.shift_tab = [];
    for (let i = 0; i < 8; i++) {
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
  // long Type and "Connected via" text: per width the horizontal scroll of the table and the page, and per row the
  // text of the Type and Connected-via cells next to their title (the full text a cut cell must still offer)
  async longtext(page) {
    const res = {};
    for (const width of [1280, 1366, 1440, 1920]) {
      await page.setViewport({ width, height: 900 });
      res[width] = await page.evaluate(() => {
        const wrap = document.querySelector('.table-wrap'), th = [...document.querySelectorAll('#tbl thead th')];
        return { table_scroll: wrap.scrollWidth - wrap.clientWidth,
                 page_scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                 col_widths: Object.fromEntries(th.filter(t => t.offsetWidth).map(t => [t.className, t.offsetWidth])) };
      });
    }
    res.cells = await page.$$eval('#rows tr', trs => Object.fromEntries(trs.map(t => {
      const c = s => { const e = t.querySelector(s); return { text: e.textContent, title: e.title }; };
      return [t.dataset.mac, { type: c('.c-type'), where: c('.c-where') }];
    })));
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
      const h = t.querySelector('.dev-sub .priv-hint'), sub = t.querySelector('.dev-sub');
      return { mac: t.dataset.mac, hint: h ? h.textContent.replace(/^\s*\u{1F575}\u{FE0F}/u, '') : null,
               hint_shown: !!h && h.offsetWidth > 0 && getComputedStyle(h).visibility !== 'hidden',
               sub_start: h ? sub.textContent.replace(/^\s*\u{1F575}\u{FE0F}?/u, '').slice(0, 15) : null,
               ico_in_mac: !!t.querySelector('.c-mac .priv') && t.querySelector('.c-mac .priv').offsetWidth > 0,
               ico_in_hint: !!h && h.querySelector('.ico').offsetWidth > 0,
               cls: t.classList.contains('is-private'), shadow: getComputedStyle(t.querySelector('td')).boxShadow,
               shown: !!p && s.display !== 'none' && p.offsetWidth > 0, emoji: p ? p.textContent.includes('\u{1F575}\u{FE0F}') : false,
               title: p ? p.getAttribute('title') : null,
               copy_text: t.querySelector('.c-mac .cp') ? t.querySelector('.c-mac .cp').textContent : null };
    }));
    // below 900 px the MAC column is hidden: the sleuth moves into the hint, and the page does not scroll sideways
    await page.setViewport({ width: 800, height: 900 });
    const narrow = { scroll: await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth),
      rows: await page.$$eval('#rows tr', trs => Object.fromEntries(trs.map(t => {
        const h = t.querySelector('.dev-sub .priv-hint'), m = t.querySelector('.c-mac');
        return [t.dataset.mac, { hint: h ? h.textContent.replace(/^\s*\u{1F575}\u{FE0F}/u, '') : null,
          hint_shown: !!h && h.offsetWidth > 0, mac_shown: m.offsetWidth > 0,
          ico_in_hint: !!h && h.querySelector('.ico').offsetWidth > 0 }];
      }))) };
    await page.setViewport({ width: 1400, height: 900 });
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
    // the event list names the merge in words, like every other kind
    await page.waitForSelector('#events .k.merged');
    const merged_event = await page.$$eval('#events li', ls => ls.filter(l => l.querySelector('.k.merged'))
      .map(l => ({ label: l.querySelector('.k.merged').textContent, detail: l.querySelector('.muted').textContent })));
    return { rows, narrow, drawer, plain, merged_event };
  },
  // an offline event in the drawer history carries its kind as a class
  async presencekinds(page, base) {
    const DEV = '02:00:00:00:10:01';
    await page.goto(base, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector(row(DEV));
    await page.click(`${row(DEV)} .c-dev`); await waitOpen(page, DEV);
    await page.waitForSelector('#dBody ul.tl .k.offline');
    return page.$eval('#dBody ul.tl .k.offline', k => ({ cls: k.className, text: k.textContent }));
  },
  // the drawer's Wi-Fi history: rows from the detail route, "now" on the current SSID, "since" near the start of counting
  async wifihistory(page, base) {
    const DEV = '02:00:00:00:10:01', UA = '00:00:5e:00:53:01';
    const detail = await page.evaluate(async m => (await (await fetch(`/api/devices/${m}`)).json()), DEV);
    const old = detail.wifi_presence.reduce((a, w) => (w.last_seen < a.last_seen ? w : a));
    // the server does not send the start of counting in /api/devices: the page is handed one 30 s before the old row
    await page.setRequestInterception(true);
    page.on('request', async r => {
      if (new URL(r.url()).pathname !== '/api/devices' || r.method() !== 'GET') return r.continue();
      const j = await (await fetch(r.url(), { headers: r.headers() })).json();
      j.meta.wifi_presence_since = old.first_seen - 30;
      r.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(j) });
    });
    await page.goto(base, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector(row(DEV));
    const read = () => page.evaluate(() => {
      const t = document.querySelector('#dBody table.wifi'), h = [...document.querySelectorAll('#dBody h3')];
      return { headings: h.map(x => x.textContent), head: t ? [...t.querySelectorAll('thead th')].map(x => x.textContent) : null,
               rows: t ? [...t.querySelectorAll('tbody tr')].map(r => [...r.querySelectorAll('td')].map(td => td.textContent)) : null,
               titles: t ? [...t.querySelectorAll('tbody tr')].map(r => r.children[3].title) : null,
               italics: t ? t.querySelectorAll('i').length : 0 };
    });
    await page.click(`${row(DEV)} .c-dev`);
    await waitOpen(page, DEV);
    await page.waitForSelector('#dBody table.wifi');
    const shown = await read();
    shown.since_ts = old.first_seen - 30;
    await page.keyboard.press('Escape');
    await waitClosed(page);
    await page.click(`${row(UA)} .c-dev`);
    await waitOpen(page, UA);
    return { shown, detail: detail.wifi_presence, none: await read() };
  },
  // a merged MAC typed into the search finds the device it was merged into, and no other row
  // a device with only a label shows it as its name, the drawer lists it, and the search finds it by it
  async labelsearch(page) {
    const names = await rowNames(page);
    await page.click('#q', { clickCount: 3 });
    await page.type('#q', 'kitchen shelf');
    await page.waitForFunction(v => new URLSearchParams(location.search).get('q') === v, {}, 'kitchen shelf');
    const found = await rowNames(page);
    await page.click('#rows tr .nm');
    await page.waitForSelector('#dBody dt');
    const dts = await page.$$eval('#dBody dt', e => e.map(x => x.textContent));
    const dd = await page.$$eval('#dBody dt', e => e.filter(x => x.textContent === 'Label').map(x => x.nextElementSibling.textContent));
    return { names, found, dts, dd };
  },
  async aliassearch(page) {
    await page.click('#q', { clickCount: 3 });
    await page.type('#q', '06:00:00:00:10:02');
    await page.waitForFunction(v => new URLSearchParams(location.search).get('q') === v, {}, '06:00:00:00:10:02');
    return { rows: await visibleRows(page) };
  },
  // ?device=<mac> opens that device's drawer after the load (an alias MAC opens its owner); closing removes the key;
  // an unknown MAC opens nothing, shows no banner and leaves no key
  async deeplink(page, base) {
    const DEV = '02:00:00:00:10:01', ALIAS = '06:00:00:00:10:02', UNKNOWN = '02:00:00:00:99:99';
    const go = async q => { await page.goto(`${base}?device=${q}`, { waitUntil: 'domcontentloaded' }); await page.waitForSelector('#rows tr'); };
    const state = () => page.evaluate(() => ({ search: location.search, title: document.querySelector('#dTitle').textContent,
      open: document.querySelector('#drawer').classList.contains('open'), banner: !document.querySelector('#banner').classList.contains('hidden'),
      shown: [...document.querySelectorAll('#dBody dd.mono')].map(d => d.textContent) }));
    const res = {};
    await go(DEV); await waitOpen(page, DEV);
    res.direct = await state();
    await page.click('#dClose'); await waitClosed(page);
    res.closed = await state();
    await go(ALIAS); await waitOpen(page, DEV);
    res.alias = await state();
    await page.keyboard.press('Escape'); await waitClosed(page);
    res.alias_closed = await state();
    await go(DEV.toUpperCase()); await waitOpen(page, DEV);
    res.upper = await state();
    page.__allow = [404]; // the server is asked about a MAC the list does not have
    await go(UNKNOWN);
    await page.waitForFunction(() => !location.search.includes('device'));
    res.unknown = await state();
    page.__allow = null;
    await go('junk');
    res.junk = await state();
    return res;
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
  // the IPv6 line: row, phone meta line, drawer, search and copy, for one device with an address and one without
  async ipv6(page) {
    const A = '02:00:00:00:60:01', B = '02:00:00:00:60:02', V6 = '2001:db8:1234:5600:211:22ff:fe33:4455';
    await page.waitForSelector(row(A));
    await page.evaluate(() => {
      window.__copied = [];
      Object.defineProperty(navigator, 'clipboard', { configurable: true,
        value: { writeText: t => { window.__copied.push(t); return Promise.resolve(); } } });
    });
    const res = {};
    const info = mac => page.evaluate(m => {
      const tr = document.querySelector(`#rows tr[data-mac="${m}"]`), vis = e => !!e && e.offsetWidth > 0;
      const v6 = tr.querySelector('.c-ip .cp.ip6'), v4 = tr.querySelector('.c-ip .cp');
      return { v4: v4.textContent, v4_title: v4.title, v6: v6 ? v6.textContent : null, v6_title: v6 ? v6.title : null,
        v6_visible: vis(v6), v6_tab: v6 ? v6.tabIndex : null, v6_role: v6 ? v6.getAttribute('role') : null,
        meta_v6: tr.querySelector('.dev-meta .ip6') ? tr.querySelector('.dev-meta .ip6').textContent : null,
        focusable: [...tr.querySelectorAll('.c-ip [tabindex]')].length, meta_focusable: [...tr.querySelectorAll('.dev-meta [tabindex]')].length,
        v6_below: v6 ? v6.getBoundingClientRect().top >= v4.getBoundingClientRect().bottom - 1 : null };
    }, mac);
    res.a = await info(A); res.b = await info(B);
    // the drawer shows an IPv6 row for A only
    const drawerV6 = async mac => {
      await page.click(`${row(mac)} .nm`); await waitOpen(page, mac);
      const dts = await page.$$eval('#dBody dt', t => t.map(e => [e.textContent, e.nextElementSibling.textContent, e.nextElementSibling.className]));
      await page.keyboard.press('Escape'); await waitClosed(page);
      return dts.filter(d => d[0] === 'IPv6');
    };
    res.drawer_a = await drawerV6(A); res.drawer_b = await drawerV6(B);
    // search: the address (a prefix of it) finds A only
    await page.click('#q', { clickCount: 3 });
    await page.type('#q', '2001:db8');
    await page.waitForFunction(v => new URLSearchParams(location.search).get('q') === v, {}, '2001:db8');
    res.search = await rowNames(page);
    await page.click('#q', { clickCount: 3 });
    await page.keyboard.press('Escape');
    // click on the text copies it, the title returns to the address; the drawer stays shut
    await page.click(`${row(A)} .c-ip .cp.ip6`);
    await page.waitForFunction(() => window.__copied.length === 1);
    res.copied = await page.evaluate(() => window.__copied.slice());
    res.open_after_copy = await drawerOpen(page);
    res.copied_cls = await page.$eval(`${row(A)} .c-ip .cp.ip6`, e => e.classList.contains('copied'));
    // while "Copied" shows the text stays cut (ellipsis, nothing runs into the next column) and the bubble is there
    res.copied_look = await page.$eval(`${row(A)} .c-ip .cp.ip6`, e => { const cs = getComputedStyle(e), r = e.getBoundingClientRect();
      return { cut: e.scrollWidth > e.clientWidth, width_ok: r.width <= 160.5, overflow: cs.overflowX, text_overflow: cs.textOverflow,
        bubble: getComputedStyle(e, '::after').content }; });
    await page.waitForFunction(s => !document.querySelector(s).classList.contains('copied'), {}, `${row(A)} .c-ip .cp.ip6`);
    res.title_after = await page.$eval(`${row(A)} .c-ip .cp.ip6`, e => e.title);
    // phone widths: the meta line carries the address, in at most two lines, and nothing scrolls sideways
    for (const width of [400, 360]) {
      await page.setViewport({ width, height: 900 });
      res[width] = await page.evaluate(([a, b]) => {
        const wrap = document.querySelector('.table-wrap'), de = document.documentElement;
        const tr = m => document.querySelector(`#rows tr[data-mac="${m}"]`);
        const meta = m => { // the items' centres: items of unequal height on one line have unequal tops
          const ys = [...tr(m).querySelectorAll('.dev-meta > *')].filter(e => e.offsetWidth > 0)
            .map(e => { const r = e.getBoundingClientRect(); return Math.round((r.top + r.bottom) / 2); }).sort((p, q) => p - q);
          return ys.filter((y, i) => i === 0 || y - ys[i - 1] > 6);
        };
        const v6 = tr(a).querySelector('.dev-meta .ip6');
        return { table_scroll: wrap.scrollWidth - wrap.clientWidth, page_scroll: de.scrollWidth - de.clientWidth,
          lines_a: meta(a).length, lines_b: meta(b).length,
          dev_h_a: tr(a).querySelector('.c-dev').offsetHeight, dev_h_b: tr(b).querySelector('.c-dev').offsetHeight,
          meta_v6: v6.textContent, meta_v6_title: v6.title, meta_v6_visible: v6.offsetWidth > 0,
          col_v6_visible: tr(a).querySelector('.c-ip .cp.ip6').offsetWidth > 0,
          over: [...wrap.querySelectorAll('*')].filter(e => e.getBoundingClientRect().right > wrap.getBoundingClientRect().right + 0.5 && e.offsetWidth > 0)
            .slice(0, 10).map(e => `${e.tagName.toLowerCase()}.${e.className}`) };
      }, [A, B]);
    }
    // phone width, keyboard: the focused meta address survives the rebuild of the rows, and Enter on it copies
    await page.setViewport({ width: 400, height: 900 });
    const sel = `${row(A)} .dev-meta .ip6`;
    await page.evaluate(() => { window.__copied = []; window.__rebuilt = 0;
      new MutationObserver(() => window.__rebuilt++).observe(document.querySelector('#rows'), { childList: true }); });
    await page.focus(sel);
    await page.evaluate(() => { const s = document.querySelector('#fStatus'); s.dispatchEvent(new Event('change')); });
    await page.waitForFunction(() => window.__rebuilt > 0);
    res.meta_focus = await page.evaluate(s => ({ restored: document.activeElement === document.querySelector(s),
      active: document.activeElement.className }), sel);
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => window.__copied.length === 1);
    res.meta_enter = { copied: await page.evaluate(() => window.__copied.slice()), open: await drawerOpen(page),
      cls: await page.$eval(sel, e => e.classList.contains('copied')), title: await page.$eval(sel, e => e.title),
      look: await page.$eval(sel, e => { const cs = getComputedStyle(e);
        return { cut: e.scrollWidth > e.clientWidth, width_ok: e.getBoundingClientRect().width <= 160.5, text_overflow: cs.textOverflow,
          bubble: getComputedStyle(e, '::after').content }; }) };
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
  // archiving the only device of an earlier network leaves the colour of a later network as it was
  async vlancolor(page) {
    const snap = async () => ({
      chips: await page.$$eval('#vlans .chip', cs => Object.fromEntries(cs.map(c => [c.textContent.replace(/\s*\d+\/\d+$/, '').trim(),
        getComputedStyle(c.querySelector('.sw')).getPropertyValue('--vc').trim()]))),
      row: await page.$eval('#rows tr:not([data-mac="0a:00:00:00:10:03"]) .c-vlan .badge', b => getComputedStyle(b).getPropertyValue('--vc').trim()) });
    const M = '0a:00:00:00:10:03';
    const res = { before: await snap() };
    await page.click(`${row(M)} .c-dev`); await waitOpen(page, M);
    await page.click('#fArch');
    await page.waitForFunction(s => !document.querySelector(s), {}, row(M));
    await page.waitForFunction(() => ![...document.querySelectorAll('#vlans .chip')].some(c => c.textContent.startsWith('Aaa')));
    res.after = await snap();
    return res;
  },
  // connector events (mac ""): plain text, no who button, nothing to open
  async sourceevents(page) {
    await page.waitForSelector('#events .k.source_down');
    const rows = await page.$$eval('#events li', lis => lis.filter(li => li.querySelector('.k.source_down, .k.source_up')).map(li => ({
      text: li.textContent, who: li.querySelector('.who') !== null, kind: li.querySelector('.k').className })));
    await page.click('#events li:has(.k.source_down) .src');
    return { count: rows.length, texts: rows.map(r => r.text), who: rows.some(r => r.who), kinds: rows.map(r => r.kind),
             drawer_open_after_click: await drawerOpen(page) };
  },
  // events view: 150 seeded events (3 kinds, 3 days): paging by 60, the kind select, a one-day range, the export link
  async eventsview(page) {
    const rows = n => page.waitForFunction(c => document.querySelectorAll('#events li').length === c, {}, n);
    const moreHidden = () => page.$eval('#evMore', b => b.classList.contains('hidden'));
    const csv = () => page.$eval('#evCsv', a => a.getAttribute('href'));
    const scroll = () => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    const res = {};
    await rows(60);
    res.first = 60; res.more_hidden_first = await moreHidden(); res.csv_plain = await csv();
    res.kind_options = await page.$$eval('#evKind option', os => os.map(o => ({ value: o.value, text: o.textContent })));
    await page.click('#evMore'); await rows(120); res.second = 120;
    await page.click('#evMore'); await rows(150); res.third = 150;
    res.more_hidden_end = await moreHidden();
    res.unique_after_paging = await page.$$eval('#events li', ls => new Set(ls.map(l => l.textContent)).size);
    await page.select('#evKind', 'ip'); await rows(50);
    res.kind_rows = 50; res.kind_csv = await csv(); res.kind_more_hidden = await moreHidden();
    res.kind_url = await page.evaluate(() => location.search);
    await page.select('#evKind', ''); await rows(60);
    const d = new Date(); d.setDate(d.getDate() - 2);
    res.day = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    for (const id of ['#evFrom', '#evTo']) await page.$eval(id, (el, v) => { el.value = v; el.dispatchEvent(new Event('change', { bubbles: true })); }, res.day);
    await rows(50);
    res.day_rows = 50; res.day_csv = await csv();
    // a filter change after paging starts over at the first page
    await page.select('#evKind', 'hostname'); await rows(16);
    res.kind_day_rows = 16;
    res.scroll_1400 = await scroll();
    await page.setViewport({ width: 1280, height: 900 }); res.scroll_1280 = await scroll();
    await page.setViewport({ width: 800, height: 900 }); res.scroll_800 = await scroll();
    return res;
  },
  // From after To: the list stays empty under the active filters, on load and on the 60 s reload, and no events request goes out
  async evinvalid(page, base) {
    const asked = [];
    page.on('request', r => { if (new URL(r.url()).pathname === '/api/events') asked.push(r.url()); });
    await page.goto(`${base}?ek=ip&es=2026-05-02&eu=2026-05-01`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#rows tr');
    await page.waitForFunction(() => window.__lwReload);
    const state = () => page.evaluate(() => ({ items: document.querySelectorAll('#events li .k').length, empty: document.querySelector('#events').textContent.includes('No events match'),
      note_hidden: document.querySelector('#evRange').classList.contains('hidden'), note: document.querySelector('#evRange').textContent,
      csv_hidden: document.querySelector('#evCsv').classList.contains('hidden'), more_hidden: document.querySelector('#evMore').classList.contains('hidden') }));
    const res = { loaded: await state(), asked_on_load: asked.length };
    await page.evaluate(() => window.__lwReload());
    await page.waitForFunction(() => window.__lwReloads === 1);
    res.reloaded = await state(); res.asked_after_reload = asked.length;
    // a valid range brings the list back
    await page.$eval('#evTo', el => { el.value = ''; el.dispatchEvent(new Event('change', { bubbles: true })); });
    await page.waitForFunction(() => document.querySelectorAll('#events li .k').length > 0);
    res.fixed = await state();
    return res;
  },
  // an impossible day in the address (2026-02-31) is dropped, not kept as a hidden filter
  async evbadday(page, base) {
    await page.goto(`${base}?es=2026-02-31&eu=2026-04-31`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#rows tr');
    await page.waitForSelector('#events li .k');
    return { search: await page.evaluate(() => location.search), csv: await page.$eval('#evCsv', a => a.getAttribute('href')),
             from: await page.$eval('#evFrom', e => e.value), to: await page.$eval('#evTo', e => e.value) };
  },
  // the Select mode below 1280 px: First seen gives way to the checkbox column, so neither the table nor the page scrolls sideways
  async selectnarrow(page) {
    const res = {};
    const measure = () => page.evaluate(() => {
      const wrap = document.querySelector('.table-wrap'), th = [...document.querySelectorAll('#tbl thead th')];
      return { shown: th.filter(t => getComputedStyle(t).display !== 'none').map(t => t.className),
               table_scroll: wrap.scrollWidth - wrap.clientWidth,
               page_scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth };
    });
    res.plain = {};
    for (const width of [1280, 1024, 800]) { await page.setViewport({ width, height: 900 }); res.plain[width] = await measure(); }
    await page.click('#selBtn');
    for (const width of [1280, 1024, 800]) {
      await page.setViewport({ width, height: 900 });
      res[width] = await page.evaluate(() => {
        const wrap = document.querySelector('.table-wrap'), th = [...document.querySelectorAll('#tbl thead th')];
        return { shown: th.filter(t => getComputedStyle(t).display !== 'none').map(t => t.className),
                 table_scroll: wrap.scrollWidth - wrap.clientWidth,
                 page_scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth };
      });
    }
    return res;
  },
  // tags from the Select bar: three rows tagged and untagged at once, a row already holding eight tags left out after a
  // confirm, the bar at phone width and its Swedish labels
  async sel_tags(page, base) {
    const P = '02:00:00:00:60:01', Q = '02:00:00:00:60:02', R = '02:00:00:00:60:03', F = '02:00:00:00:60:04';
    const dialogs = [];
    page.on('dialog', async d => { dialogs.push(d.message()); await d.accept(); });
    const badges = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('#rows tr')].map(t =>
      [t.dataset.mac, [...t.querySelectorAll('.dev-tags .badge.tag')].map(b => b.dataset.tag)])));
    const chip = () => page.evaluate(() => { const c = document.querySelector('#tags .chip[data-tag="iot"]');
      return c ? c.querySelector('.tg').textContent + ' ' + c.querySelector('.n').textContent : null; });
    const tick = async macs => { for (const m of macs) await page.click(`${row(m)} .c-sel input`); };
    const server = async () => Object.fromEntries(await Promise.all([P, Q, R, F].map(async m => [m, (await serverDevice(page, m)).tags])));
    const res = {};
    await page.setViewport({ width: 1280, height: 900 });
    await page.click('#selBtn');
    await tick([P, Q, R]);
    res.ph = await page.$eval('#selTags', e => e.placeholder);
    res.maxlength = await page.$eval('#selTags', e => e.maxLength);
    res.empty_add = await (async () => { await page.click('#selTagAdd'); return { server: await server(), dialogs: dialogs.length }; })();
    await page.type('#selTags', 'iot');
    await page.click('#selTagAdd');
    await page.waitForFunction(() => document.querySelectorAll('#rows .badge.tag[data-tag="iot"]').length === 3);
    res.added = { badges: await badges(), chip: await chip(), banner: await page.$eval('#banner', b => b.textContent), server: await server() };
    await page.click('#selBtn'); await page.click('#selBtn'); // leave and enter: the ticks were cleared by the request
    await tick([P, Q, R]);
    await page.click('#selTagRemove');
    await page.waitForFunction(() => document.querySelectorAll('#rows .badge.tag[data-tag="iot"]').length === 0);
    res.removed = { badges: await badges(), chip: await chip(), banner: await page.$eval('#banner', b => b.textContent), server: await server() };
    // F holds eight tags: the confirm names it, it keeps eight, the others get the tag
    await page.evaluate(async m => { await fetch(`/api/devices/${m}`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: 'a1,a2,a3,a4,a5,a6,a7,a8' }) }); }, F);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForSelector(`${row(F)} .dev-tags .badge.tag`);
    await page.click('#selBtn');
    await tick([P, Q, F]);
    await page.type('#selTags', 'iot');
    await page.click('#selTagAdd');
    await page.waitForFunction(() => document.querySelectorAll('#rows .badge.tag[data-tag="iot"]').length === 2);
    res.full = { dialogs: [...dialogs], server: await server(), chip: await chip() };
    // phone width: the bar wraps, nothing scrolls sideways, and the last row can be scrolled clear of the bar
    await page.click('#selBtn'); await page.click('#selBtn');
    await tick([P]);
    res.narrow = {};
    for (const width of [400, 360]) {
      await page.setViewport({ width, height: 700 });
      await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
      res.narrow[width] = await page.evaluate(() => {
        const bar = document.querySelector('#selbar').getBoundingClientRect(), rows = document.querySelectorAll('#rows tr'),
              last = rows[rows.length - 1].getBoundingClientRect(), de = document.documentElement;
        return { page_scroll: de.scrollWidth - de.clientWidth, bar_left: bar.left, bar_right: bar.right, vw: de.clientWidth,
                 bar_h: bar.height, last_clear: last.bottom <= bar.top + 0.5,
                 btns: [...document.querySelectorAll('#selbar > *:not(.hidden)')].filter(e => e.getBoundingClientRect().right > bar.right + 0.5).length };
      });
    }
    await page.goto(`${base}?lang=sv`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector(`${row(P)}`);
    await page.click('#selBtn');
    await tick([P]);
    res.sv = await page.evaluate(() => ({ add: document.querySelector('#selTagAdd').textContent, remove: document.querySelector('#selTagRemove').textContent,
      ph: document.querySelector('#selTags').placeholder, label: document.querySelector('#selTags').getAttribute('aria-label') }));
    return res;
  },
  // a ?device= link whose first load fails: the drawer opens after the next successful load
  async deeplinkretry(page, base) {
    const DEV = '02:00:00:00:10:01';
    page.__allow = [503]; // the one refused /api/devices
    let refused = 0;
    await page.setRequestInterception(true);
    page.on('request', r => {
      if (!refused && new URL(r.url()).pathname === '/api/devices') {
        refused++;
        r.respond({ status: 503, contentType: 'application/json', body: '{"error":"down"}' });
      } else r.continue();
    });
    await page.goto(`${base}?device=${DEV}`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => !document.querySelector('#banner').classList.contains('hidden'));
    await page.waitForFunction(() => window.__lwReload);
    const res = { refused, banner: await page.$eval('#banner', b => b.textContent), open_before: await drawerOpen(page),
                  url_before: await page.evaluate(() => location.search) };
    await page.evaluate(() => window.__lwReload());
    await page.waitForFunction(() => window.__lwReloads === 1);
    await waitOpen(page, DEV);
    res.open_after = await drawerOpen(page);
    res.title = await page.$eval('#dTitle', e => e.textContent);
    res.url_after = await page.evaluate(() => location.search);
    res.banner_hidden = await page.$eval('#banner', b => b.classList.contains('hidden'));
    return res;
  },
  // the page's 60 s reload, run now: the second /api/devices is a 304 and the table keeps its rows
  async etag(page) {
    const rows0 = (await rowNames(page)).length;
    const seen = [];
    const onResponse = r => { const u = new URL(r.url()).pathname; if (u === '/api/devices' || u === '/api/events') seen.push({ path: u, status: r.status(),
      etag: r.headers().etag || null, sent: r.request().headers()['if-none-match'] || null }); };
    page.on('response', onResponse);
    await page.evaluate(() => window.__lwReload());
    await page.waitForFunction(() => window.__lwReloads === 1);
    page.off('response', onResponse);
    return { rows_before: rows0, rows_after: (await rowNames(page)).length, responses: seen,
             status_after: await page.$eval('#statusText', e => e.textContent),
             banner_hidden: await page.$eval('#banner', b => b.classList.contains('hidden')) };
  },
  // Split on a merged address: cancel changes nothing; ok makes the address a device of its own, the drawer stays on the
  // device and loses the row, the new row is private and its drawer says where it came from (changes server state)
  async split(page, base) {
    const DEV = '02:00:00:00:10:01', ALIAS = '06:00:00:00:10:02';
    let answer = false; const dialogs = [];
    page.on('dialog', async d => { dialogs.push(d.message()); await (answer ? d.accept() : d.dismiss()); });
    const aliases = () => page.$$eval('#dBody table.aliases tbody tr', trs => trs.map(t => t.querySelector('td').textContent));
    const serverAliases = () => page.evaluate(async m => (await (await fetch(`/api/devices/${m}`)).json()).aliases.map(a => a.mac), DEV);
    const res = {};
    await page.click(`${row(DEV)} .c-dev`); await waitOpen(page, DEV);
    res.before = { aliases: await aliases(), buttons: await page.$$eval('#dBody [data-split]', bs => bs.map(b => [b.dataset.split, b.textContent])),
                   head: await page.$$eval('#dBody table.aliases thead th', ths => ths.map(t => t.textContent)),
                   note: await page.$eval('#dBody table.aliases', t => t.previousElementSibling.textContent),
                   visible: await page.$eval('#dBody [data-split]', b => b.offsetWidth > 0 && getComputedStyle(b).visibility !== 'hidden' && getComputedStyle(b).opacity === '1') };
    await page.click('#dBody [data-split]');
    await new Promise(r => setTimeout(r, 400));
    res.cancelled = { dialogs: dialogs.length, aliases: await aliases(), server: await serverAliases(), open: await drawerOpen(page),
                      new_row: !!(await page.$(row(ALIAS))) };
    answer = true;
    // unsaved text in Name, which keeps focus: the split is clicked from script, so focus does not move to the button
    await page.focus('#fName'); await page.keyboard.type(' typed');
    await page.evaluate(() => { window.__oldSplit = document.querySelector('#dBody [data-split]'); setTimeout(() => window.__oldSplit.click()); });
    await page.waitForFunction(() => document.querySelector('#fSaved') && document.querySelector('#fSaved').textContent === 'split');
    await page.waitForSelector(row(ALIAS));
    res.done = { dialogs: [...dialogs], aliases: await aliases(), headings: await page.$$eval('#dBody h3', hs => hs.map(h => h.textContent)),
                 server: await serverAliases(), open: await drawerOpen(page), title: await page.$eval('#dTitle', e => e.textContent),
                 mac: await page.$$eval('#dBody dd.mono', ds => ds.map(d => d.textContent)),
                 row_private: await page.$eval(`${row(ALIAS)} .c-mac .priv`, e => e.title),
                 buttons: (await page.$$('#dBody [data-split]')).length, name: await page.$eval('#fName', e => e.value),
                 focus: await page.evaluate(() => document.activeElement && document.activeElement.id) };
    // the old button, kept from before the split: a second split of the same address fails and says so
    page.__allow = [404]; // the server no longer has the address as an alias
    await page.evaluate(() => setTimeout(() => window.__oldSplit.click()));
    await page.waitForFunction(() => !document.querySelector('#banner').classList.contains('hidden'));
    res.again = { banner: await page.$eval('#banner', b => b.textContent), dialogs: dialogs.length, name: await page.$eval('#fName', e => e.value) };
    page.__allow = null;
    await page.waitForSelector('#events .k.split');
    res.events = await page.$$eval('#events .k.split', ks => ks.map(k => k.textContent));
    // the events kind filter offers split
    await page.select('#evKind', 'split');
    await page.waitForFunction(() => { const ks = [...document.querySelectorAll('#events li .k')]; return ks.length && ks.every(k => k.classList.contains('split')); });
    res.ev_filter = { kinds: await page.$$eval('#events li .k', ks => ks.map(k => k.textContent)), url: await page.evaluate(() => location.search) };
    await page.keyboard.press('Escape'); await waitClosed(page); // accepts "Discard unsaved changes?"
    await page.click(`${row(ALIAS)} .c-dev`); await waitOpen(page, ALIAS);
    res.split_row = await page.evaluate(() => {
      const dt = [...document.querySelectorAll('#dBody dt')].find(x => x.textContent === 'Split from');
      const status = [...document.querySelectorAll('#dBody dt')].find(x => x.textContent === 'Status');
      const b = dt && dt.nextElementSibling.querySelector('button.who');
      return { split_from: b ? [b.textContent, b.dataset.mac] : null, status: status.nextElementSibling.textContent.trim(),
               aliases_table: !!document.querySelector('#dBody table.aliases'),
               kinds: [...document.querySelectorAll('#dBody ul.tl .k')].map(k => k.textContent) };
    });
    await page.click('#dBody button.who'); await waitOpen(page, DEV);
    res.back = { title: await page.$eval('#dTitle', e => e.textContent), open: await drawerOpen(page) };
    // ?ek=split in the address survives readUrl: the list offers the kind
    await page.goto(`${base}?ek=split`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.querySelectorAll('#events li .k').length > 0);
    res.ek_url = { select: await page.$eval('#evKind', s => s.value), url: await page.evaluate(() => location.search),
                   kinds: await page.$$eval('#events li .k', ks => ks.map(k => k.textContent)) };
    return res;
  },
  // READ_ONLY server: a merged address is listed without a Split button or its column
  async splitro(page) {
    const DEV = '02:00:00:00:00:01';
    await page.click(`${row(DEV)} .c-dev`); await waitOpen(page, DEV);
    return { table: !!(await page.$('#dBody table.aliases')), buttons: (await page.$$('#dBody [data-split]')).length,
             head: await page.$$eval('#dBody table.aliases thead th', ths => ths.map(t => t.textContent)) };
  },
  // server with READ_ONLY=1: no edit controls in the rows or the drawer, one line that says why
  async readonly(page) {
    const MAC = '02:00:00:00:00:06'; // new and not yet known: it would have a "Mark known" button
    const rowAcks = await page.$$eval('#rows .ack', bs => bs.length);
    await page.click(`${row(MAC)} .c-dev`);
    await waitOpen(page, MAC);
    return { row_acks: rowAcks, can_write: await page.evaluate(async () => (await (await fetch('/api/status')).json()).meta.can_write),
             line: await page.$eval('#fReadOnly', e => e.textContent),
             buttons: await page.$$eval('#dBody .actions button', bs => bs.map(b => b.id)),
             name_readonly: await page.$eval('#fName', e => e.readOnly), note_readonly: await page.$eval('#fNote', e => e.readOnly) };
  },
  // the "Baseline, not checked" filter and its card: the option, the card's number and visibility, ?filter=baseline,
  // and the page width at 1280 px with the fifth card shown
  async baseline(page, base) {
    const card = () => page.evaluate(() => {
      const c = document.querySelector('#cardBaseline');
      return { hidden: getComputedStyle(c).display === 'none', num: c.querySelector('.num').textContent,
               five: document.querySelector('#cards').classList.contains('five'),
               pressed: c.getAttribute('aria-pressed') };
    });
    const res = { option: await page.$$eval('#fStatus option', os => os.map(o => [o.value, o.textContent])) };
    res.card = await card();
    await page.setViewport({ width: 1280, height: 900 });
    res.scroll_1280 = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    res.card_box = await page.evaluate(() => { const r = document.querySelector('#cardBaseline').getBoundingClientRect(); return { w: r.width, right: r.right }; });
    await page.goto(`${base}?filter=baseline`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.querySelector('#cTotal').textContent !== '–');
    res.restored = await page.$eval('#fStatus', e => e.value);
    res.names = await rowNames(page);
    res.card_filtered = await card();
    res.empty = await page.$eval('#empty', e => e.classList.contains('hidden') ? '' : document.querySelector('#emptyText').textContent);
    res.scroll_filtered = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    await page.click('#cardBaseline:not(.hidden)').catch(() => {});
    res.after_click_filter = await page.$eval('#fStatus', e => e.value);
    return res;
  },
  // the Select mode at 1280 px: the checkbox column replaces Type, three rows ticked (one by Space), Mark known for all
  // three in one request, select all visible, and leaving the mode. Changes server state (three acks)
  async bulk(page) {
    const PICK = ['02:00:00:00:00:06', '02:00:00:00:00:08', '02:00:00:00:00:0c'];
    const cols = () => page.evaluate(() => {
      const wrap = document.querySelector('.table-wrap'), th = [...document.querySelectorAll('#tbl thead th')];
      return { shown: th.filter(t => getComputedStyle(t).display !== 'none').map(t => t.className),
               table_scroll: wrap.scrollWidth - wrap.clientWidth,
               page_scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
               sel_width: document.querySelector('#tbl thead th.c-sel').offsetWidth };
    });
    const bar = () => page.evaluate(() => {
      const b = document.querySelector('#selbar'), vis = id => !document.getElementById(id).classList.contains('hidden');
      return { shown: !b.classList.contains('hidden'), count: document.querySelector('#selCount').textContent,
               ack: vis('selAck'), archive: vis('selArchive'), restore: vis('selRestore'),
               all: document.querySelector('#selAll').checked, some: document.querySelector('#selAll').indeterminate,
               pressed: document.querySelector('#selBtn').getAttribute('aria-pressed') };
    });
    const res = {};
    await page.setViewport({ width: 1280, height: 900 });
    res.before = await cols();
    await page.click('#selBtn');
    res.selecting = await cols();
    res.bar_empty = await bar();
    await page.click(`${row(PICK[0])} .c-sel input`);
    await page.click(`${row(PICK[1])} td.c-sel`); // the cell around the box toggles it too
    await page.focus(`${row(PICK[2])} .c-sel input`);
    await page.keyboard.press('Space');
    res.space_drawer = await drawerOpen(page);
    res.ticked = await page.$$eval('#rows .c-sel input', cs => cs.filter(c => c.checked).map(c => c.closest('tr').dataset.mac));
    res.bar3 = await bar();
    res.labels = await page.$$eval(PICK.map(m => `${row(m)} .c-sel input`).join(','), cs => cs.map(c => c.getAttribute('aria-label')));
    await page.click('#selAck');
    await page.waitForFunction(() => document.querySelector('#selbar').classList.contains('hidden'));
    await page.waitForFunction(ms => ms.every(m => !document.querySelector(`#rows tr[data-mac="${m}"]`).classList.contains('is-new')), {}, PICK);
    res.after = {
      bar: await bar(),
      new_badges: await page.$$eval(PICK.map(m => `${row(m)} .badge.new`).join(','), bs => bs.length),
      server: await Promise.all(PICK.map(async m => (await serverDevice(page, m)).acked)),
      acked_events: await page.evaluate(async ms => (await (await fetch('/api/events')).json()).events
        .filter(e => e.kind === 'acked' && ms.includes(e.mac)).length, PICK),
      ticked: await page.$$eval('#rows .c-sel input', cs => cs.filter(c => c.checked).length),
      still_selecting: await page.$eval('#tbl', t => t.classList.contains('selecting')),
    };
    // the header box: all visible rows, then none; one row gives the mixed state
    await page.type('#q', 'HomeNet');
    await page.waitForFunction(() => document.querySelectorAll('#rows tr').length === 8);
    await page.click('#selAll');
    res.all = { bar: await bar(), rows: await page.$$eval('#rows tr', ts => ts.length) };
    await page.click('#selAll');
    res.none = await bar();
    await page.click(`${row(PICK[0])} .c-sel input`);
    res.one = await bar();
    // leaving the mode: Type comes back and the selection is gone
    await page.click('#selBtn');
    res.left = { cols: await cols(), bar: await bar(), sel: await page.evaluate(() => document.querySelectorAll('#rows .c-sel input:checked').length) };
    await page.click('#selBtn');
    res.reentered = await bar();
    return res;
  },
  // a client that may not write: no Select button, no checkbox column
  async bulkro(page) {
    return { button: await page.$eval('#selBtn', b => getComputedStyle(b).display),
             column: await page.$eval('#tbl thead th.c-sel', t => getComputedStyle(t).display) };
  },
  // changes server state (a name, two acks): runs after the read-only scenarios
  // no SSID was ever recorded: the Wi-Fi chip row stays hidden and the headers keep their names
  async nossid(page) {
    return { hidden: await page.$eval('#ssids', e => e.classList.contains('hidden') && e.offsetHeight === 0),
             chips: await page.$$eval('#ssids .chip[data-ssid]', cs => cs.length),
             heads: await page.$$eval('#thFirst, #thLast', hs => hs.map(h => h.textContent)) };
  },
  // the SSID chip row: counts and titles, the "ever" and "now only" filters, the address, a reload, the SSID's times in
  // the rows, the keyboard, Clear filters and the width. The SSID names carry markup, which must stay text
  async ssids(page, base) {
    await page.waitForSelector('#ssids .chip[data-ssid]');
    const chip = s => page.evaluateHandle(v => [...document.querySelectorAll('#ssids .chip[data-ssid]')].find(c => c.dataset.ssid === v), s);
    const view = () => page.evaluate(() => {
      const p = new URLSearchParams(location.search), now = document.querySelector('#ssidNow');
      return {
        rows: [...document.querySelectorAll('#rows tr')].map(t => ({ mac: t.dataset.mac, first: t.querySelector('.c-first').textContent,
          last: t.querySelector('.c-last').textContent, meta: t.querySelector('.dev-meta .last').textContent })),
        heads: [...document.querySelectorAll('#thFirst, #thLast')].map(h => h.textContent),
        ssid: p.get('ssid'), ssidnow: p.get('ssidnow'),
        now_shown: !now.classList.contains('hidden') && now.offsetWidth > 0, now_pressed: now.getAttribute('aria-pressed'),
        pressed: [...document.querySelectorAll('#ssids .chip[data-ssid]')].filter(c => c.getAttribute('aria-pressed') === 'true').map(c => c.dataset.ssid),
        markup: document.querySelectorAll('#ssids b, #rows b').length,
      };
    });
    const waitUrl = (k, v) => page.waitForFunction((a, b) => new URLSearchParams(location.search).get(a) === b, {}, k, v);
    const res = { hidden: await page.$eval('#ssids', e => e.classList.contains('hidden')), before: await view() };
    res.chips = await page.$$eval('#ssids .chip[data-ssid]', cs => cs.map(c => ({ ssid: c.dataset.ssid, text: c.querySelector('.ssid').textContent,
      n: c.querySelector('.n').textContent, title: c.title, tag: c.tagName.toLowerCase(), b: c.querySelectorAll('b').length })));
    const GUEST = res.chips[0].ssid;
    await (await chip(GUEST)).click();
    await waitUrl('ssid', GUEST);
    res.ever = await view();
    await page.click('#ssidNow');
    await waitUrl('ssidnow', '1');
    res.now = await view();
    // a reload of the address brings the same filter back
    await page.goto(page.url(), { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#rows tr');
    await page.waitForSelector('#ssids .chip.active[data-ssid]');
    res.reloaded = await view();
    // both devices that were on the guest network, so the sub line of each is measured
    await page.click('#ssidNow');
    await waitUrl('ssidnow', null);
    await page.waitForFunction(() => document.querySelectorAll('#rows tr').length === 2);
    for (const width of [1280, 800, 600, 400]) {
      await page.setViewport({ width, height: 900 });
      res[width] = await page.evaluate(() => {
        const wrap = document.querySelector('.table-wrap');
        return { table_scroll: wrap.scrollWidth - wrap.clientWidth, page_scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          last_col: getComputedStyle(document.querySelector('#rows .c-last')).display,
          sub: [...document.querySelectorAll('#rows tr')].map(t => { const e = t.querySelector('.dev-sub .ssid-last');
            return { mac: t.dataset.mac, shown: !!e && e.offsetWidth > 0 && e.offsetHeight > 0, text: e ? e.textContent : null }; }) };
      });
    }
    await page.setViewport({ width: 1400, height: 900 });
    // the keyboard: Space on the focused chip turns the filter off, and the focus stays on the rebuilt chip
    await (await chip(GUEST)).focus();
    await page.keyboard.press('Space');
    await page.waitForFunction(() => !new URLSearchParams(location.search).has('ssid'));
    res.key_off = { ...await view(), focus: await page.evaluate(() => document.activeElement.dataset.ssid || null) };
    await page.keyboard.press('Enter');
    await waitUrl('ssid', GUEST);
    res.key_on = await view();
    // Clear filters (offered when nothing matches) drops the SSID filter too
    await page.type('#q', 'zzz-nothing');
    await page.waitForSelector('#empty:not(.hidden) #emptyClear:not(.hidden)');
    await page.click('#emptyClear');
    await page.waitForFunction(() => !location.search);
    res.cleared = await view();
    return res;
  },
  // long SSIDs, a NEW private-MAC row and a NEW watched row with a long name at phone widths: the page and the table must
  // not scroll sideways
  async ssidwidth(page, base) {
    const res = {};
    const cases = { none: '', ever32: '?ssid=Guest-Network-Long-SSID-Name-32c', now32: '?ssid=Guest-Network-Long-SSID-Name-32c&ssidnow=1',
      ever40: '?ssid=VeryLongNetworkNameWithoutAnyBreaksAtAll' };
    for (const [name, qs] of Object.entries(cases)) {
      await page.setViewport({ width: 1280, height: 900 });
      await page.goto(new URL(qs, base).href, { waitUntil: 'domcontentloaded' });
      await page.waitForSelector('#rows tr');
      for (const width of [400, 360]) {
        await page.setViewport({ width, height: 900 });
        res[`${name}_${width}`] = await page.evaluate(() => {
          const wrap = document.querySelector('.table-wrap'), de = document.documentElement;
          return { rows: document.querySelectorAll('#rows tr').length, table_scroll: wrap.scrollWidth - wrap.clientWidth,
            watched_new: [...document.querySelectorAll('#rows tr')].filter(t => t.querySelector('.badge.new') && t.querySelector('.badge.watch'))
              .map(t => t.querySelector('.nm').textContent),
            page_scroll: de.scrollWidth - de.clientWidth,
            over: [...wrap.querySelectorAll('*')].filter(e => e.getBoundingClientRect().right > wrap.getBoundingClientRect().right + 0.5 && e.offsetWidth > 0)
              .slice(0, 10).map(e => `${e.tagName.toLowerCase()}.${e.className}:${Math.round(e.getBoundingClientRect().right)}`) };
        });
      }
    }
    return res;
  },
  // tags end to end: typed in the drawer, normalised by the server, badges in the row, the chip row and its filter in the
  // address, a reload, Clear filters, a refused tag, and many badges at phone width
  async tags(page, base) {
    const A = '02:00:00:00:50:01', B = '02:00:00:00:50:02', W = '02:00:00:00:50:03';
    const waitUrl = v => page.waitForFunction(t => new URLSearchParams(location.search).get('tag') === t, {}, v);
    const view = () => page.evaluate(() => ({
      hidden: document.querySelector('#tags').classList.contains('hidden'),
      chips: [...document.querySelectorAll('#tags .chip[data-tag]')].map(c => ({ tag: c.dataset.tag, text: c.querySelector('.tg').textContent,
        n: c.querySelector('.n').textContent, pressed: c.getAttribute('aria-pressed'), title: c.title })),
      grp: [...document.querySelectorAll('#tags .grp')].map(g => ({ text: g.textContent, tag: g.tagName.toLowerCase(), tabindex: g.getAttribute('tabindex') })),
      rows: [...document.querySelectorAll('#rows tr')].map(t => t.dataset.mac).sort(),
      badges: Object.fromEntries([...document.querySelectorAll('#rows tr')].map(t => [t.dataset.mac,
        [...t.querySelectorAll('.dev-tags .badge.tag')].map(b => ({ tag: b.dataset.tag, text: b.textContent, owner: b.classList.contains('owner') }))])),
      tag: new URLSearchParams(location.search).get('tag'),
    }));
    const res = { before: await view() };
    // A: type the tags, Save; the POST carries them with the name and the note
    let body = null;
    const onReq = r => { if (r.method() === 'POST') body = r.postData(); };
    page.on('request', onReq);
    await page.click(`${row(A)} .c-dev`); await waitOpen(page, A);
    await page.type('#fTags', 'IoT, owner:alex');
    await page.click('#fSave');
    await page.waitForFunction(() => document.querySelector('#fSaved') && document.querySelector('#fSaved').textContent === 'saved');
    page.off('request', onReq);
    res.saved = { body: JSON.parse(body), server: (await serverDevice(page, A)).tags, input: await page.$eval('#fTags', e => e.value) };
    await page.keyboard.press('Escape'); await waitClosed(page);
    await page.waitForSelector('#tags .chip[data-tag]');
    res.after = await view();
    // the owner chip shows the name, filters on the full tag, and the address keeps owner:alex
    await page.click('#tags .chip[data-tag="owner:alex"]');
    await waitUrl('owner:alex');
    res.owner = await view();
    res.owner_url = page.url();
    await page.click('#tags .chip[data-tag="owner:alex"]');
    await waitUrl(null);
    // the iot chip filters to A and writes the address; a reload keeps it
    await page.click('#tags .chip[data-tag="iot"]');
    await waitUrl('iot');
    res.filtered = await view();
    await page.goto(page.url(), { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#tags .chip.active[data-tag]');
    res.reloaded = await view();
    // Clear filters (offered when nothing matches) drops the tag too
    await page.type('#q', 'zzz-nothing');
    await page.waitForSelector('#empty:not(.hidden) #emptyClear:not(.hidden)');
    await page.click('#emptyClear');
    await page.waitForFunction(() => !location.search);
    res.cleared = await view();
    // B: a tag the server refuses; the banner says why and the input keeps what was typed
    page.__allow = [400];
    await page.click(`${row(B)} .c-dev`); await waitOpen(page, B);
    await page.type('#fTags', 'tag!');
    await page.click('#fSave');
    await page.waitForFunction(() => !document.querySelector('#banner').classList.contains('hidden'));
    res.refused = { banner: await page.$eval('#banner', e => e.textContent), input: await page.$eval('#fTags', e => e.value),
                    open: await drawerOpen(page), server: (await serverDevice(page, B)).tags };
    page.__allow = null;
    await page.click('#fTags', { clickCount: 3 }); await page.keyboard.press('Backspace'); // nothing left to discard
    await page.keyboard.press('Escape'); await waitClosed(page);
    // W: eight long tags, at phone widths
    await page.evaluate(async m => { await fetch(`/api/devices/${m}`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: 'living-room-speaker-01, owner:alexandra-long, upstairs-hallway-ceil, media-streaming-box, firmware-pinned-v2, kids-bedtime-schedule, guest-network-allowed, energy-monitoring-on' }) }); }, W);
    await page.evaluate(() => window.__lwReload());
    await page.waitForFunction(m => document.querySelectorAll(`#rows tr[data-mac="${m}"] .badge.tag`).length === 8, {}, W);
    for (const width of [400, 360]) {
      await page.setViewport({ width, height: 900 });
      res[width] = await page.evaluate(m => {
        const wrap = document.querySelector('.table-wrap'), de = document.documentElement, tr = document.querySelector(`#rows tr[data-mac="${m}"]`);
        return { table_scroll: wrap.scrollWidth - wrap.clientWidth, page_scroll: de.scrollWidth - de.clientWidth,
          lines: new Set([...tr.querySelectorAll('.badge.tag')].map(b => Math.round(b.getBoundingClientRect().top))).size,
          over: [...wrap.querySelectorAll('*')].filter(e => e.getBoundingClientRect().right > wrap.getBoundingClientRect().right + 0.5 && e.offsetWidth > 0)
            .slice(0, 10).map(e => `${e.tagName.toLowerCase()}.${e.className}:${Math.round(e.getBoundingClientRect().right)}`) };
      }, W);
    }
    // 14 distinct tags (W's eight and six on B, A's taken off), all on one device each, so they rank by name: 12 chips and
    // "+2 more"; upstairs-hallway-ceil ranks 14th, printer-f 13th
    const post = ms => page.evaluate(async ms => { for (const [m, tags] of ms) await fetch(`/api/devices/${m}`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tags }) }); }, ms);
    await page.setViewport({ width: 1280, height: 900 });
    await post([[A, ''], [B, 'printer-a, printer-b, printer-c, printer-d, printer-e, printer-f']]);
    await page.evaluate(() => window.__lwReload());
    await page.waitForFunction(() => document.querySelector('#tagMore') && document.querySelectorAll('#tags .chip[data-tag]').length === 12);
    const cap = () => page.evaluate(() => ({ chips: [...document.querySelectorAll('#tags .chip[data-tag]')].map(c => c.dataset.tag),
      more: document.querySelector('#tagMore')?.textContent ?? null, focus: document.activeElement.dataset.tag ?? document.activeElement.id }));
    res.capped = await cap();
    await page.click('#tagMore');
    await page.waitForFunction(() => !document.querySelector('#tagMore'));
    res.all = await cap();
    // the active tag from beyond the cap joins the 12; "+1 more" brings in printer-f, the one tag left out
    const far = new URL(page.url()); far.search = '?tag=upstairs-hallway-ceil';
    await page.goto(far.href, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#tags .chip.active[data-tag]');
    res.far = await cap();
    await page.click('#tagMore');
    await page.waitForFunction(() => !document.querySelector('#tagMore'));
    res.far_more = await cap();
    // clicked off from the keyboard, the active chip leaves the row; the focus goes to "+2 more", not the top of the page
    await page.goto(far.href, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#tags .chip.active[data-tag]');
    await page.focus('#tags .chip[data-tag="upstairs-hallway-ceil"]');
    await page.keyboard.press('Enter');
    await waitUrl(null);
    res.far_off = await cap();
    // 14 tags with an owner among the two left out: the row is plain tags, then owners, so "+2 more" focuses the first new
    // chip in row order (printer-a), not the better ranked owner:bob that sits at the end of the row
    await post([[W, 'energy-monitoring-on, firmware-pinned-v2, guest-network-allowed, kids-bedtime-schedule, living-room-speaker-01, media-streaming-box, owner:alexandra-long'],
      [A, 'owner:bob'], [B, 'alpha-1, alpha-2, alpha-3, alpha-4, alpha-5, printer-a']]);
    await page.goto(new URL(page.url()).origin + '/', { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.querySelector('#tagMore') && document.querySelectorAll('#tags .chip[data-tag]').length === 12);
    res.owner_capped = await cap();
    await page.click('#tagMore');
    await page.waitForFunction(() => !document.querySelector('#tagMore'));
    res.owner_all = await cap();
    // only plain tags left: the row looks as before, no headings
    await post([[A, 'iot'], [B, ''], [W, 'speaker']]);
    await page.evaluate(() => window.__lwReload());
    await page.waitForFunction(() => document.querySelectorAll('#tags .chip[data-tag]').length === 2);
    res.plain = await view();
    return res;
  },
  // a device archived after it was on the guest network: not in its list under the default status filter, listed under
  // "Archived", and not in the chip's count
  async ssidarchived(page, base) {
    await page.waitForSelector('#ssids .chip[data-ssid]');
    const chipN = () => page.$eval('#ssids .chip[data-ssid="Guest"] .n', e => e.textContent);
    const macs = () => page.$$eval('#rows tr', ts => ts.map(t => t.dataset.mac).sort());
    const res = { chip_before: await chipN() };
    await page.goto(new URL('?ssid=Guest', base).href, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#ssids .chip.active[data-ssid]');
    res.default_rows = await macs();
    res.chip_filtered = await chipN();
    await page.evaluate(() => { const s = document.querySelector('#fStatus'); s.value = 'archived'; s.dispatchEvent(new Event('change')); });
    await page.waitForFunction(() => document.querySelectorAll('#rows tr').length === 1);
    res.archived_rows = await macs();
    res.chip_archived = await chipN();
    return res;
  },
  // the guest-SSID question end to end: data written by the real collector over four polls. The chips, the Guest list with the
  // SSID's own times, the drawer of the merged device, the CSV of the SSID, and the width
  async guestflow(page, base) {
    await page.waitForSelector('#ssids .chip[data-ssid]');
    const GUEST = 'Guest', X = '02:00:00:00:40:01';
    const chips = await page.$$eval('#ssids .chip[data-ssid]', cs => cs.map(c => ({ ssid: c.dataset.ssid, n: c.querySelector('.n').textContent })));
    await page.evaluate(v => [...document.querySelectorAll('#ssids .chip[data-ssid]')].find(c => c.dataset.ssid === v).click(), GUEST);
    await page.waitForFunction(v => new URLSearchParams(location.search).get('ssid') === v, {}, GUEST);
    await page.waitForFunction(() => document.querySelector('#thFirst').textContent === 'First on SSID');
    const list = await page.evaluate(() => ({
      heads: [...document.querySelectorAll('#thFirst, #thLast')].map(h => h.textContent),
      rows: [...document.querySelectorAll('#rows tr')].map(t => ({ mac: t.dataset.mac, name: t.querySelector('.nm').textContent,
        first: t.querySelector('.c-first').textContent, last: t.querySelector('.c-last').textContent }))
    }));
    await page.click(`${row(X)} .c-dev`);
    await waitOpen(page, X);
    await page.waitForSelector('#dBody table.wifi');
    const drawer = await page.evaluate(() => [...document.querySelectorAll('#dBody table.wifi tbody tr')].map(r => [...r.querySelectorAll('td')].map(td => td.textContent)));
    await page.keyboard.press('Escape');
    await waitClosed(page);
    const csv = await page.evaluate(async () => {
      const r = await fetch('/api/wifi.csv?ssid=Guest');
      return { status: r.status, type: r.headers.get('content-type'), text: await r.text() };
    });
    await page.setViewport({ width: 1280, height: 900 });
    const scroll = await page.evaluate(() => ({ page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      table: document.querySelector('.table-wrap').scrollWidth - document.querySelector('.table-wrap').clientWidth }));
    return { chips, list, drawer, csv, scroll };
  },
  async drawer(page) {
    const res = {};
    const CLICK = '02:00:00:00:00:06', KEY = '02:00:00:00:00:0d', ROWACK = '02:00:00:00:00:0c';
    // open by click, close with Escape: focus goes back to the row
    await page.click(`${row(CLICK)} .c-dev`);
    await waitOpen(page, CLICK);
    res.click = { open: await drawerOpen(page), title: await page.$eval('#dTitle', e => e.textContent), focus: await focused(page),
                  badges: await page.$$eval('#dBody .badge.vlan', bs => bs.map(b => getComputedStyle(b).getPropertyValue('--vc').trim())) };
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
    // Watch in the drawer posts only the watch state, and the row gets the watch badge
    await page.click(`${row(KEY)} .c-dev`);
    await waitOpen(page, KEY);
    let watchBody = null;
    const onReq = r => { if (r.method() === 'POST') watchBody = r.postData(); };
    page.on('request', onReq);
    res.watch_label = await page.$eval('#fWatch', e => e.textContent);
    await page.click('#fWatch');
    await page.waitForFunction(s => document.querySelector(s) && document.querySelector('#fWatch')?.textContent === 'Unwatch', {}, `${row(KEY)} .badge.watch`);
    page.off('request', onReq);
    res.watched = { body: watchBody, badge: await page.$eval(`${row(KEY)} .badge.watch`, e => e.textContent),
                    server: (await serverDevice(page, KEY)).watch };
    await page.keyboard.press('Escape');
    await waitClosed(page);
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
  const res = { scenario: name, pass: false, details: null, console_errors: [], failed_requests: [], csp_violations: [],
                csp: null, error: null };
  const page = await browser.newPage();
  try {
    // LW_TEST_AUTH="user:password": the server has basic auth on; the browser answers its 401 with these
    const creds = process.env.LW_TEST_AUTH;
    if (creds) {
      const i = creds.indexOf(':');
      await page.authenticate({ username: creds.slice(0, i), password: creds.slice(i + 1) });
    }
    // listeners before goto, or the first load's errors are missed
    page.on('console', m => {
      // a scenario that asks for a known 404 (page.__allow) does not fail on Chrome's console line for it
      if (m.type() === 'error' && !(page.__allow && /Failed to load resource.* \((Not Found|Service Unavailable|Bad Request)\)/.test(m.text()))) res.console_errors.push(m.text());
      if (/^Refused to|Content Security Policy/.test(m.text())) res.csp_violations.push(`console: ${m.text()}`);
    });
    // the page's own report of anything the CSP blocked, from every document the page loads
    await page.exposeFunction('__lwCspViolation', v => res.csp_violations.push(v));
    await page.evaluateOnNewDocument(() => document.addEventListener('securitypolicyviolation', e =>
      window.__lwCspViolation(`${e.effectiveDirective} blocked ${e.blockedURI || '(inline)'} at ${e.sourceFile}:${e.lineNumber}`)));
    // the page's 60 s reload as a function a scenario can call (window.__lwReload), counted when it settles
    await page.evaluateOnNewDocument(() => {
      const si = window.setInterval;
      window.__lwReloads = 0;
      window.setInterval = (f, ms, ...a) => {
        if (ms === 60000) window.__lwReload = async () => { await f(); window.__lwReloads++; };
        return si(f, ms, ...a);
      };
    });
    page.on('pageerror', e => res.console_errors.push(`pageerror: ${e.message}`));
    page.on('requestfailed', r => res.failed_requests.push(`${r.failure() ? r.failure().errorText : 'failed'} ${r.url()}`));
    page.on('response', r => { if (r.status() >= 400 && !(page.__allow || []).includes(r.status())) res.failed_requests.push(`http ${r.status()} ${r.url()}`); });
    if (!scenarios[name]) throw new Error(`unknown scenario ${name}`);
    await page.setViewport({ width: 1400, height: 900 });
    const doc = await page.goto(base, { waitUntil: 'domcontentloaded', timeout: 15000 });
    res.csp = doc.headers()['content-security-policy'] || null;
    await page.waitForSelector('#rows tr', { timeout: 15000 }); // the first load() has rendered
    res.details = await scenarios[name](page, base);
    res.pass = !res.console_errors.length && !res.failed_requests.length && !res.csp_violations.length;
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
