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
