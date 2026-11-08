/* leasewatch UI — vanilla JS, no dependencies. Talks to /api/*. */
(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

  // ---------- language ----------
  // the strings come from i18n.js (window.LW_STRINGS); without it every text falls back to its key
  const T = window.LW_STRINGS || { en: {} };
  // ?lang= in the address, then UI_LANG from the server (data-lang; "auto" goes on), then the browser's first language
  function pickLang() {
    const q = new URLSearchParams(location.search).get("lang");
    if (q === "en" || q === "sv") return q;
    const d = document.documentElement.dataset.lang;
    if (d === "en" || d === "sv") return d;
    return String((navigator.languages || [navigator.language || ""])[0] || "").toLowerCase().startsWith("sv") ? "sv" : "en";
  }
  const lang = pickLang();
  // a ?lang= the address had (a valid one decided the language): syncUrl() keeps it, so a filter click does not drop it
  const langParam = new URLSearchParams(location.search).get("lang") === lang ? lang : null;
  // the text of a key in the page's language, else English, else the key. A plural value picks its form by p.n;
  // {x} takes p.x, a missing parameter stays as written. Plain text: callers escape it for HTML
  function t(key, p) {
    let v = T[lang]?.[key] ?? T.en?.[key] ?? key;
    if (v && typeof v === "object") v = v[new Intl.PluralRules(lang).select(p?.n ?? 0)] ?? v.other;
    return String(v).replace(/\{(\w+)\}/g, (m, x) => (p && p[x] !== undefined ? String(p[x]) : m));
  }

  // the marked static strings (data-i18n: the text, data-i18n-attr: "attr:key,attr:key") in the page's language; English is
  // already in the HTML, so it does nothing there. Run once, before the first render: a re-render clones the translated template
  function applyI18n(root) {
    if (lang === "en") return;
    for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
    for (const el of root.querySelectorAll("[data-i18n-attr]")) {
      for (const pair of el.dataset.i18nAttr.split(",")) {
        const i = pair.indexOf(":");
        if (i > 0) el.setAttribute(pair.slice(0, i).trim(), t(pair.slice(i + 1).trim()));
      }
    }
  }

  const state = {
    devices: [], meta: null, stats: null, events: [],
    evNext: null, // id to pass as before= for the next events page (null: the list is complete)
    evPaged: false, // a "Load more" page is on screen: the periodic refresh then merges instead of replacing
    evKind: "", evFrom: "", evTo: "", // events filters: one kind, local days as YYYY-MM-DD
    evGen: 0, // bumped by a filter change: a page requested under an older filter is dropped when it arrives
    q: "", status: "all", vlan: null, sort: "first_desc", open: null, returnTo: null, apiDown: false,
    ssid: null, ssidNow: false, // the Wi-Fi network filter: devices ever seen on it, or (ssidNow) online on it now
    tag: null, tagsAll: false, // the tag filter (one tag); tagsAll: the "+N more" chip has opened the whole tag row
    deepLink: null, // the ?device= MAC from the address, until the first load has opened its drawer
    renderError: null, // kept so the 15 s status refresh does not hide a page error while the table is still broken
    loadSeq: 0, // number of the newest load(): an older one that answers later must not write its snapshot over it
    drawerGet: null, // {mac, focus, ctl} of the one drawer GET in flight: only its reply is applied; replacing it aborts it
    skew: 0, // server clock minus browser clock at the last load: "on the wire" is judged in server time
    form: null, // {mac, name, note} the drawer form was rendered with (or last saved): what "edited" is measured against
    saving: null, // {form, name, note} posted from that Name input while its save runs: its reference until the POST settles
    // URL -> {etag, data} of the last 200 of the two big GETs, in memory (the server sends Cache-Control: no-store, so
    // the browser cache keeps nothing): the request says which copy it has, and a 304 means that copy is still current
    revalidated: new Map(),
    selecting: false, // the "Select" mode: the checkbox column shows (and Type hides, so the table keeps its width)
    sel: new Set(), // device keys of the ticked rows; cut down to the visible rows on every renderTable()
    bulkBusy: false, // a bulk POST runs: a second click on the bar waits for it
  };
  const VLAN_COLORS = ["--vlan1", "--vlan2", "--vlan3", "--vlan4", "--vlan5", "--vlan6", "--vlan7", "--vlan8"];
  // stable colour per network: alphabetical position among every network of any device (archived too), so colours
  // shift neither when counts change nor when a network's last listed device is archived
  const vlanColor = v => {
    if (!v) return "var(--vlan0)";
    const all = (state.stats?.all_vlans || []).filter(Boolean).sort();
    const i = all.indexOf(v);
    return `var(${i < 0 ? "--vlan0" : VLAN_COLORS[i % VLAN_COLORS.length]})`;
  };

  // ---------- helpers ----------
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  // the CSP blocks style="…" in parsed HTML: templates carry the network colour as data-vc, set here through the CSSOM
  const paintVc = root => root.querySelectorAll("[data-vc]").forEach(el => el.style.setProperty("--vc", el.dataset.vc));
  const pad = n => String(n).padStart(2, "0");
  const abs = ts => { if (!ts) return "–"; const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const rel = ts => {
    if (!ts) return "–";
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (s < 45) return t("time.just_now");
    // the unit is picked on the rounded value, so 3590 s reads "1 h ago", not "60 min ago"
    const m = Math.round(s / 60); if (m < 60) return t("time.min_ago", { n: m });
    const h = Math.round(s / 3600); if (h < 48) return t("time.h_ago", { n: h });
    const n = Math.round(s / 86400); if (n < 30) return t("time.d_ago", { n });
    const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  };
  // a length of time in seconds: "< 1 min", "40 min", "3.5 h", "4 d 2 h". The unit is picked on the rounded value, so
  // 3570 s reads "1.0 h", not "60 min", and 172799 s reads "2 d 0 h", not "48.0 h"
  const durText = s => {
    s = Math.max(0, Math.round(s || 0));
    if (s < 60) return t("time.less_min");
    const m = Math.round(s / 60); if (m < 60) return t("time.min", { n: m });
    // one decimal in the page's language: "3.5" in English, "3,5" in Swedish
    const x = Math.round(s / 360) / 10; if (x < 48) return t("time.hours", { n: x.toLocaleString(lang, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) });
    const h = Math.round(s / 3600); return t("time.days_hours", { d: Math.floor(h / 24), h: h % 24 });
  };
  const pad3 = x => String(x).padStart(3, "0");
  const ipKey = ip => (ip || "").split(".").map(pad3).join(".");
  // a device without an address sorts after every real one, as an empty vendor does
  const ipCmp = (a, b) => (!a.ip - !b.ip) || ipKey(a.ip).localeCompare(ipKey(b.ip), lang);
  const isNew = d => !d.baseline && state.meta && (state.meta.now - d.first_seen) < state.meta.new_days * 86400;
  const label = d => d.name || d.wifi_alias || d.hostname || d.label || d.vendor || d.mac;
  const typeText = d => d.lease_type === "static" ? t("type.static") : d.lease_type === "dynamic" ? t("type.dynamic") : t("type.arp");
  const sourcesText = s => String(s || "").split(",").filter(Boolean).map(x => x.toUpperCase()).join(" + ");
  // a controller client can come without an SSID (hidden network, mid-association): its AP and signal still place it.
  // merge clears the port when a device goes on Wi-Fi, so an SSID-less row with a port is one a switch placed since
  const onWifi = d => !!(d.wifi_ssid || ((d.wifi_ap || d.link === "wifi") && !d.sw_port));
  // the device's presence row of the filtered SSID (null without the filter, or when it has none yet)
  const ssidRow = d => state.ssid === null ? null : (d.wifi_presence || []).find(p => p.ssid === state.ssid) || null;
  const onSsidNow = d => !!d.online && onWifi(d) && d.wifi_ssid === state.ssid;
  // display label of a connector instance ("Wi-Fi", the switch's NAME), the instance id when the meta has none
  const connLabel = n => state.meta?.connectors?.find(c => c.name === n)?.label || n;
  // "Connected via": Wi-Fi SSID @ AP, or switch port (+ what hangs on it), as HTML
  const whereHtml = (d, long) => {
    if (onWifi(d)) return `<span class="w">${esc(d.wifi_ssid || "Wi-Fi")}</span> <span class="muted">@ ${esc(d.wifi_ap || "?")}${d.wifi_signal != null ? ` <span class="sig">${esc(d.wifi_signal)} dBm</span>` : ""}${long && d.wifi_radio ? ` · ${esc(d.wifi_radio)}` : ""}</span>`;
    // long (drawer): name the switch too, as two switches can have a port of the same name. A controller never places
    // a port (it lists a wired client without one), so a controller as loc_source does not name the port's switch
    const ctl = state.meta?.connectors?.find(c => c.name === d.loc_source)?.type === "unifi";
    if (d.sw_port) return `<span class="w">${esc(d.sw_port)}</span>${d.sw_via ? ` <span class="muted">→ ${esc(d.sw_via)}</span>` : ""}${long && d.loc_source && !ctl ? ` <span class="muted">${esc(t("drawer.on_switch", { name: connLabel(d.loc_source) }))}</span>` : ""}`;
    return "";
  };
  const whereText = d => onWifi(d) ? `${d.wifi_ssid || "Wi-Fi"} @ ${d.wifi_ap || ""}` : d.sw_port ? `${d.sw_port} ${d.sw_via || ""}` : "";

  // the server's error messages a user can meet, in the page's language; any other message is shown as sent
  const apiErrorText = m => m === "read-only" ? t("err.read_only") : m === "writes are not allowed from this address" ? t("err.not_allowed_from_address")
    : m === "not found" ? t("err.not_found") : m;
  async function api(path, opts) {
    // a stalled reply (a proxy holding the connection) must not hang a poll or a save for the browser's minutes-long limit
    // built by hand, not with AbortSignal.timeout (missing before Chrome 103, Firefox 100, Safari 16) or AbortSignal.any
    // (missing before Chrome 116, Firefox 124, Safari 17.4): without it a stalled load, save or drawer GET never settles
    const own = opts?.signal, ctl = new AbortController();
    let relay = null;
    if (own) {
      // a caller's signal (the drawer's) is relayed, so it still cancels the request and keeps the timeout
      relay = () => ctl.abort(own.reason);
      if (own.aborted) relay(); else own.addEventListener("abort", relay);
    }
    const timer = setTimeout(() => ctl.abort(new DOMException(t("err.timeout"), "TimeoutError")), 30000), signal = ctl.signal;
    const keep = !opts?.method && ["/api/devices", "/api/events"].includes(path.split("?")[0]), prev = keep ? state.revalidated.get(path) : null;
    const headers = prev ? { ...opts?.headers, "If-None-Match": prev.etag } : opts?.headers;
    try {
      const r = await fetch(path, { cache: "no-store", ...opts, ...(headers ? { headers } : {}), signal });
      if (r.status === 304 && prev) {
        // the server's "now" is per request: from the browser clock and the offset of the last 200
        if (prev.data.meta) prev.data.meta.now = Date.now() / 1000 + state.skew;
        return prev.data;
      }
      if (!r.ok) { let m = `${r.status}`; try { m = (await r.json()).error || m; } catch (_) {} throw new Error(apiErrorText(m)); }
      // a 2xx that is not JSON is some proxy's page (login, maintenance): say so instead of quoting its body
      let data;
      try { data = await r.json(); } catch (e) { if (e.name === "SyntaxError") throw new Error(t("err.not_json", { status: r.status })); throw e; }
      if (keep) { const etag = r.headers.get("ETag"); if (etag) state.revalidated.set(path, { etag, data }); else state.revalidated.delete(path); }
      return data;
    } finally {
      // the body is read too before this settles; a timer or listener left behind would abort or pin a finished request
      clearTimeout(timer); own?.removeEventListener("abort", relay);
    }
  }

  // ---------- load ----------
  async function load() {
    const seq = ++state.loadSeq, gen = state.evGen, bad = eventsFilter() === null;
    try {
      const [d, s, e] = await Promise.all([api("/api/devices"), api("/api/stats"), bad ? null : api(eventsPath())]);
      if (seq !== state.loadSeq) return; // a newer load (e.g. the one after a save) already rendered fresher data
      state.skew = d.meta?.now ? d.meta.now - Date.now() / 1000 : 0;
      state.apiDown = false; state.devices = d.devices; state.meta = d.meta; state.stats = s.stats; if (gen === state.evGen) { if (bad) clearEvents(); else mergeFirstPage(e); }
      state.renderError = null;
      try { renderStatus(); renderCards(); renderVlans(); renderSsids(); renderTags(); renderTable(); renderEvents(); if (state.open) await refreshDrawer(state.open, false); }
      catch (err) { console.error(err); state.renderError = err.message; showBanner(t("err.page", { msg: err.message })); return; } // a UI bug, not an unreachable API (refreshDrawer handles its own fetch errors)
      // a ?device= link not opened yet (the first load failed): this render has the list and meta it needs
      if (state.deepLink) await openDeepLink();
    } catch (err) {
      if (seq !== state.loadSeq) return;
      state.apiDown = true; showBanner(t("err.api", { msg: err.message })); $("#statusDot").className = "dot bad";
      // the poll age and the connector dots are from the last good reply: do not keep showing them as current
      $("#statusText").textContent = t("status.api_unreachable"); $("#status").title = "";
    }
  }

  function showBanner(msg) { const b = $("#banner"); if (!msg) { b.classList.add("hidden"); return; } b.textContent = msg; b.classList.remove("hidden"); }

  // the collector's counts ("N leases, N arp[, N reservations][, N ndp][, N leases6][, ndp unavailable][, kea6 unavailable]")
  // in the page's language; a text of any other shape is shown as sent
  const RAW_RE = /^(\d+) leases, (\d+) arp(?:, (\d+) reservations)?(?:, (\d+) ndp)?(?:, (\d+) leases6)?(, ndp unavailable)?(, kea6 unavailable)?$/;
  function rawText(raw) {
    const m = RAW_RE.exec(raw || "");
    if (!m) return raw || "";
    const parts = [t("status.leases", { n: +m[1] }), t("status.arp", { n: +m[2] })];
    if (m[3] !== undefined) parts.push(t("status.reservations", { n: +m[3] }));
    if (m[4] !== undefined) parts.push(t("status.ndp", { n: +m[4] }));
    if (m[5] !== undefined) parts.push(t("status.leases6", { n: +m[5] }));
    if (m[6]) parts.push(t("status.ndp_unavailable"));
    if (m[7]) parts.push(t("status.kea6_unavailable"));
    return parts.join(", ");
  }

  function renderStatus() {
    const m = state.meta, dot = $("#statusDot"), txt = $("#statusText");
    if (!m) return;
    // + 60: the meta is refetched once a minute, so a poll newer than that cannot be known here yet
    const stale = m.stale || (Date.now() / 1000 - m.last_poll_ts) > m.poll_seconds * 3 + 60;
    const ok = m.last_poll_ok && !stale;
    dot.className = "dot " + (ok ? "ok" : "bad");
    txt.innerHTML = m.last_poll_ts ? esc(t("status.polled", { ago: rel(m.last_poll_ts), raw: rawText(m.last_raw) })) : esc(t("status.no_poll"));
    // one dot per connector instance, text = its display label, tooltip = its instance name; a server without
    // label (1.1 before labels) gives the name
    // an instance disabled at start (invalid settings) gets no dot: it never polls, and the start log names the problem
    const sources = (m.connectors || []).filter(c => c.enabled !== false).map(c => [c.label || c.name, c.name, c]);
    for (const [label, name, s] of sources) {
      // a failed poll stops before the enrichers run: an instance last read at or before the last good poll was not
      // read in the failing ones, so its old "ok" is shown grey, not green
      // a last good poll in the future (the clock stepped back) says nothing: then the instance's own result is shown
      const old = !m.last_poll_ok && s.ts && m.last_poll_ts && s.ts <= m.last_poll_ts && !(m.last_poll_ts > m.now);
      const tip = old ? t("status.not_read", { name, ago: rel(s.ts) }) : s.ok ? t("status.ok", { name }) : `${name}: ${s.error}`;
      txt.insertAdjacentHTML("beforeend", `<span class="src" title="${esc(tip)}"><span class="dot ${old ? "" : s.ok ? "ok" : "bad"}"></span>${esc(label)}</span>`);
    }
    $("#status").title = m.last_error ? t("status.last_error", { msg: m.last_error }) : t("status.polls_every", { n: m.poll_seconds });
    if (m.collector_stale && m.last_attempt_ts && m.now < m.last_attempt_ts) showBanner(t("status.clock_back"));
    else if (m.collector_stale) showBanner(m.last_attempt_ts ? t("status.collector_stale", { ago: rel(m.last_attempt_ts) }) : t("status.collector_stale_start"));
    else if (!m.last_poll_ok && m.last_error) showBanner(t("status.firewall", { msg: m.last_error, ago: rel(m.last_poll_ts) }));
    else if (stale) showBanner(t("status.stale", { ago: rel(m.last_poll_ts) }));
    else if (state.renderError) showBanner(t("err.page", { msg: state.renderError }));
    else showBanner("");
    // the whole label, so a language can place the number where it needs it
    $('.card[data-filter="new"] .lbl').textContent = t("card.new_days", { n: m.new_days });
  }

  function renderCards() {
    const s = state.stats; if (!s) return;
    $("#cTotal").textContent = s.total; $("#cOnline").textContent = s.online; $("#cNew").textContent = s.new; $("#cUnacked").textContent = s.unacked;
    // the baseline card shows only while there is something to check (or its filter is on, so the click can be undone)
    const nb = s.baseline_unchecked || 0, showB = nb > 0 || state.status === "baseline";
    $("#cBaseline").textContent = nb; $("#cardBaseline").classList.toggle("hidden", !showB); $("#cards").classList.toggle("five", showB);
    $$(".card[data-filter]").forEach(c => { const on = c.dataset.filter === state.status && state.status !== "all"; c.classList.toggle("active", on); c.setAttribute("aria-pressed", on); });
    const bars = $("#bars"); bars.innerHTML = "";
    const dayKey = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    // the server's window is a rolling 30 × 24 h, which touches 31 calendar days; a time outside the bars (browser
    // clock off) is counted in the nearest one, so the sum matches the server's
    const keys = []; const today = new Date(); today.setHours(0, 0, 0, 0);
    for (let i = 30; i >= 0; i--) keys.push(dayKey(new Date(today.getFullYear(), today.getMonth(), today.getDate() - i)));
    const perDay = {}; for (const t of s.new_recent || []) { let k = dayKey(new Date(t * 1000)); k = k < keys[0] ? keys[0] : k > keys[30] ? keys[30] : k; perDay[k] = (perDay[k] || 0) + 1; }
    let max = 1;
    const days = keys.map(k => { const n = perDay[k] || 0; max = Math.max(max, n); return [k, n]; });
    for (const [k, n] of days) { const b = document.createElement("span"); b.style.height = n ? `${Math.max(18, Math.round(n / max * 100))}%` : "2px"; b.title = t("card.bar_title", { day: k, n }); if (n) b.classList.add("has"); bars.appendChild(b); }
    $("#barsSum").textContent = t("card.sum", { n: days.reduce((a, [, n]) => a + n, 0) });
  }

  function renderVlans() {
    const box = $("#vlans");
    // rebuilding the chips drops keyboard focus: put it back on the chip of the same network
    const had = box.contains(document.activeElement) ? document.activeElement.dataset.vlan : null;
    box.innerHTML = "";
    for (const v of state.stats?.vlans || []) { // no stats before the first good load (Clear filters can run then)
      const c = document.createElement("button"); c.className = "chip" + (state.vlan === v.vlan ? " active" : "");
      c.setAttribute("aria-pressed", state.vlan === v.vlan); c.dataset.vlan = v.vlan ?? "";
      c.innerHTML = `<span class="sw" data-vc="${esc(vlanColor(v.vlan))}"></span>${esc(v.vlan || "?")} <span class="n">${v.online}/${v.n}</span>`;
      paintVc(c);
      c.title = t("chip.vlan_title", { online: v.online, devices: t("count.devices", { n: v.n }) });
      c.onclick = () => { state.vlan = state.vlan === v.vlan ? null : v.vlan; renderVlans(); renderTable(); syncUrl(); };
      box.appendChild(c);
      if (had != null && had === c.dataset.vlan) c.focus();
    }
  }

  // the Wi-Fi networks: SSID names come from the air, so they go into the page only as escaped text
  function renderSsids() {
    const box = $("#ssids"), now = $("#ssidNow");
    const had = box.contains(document.activeElement) && document.activeElement !== now ? document.activeElement.dataset.ssid : null;
    $$(".chip[data-ssid]", box).forEach(c => c.remove());
    const list = (state.stats?.ssids || []).slice();
    // a filter from the address on an SSID the stats no longer list keeps a chip, so it can be clicked off
    if (state.ssid !== null && !list.some(s => s.ssid === state.ssid)) list.push({ ssid: state.ssid, devices_now: 0, devices_ever: 0 });
    box.classList.toggle("hidden", !list.length);
    const since = state.meta?.wifi_presence_since ? abs(state.meta.wifi_presence_since).slice(0, 10) : "";
    for (const s of list) {
      const on = state.ssid === s.ssid, c = document.createElement("button");
      c.type = "button"; c.className = "chip" + (on ? " active" : ""); c.setAttribute("aria-pressed", on); c.dataset.ssid = s.ssid;
      c.innerHTML = `<span class="ssid">${esc(s.ssid)}</span> <span class="n">${esc(s.devices_now)}/${esc(s.devices_ever)}</span>`;
      const p = { now: s.devices_now, ssid: s.ssid, devices: t("count.devices", { n: s.devices_ever }), day: since };
      c.title = since ? t("chip.ssid_title_since", p) : t("chip.ssid_title", p);
      c.onclick = () => { state.ssid = on ? null : s.ssid; if (on) state.ssidNow = false; renderSsids(); renderTable(); syncUrl(); };
      box.insertBefore(c, now);
      if (had != null && had === s.ssid) c.focus();
    }
    now.classList.toggle("hidden", state.ssid === null);
    now.classList.toggle("active", state.ssidNow); now.setAttribute("aria-pressed", state.ssidNow);
  }

  // a device's tags: the server stores them normalised, as a comma list ("" = none)
  const tagsOf = d => (d.tags || "").split(",").filter(Boolean);
  // the tag chips from the device list, archived devices left out as the network chips leave them out: [{tag, online,
  // n}], most used first, then by name
  function tagCounts(devices) {
    const m = new Map();
    for (const d of devices) {
      if (d.archived_ts != null) continue;
      for (const t of tagsOf(d)) { const c = m.get(t) || { tag: t, online: 0, n: 0 }; c.n++; if (d.online) c.online++; m.set(t, c); }
    }
    return [...m.values()].sort((a, b) => (b.n - a.n) || (a.tag < b.tag ? -1 : a.tag > b.tag ? 1 : 0));
  }
  // the name in an owner:name tag, or null for any other tag (and for a bare "owner:")
  const ownerOf = t => t.startsWith("owner:") && t.length > 6 ? t.slice(6) : null;
  const TAGS_SHOWN = 12; // chips before "+N more"
  // the tag row: an owner: tag keeps its full tag in data-tag and the title, and shows only the name
  function renderTags() {
    const box = $("#tags");
    const fe = box.contains(document.activeElement) ? document.activeElement : null, had = fe?.dataset.tag ?? null;
    box.innerHTML = "";
    const list = tagCounts(state.devices);
    // a filter from the address on a tag no device has keeps a chip, so it can be clicked off
    if (state.tag !== null && !list.some(t => t.tag === state.tag)) list.push({ tag: state.tag, online: 0, n: 0 });
    box.classList.toggle("hidden", !list.length);
    // the most used ones, and the active one wherever it ranks
    const shown = state.tagsAll ? list : list.filter((t, i) => i < TAGS_SHOWN || t.tag === state.tag);
    // the plain tags first, then the owners; headings only once there is an owner tag to tell them apart from
    const plain = shown.filter(t => ownerOf(t.tag) === null), owners = shown.filter(t => ownerOf(t.tag) !== null);
    const heading = text => { const h = document.createElement("span"); h.className = "grp"; h.textContent = text; box.appendChild(h); };
    const grouped = list.some(t => ownerOf(t.tag) !== null);
    const chips = [];
    if (grouped && plain.length) heading(t("chip.tags"));
    plain.forEach(chip);
    if (owners.length) { if (grouped) heading(t("chip.owner")); owners.forEach(chip); }
    function chip(tg) {
      const on = state.tag === tg.tag, c = document.createElement("button"), who = ownerOf(tg.tag);
      c.type = "button"; c.className = "chip" + (on ? " active" : ""); c.setAttribute("aria-pressed", on); c.dataset.tag = tg.tag;
      c.innerHTML = `<span class="tg">${esc(who ?? tg.tag)}</span> <span class="n">${esc(tg.online)}/${esc(tg.n)}</span>`;
      c.title = t("chip.tag_title", { online: tg.online, devices: t("count.devices", { n: tg.n }), tag: tg.tag });
      c.onclick = () => { state.tag = on ? null : tg.tag; renderTags(); renderTable(); syncUrl(); };
      box.appendChild(c);
      if (had != null && had === tg.tag) c.focus();
      chips.push(c);
    }
    let more = null;
    if (shown.length < list.length) {
      const next = list.find(t => !shown.includes(t)).tag; // not list[shown.length]: an active tag from beyond the cap is in shown
      more = document.createElement("button");
      more.type = "button"; more.className = "chip toggle"; more.id = "tagMore"; more.textContent = t("chip.more", { n: list.length - shown.length });
      more.title = t("chip.show_all");
      // the button goes with the click: the focus moves to the first chip it brought in
      more.onclick = () => { state.tagsAll = true; renderTags(); $$(".chip[data-tag]", box).find(c => c.dataset.tag === next)?.focus(); };
      box.appendChild(more);
      if (fe?.id === "tagMore") more.focus();
    } else if (fe?.id === "tagMore") chips[0]?.focus();
    // the focused chip is gone (an active chip from beyond the cap, clicked off): the focus stays in the row
    if (had != null && !chips.some(c => c.dataset.tag === had)) (more || chips[0])?.focus();
  }

  function filtered() {
    const q = state.q.trim().toLowerCase();
    const list = state.devices.filter(d => {
      if (state.vlan !== null && d.vlan !== state.vlan) return false; // null = no filter; "" is the unnamed network
      if (state.ssid !== null && !(state.ssidNow ? onSsidNow(d) : ssidRow(d))) return false;
      if (state.tag !== null && !tagsOf(d).includes(state.tag)) return false;
      if ((d.archived_ts != null) !== (state.status === "archived")) return false; // archived devices only under their own filter
      switch (state.status) {
        case "new": if (!isNew(d)) return false; break;
        case "unacked": if (d.acked || d.baseline) return false; break;
        case "baseline": if (!d.baseline || d.acked) return false; break;
        case "online": if (!d.online) return false; break;
        case "offline": if (d.online) return false; break;
        case "dynamic": if (d.lease_type !== "dynamic") return false; break;
        case "static": if (d.lease_type !== "static") return false; break;
        case "arp": if (d.lease_type) return false; break;
        case "wifi": if (!onWifi(d)) return false; break;
        case "wired": if (onWifi(d) || (d.link !== "wired" && !d.sw_port)) return false; break;
      }
      if (q) {
        const hay = `${d.name} ${d.hostname} ${d.ip} ${d.ip6 || ""} ${d.mac} ${d.vendor} ${d.vlan} ${d.note} ${whereText(d)} ${d.wifi_alias} ${d.label} ${(d.aliases || []).join(" ")} ${tagsOf(d).join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    // the unnamed network after the named ones, as a missing IP or vendor sorts last
    const byVlanIp = (a, b) => (!a.vlan - !b.vlan) || (a.vlan || "").localeCompare(b.vlan || "", lang) || ipCmp(a, b);
    const ssidFirst = d => ssidRow(d)?.first_seen || 0;
    const cmp = {
      // real newcomers first (newest on top), then the baseline devices grouped by network and address; under an SSID
      // filter the newest arrivals on that network lead
      first_desc: state.ssid !== null ? (a, b) => (ssidFirst(b) - ssidFirst(a)) || byVlanIp(a, b) : (a, b) => (a.baseline - b.baseline) || (a.baseline ? byVlanIp(a, b) : (b.first_seen - a.first_seen) || byVlanIp(a, b)),
      // under an SSID filter the order follows the "Last on SSID" column: online on that network now, then its last_seen
      last_desc: state.ssid !== null ? (a, b) => (onSsidNow(b) - onSsidNow(a)) || ((ssidRow(b)?.last_seen || 0) - (ssidRow(a)?.last_seen || 0)) || byVlanIp(a, b) : (a, b) => (b.online - a.online) || ((b.last_online || 0) - (a.last_online || 0)) || byVlanIp(a, b),
      name: (a, b) => label(a).localeCompare(label(b), lang, { sensitivity: "base" }) || byVlanIp(a, b),
      ip: ipCmp,
      vlan: byVlanIp,
      vendor: (a, b) => (a.vendor ? 0 : 1) - (b.vendor ? 0 : 1) || (a.vendor || "").localeCompare(b.vendor || "", lang) || label(a).localeCompare(label(b), lang),
    }[state.sort] || byVlanIp;
    return list.sort(cmp);
  }

  function renderTable() {
    const list = filtered();
    const tb = $("#rows");
    // a selection covers only the rows on screen: an action must never touch a row a search, filter or refresh hid
    const shown = new Set(list.map(d => d.mac));
    state.sel = new Set([...state.sel].filter(m => shown.has(m)));
    // can_write false: the server refuses this client's changes, so there is nothing to select for
    const canWrite = !!state.meta && state.meta.can_write !== false;
    if (!canWrite && state.selecting) { state.selecting = false; state.sel.clear(); }
    const sb = $("#selBtn"); sb.classList.toggle("hidden", !canWrite);
    sb.setAttribute("aria-pressed", String(state.selecting)); sb.textContent = state.selecting ? t("tool.done") : t("tool.select");
    $("#tbl").classList.toggle("selecting", state.selecting);
    $("#tbl").classList.toggle("ssidfilter", state.ssid !== null);
    // the count, the header box and the bar's buttons, after any change of the ticked rows
    const paintSel = () => {
      const n = state.sel.size, all = $("#selAll"), arch = state.status === "archived";
      all.checked = n > 0 && n === list.length; all.indeterminate = n > 0 && n < list.length;
      $("#selCount").textContent = t("sel.count", { n });
      $("#selAck").classList.toggle("hidden", !list.some(d => state.sel.has(d.mac) && !d.acked));
      $("#selArchive").classList.toggle("hidden", arch); $("#selRestore").classList.toggle("hidden", !arch);
      const bar = state.selecting && n > 0;
      $("#selbar").classList.toggle("hidden", !bar); $("main").classList.toggle("has-selbar", bar); // the bar never covers the last row
    };
    // rebuilding the rows drops keyboard focus: note the focused row (or its button or copy target) to focus its replacement
    const fa = tb.contains(document.activeElement) ? document.activeElement : null;
    const fmac = fa?.closest("tr")?.dataset.mac, fack = !!fa?.classList.contains("ack");
    const fcp = fmac ? [".c-ip .cp", ".c-ip .cp.ip6", ".dev-meta .ip6", ".c-mac .cp", ".c-sel input"].find(s => $(s, fa.closest("tr")) === fa) : null; // Enter there copies, not opens
    tb.innerHTML = "";
    const tpl = $("#rowTpl").content;
    const frag = document.createDocumentFragment();
    for (const d of list) {
      const tr = tpl.cloneNode(true).firstElementChild;
      tr.dataset.mac = d.mac;
      const fresh = isNew(d) && !d.acked;
      if (fresh) tr.classList.add("is-new");
      const dot = $(".online-dot", tr); dot.classList.toggle("on", !!d.online);
      dot.title = d.online ? t("row.online") : (d.last_online ? t("row.offline_last", { ago: rel(d.last_online) }) : t("row.offline_never"));
      const nm = $(".dev-name", tr), lbl = label(d);
      $(".nm", nm).textContent = lbl;
      // a real checkbox: Tab reaches it and Space toggles it natively (the row's own keys ignore it); a click anywhere
      // in the cell toggles it, for a larger target, and never opens the drawer
      const cb = $(".c-sel input", tr);
      cb.checked = state.sel.has(d.mac); cb.setAttribute("aria-label", t("row.select_aria", { name: lbl }));
      cb.onchange = () => { if (cb.checked) state.sel.add(d.mac); else state.sel.delete(d.mac); paintSel(); };
      $(".c-sel", tr).onclick = ev => { ev.stopPropagation(); if (ev.target !== cb) cb.click(); };
      nm.classList.toggle("unnamed", !d.name && !d.wifi_alias && !d.hostname && !d.label); // label() ranks the UniFi alias before the hostname
      if (fresh) nm.insertAdjacentHTML("beforeend", `<span class="badge new">${esc(t("row.new"))}</span>`);
      else if (!d.acked && !d.baseline) nm.insertAdjacentHTML("beforeend", `<span class="badge base">${esc(t("row.not_known"))}</span>`);
      if (d.watch) nm.insertAdjacentHTML("beforeend", `<span class="badge watch" title="${esc(t("row.watched"))}">${esc(t("row.watch"))}</span>`);
      // the tags on their own line under the name, which wraps: an owner: tag shows the owner after a person glyph
      $(".dev-tags", tr).innerHTML = tagsOf(d).map(tg => {
        const who = ownerOf(tg);
        return `<span class="badge tag${who ? " owner" : ""}" data-tag="${esc(tg)}" title="${esc(t("row.tag_title", { tag: tg }))}">${who ? `<span class="ico" aria-hidden="true">\u{1F464}</span>${esc(who)}` : esc(tg)}</span>`;
      }).join("");
      const sub = [];
      if ((d.name || d.wifi_alias) && d.hostname && d.hostname !== lbl) sub.push(`<span class="host">${esc(d.hostname)}</span>`);
      if (d.vendor && d.vendor !== lbl) sub.push(esc(d.vendor));
      if (!sub.length && !d.name && !d.wifi_alias && !d.hostname && !d.label) sub.push(`<span class="host">${esc(d.mac)}</span>`);
      // a private address says so in words at every width; the sleuth shows here only where the MAC column is hidden
      if (d.private) sub.unshift('<span class="priv-hint"><span class="ico" aria-hidden="true">\u{1F575}\u{FE0F}</span>' + esc(t("row.private")) + "</span>");
      $(".dev-sub", tr).innerHTML = sub.join(" · ");
      $(".dev-meta .ip", tr).textContent = d.ip || "–";
      const vm = $(".dev-meta .badge", tr); vm.textContent = d.vlan || "?"; vm.style.setProperty("--vc", vlanColor(d.vlan));
      $(".dev-meta .last", tr).textContent = d.online ? t("row.online") : (d.last_online ? t("row.last", { ago: rel(d.last_online) }) : t("row.offline"));
      $(".dev-meta .where", tr).textContent = onWifi(d) ? `${d.wifi_ssid || "Wi-Fi"} @ ${d.wifi_ap || "?"}` : d.sw_port ? `${d.sw_port}${d.sw_via ? " → " + d.sw_via : ""}` : "";
      const wh = $(".c-where", tr); wh.innerHTML = whereHtml(d, false); wh.title = wh.textContent.replace(/\s+/g, " ").trim(); // the full text, signal included, when the cell is cut
      // the IPv6 address: a second line in the IP column and a span in the phone meta line, only when the device has one
      const v6 = [$(".c-ip .cp.ip6", tr), $(".dev-meta .ip6", tr)];
      if (d.ip6) v6.forEach(e => { e.title = d.ip6; copyable(e, d.ip6); e.classList.remove("hidden"); }); // the title keeps the whole address when the text is cut
      if (d.ip) copyable($(".c-ip .cp", tr), d.ip); else { $(".c-ip .cp", tr).remove(); $(".c-ip", tr).prepend("–"); } // nothing to copy
      if (!d.ip6) v6.forEach(e => e.remove()); // no empty focusable element
      copyable($(".c-mac .cp", tr), d.mac);
      // a private (locally administered) MAC: tinted row border, the sleuth and its "private address" hint
      if (d.private) { tr.classList.add("is-private"); $(".c-mac .priv", tr).classList.remove("hidden"); }
      const vb = $(".c-vlan .badge", tr); vb.textContent = d.vlan || "?"; vb.style.setProperty("--vc", vlanColor(d.vlan));
      const ty = $(".c-type", tr); ty.textContent = ty.title = typeText(d);
      const fs = $(".c-first", tr); fs.textContent = d.baseline ? t("row.since_start") : rel(d.first_seen); fs.title = d.baseline ? t("row.baseline_title", { when: abs(state.meta.baseline_ts) }) : abs(d.first_seen);
      if (isNew(d)) fs.classList.add("recent");
      const ls = $(".c-last", tr); ls.textContent = d.online ? t("row.now") : (d.last_online ? rel(d.last_online) : t("row.not_since_start")); ls.title = d.last_online ? t("row.last_title", { when: abs(d.last_online), seen: abs(d.last_seen) }) : t("row.listed_title", { seen: abs(d.last_seen) });
      if (state.ssid !== null) {
        // the SSID filter turns the two time columns into that network's: when the device first and last was on it
        const p = ssidRow(d), ssid = state.ssid, dur = p ? t("row.ssid_dur", { dur: durText(p.seconds_seen), ssid }) : "";
        fs.textContent = p ? rel(p.first_seen) : "–"; fs.title = p ? t("row.first_on", { ssid, when: abs(p.first_seen) }) : "";
        ls.textContent = onSsidNow(d) ? t("row.now") : p ? rel(p.last_seen) : "–"; ls.title = p ? `${t("row.last_on", { ssid, when: abs(p.last_seen) })} · ${dur}` : "";
        if (dur) $(".dev-meta .last", tr).textContent += ` · ${dur}`;
        // between 561 and 900 px both time columns and .dev-meta are hidden: the sub line carries that network's last time
        if (p) $(".dev-sub", tr).insertAdjacentHTML("beforeend", `<span class="ssid-last">${esc(onSsidNow(d) ? t("row.on_now", { ssid }) : t("row.last_on", { ssid, when: rel(p.last_seen) }))} · ${esc(durText(p.seconds_seen))}</span>`);
      }
      const ack = $(".ack", tr);
      // can_write false: the server refuses this client's changes (READ_ONLY, or outside WRITE_ALLOW)
      if (d.acked || d.baseline || state.meta?.can_write === false) ack.remove();
      else ack.onclick = ev => { ev.stopPropagation(); setFields(d.mac, { acked: true }); };
      tr.onclick = () => openDrawer(d.mac);
      tr.onkeydown = ev => { if (ev.target !== tr) return; /* keys on the row's buttons are theirs */ if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); openDrawer(d.mac); } };
      frag.appendChild(tr);
    }
    tb.appendChild(frag);
    paintSel();
    if (fmac) { const tr = $$("#rows tr").find(t => t.dataset.mac === fmac); ((fack && tr && $(".ack", tr)) || (fcp && tr && $(fcp, tr)) || tr)?.focus({ preventScroll: true }); } // the reader may have scrolled away from it
    // the total is the devices this filter could show: archived ones only under "Archived", as the cards leave them out
    const total = state.devices.filter(d => (d.archived_ts != null) === (state.status === "archived")).length;
    $("#count").textContent = t("count.of", { n: list.length, total });
    $("#empty").classList.toggle("hidden", list.length > 0);
    $("#thFirst").textContent = state.ssid !== null ? t("th.first_ssid") : t("th.first");
    $("#thLast").textContent = state.ssid !== null ? t("th.last_ssid") : t("th.last");
    $("#emptyText").textContent = state.q || state.vlan !== null || state.ssid !== null || state.tag !== null ? t("empty.text") : state.status === "unacked" ? t("empty.unacked") : state.status === "baseline" ? t("empty.baseline") : state.status === "new" ? t("empty.new", { n: state.meta?.new_days ?? 7 }) : t("empty.text");
    $("#emptyClear").classList.toggle("hidden", !(state.q || state.vlan !== null || state.ssid !== null || state.tag !== null || state.status !== "all"));
  }

  // the whole MAC or IP text copies on click, Enter or Space; the feedback is a class and a title, so the table keeps
  // its column widths
  function copyable(el, text) {
    el.textContent = text;
    const rest = el.title || t("app.click_to_copy"); // the title back after "Copied" or the Ctrl+C hint
    let timer = 0; // a second copy restarts the "Copied" time: an earlier copy's timer would end it early
    const done = () => { clearTimeout(timer); el.classList.add("copied"); el.title = el.dataset.copied = t("app.copied"); timer = setTimeout(() => { el.classList.remove("copied"); el.title = rest; }, 900); };
    // plain HTTP to a LAN address has no clipboard API, and a secure page can refuse the write (permission, focus):
    // select the text so Ctrl+C copies it, and try the old copy command
    const fallback = () => {
      const sel = getSelection(), r = document.createRange(); r.selectNodeContents(el); sel.removeAllRanges(); sel.addRange(r);
      let ok = false; try { ok = document.execCommand("copy"); } catch (_) {}
      if (ok) done();
      // the hint is for this click or key: it goes when the pointer or the keyboard focus leaves
      else { el.title = t("app.copy_hint"); el.onmouseleave = el.onblur = () => { el.title = rest; el.onmouseleave = el.onblur = null; }; }
    };
    const copy = ev => { ev.stopPropagation(); /* not the row's drawer */ if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, fallback); else fallback(); };
    el.onclick = copy;
    el.onkeydown = ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); copy(ev); } };
  }

  function renderEvents() {
    const ul = $("#events"); ul.innerHTML = "";
    renderEventControls();
    if (!state.events.length) {
      const none = state.evKind || state.evFrom || state.evTo ? t("ev.none_filtered") : t("ev.none");
      ul.innerHTML = `<li><span class="t">–</span><span></span><span class="muted">${esc(none)}</span></li>`; return;
    }
    for (const e of state.events) {
      const li = document.createElement("li");
      const head = `<span class="t" title="${esc(abs(e.ts))}">${esc(abs(e.ts))}</span><span class="k ${esc(e.kind)}">${esc(kindText(e.kind))}</span>`;
      if (e.kind === "source_down" || e.kind === "source_up") {
        // a connector instance, not a device (mac ""): "<instance>: <text>", named as plain text with no drawer to open
        const d = String(e.detail || ""), i = d.indexOf(": ");
        const inst = i < 0 ? d : d.slice(0, i), text = i < 0 ? "" : d.slice(i + 2);
        li.innerHTML = `${head}<span><span class="src">${esc(connLabel(inst))}</span> <span class="muted">${esc(text)}</span></span>`;
        ul.appendChild(li);
        continue;
      }
      const who = e.name || e.hostname || e.mac;
      let detail = String(e.detail || "").replace(" -> ", " → ");
      if (e.kind === "new") {
        // "ip hostname vendor (network then)": the network is dropped only when the badge (the device's current
        // network) shows the same one, and the hostname only as a whole, as the who button shows it
        const net = ` (${e.vlan})`;
        if (e.vlan && detail.endsWith(net)) detail = detail.slice(0, -net.length);
        if (e.hostname && who === e.hostname) detail = ` ${detail} `.replace(` ${who} `, " ").trim();
      }
      li.innerHTML = `${head}<span><button class="who" data-mac="${esc(e.mac)}">${esc(who)}</button> <span class="muted">${esc(detail)}</span>${e.vlan ? ` <span class="badge vlan" data-vc="${esc(vlanColor(e.vlan))}" title="${esc(t("ev.vlan_title"))}">${esc(e.vlan)}</span>` : ""}</span>`;
      paintVc(li);
      $(".who", li).onclick = () => openDrawer(e.mac);
      ul.appendChild(li);
    }
  }
  // ---------- events list: filters, paging ----------
  const EV_PAGE = 60;
  const EV_KINDS = [[t("evgroup.devices"), ["new", "back", "archived", "restored", "merged", "split"]], [t("evgroup.presence"), ["offline", "online"]],
    [t("evgroup.changes"), ["ip", "hostname", "vlan", "lease_type", "port", "wifi"]],
    [t("evgroup.review"), ["acked", "unacked", "renamed", "note", "tags", "watched", "unwatched"]], [t("evgroup.sources"), ["source_down", "source_up"]]];
  // a real calendar day: 2026-02-31 would roll over to March 3, so the day must come back unchanged
  const isDay = v => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
    const [y, m, d] = v.split("-").map(Number), t = new Date(y, m - 1, d);
    return t.getFullYear() === y && t.getMonth() === m - 1 && t.getDate() === d;
  };
  // local midnight of a YYYY-MM-DD day, plus n days, as epoch seconds
  const dayTs = (v, n = 0) => { const [y, m, d] = v.split("-").map(Number); return Math.floor(new Date(y, m - 1, d + n).getTime() / 1000); };
  // the filters as query parameters; null when From is after To (the server would answer 400)
  function eventsFilter() {
    if (state.evFrom && state.evTo && state.evFrom > state.evTo) return null;
    const p = new URLSearchParams();
    if (state.evKind) p.set("kind", state.evKind);
    if (state.evFrom) p.set("since", dayTs(state.evFrom));
    if (state.evTo) p.set("until", dayTs(state.evTo, 1));
    return p;
  }
  function eventsPath(before) {
    const q = new URLSearchParams({ limit: EV_PAGE });
    for (const [k, v] of eventsFilter() || []) q.set(k, v);
    if (before) q.set("before", before);
    return `/api/events?${q}`;
  }
  function renderEventControls() {
    const p = eventsFilter(), bad = p === null;
    $("#evMore").classList.toggle("hidden", state.evNext === null || bad);
    $("#evCsv").classList.toggle("hidden", bad); $("#evRange").classList.toggle("hidden", !bad);
    if (p) $("#evCsv").href = `/api/events.csv${p.toString() ? `?${p}` : ""}`;
  }
  // the periodic refresh: the first page. With "Load more" pages on screen it only adds the newer events, and only when
  // the page still reaches the newest one shown; otherwise more than a page arrived, there could be a gap, so reset
  function clearEvents() { state.events = []; state.evNext = null; state.evPaged = false; }
  function mergeFirstPage(e) {
    const had = state.events, top = had.length ? had[0].id : null, i = e.events.findIndex(x => x.id === top);
    if (state.evPaged && i >= 0) state.events = e.events.slice(0, i).concat(had);
    else { state.events = e.events; state.evNext = e.next; state.evPaged = false; state.evGen++; } // replaced: a "Load more" in flight is for the old list
  }
  // a changed filter starts over: first page, with the address and the controls following
  async function eventsFilterChanged() {
    const gen = ++state.evGen;
    syncUrl();
    if (eventsFilter() === null) { clearEvents(); renderEvents(); return; }
    try {
      const e = await api(eventsPath());
      if (gen !== state.evGen) return;
      state.events = e.events; state.evNext = e.next; state.evPaged = false;
      renderEvents();
    } catch (err) { if (gen === state.evGen) showBanner(t("err.events", { msg: err.message })); }
  }
  async function loadMoreEvents() {
    const btn = $("#evMore"), gen = state.evGen, next = state.evNext;
    if (!next || btn.disabled) return;
    btn.disabled = true;
    try {
      const e = await api(eventsPath(next));
      if (gen !== state.evGen || next !== state.evNext) return; // a refresh replaced the list meanwhile: its cursor is not this one
      const seen = new Set(state.events.map(x => x.id));
      state.events = state.events.concat(e.events.filter(x => !seen.has(x.id))); state.evNext = e.next; state.evPaged = true;
      renderEvents();
    } catch (err) { showBanner(t("err.more_events", { msg: err.message })); }
    finally { btn.disabled = false; }
  }
  // an event kind's label; a kind the table lacks (a newer server) shows as sent
  const kindText = k => { const key = "kind." + k, v = t(key); return v === key ? k : v; };

  // ---------- drawer ----------
  // typed Name/Note not saved yet are dropped by a close or by opening another device: true when there are none,
  // or the user agrees to drop them
  function discardOk() {
    return !formEdited(state.open) || confirm(t("drawer.discard"));
  }
  // the drawer's text fields, by the key the API takes: a new field is added here and in the form markup only
  const FORM_FIELDS = { name: "#fName", note: "#fNote", tags: "#fTags" };
  // the values now typed in the drawer form: {name, note, tags}
  function formValues() {
    return Object.fromEntries(Object.entries(FORM_FIELDS).map(([k, sel]) => [k, $(sel).value]));
  }
  // a form reference from values (keys that are missing, as in a partial save, keep those of base)
  function applyForm(values, base) {
    return Object.fromEntries(Object.keys(FORM_FIELDS).map(k => [k, values[k] ?? base[k]]));
  }
  // the drawer form of mac differs from its reference: the values a running save of this form posts, else what the
  // form was rendered with or last saved (a close during the save asks only about text typed after Save)
  function formEdited(mac) {
    const f = $("#fName", $("#dBody"));
    if (!f || state.form?.mac !== mac) return false;
    const ref = state.saving?.form === f ? state.saving : state.form;
    const v = formValues();
    return Object.keys(FORM_FIELDS).some(k => v[k] !== ref[k]);
  }
  async function openDrawer(mac) {
    if (state.open && state.open !== mac && !discardOk()) return;
    // another device's form must not stay live while this one loads: Save would act on that device
    if (state.open !== mac) { $("#dTitle").textContent = t("drawer.title"); $("#dBody").innerHTML = `<p class="muted">${esc(t("nav.loading"))}</p>`; state.form = null; }
    // a switch from inside the drawer keeps the control outside it to return to (a drawer control is inert after close)
    if (!$("#drawer").contains(document.activeElement)) state.returnTo = document.activeElement;
    state.open = mac; syncUrl();
    $("#drawer").classList.add("open"); $("#scrim").classList.add("show"); $("#drawer").setAttribute("aria-hidden", "false"); $("#drawer").inert = false;
    // the page behind the modal drawer takes no focus or clicks until it closes (Tab wraps inside it, see the keydown)
    $$("body > header, body > main, body > footer").forEach(e => { e.inert = true; });
    await refreshDrawer(mac, true);
  }
  function closeDrawer() {
    if (!state.open || !discardOk()) return;
    const mac = state.open;
    state.drawerGet?.ctl.abort(); state.drawerGet = null;
    state.open = null; syncUrl(); $("#drawer").classList.remove("open"); $("#scrim").classList.remove("show"); $("#drawer").setAttribute("aria-hidden", "true"); $("#drawer").inert = true;
    $$("body > header, body > main, body > footer").forEach(e => { e.inert = false; }); // before the focus goes back to a row
    // the row that opened the drawer may have been re-rendered by a poll: fall back to its replacement, then the search box
    const back = state.returnTo?.isConnected ? state.returnTo : ($$("#rows tr").find(tr => tr.dataset.mac === mac) || $("#q"));
    back.focus?.();
  }

  // one line per connector instance that listed the device, newest first; "on the wire" when that instance saw it
  // present within the grace window (an older server sends no seen list: no row)
  function seenHtml(seen) {
    if (!seen || !seen.length) return "";
    const grace = (state.meta?.grace_minutes ?? 10) * 60, now = Date.now() / 1000 + state.skew; // last_present is server time
    // the age in browser time (- skew), as rel() counts: else "12 min ago · on the wire" with a 10 min grace
    const line = s => `${esc(connLabel(s.source))} · ${esc(rel(s.last_seen - state.skew))}${s.last_present && now - s.last_present <= grace ? ` · <span class="muted">${esc(t("drawer.on_wire"))}</span>` : ""}`;
    return `<dt>${esc(t("drawer.seen_by"))}</dt><dd>${seen.map(line).join("<br>")}</dd>`;
  }

  // the private MACs merged into the device, and why (an older server sends no aliases list: no section)
  function aliasesHtml(aliases) {
    if (!aliases || !aliases.length) return "";
    // the server refuses this client's changes: no Split buttons, no column for them
    const canWrite = state.meta?.can_write !== false;
    const why = a => a.reason === "client-id" ? t("drawer.match_client_id", { detail: a.detail }) : a.reason === "hostname" ? t("drawer.match_hostname", { detail: a.detail }) : `${a.reason} ${a.detail}`;
    return `<h3>${esc(t("drawer.merged"))}</h3>
      <p class="muted note">${esc(t("drawer.merged_note"))}</p>
      <table class="aliases"><thead><tr><th scope="col">${esc(t("drawer.mac"))}</th><th scope="col">${esc(t("drawer.th_matched"))}</th><th scope="col">${esc(t("drawer.th_merged"))}</th><th scope="col">${esc(t("drawer.th_last_seen"))}</th>${canWrite ? `<th scope="col">${esc(t("drawer.th_action"))}</th>` : ""}</tr></thead>
      <tbody>${aliases.map(a => `<tr><td class="mono">${esc(a.mac)}</td><td>${esc(why(a))}</td><td title="${esc(abs(a.merged_ts))}">${esc(abs(a.merged_ts))}</td><td title="${esc(abs(a.last_seen))}">${esc(rel(a.last_seen - state.skew))}</td>${canWrite ? `<td><button class="btn small" data-split="${esc(a.mac)}">${esc(t("drawer.split"))}</button></td>` : ""}</tr>`).join("")}</tbody></table>`;
  }

  // the SSIDs the device was seen on, newest first (an older server sends no list: no section). "now" marks the row of
  // the SSID the device is on while it is online. A first sighting within one poll of the day counting began says
  // nothing about the device's first visit, so it reads "since <date>"
  function wifiHtml(list, meta, d) {
    if (!list || !list.length) return "";
    const poll = meta?.poll_seconds ?? 120, since = meta?.wifi_presence_since ? Number(meta.wifi_presence_since) : 0;
    const row = w => {
      const first = since && Math.abs(w.first_seen - since) <= poll ? t("drawer.wifi_since", { when: abs(since) }) : abs(w.first_seen);
      const last = d?.online && d.wifi_ssid && d.wifi_ssid === w.ssid ? t("row.now") : abs(w.last_seen);
      const title = t("drawer.wifi_time_title", { h: (w.seconds_seen / 3600).toFixed(2), polls: w.polls_seen });
      return `<tr><td>${esc(w.ssid)}</td><td>${esc(first)}</td><td>${esc(last)}</td><td title="${esc(title)}">${esc(durText(w.seconds_seen))}</td><td>${esc(w.last_ap || "–")}</td></tr>`;
    };
    return `<h3>${esc(t("drawer.wifi_history"))}</h3>
      <table class="wifi"><thead><tr><th scope="col">${esc(t("drawer.th_ssid"))}</th><th scope="col">${esc(t("drawer.th_first"))}</th><th scope="col">${esc(t("drawer.th_last"))}</th><th scope="col">${esc(t("drawer.th_time"))}</th><th scope="col">${esc(t("drawer.th_last_ap"))}</th></tr></thead>
      <tbody>${list.map(row).join("")}</tbody></table>`;
  }

  async function refreshDrawer(mac, focus) {
    // edited = differs from what the form was rendered with or last saved, not from the server's values: a rename by
    // another viewer must still refresh a clean form, and text typed while a save ran must survive its refresh. A form
    // whose save runs is kept too: a poll's GET may predate the POST
    const edited = () => formEdited(mac) || (!!state.saving && state.saving.form === $("#fName", $("#dBody")));
    // one drawer GET at a time. A poll refresh leaves a running one alone: its reply is as fresh, and an open's reply
    // still has to focus Name. An open replaces it; a close, another device's open or a save of this device abort it
    if (!focus && state.drawerGet?.mac === mac) return;
    state.drawerGet?.ctl.abort();
    const g = state.drawerGet = { mac, focus, ctl: new AbortController() };
    let r; try { r = await api(`/api/devices/${mac}`, { signal: g.ctl.signal }); } catch (e) {
      if (state.drawerGet !== g) return; // aborted, or replaced while a fetch that ignores the abort ran
      state.drawerGet = null;
      // a refresh failing (also the one after a save) must not wipe an edit in progress, nor a form a poll may refresh later
      if (!edited() && (focus || !$("#fName", $("#dBody")))) $("#dBody").innerHTML = `<p>${esc(e.message)}</p>`;
      return;
    }
    if (state.drawerGet !== g) return;
    state.drawerGet = null;
    const d = r.device;
    $("#dTitle").textContent = label(d);
    const b = $("#dBody");
    const kv = `
        <dt>${esc(t("drawer.status"))}</dt><dd><span class="online-dot ${d.online ? "on" : ""}"></span> ${esc(d.online ? t("row.online") : (d.last_online ? t("drawer.offline_last", { ago: rel(d.last_online) }) : (d.sources === "" ? t("drawer.offline_split") : t("drawer.offline_never"))))}</dd>
        <dt>${esc(t("drawer.ip"))}</dt><dd class="mono">${esc(d.ip || "–")}</dd>
        ${d.ip6 ? `<dt>${esc(t("drawer.ip6"))}</dt><dd class="mono">${esc(d.ip6)}</dd>` : ""}
        <dt>${esc(t("drawer.mac"))}</dt><dd class="mono">${esc(d.mac)}</dd>
        ${d.private ? `<dt>${esc(t("drawer.address"))}</dt><dd><span class="priv" title="${esc(t("row.private"))}"><span aria-hidden="true">\u{1F575}\u{FE0F}</span></span> ${esc(t("drawer.private"))}</dd>` : ""}
        ${d.split_from ? `<dt>${esc(t("drawer.split_from"))}</dt><dd><button class="who" id="fSplitFrom" data-mac="${esc(d.split_from)}">${esc(splitFromLabel(d.split_from))}</button></dd>` : ""}
        <dt>${esc(t("drawer.hostname"))}</dt><dd>${esc(d.hostname || "–")}</dd>
        ${d.label ? `<dt>${esc(t("drawer.label"))}</dt><dd>${esc(d.label)}</dd>` : ""}
        <dt>${esc(t("drawer.vendor"))}</dt><dd>${esc(d.vendor || t("drawer.vendor_unknown"))}</dd>
        <dt>${esc(t("drawer.network"))}</dt><dd><span class="badge vlan" data-vc="${esc(vlanColor(d.vlan))}">${esc(d.vlan || "?")}</span> <span class="muted" title="${esc(t("drawer.iface_title"))}">${esc(d.iface)}</span></dd>
        <dt>${esc(t("drawer.type"))}</dt><dd>${esc(typeText(d))} <span class="muted">${esc(t("drawer.seen_in", { sources: sourcesText(d.sources) }))}</span></dd>
        ${whereHtml(d, true) ? `<dt>${esc(t("drawer.where"))}</dt><dd>${whereHtml(d, true)}</dd>` : ""}${d.wifi_alias ? `<dt>${esc(t("drawer.unifi_name"))}</dt><dd>${esc(d.wifi_alias)}</dd>` : ""}
        <dt>${esc(t("drawer.first_seen"))}</dt><dd>${esc(d.baseline ? t("drawer.since_start", { when: abs(state.meta.baseline_ts) }) : abs(d.first_seen))}${isNew(d) ? ` <span class="badge new">${esc(t("row.new"))}</span>` : ""}</dd>
        <dt>${esc(t("drawer.last_online"))}</dt><dd>${esc(d.last_online ? abs(d.last_online) : t("drawer.never"))} <span class="muted">${esc(t("drawer.last_listed", { when: abs(d.last_seen) }))}</span></dd>
        ${seenHtml(r.seen)}
        <dt>${esc(t("drawer.known"))}</dt><dd>${esc(d.acked ? t("drawer.known_marked", { when: abs(d.acked_at) }) : d.baseline ? t("drawer.known_start") : t("drawer.known_not"))}</dd>
        ${d.archived_ts != null ? `<dt>${esc(t("drawer.archived"))}</dt><dd>${esc(abs(d.archived_ts))} <span class="muted">${esc(t("drawer.archived_note"))}</span></dd>` : ""}`;
    // don't clobber an edit in progress, but show what a save changed outside the form (Known and the ack button)
    // the merged addresses too, so a split address leaves the table; a Split button that had focus hands it on (to the
    // same button, else to Name)
    if (edited()) {
      $("dl.kv", b).innerHTML = kv;
      const al = $("#dAliases", b);
      if (al) {
        const fs = al.contains(document.activeElement) ? document.activeElement.dataset.split : null;
        al.innerHTML = aliasesHtml(r.aliases);
        if (fs != null) (al.querySelector(`[data-split="${CSS.escape(fs)}"]`) || $("#fName", b)).focus({ preventScroll: true });
      }
      paintVc(b); drawerActions(d); return; // the user is typing: focus stays put
    }
    // rebuilding the body drops keyboard focus: note the focused control (and caret) to focus its replacement
    const fe = b.contains(document.activeElement) ? document.activeElement : null;
    const fid = fe?.id || "", caret = fe && "selectionStart" in fe ? [fe.selectionStart, fe.selectionEnd] : null;
    // the server refuses this client's changes: no buttons, Name and Note read-only, one line that says why
    const ro = state.meta?.can_write === false ? " readonly" : "";
    b.innerHTML = `
      <dl class="kv">${kv}
      </dl>
      <div class="form">
        <label>${esc(t("drawer.name"))}<input id="fName" maxlength="80" value="${esc(d.name)}" placeholder="${esc(t("drawer.name_ph"))}"${ro}></label>
        <label>${esc(t("drawer.note"))}<textarea id="fNote" rows="2" maxlength="1000" placeholder="${esc(t("drawer.note_ph"))}"${ro}>${esc(d.note)}</textarea></label>
        <label>${esc(t("drawer.tags"))}<input id="fTags" maxlength="232" value="${esc(tagsOf(d).join(", "))}" placeholder="${esc(t("drawer.tags_ph"))}"${ro}></label>
        <div class="actions">${ro ? `
          <span class="muted" id="fReadOnly">${esc(state.meta.role === "ro" ? t("drawer.ro_login") : state.meta.read_only ? t("err.read_only") : t("err.not_allowed_from_address"))}</span>` : `
          <button class="btn" id="fSave">${esc(t("drawer.save"))}</button>
          <button class="btn" id="fAck"></button>
          <button class="btn" id="fArch"></button>
          <button class="btn" id="fWatch"></button>
          <span class="saved" id="fSaved"></span>`}
        </div>
      </div>
      <div id="dAliases">${aliasesHtml(r.aliases)}</div>
      ${wifiHtml(r.wifi_presence, state.meta, d)}
      <h3>${esc(t("drawer.history"))}</h3>
      <ul class="tl">${r.history.map(h => `<li><span class="t">${esc(abs(h.ts))}</span><span class="mono">${esc(h.ip)}</span> ${esc(h.hostname || "")} <span class="badge vlan" data-vc="${esc(vlanColor(h.vlan))}">${esc(h.vlan)}</span> <span class="muted">${esc(h.lease_type)}</span></li>`).join("") || `<li class="none">${esc(t("drawer.no_changes"))}</li>`}</ul>
      <h3>${esc(t("drawer.events"))}</h3>
      <ul class="tl">${r.events.map(e => `<li><span class="t">${esc(abs(e.ts))}</span><span class="k ${esc(e.kind)}">${esc(kindText(e.kind))}</span> <span class="muted">${esc(String(e.detail || "").replace(" -> ", " → "))}</span></li>`).join("") || `<li class="none">${esc(t("drawer.no_events"))}</li>`}</ul>`;
    paintVc(b);
    drawerActions(d);
    state.form = { mac, ...formValues() };
    if (focus) $("#fName").focus();
    else if (fid && document.getElementById(fid)) { const el = document.getElementById(fid); el.focus({ preventScroll: true }); /* the reader may have scrolled the body */ if (caret) el.setSelectionRange(...caret); }
  }

  // the drawer's buttons follow the device's ack state; a baseline device is known already, so Save is the main one
  function drawerActions(d) {
    const from = $("#fSplitFrom"); if (from) from.onclick = () => openDrawer(from.dataset.mac);
    $$("[data-split]", $("#dBody")).forEach(btn => btn.onclick = () => {
      const alias = btn.dataset.split;
      if (confirm(t("drawer.split_confirm", { alias, name: label(d) }))) splitOff(d.mac, alias);
    });
    const save = $("#fSave"), ack = $("#fAck"), main = !d.acked && !d.baseline;
    if (!save) return; // read-only drawer: no buttons
    save.className = main ? "btn" : "btn primary"; ack.className = main ? "btn primary" : "btn";
    // a baseline device is called known already ("present at the start"): its ack only records that it was checked
    ack.textContent = d.acked ? t("drawer.mark_unknown") : d.baseline ? t("drawer.save_checked") : t("drawer.save_known");
    save.onclick = () => setFields(d.mac, formValues(), $("#fName"));
    ack.onclick = () => setFields(d.mac, { acked: !d.acked, ...formValues() }, $("#fName"));
    // posts only the archive state: typed Name/Note stay an unsaved edit (the drawer stays open on the device). No form:
    // nothing typed was saved, so no "saved" flash; the load() after the POST refreshes the drawer
    const arch = $("#fArch"), archived = d.archived_ts != null;
    arch.textContent = archived ? t("drawer.restore") : t("drawer.archive");
    arch.onclick = () => setFields(d.mac, { archived: !archived });
    // like Archive: posts only the watch state, at once
    const watch = $("#fWatch");
    watch.textContent = d.watch ? t("drawer.unwatch") : t("drawer.watch"); watch.onclick = () => setFields(d.mac, { watch: !d.watch });
  }

  // the device a split row came from, by its name when the list has it
  const splitFromLabel = mac => { const o = state.devices.find(x => x.mac === mac); return o ? label(o) : mac; };

  // splits a merged address off a device; like setFields, a drawer GET still running is stale and is dropped. The
  // drawer stays on the device, which no longer lists the address
  async function splitOff(mac, alias) {
    try {
      await api(`/api/devices/${mac}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ split: alias }) });
      const g = state.drawerGet?.mac === mac ? state.drawerGet : null;
      if (g) { g.ctl.abort(); state.drawerGet = null; }
      await load();
      if (state.open === mac) {
        await refreshDrawer(mac, true);
        const s = $("#fSaved"); if (s) { s.textContent = t("drawer.split_done"); setTimeout(() => { if (s.isConnected) s.textContent = ""; }, 1500); }
      }
    } catch (e) { showBanner(t("err.split_failed", { msg: e.message })); }
  }

  // form: the drawer's Name input the save was started from (none for a table-row ack)
  async function setFields(mac, fields, form) {
    // module state: while the POST runs, what it posts is the reference of the form it was typed in (see formEdited)
    const saving = form && form === $("#fName") && state.form?.mac === mac ? { form, ...applyForm(fields, state.form) } : null;
    if (saving) state.saving = saving;
    try {
      try { await api(`/api/devices/${mac}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(fields) }); }
      finally { if (state.saving === saving) state.saving = null; } // on a failure the form's reference is state.form again
      // a drawer GET of this device still running may have been served before the save: its reply is stale. An open's
      // pending Name focus moves to the refresh below. Another device's GET is left alone
      const g = state.drawerGet?.mac === mac ? state.drawerGet : null;
      if (g) { g.ctl.abort(); state.drawerGet = null; }
      // what was saved is the new reference of the form it was typed in (text typed while the save ran stays an edit in
      // progress); not of a form rebuilt meanwhile by a close and reopen, which shows what its GET returned
      if (form && form === $("#fName") && state.form?.mac === mac) state.form = { mac, ...applyForm(fields, state.form) };
      await load();
      if (state.open === mac && (form || g?.focus)) { await refreshDrawer(mac, true); if (!form) return; const s = $("#fSaved"); if (s) { s.textContent = t("drawer.saved"); setTimeout(() => { if (s.isConnected) s.textContent = ""; }, 1500); } }
    } catch (e) { showBanner(t("err.save_failed", { msg: e.message })); }
  }

  // the ticked rows in requests of up to BULK_MAX (the server's limit), one after another; the server applies each one
  // all or nothing. At the first failure the rest stay as they are and the banner says how far it got
  const BULK_MAX = 200;
  // partial: the banner text when only some requests went through, from {done, total, msg}
  async function bulkSet(fields, partial) {
    if (state.bulkBusy || !state.sel.size) return;
    state.bulkBusy = true;
    const macs = [...state.sel];
    let done = 0, err = null;
    try {
      for (let i = 0; i < macs.length; i += BULK_MAX) {
        const part = macs.slice(i, i + BULK_MAX);
        await api("/api/devices", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ macs: part, ...fields }) });
        done += part.length;
      }
      state.sel.clear();
    } catch (e) { err = e; }
    finally { state.bulkBusy = false; }
    await load();
    // after the load: its status line would clear a banner shown before it
    if (err) showBanner(done ? partial({ done, total: macs.length, msg: err.message }) : t("err.save_failed", { msg: err.message }));
  }

  // ---------- url state ----------
  let urlRetry = 0; // timer of the write retried after a throttled one
  function syncUrl() {
    clearTimeout(urlRetry);
    const p = new URLSearchParams();
    if (state.q) p.set("q", state.q); if (state.status !== "all") p.set("filter", state.status); if (state.vlan !== null) p.set("vlan", state.vlan); if (state.sort !== "first_desc") p.set("sort", state.sort);
    if (state.ssid !== null) { p.set("ssid", state.ssid); if (state.ssidNow) p.set("ssidnow", "1"); }
    if (state.tag !== null) p.set("tag", state.tag);
    if (state.evKind) p.set("ek", state.evKind); if (state.evFrom) p.set("es", state.evFrom); if (state.evTo) p.set("eu", state.evTo);
    if (langParam) p.set("lang", langParam); // not a filter: clearFilters() keeps it
    // the open drawer is part of the address, so a copied URL shows the same device; a link not yet opened stays
    const dev = state.open || state.deepLink;
    // WebKit throws after ~100 calls in a short window (fast typing): retry until the window ends, or the URL keeps
    // the last state written before it
    // the colons stay as they are, as in the links of the notifications
    const qs = [p.toString(), dev ? `device=${encodeURIComponent(dev).replace(/%3A/gi, ":")}` : ""].filter(Boolean).join("&");
    try { history.replaceState(null, "", qs ? `?${qs}` : location.pathname); } catch (_) { urlRetry = setTimeout(syncUrl, 1000); }
  }
  function readUrl() {
    const p = new URLSearchParams(location.search);
    state.q = p.get("q") || ""; state.status = p.get("filter") || "all"; state.vlan = p.get("vlan"); state.sort = p.get("sort") || "first_desc";
    state.ssid = p.get("ssid") || null; state.ssidNow = state.ssid !== null && p.get("ssidnow") === "1"; // no SSID is empty
    state.tag = p.get("tag") || null; // no tag is empty
    $("#q").value = state.q; $("#fStatus").value = state.status; $("#sort").value = state.sort;
    const ek = p.get("ek") || "", es = p.get("es") || "", eu = p.get("eu") || "";
    state.evKind = /^[a-z_]{1,20}$/.test(ek) ? ek : ""; state.evFrom = isDay(es) ? es : ""; state.evTo = isDay(eu) ? eu : "";
    $("#evKind").value = state.evKind; $("#evFrom").value = state.evFrom; $("#evTo").value = state.evTo;
    if (!$("#evKind").value) state.evKind = ""; // a kind the list does not offer
    // lower case, colon form only: anything else is ignored, and the next syncUrl() drops it from the address
    const dl = (p.get("device") || "").toLowerCase();
    state.deepLink = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(dl) ? dl : null;
    if (!$("#fStatus").value) { state.status = "all"; $("#fStatus").value = "all"; }
    if (!$("#sort").value) { state.sort = "first_desc"; $("#sort").value = "first_desc"; }
  }
  // the drawer of the ?device= link, once the first load has the list and meta the drawer needs. The MAC may be one that
  // was merged into a device (the rows list their aliases); one in no row is asked of the server, which also knows
  // merged MACs and devices newer than the list. One that nothing knows opens no drawer
  async function openDeepLink() {
    const m = state.deepLink;
    if (!state.meta) return; // the API was unreachable: the key stays in the address
    if (!m) { syncUrl(); return; } // no link, or a malformed one: leave no stray key in the address
    state.deepLink = null;
    let key = state.devices.find(d => d.mac === m || (d.aliases || []).includes(m))?.mac;
    if (!key) { try { key = (await api(`/api/devices/${m}`)).device.mac; } catch (_) { syncUrl(); return; } }
    await openDrawer(key);
  }
  function clearFilters() { state.q = ""; state.vlan = null; state.ssid = null; state.ssidNow = false; state.tag = null; state.status = "all"; $("#q").value = ""; $("#fStatus").value = "all"; renderCards(); renderVlans(); renderSsids(); renderTags(); renderTable(); syncUrl(); }

  // ---------- wiring ----------
  // a table rebuild per key costs ~100 ms at 2000 devices: render (and write the URL) once typing pauses
  let qTimer = 0; // pending search render (0: none)
  const searchNow = () => { clearTimeout(qTimer); qTimer = 0; renderTable(); syncUrl(); };
  $("#q").addEventListener("input", e => { state.q = e.target.value; clearTimeout(qTimer); qTimer = setTimeout(searchNow, 150); });
  $("#fStatus").addEventListener("change", e => { state.status = e.target.value; renderCards(); renderTable(); syncUrl(); });
  $("#sort").addEventListener("change", e => { state.sort = e.target.value; renderTable(); syncUrl(); });
  $$(".card[data-filter]").forEach(c => c.onclick = () => { state.status = state.status === c.dataset.filter ? "all" : c.dataset.filter; $("#fStatus").value = state.status; renderCards(); renderTable(); syncUrl(); });
  for (const [label, kinds] of EV_KINDS) {
    const g = document.createElement("optgroup"); g.label = label;
    for (const k of kinds) { const o = document.createElement("option"); o.value = k; o.textContent = kindText(k); g.appendChild(o); }
    $("#evKind").appendChild(g);
  }
  $("#evKind").addEventListener("change", e => { state.evKind = e.target.value; eventsFilterChanged(); });
  $("#evFrom").addEventListener("change", e => { state.evFrom = isDay(e.target.value) ? e.target.value : ""; eventsFilterChanged(); });
  $("#evTo").addEventListener("change", e => { state.evTo = isDay(e.target.value) ? e.target.value : ""; eventsFilterChanged(); });
  $("#evMore").onclick = loadMoreEvents;
  $("#emptyClear").onclick = clearFilters;
  $("#ssidNow").onclick = () => { state.ssidNow = !state.ssidNow; renderSsids(); renderTable(); syncUrl(); };
  // leaving the mode clears the selection, so no hidden ticks wait for the next time
  $("#selBtn").onclick = () => { state.selecting = !state.selecting; state.sel.clear(); renderTable(); };
  $("#selAll").onchange = e => { state.sel = new Set(e.target.checked ? filtered().map(d => d.mac) : []); renderTable(); };
  $("#selClear").onclick = () => { state.sel.clear(); renderTable(); };
  $("#selAck").onclick = () => bulkSet({ acked: true }, p => t("err.bulk_marked", p));
  $("#selArchive").onclick = () => bulkSet({ archived: true }, p => t("err.bulk_archived", p));
  $("#selRestore").onclick = () => bulkSet({ archived: false }, p => t("err.bulk_restored", p));
  $("#dClose").onclick = closeDrawer; $("#scrim").onclick = closeDrawer;
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && document.activeElement === $("#q") && state.q) { state.q = ""; $("#q").value = ""; searchNow(); return; }
    if (e.key === "Enter" && document.activeElement === $("#q")) { if (qTimer) searchNow(); return; } // no wait for the pause; nothing pending, no rebuild
    if (e.key === "Escape") closeDrawer();
    if (e.key === "Tab" && state.open) {
      // the background is inert, so Tab past the drawer's last control would leave the page: wrap to its first one
      const f = $$("button, input, textarea, select, a[href], [tabindex]:not([tabindex='-1'])", $("#drawer")).filter(x => !x.disabled && x.offsetParent);
      const i = f.indexOf(document.activeElement), last = f.length - 1;
      if (e.shiftKey ? i <= 0 : i === last || i < 0) { e.preventDefault(); f[e.shiftKey ? last : 0]?.focus(); }
    }
    if (e.key === "/" && !/input|textarea|select/i.test(document.activeElement.tagName)) { e.preventDefault(); $("#q").focus(); $("#q").select(); }
  });
  const store = { get: k => { try { return localStorage.getItem(k); } catch (_) { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch (_) {} } };
  const theme = store.get("theme"); if (theme) document.documentElement.dataset.theme = theme;
  if (document.documentElement.lang !== lang) document.documentElement.lang = lang;
  applyI18n(document); applyI18n($("#rowTpl").content);
  $("#themeBtn").onclick = () => { const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); const next = cur === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = next; store.set("theme", next); };

  readUrl(); load().then(openDeepLink);
  setInterval(load, 60000);
  setInterval(() => { if (state.meta && !state.apiDown) renderStatus(); }, 15000);
})();
