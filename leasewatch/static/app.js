/* leasewatch UI — vanilla JS, no dependencies. Talks to /api/*. */
(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

  const state = {
    devices: [], meta: null, stats: null, events: [],
    q: "", status: "all", vlan: null, sort: "first_desc", open: null, returnTo: null, apiDown: false,
    renderError: null, // kept so the 15 s status refresh does not hide a page error while the table is still broken
    loadSeq: 0, // number of the newest load(): an older one that answers later must not write its snapshot over it
    drawerGet: null, // {mac, focus, ctl} of the one drawer GET in flight: only its reply is applied; replacing it aborts it
    skew: 0, // server clock minus browser clock at the last load: "on the wire" is judged in server time
    form: null, // {mac, name, note} the drawer form was rendered with (or last saved): what "edited" is measured against
    saving: null, // {form, name, note} posted from that Name input while its save runs: its reference until the POST settles
  };
  const VLAN_COLORS = ["--vlan1", "--vlan2", "--vlan3", "--vlan4", "--vlan5", "--vlan6", "--vlan7", "--vlan8"];
  // stable colour per network: alphabetical position, so colours do not shift when counts change
  const vlanColor = v => {
    if (!v) return "var(--vlan0)";
    const all = (state.stats?.vlans || []).map(x => x.vlan).filter(Boolean).sort();
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
    if (s < 45) return "just now";
    // the unit is picked on the rounded value, so 3590 s reads "1 h ago", not "60 min ago"
    const m = Math.round(s / 60); if (m < 60) return `${m} min ago`;
    const h = Math.round(s / 3600); if (h < 48) return `${h} h ago`;
    const n = Math.round(s / 86400); if (n < 30) return `${n} d ago`;
    const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  };
  const pad3 = x => String(x).padStart(3, "0");
  const ipKey = ip => (ip || "").split(".").map(pad3).join(".");
  // a device without an address sorts after every real one, as an empty vendor does
  const ipCmp = (a, b) => (!a.ip - !b.ip) || ipKey(a.ip).localeCompare(ipKey(b.ip));
  const isNew = d => !d.baseline && state.meta && (state.meta.now - d.first_seen) < state.meta.new_days * 86400;
  const label = d => d.name || d.wifi_alias || d.hostname || d.vendor || d.mac;
  const typeText = d => d.lease_type === "static" ? "DHCP static" : d.lease_type === "dynamic" ? "DHCP" : "fixed address";
  const sourcesText = s => String(s || "").split(",").filter(Boolean).map(x => x.toUpperCase()).join(" + ");
  // a controller client can come without an SSID (hidden network, mid-association): its AP and signal still place it.
  // merge clears the port when a device goes on Wi-Fi, so an SSID-less row with a port is one a switch placed since
  const onWifi = d => !!(d.wifi_ssid || ((d.wifi_ap || d.link === "wifi") && !d.sw_port));
  // display label of a connector instance ("Wi-Fi", the switch's NAME), the instance id when the meta has none
  const connLabel = n => state.meta?.connectors?.find(c => c.name === n)?.label || n;
  // "Connected via": Wi-Fi SSID @ AP, or switch port (+ what hangs on it), as HTML
  const whereHtml = (d, long) => {
    if (onWifi(d)) return `<span class="w">${esc(d.wifi_ssid || "Wi-Fi")}</span> <span class="muted">@ ${esc(d.wifi_ap || "?")}${d.wifi_signal != null ? ` <span class="sig">${esc(d.wifi_signal)} dBm</span>` : ""}${long && d.wifi_radio ? ` · ${esc(d.wifi_radio)}` : ""}</span>`;
    // long (drawer): name the switch too, as two switches can have a port of the same name. A controller never places
    // a port (it lists a wired client without one), so a controller as loc_source does not name the port's switch
    const ctl = state.meta?.connectors?.find(c => c.name === d.loc_source)?.type === "unifi";
    if (d.sw_port) return `<span class="w">${esc(d.sw_port)}</span>${d.sw_via ? ` <span class="muted">→ ${esc(d.sw_via)}</span>` : ""}${long && d.loc_source && !ctl ? ` <span class="muted">on ${esc(connLabel(d.loc_source))}</span>` : ""}`;
    return "";
  };
  const whereText = d => onWifi(d) ? `${d.wifi_ssid || "Wi-Fi"} @ ${d.wifi_ap || ""}` : d.sw_port ? `${d.sw_port} ${d.sw_via || ""}` : "";

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
    const timer = setTimeout(() => ctl.abort(new DOMException("signal timed out", "TimeoutError")), 30000), signal = ctl.signal;
    try {
      const r = await fetch(path, { cache: "no-store", ...opts, signal });
      if (!r.ok) { let m = `${r.status}`; try { m = (await r.json()).error || m; } catch (_) {} throw new Error(m); }
      // a 2xx that is not JSON is some proxy's page (login, maintenance): say so instead of quoting its body
      try { return await r.json(); } catch (e) { if (e.name === "SyntaxError") throw new Error(`${r.status}: reply is not JSON`); throw e; }
    } finally {
      // the body is read too before this settles; a timer or listener left behind would abort or pin a finished request
      clearTimeout(timer); own?.removeEventListener("abort", relay);
    }
  }

  // ---------- load ----------
  async function load() {
    const seq = ++state.loadSeq;
    try {
      const [d, s, e] = await Promise.all([api("/api/devices"), api("/api/stats"), api("/api/events")]);
      if (seq !== state.loadSeq) return; // a newer load (e.g. the one after a save) already rendered fresher data
      state.skew = d.meta?.now ? d.meta.now - Date.now() / 1000 : 0;
      state.apiDown = false; state.devices = d.devices; state.meta = d.meta; state.stats = s.stats; state.events = e.events;
      state.renderError = null;
      try { renderStatus(); renderCards(); renderVlans(); renderTable(); renderEvents(); if (state.open) await refreshDrawer(state.open, false); }
      catch (err) { console.error(err); state.renderError = err.message; showBanner(`Page error: ${err.message}`); return; } // a UI bug, not an unreachable API (refreshDrawer handles its own fetch errors)
    } catch (err) {
      if (seq !== state.loadSeq) return;
      state.apiDown = true; showBanner(`Cannot reach the leasewatch API: ${err.message}`); $("#statusDot").className = "dot bad";
      // the poll age and the connector dots are from the last good reply: do not keep showing them as current
      $("#statusText").textContent = "API unreachable"; $("#status").title = "";
    }
  }

  function showBanner(msg) { const b = $("#banner"); if (!msg) { b.classList.add("hidden"); return; } b.textContent = msg; b.classList.remove("hidden"); }

  function renderStatus() {
    const m = state.meta, dot = $("#statusDot"), txt = $("#statusText");
    if (!m) return;
    // + 60: the meta is refetched once a minute, so a poll newer than that cannot be known here yet
    const stale = m.stale || (Date.now() / 1000 - m.last_poll_ts) > m.poll_seconds * 3 + 60;
    const ok = m.last_poll_ok && !stale;
    dot.className = "dot " + (ok ? "ok" : "bad");
    txt.innerHTML = m.last_poll_ts ? `polled ${esc(rel(m.last_poll_ts))} · ${esc(m.last_raw.replace("arp", "ARP entries"))}` : "no poll yet";
    // one dot per connector instance, text = its display label, tooltip = its instance name; a server without
    // label (1.1 before labels) gives the name
    // an instance disabled at start (invalid settings) gets no dot: it never polls, and the start log names the problem
    const sources = (m.connectors || []).filter(c => c.enabled !== false).map(c => [c.label || c.name, c.name, c]);
    for (const [label, name, s] of sources) {
      // a failed poll stops before the enrichers run: an instance last read at or before the last good poll was not
      // read in the failing ones, so its old "ok" is shown grey, not green
      // a last good poll in the future (the clock stepped back) says nothing: then the instance's own result is shown
      const old = !m.last_poll_ok && s.ts && m.last_poll_ts && s.ts <= m.last_poll_ts && !(m.last_poll_ts > m.now);
      const tip = old ? `${name}: not read since ${rel(s.ts)}` : s.ok ? `${name}: OK` : `${name}: ${s.error}`;
      txt.insertAdjacentHTML("beforeend", `<span class="src" title="${esc(tip)}"><span class="dot ${old ? "" : s.ok ? "ok" : "bad"}"></span>${esc(label)}</span>`);
    }
    $("#status").title = m.last_error ? `Last error: ${m.last_error}` : `Polls every ${m.poll_seconds}s`;
    if (m.collector_stale && m.last_attempt_ts && m.now < m.last_attempt_ts) showBanner("The clock moved back; polls resume after the next interval");
    else if (m.collector_stale) showBanner(`Collector has not run a poll since ${m.last_attempt_ts ? rel(m.last_attempt_ts) : "start"}; restart the service`);
    else if (!m.last_poll_ok && m.last_error) showBanner(`Collector cannot read the firewall: ${m.last_error} (last good data ${rel(m.last_poll_ts)})`);
    else if (stale) showBanner(`Data is stale: last successful poll ${rel(m.last_poll_ts)}.`);
    else if (state.renderError) showBanner(`Page error: ${state.renderError}`);
    else showBanner("");
    $("#newDays").textContent = m.new_days;
  }

  function renderCards() {
    const s = state.stats; if (!s) return;
    $("#cTotal").textContent = s.total; $("#cOnline").textContent = s.online; $("#cNew").textContent = s.new; $("#cUnacked").textContent = s.unacked;
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
    for (const [k, n] of days) { const b = document.createElement("span"); b.style.height = n ? `${Math.max(18, Math.round(n / max * 100))}%` : "2px"; b.title = `${k}: ${n} new`; if (n) b.classList.add("has"); bars.appendChild(b); }
    $("#barsSum").textContent = `${days.reduce((a, [, n]) => a + n, 0)} in 30 d`;
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
      c.title = `${v.online} online of ${v.n} devices`;
      c.onclick = () => { state.vlan = state.vlan === v.vlan ? null : v.vlan; renderVlans(); renderTable(); syncUrl(); };
      box.appendChild(c);
      if (had != null && had === c.dataset.vlan) c.focus();
    }
  }

  function filtered() {
    const q = state.q.trim().toLowerCase();
    const list = state.devices.filter(d => {
      if (state.vlan !== null && d.vlan !== state.vlan) return false; // null = no filter; "" is the unnamed network
      if ((d.archived_ts != null) !== (state.status === "archived")) return false; // archived devices only under their own filter
      switch (state.status) {
        case "new": if (!isNew(d)) return false; break;
        case "unacked": if (d.acked || d.baseline) return false; break;
        case "online": if (!d.online) return false; break;
        case "offline": if (d.online) return false; break;
        case "dynamic": if (d.lease_type !== "dynamic") return false; break;
        case "static": if (d.lease_type !== "static") return false; break;
        case "arp": if (d.lease_type) return false; break;
        case "wifi": if (!onWifi(d)) return false; break;
        case "wired": if (onWifi(d) || (d.link !== "wired" && !d.sw_port)) return false; break;
      }
      if (q) {
        const hay = `${d.name} ${d.hostname} ${d.ip} ${d.mac} ${d.vendor} ${d.vlan} ${d.note} ${whereText(d)} ${d.wifi_alias}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    // the unnamed network after the named ones, as a missing IP or vendor sorts last
    const byVlanIp = (a, b) => (!a.vlan - !b.vlan) || (a.vlan || "").localeCompare(b.vlan || "") || ipCmp(a, b);
    const cmp = {
      // real newcomers first (newest on top), then the baseline devices grouped by network and address
      first_desc: (a, b) => (a.baseline - b.baseline) || (a.baseline ? byVlanIp(a, b) : (b.first_seen - a.first_seen) || byVlanIp(a, b)),
      last_desc: (a, b) => (b.online - a.online) || ((b.last_online || 0) - (a.last_online || 0)) || byVlanIp(a, b),
      name: (a, b) => label(a).localeCompare(label(b), undefined, { sensitivity: "base" }) || byVlanIp(a, b),
      ip: ipCmp,
      vlan: byVlanIp,
      vendor: (a, b) => (a.vendor ? 0 : 1) - (b.vendor ? 0 : 1) || (a.vendor || "").localeCompare(b.vendor || "") || label(a).localeCompare(label(b)),
    }[state.sort] || byVlanIp;
    return list.sort(cmp);
  }

  function renderTable() {
    const list = filtered();
    const tb = $("#rows");
    // rebuilding the rows drops keyboard focus: note the focused row (or its button or copy target) to focus its replacement
    const fa = tb.contains(document.activeElement) ? document.activeElement : null;
    const fmac = fa?.closest("tr")?.dataset.mac, fack = !!fa?.classList.contains("ack");
    const fcp = fmac ? [".c-ip .cp", ".c-mac .cp"].find(s => $(s, fa.closest("tr")) === fa) : null; // Enter there copies, not opens
    tb.innerHTML = "";
    const tpl = $("#rowTpl").content;
    const frag = document.createDocumentFragment();
    for (const d of list) {
      const tr = tpl.cloneNode(true).firstElementChild;
      tr.dataset.mac = d.mac;
      const fresh = isNew(d) && !d.acked;
      if (fresh) tr.classList.add("is-new");
      const dot = $(".online-dot", tr); dot.classList.toggle("on", !!d.online);
      dot.title = d.online ? "online" : (d.last_online ? `offline, last online ${rel(d.last_online)}` : "offline, not seen online since leasewatch started");
      const nm = $(".dev-name", tr), lbl = label(d);
      $(".nm", nm).textContent = lbl;
      nm.classList.toggle("unnamed", !d.name && !d.wifi_alias && !d.hostname); // label() ranks the UniFi alias before the hostname
      if (fresh) nm.insertAdjacentHTML("beforeend", '<span class="badge new">NEW</span>');
      else if (!d.acked && !d.baseline) nm.insertAdjacentHTML("beforeend", '<span class="badge base">not yet known</span>');
      const sub = [];
      if ((d.name || d.wifi_alias) && d.hostname && d.hostname !== lbl) sub.push(`<span class="host">${esc(d.hostname)}</span>`);
      if (d.vendor && d.vendor !== lbl) sub.push(esc(d.vendor));
      if (!sub.length && !d.name && !d.wifi_alias && !d.hostname) sub.push(`<span class="host">${esc(d.mac)}</span>`);
      $(".dev-sub", tr).innerHTML = sub.join(" · ");
      $(".dev-meta .ip", tr).textContent = d.ip || "–";
      const vm = $(".dev-meta .badge", tr); vm.textContent = d.vlan || "?"; vm.style.setProperty("--vc", vlanColor(d.vlan));
      $(".dev-meta .last", tr).textContent = d.online ? "online" : (d.last_online ? `last ${rel(d.last_online)}` : "offline");
      $(".dev-meta .where", tr).textContent = onWifi(d) ? `${d.wifi_ssid || "Wi-Fi"} @ ${d.wifi_ap || "?"}` : d.sw_port ? `${d.sw_port}${d.sw_via ? " → " + d.sw_via : ""}` : "";
      const wh = $(".c-where", tr); wh.innerHTML = whereHtml(d, false); wh.title = wh.textContent.replace(/\s+/g, " ").trim(); // the full text, signal included, when the cell is cut
      if (d.ip) copyable($(".c-ip .cp", tr), d.ip); else $(".c-ip", tr).textContent = "–"; // nothing to copy
      copyable($(".c-mac .cp", tr), d.mac);
      // a private (locally administered) MAC: tinted row border, the sleuth and its "private address" hint
      if (d.private) { tr.classList.add("is-private"); $(".c-mac .priv", tr).classList.remove("hidden"); }
      const vb = $(".c-vlan .badge", tr); vb.textContent = d.vlan || "?"; vb.style.setProperty("--vc", vlanColor(d.vlan));
      const ty = $(".c-type", tr); ty.textContent = ty.title = typeText(d);
      const fs = $(".c-first", tr); fs.textContent = d.baseline ? "since the start" : rel(d.first_seen); fs.title = d.baseline ? `Already present when leasewatch started (${abs(state.meta.baseline_ts)})` : abs(d.first_seen);
      if (isNew(d)) fs.classList.add("recent");
      const ls = $(".c-last", tr); ls.textContent = d.online ? "now" : (d.last_online ? rel(d.last_online) : "not since the start"); ls.title = d.last_online ? `last online ${abs(d.last_online)} · last listed by the firewall ${abs(d.last_seen)}` : `listed by the firewall but not seen on the wire since leasewatch started; last listed ${abs(d.last_seen)}`;
      const ack = $(".ack", tr);
      if (d.acked || d.baseline) ack.remove();
      else ack.onclick = ev => { ev.stopPropagation(); setFields(d.mac, { acked: true }); };
      tr.onclick = () => openDrawer(d.mac);
      tr.onkeydown = ev => { if (ev.target !== tr) return; /* keys on the row's buttons are theirs */ if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); openDrawer(d.mac); } };
      frag.appendChild(tr);
    }
    tb.appendChild(frag);
    if (fmac) { const tr = $$("#rows tr").find(t => t.dataset.mac === fmac); ((fack && tr && $(".ack", tr)) || (fcp && tr && $(fcp, tr)) || tr)?.focus({ preventScroll: true }); } // the reader may have scrolled away from it
    // the total is the devices this filter could show: archived ones only under "Archived", as the cards leave them out
    const total = state.devices.filter(d => (d.archived_ts != null) === (state.status === "archived")).length;
    $("#count").textContent = `${list.length} of ${total}`;
    $("#empty").classList.toggle("hidden", list.length > 0);
    $("#emptyText").textContent = state.q || state.vlan !== null ? "Nothing matches." : state.status === "unacked" ? "Every device is known." : state.status === "new" ? `No new devices in the last ${state.meta?.new_days ?? 7} days.` : "Nothing matches.";
    $("#emptyClear").classList.toggle("hidden", !(state.q || state.vlan !== null || state.status !== "all"));
  }

  // the whole MAC or IP text copies on click, Enter or Space; the feedback is a class and a title, so the table keeps
  // its column widths
  function copyable(el, text) {
    el.textContent = text;
    let t = 0; // a second copy restarts the "Copied" time: an earlier copy's timer would end it early
    const done = () => { clearTimeout(t); el.classList.add("copied"); el.title = "Copied"; t = setTimeout(() => { el.classList.remove("copied"); el.title = "Click to copy"; }, 900); };
    // plain HTTP to a LAN address has no clipboard API, and a secure page can refuse the write (permission, focus):
    // select the text so Ctrl+C copies it, and try the old copy command
    const fallback = () => {
      const sel = getSelection(), r = document.createRange(); r.selectNodeContents(el); sel.removeAllRanges(); sel.addRange(r);
      let ok = false; try { ok = document.execCommand("copy"); } catch (_) {}
      if (ok) done();
      // the hint is for this click or key: it goes when the pointer or the keyboard focus leaves
      else { el.title = "selected: press Ctrl+C to copy"; el.onmouseleave = el.onblur = () => { el.title = "Click to copy"; el.onmouseleave = el.onblur = null; }; }
    };
    const copy = ev => { ev.stopPropagation(); /* not the row's drawer */ if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, fallback); else fallback(); };
    el.onclick = copy;
    el.onkeydown = ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); copy(ev); } };
  }

  function renderEvents() {
    const ul = $("#events"); ul.innerHTML = "";
    if (!state.events.length) { ul.innerHTML = '<li><span class="t">–</span><span></span><span class="muted">No events yet. New devices, address changes and acknowledgements show up here.</span></li>'; return; }
    for (const e of state.events.slice(0, 60)) {
      const li = document.createElement("li");
      const who = e.name || e.hostname || e.mac;
      let detail = String(e.detail || "").replace(" -> ", " → ");
      if (e.kind === "new") {
        // "ip hostname vendor (network then)": the network is dropped only when the badge (the device's current
        // network) shows the same one, and the hostname only as a whole, as the who button shows it
        const net = ` (${e.vlan})`;
        if (e.vlan && detail.endsWith(net)) detail = detail.slice(0, -net.length);
        if (e.hostname && who === e.hostname) detail = ` ${detail} `.replace(` ${who} `, " ").trim();
      }
      li.innerHTML = `<span class="t" title="${esc(abs(e.ts))}">${esc(abs(e.ts))}</span><span class="k ${esc(e.kind)}">${esc(kindText(e.kind))}</span><span><button class="who" data-mac="${esc(e.mac)}">${esc(who)}</button> <span class="muted">${esc(detail)}</span>${e.vlan ? ` <span class="badge vlan" data-vc="${esc(vlanColor(e.vlan))}" title="current network of the device">${esc(e.vlan)}</span>` : ""}</span>`;
      paintVc(li);
      $(".who", li).onclick = () => openDrawer(e.mac);
      ul.appendChild(li);
    }
  }
  const kindText = k => ({ new: "new device", ip: "new IP", hostname: "hostname", vlan: "moved network", lease_type: "lease type", back: "back online", acked: "marked known", unacked: "marked unknown", archived: "archived", restored: "restored to list", merged: "merged address", port: "moved port", wifi: "moved Wi-Fi" }[k] || k);

  // ---------- drawer ----------
  // typed Name/Note not saved yet are dropped by a close or by opening another device: true when there are none,
  // or the user agrees to drop them
  function discardOk() {
    return !formEdited(state.open) || confirm("Discard unsaved changes?");
  }
  // the drawer form of mac differs from its reference: the values a running save of this form posts, else what the
  // form was rendered with or last saved (a close during the save asks only about text typed after Save)
  function formEdited(mac) {
    const f = $("#fName", $("#dBody"));
    if (!f || state.form?.mac !== mac) return false;
    const ref = state.saving?.form === f ? state.saving : state.form;
    return f.value !== ref.name || $("#fNote", $("#dBody")).value !== ref.note;
  }
  async function openDrawer(mac) {
    if (state.open && state.open !== mac && !discardOk()) return;
    // another device's form must not stay live while this one loads: Save would act on that device
    if (state.open !== mac) { $("#dTitle").textContent = "Device"; $("#dBody").innerHTML = '<p class="muted">loading…</p>'; state.form = null; }
    // a switch from inside the drawer keeps the control outside it to return to (a drawer control is inert after close)
    if (!$("#drawer").contains(document.activeElement)) state.returnTo = document.activeElement;
    state.open = mac;
    $("#drawer").classList.add("open"); $("#scrim").classList.add("show"); $("#drawer").setAttribute("aria-hidden", "false"); $("#drawer").inert = false;
    // the page behind the modal drawer takes no focus or clicks until it closes (Tab wraps inside it, see the keydown)
    $$("body > header, body > main, body > footer").forEach(e => { e.inert = true; });
    await refreshDrawer(mac, true);
  }
  function closeDrawer() {
    if (!state.open || !discardOk()) return;
    const mac = state.open;
    state.drawerGet?.ctl.abort(); state.drawerGet = null;
    state.open = null; $("#drawer").classList.remove("open"); $("#scrim").classList.remove("show"); $("#drawer").setAttribute("aria-hidden", "true"); $("#drawer").inert = true;
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
    const line = s => `${esc(connLabel(s.source))} · ${esc(rel(s.last_seen - state.skew))}${s.last_present && now - s.last_present <= grace ? ' · <span class="muted">on the wire</span>' : ""}`;
    return `<dt>Seen by</dt><dd>${seen.map(line).join("<br>")}</dd>`;
  }

  // the private MACs merged into the device, and why (an older server sends no aliases list: no section)
  function aliasesHtml(aliases) {
    if (!aliases || !aliases.length) return "";
    const why = a => a.reason === "client-id" ? `client-id ${a.detail}` : a.reason === "hostname" ? `hostname ${a.detail}` : `${a.reason} ${a.detail}`;
    return `<h3>Merged addresses</h3>
      <p class="muted note">The device used these private addresses too. Each one was merged into it because it sent the same DHCP client-id or hostname as this device.</p>
      <table class="aliases"><thead><tr><th scope="col">MAC</th><th scope="col">Matched by</th><th scope="col">Merged</th><th scope="col">Last seen</th></tr></thead>
      <tbody>${aliases.map(a => `<tr><td class="mono">${esc(a.mac)}</td><td>${esc(why(a))}</td><td title="${esc(abs(a.merged_ts))}">${esc(abs(a.merged_ts))}</td><td title="${esc(abs(a.last_seen))}">${esc(rel(a.last_seen - state.skew))}</td></tr>`).join("")}</tbody></table>`;
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
        <dt>Status</dt><dd><span class="online-dot ${d.online ? "on" : ""}"></span> ${d.online ? "online" : (d.last_online ? `offline · last online ${esc(rel(d.last_online))}` : "offline · not seen online since leasewatch started")}</dd>
        <dt>IP</dt><dd class="mono">${esc(d.ip || "–")}</dd>
        <dt>MAC</dt><dd class="mono">${esc(d.mac)}</dd>
        ${d.private ? '<dt>Address</dt><dd><span class="priv" title="private address"><span aria-hidden="true">\u{1F575}\u{FE0F}</span></span> private (locally administered): the device may change it</dd>' : ""}
        <dt>Hostname</dt><dd>${esc(d.hostname || "–")}</dd>
        <dt>Vendor</dt><dd>${esc(d.vendor || "unknown")}</dd>
        <dt>Network</dt><dd><span class="badge vlan" data-vc="${esc(vlanColor(d.vlan))}">${esc(d.vlan || "?")}</span> <span class="muted" title="fw1 interface">${esc(d.iface)}</span></dd>
        <dt>Type</dt><dd>${esc(typeText(d))} <span class="muted">· seen in ${esc(sourcesText(d.sources))}</span></dd>
        ${whereHtml(d, true) ? `<dt>Connected via</dt><dd>${whereHtml(d, true)}</dd>` : ""}${d.wifi_alias ? `<dt>UniFi name</dt><dd>${esc(d.wifi_alias)}</dd>` : ""}
        <dt>First seen</dt><dd>${d.baseline ? `since the start (${esc(abs(state.meta.baseline_ts))})` : esc(abs(d.first_seen))}${isNew(d) ? ' <span class="badge new">NEW</span>' : ""}</dd>
        <dt>Last online</dt><dd>${d.last_online ? esc(abs(d.last_online)) : "never"} <span class="muted">· last listed by the firewall ${esc(abs(d.last_seen))}</span></dd>
        ${seenHtml(r.seen)}
        <dt>Known</dt><dd>${d.acked ? `yes, marked ${esc(abs(d.acked_at))}` : d.baseline ? "yes, present at the start" : "not yet"}</dd>
        ${d.archived_ts != null ? `<dt>Archived</dt><dd>${esc(abs(d.archived_ts))} <span class="muted">· not in the list until it is online again</span></dd>` : ""}`;
    // don't clobber an edit in progress, but show what a save changed outside the form (Known and the ack button)
    if (edited()) { $("dl.kv", b).innerHTML = kv; paintVc(b); drawerActions(d); return; } // the user is typing: focus stays put
    // rebuilding the body drops keyboard focus: note the focused control (and caret) to focus its replacement
    const fe = b.contains(document.activeElement) ? document.activeElement : null;
    const fid = fe?.id || "", caret = fe && "selectionStart" in fe ? [fe.selectionStart, fe.selectionEnd] : null;
    b.innerHTML = `
      <dl class="kv">${kv}
      </dl>
      <div class="form">
        <label>Name (what this device is)<input id="fName" maxlength="80" value="${esc(d.name)}" placeholder="e.g. Alex's iPad"></label>
        <label>Note<textarea id="fNote" rows="2" maxlength="1000" placeholder="where it lives, who owns it, anything useful">${esc(d.note)}</textarea></label>
        <div class="actions">
          <button class="btn" id="fSave">Save</button>
          <button class="btn" id="fAck"></button>
          <button class="btn" id="fArch"></button>
          <span class="saved" id="fSaved"></span>
        </div>
      </div>
      ${aliasesHtml(r.aliases)}
      <h3>History</h3>
      <ul class="tl">${r.history.map(h => `<li><span class="t">${esc(abs(h.ts))}</span><span class="mono">${esc(h.ip)}</span> ${esc(h.hostname || "")} <span class="badge vlan" data-vc="${esc(vlanColor(h.vlan))}">${esc(h.vlan)}</span> <span class="muted">${esc(h.lease_type)}</span></li>`).join("") || '<li class="none">No changes recorded</li>'}</ul>
      <h3>Events</h3>
      <ul class="tl">${r.events.map(e => `<li><span class="t">${esc(abs(e.ts))}</span><span class="k ${esc(e.kind)}">${esc(kindText(e.kind))}</span> <span class="muted">${esc(String(e.detail || "").replace(" -> ", " → "))}</span></li>`).join("") || '<li class="none">No events</li>'}</ul>`;
    paintVc(b);
    drawerActions(d);
    state.form = { mac, name: $("#fName").value, note: $("#fNote").value };
    if (focus) $("#fName").focus();
    else if (fid && document.getElementById(fid)) { const el = document.getElementById(fid); el.focus({ preventScroll: true }); /* the reader may have scrolled the body */ if (caret) el.setSelectionRange(...caret); }
  }

  // the drawer's buttons follow the device's ack state; a baseline device is known already, so Save is the main one
  function drawerActions(d) {
    const save = $("#fSave"), ack = $("#fAck"), main = !d.acked && !d.baseline;
    save.className = main ? "btn" : "btn primary"; ack.className = main ? "btn primary" : "btn";
    // a baseline device is called known already ("present at the start"): its ack only records that it was checked
    ack.textContent = d.acked ? "Mark unknown" : d.baseline ? "Save & mark checked" : "Save & mark known";
    save.onclick = () => setFields(d.mac, { name: $("#fName").value, note: $("#fNote").value }, $("#fName"));
    ack.onclick = () => setFields(d.mac, { acked: !d.acked, name: $("#fName").value, note: $("#fNote").value }, $("#fName"));
    // posts only the archive state: typed Name/Note stay an unsaved edit (the drawer stays open on the device). No form:
    // nothing typed was saved, so no "saved" flash; the load() after the POST refreshes the drawer
    const arch = $("#fArch"), archived = d.archived_ts != null;
    arch.textContent = archived ? "Restore to list" : "Archive";
    arch.onclick = () => setFields(d.mac, { archived: !archived });
  }

  // form: the drawer's Name input the save was started from (none for a table-row ack)
  async function setFields(mac, fields, form) {
    // module state: while the POST runs, what it posts is the reference of the form it was typed in (see formEdited)
    const saving = form && form === $("#fName") && state.form?.mac === mac ? { form, name: fields.name ?? state.form.name, note: fields.note ?? state.form.note } : null;
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
      if (form && form === $("#fName") && state.form?.mac === mac) state.form = { mac, name: fields.name ?? state.form.name, note: fields.note ?? state.form.note };
      await load();
      if (state.open === mac && (form || g?.focus)) { await refreshDrawer(mac, true); if (!form) return; const s = $("#fSaved"); if (s) { s.textContent = "saved"; setTimeout(() => { if (s.isConnected) s.textContent = ""; }, 1500); } }
    } catch (e) { showBanner(`Save failed: ${e.message}`); }
  }

  // ---------- url state ----------
  let urlRetry = 0; // timer of the write retried after a throttled one
  function syncUrl() {
    clearTimeout(urlRetry);
    const p = new URLSearchParams();
    if (state.q) p.set("q", state.q); if (state.status !== "all") p.set("filter", state.status); if (state.vlan !== null) p.set("vlan", state.vlan); if (state.sort !== "first_desc") p.set("sort", state.sort);
    // WebKit throws after ~100 calls in a short window (fast typing): retry until the window ends, or the URL keeps
    // the last state written before it
    try { history.replaceState(null, "", p.toString() ? `?${p}` : location.pathname); } catch (_) { urlRetry = setTimeout(syncUrl, 1000); }
  }
  function readUrl() {
    const p = new URLSearchParams(location.search);
    state.q = p.get("q") || ""; state.status = p.get("filter") || "all"; state.vlan = p.get("vlan"); state.sort = p.get("sort") || "first_desc";
    $("#q").value = state.q; $("#fStatus").value = state.status; $("#sort").value = state.sort;
    if (!$("#fStatus").value) { state.status = "all"; $("#fStatus").value = "all"; }
    if (!$("#sort").value) { state.sort = "first_desc"; $("#sort").value = "first_desc"; }
  }
  function clearFilters() { state.q = ""; state.vlan = null; state.status = "all"; $("#q").value = ""; $("#fStatus").value = "all"; renderCards(); renderVlans(); renderTable(); syncUrl(); }

  // ---------- wiring ----------
  // a table rebuild per key costs ~100 ms at 2000 devices: render (and write the URL) once typing pauses
  let qTimer = 0; // pending search render (0: none)
  const searchNow = () => { clearTimeout(qTimer); qTimer = 0; renderTable(); syncUrl(); };
  $("#q").addEventListener("input", e => { state.q = e.target.value; clearTimeout(qTimer); qTimer = setTimeout(searchNow, 150); });
  $("#fStatus").addEventListener("change", e => { state.status = e.target.value; renderCards(); renderTable(); syncUrl(); });
  $("#sort").addEventListener("change", e => { state.sort = e.target.value; renderTable(); syncUrl(); });
  $$(".card[data-filter]").forEach(c => c.onclick = () => { state.status = state.status === c.dataset.filter ? "all" : c.dataset.filter; $("#fStatus").value = state.status; renderCards(); renderTable(); syncUrl(); });
  $("#emptyClear").onclick = clearFilters;
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
  $("#themeBtn").onclick = () => { const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); const next = cur === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = next; store.set("theme", next); };

  readUrl(); load();
  setInterval(load, 60000);
  setInterval(() => { if (state.meta && !state.apiDown) renderStatus(); }, 15000);
})();
