/* leasewatch UI — vanilla JS, no dependencies. Talks to /api/*. */
(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

  const state = {
    devices: [], meta: null, stats: null, events: [],
    q: "", status: "all", vlan: "", sort: "first_desc", open: null, returnTo: null, apiDown: false,
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
  const pad = n => String(n).padStart(2, "0");
  const abs = ts => { if (!ts) return "–"; const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const rel = ts => {
    if (!ts) return "–";
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (s < 45) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400 * 2) return `${Math.round(s / 3600)} h ago`;
    if (s < 86400 * 30) return `${Math.round(s / 86400)} d ago`;
    const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  };
  const pad3 = x => String(x).padStart(3, "0");
  const ipKey = ip => (ip || "").split(".").map(pad3).join(".");
  const isNew = d => !d.baseline && state.meta && (state.meta.now - d.first_seen) < state.meta.new_days * 86400;
  const label = d => d.name || d.wifi_alias || d.hostname || d.vendor || d.mac;
  const typeText = d => d.lease_type === "static" ? "DHCP static" : d.lease_type === "dynamic" ? "DHCP" : "fixed address";
  const sourcesText = s => String(s || "").split(",").filter(Boolean).map(x => x.toUpperCase()).join(" + ");
  // "Connected via": Wi-Fi SSID @ AP, or switch port (+ what hangs on it), as HTML
  const whereHtml = (d, long) => {
    if (d.wifi_ssid) return `<span class="w">${esc(d.wifi_ssid)}</span> <span class="muted">@ ${esc(d.wifi_ap || "?")}${d.wifi_signal != null ? ` <span class="sig">${esc(d.wifi_signal)} dBm</span>` : ""}${long && d.wifi_radio ? ` · ${esc(d.wifi_radio)}` : ""}</span>`;
    if (d.sw_port) return `<span class="w">${esc(d.sw_port)}</span>${d.sw_via ? ` <span class="muted">→ ${esc(d.sw_via)}</span>` : ""}`;
    return "";
  };
  const whereText = d => d.wifi_ssid ? `${d.wifi_ssid} @ ${d.wifi_ap}` : d.sw_port ? `${d.sw_port} ${d.sw_via}` : "";

  async function api(path, opts) {
    const r = await fetch(path, { cache: "no-store", ...opts });
    if (!r.ok) { let m = `${r.status}`; try { m = (await r.json()).error || m; } catch (_) {} throw new Error(m); }
    return r.json();
  }

  // ---------- load ----------
  async function load() {
    try {
      const [d, s, e] = await Promise.all([api("/api/devices"), api("/api/stats"), api("/api/events")]);
      state.apiDown = false; state.devices = d.devices; state.meta = d.meta; state.stats = s.stats; state.events = e.events;
      renderStatus(); renderCards(); renderVlans(); renderTable(); renderEvents();
      if (state.open) refreshDrawer(state.open, false);
    } catch (err) {
      state.apiDown = true; showBanner(`Cannot reach the leasewatch API: ${err.message}`); $("#statusDot").className = "dot bad";
    }
  }

  function showBanner(msg) { const b = $("#banner"); if (!msg) { b.classList.add("hidden"); return; } b.textContent = msg; b.classList.remove("hidden"); }

  function renderStatus() {
    const m = state.meta, dot = $("#statusDot"), txt = $("#statusText");
    if (!m) return;
    const stale = m.stale || (Date.now() / 1000 - m.last_poll_ts) > m.poll_seconds * 3;
    const ok = m.last_poll_ok && !stale;
    dot.className = "dot " + (ok ? "ok" : "bad");
    txt.innerHTML = m.last_poll_ts ? `fw1 polled ${esc(rel(m.last_poll_ts))} · ${esc(m.last_raw.replace("arp", "ARP entries"))}` : "no poll yet";
    for (const [key, label] of [["switch", m.switch?.name || "switch"], ["unifi", "Wi-Fi"]]) {
      const s = m[key]; if (!s || !s.enabled) continue;
      txt.insertAdjacentHTML("beforeend", `<span class="src" title="${esc(s.ok ? `${label}: OK` : `${label}: ${s.error}`)}"><span class="dot ${s.ok ? "ok" : "bad"}"></span>${esc(label)}</span>`);
    }
    $("#status").title = m.last_error ? `Last error: ${m.last_error}` : `Polls every ${m.poll_seconds}s`;
    if (!m.last_poll_ok && m.last_error) showBanner(`Collector cannot read fw1: ${m.last_error} (last good data ${rel(m.last_poll_ts)})`);
    else if (stale) showBanner(`Data is stale: last successful poll ${rel(m.last_poll_ts)}.`);
    else showBanner("");
    $("#newDays").textContent = m.new_days;
  }

  function renderCards() {
    const s = state.stats; if (!s) return;
    $("#cTotal").textContent = s.total; $("#cOnline").textContent = s.online; $("#cNew").textContent = s.new; $("#cUnacked").textContent = s.unacked;
    $$(".card[data-filter]").forEach(c => { const on = c.dataset.filter === state.status && state.status !== "all"; c.classList.toggle("active", on); c.setAttribute("aria-pressed", on); });
    const bars = $("#bars"); bars.innerHTML = "";
    const dayKey = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    const perDay = {}; for (const t of s.new_recent || []) { const k = dayKey(new Date(t * 1000)); perDay[k] = (perDay[k] || 0) + 1; }
    const days = []; const today = new Date(); today.setHours(0, 0, 0, 0);
    let max = 1;
    for (let i = 29; i >= 0; i--) { const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - i); const k = dayKey(d); const n = perDay[k] || 0; max = Math.max(max, n); days.push([k, n]); }
    for (const [k, n] of days) { const b = document.createElement("span"); b.style.height = n ? `${Math.max(18, Math.round(n / max * 100))}%` : "2px"; b.title = `${k}: ${n} new`; if (n) b.classList.add("has"); bars.appendChild(b); }
    $("#barsSum").textContent = `${days.reduce((a, [, n]) => a + n, 0)} in 30 d`;
  }

  function renderVlans() {
    const box = $("#vlans"); box.innerHTML = "";
    for (const v of state.stats.vlans) {
      const c = document.createElement("button"); c.className = "chip" + (state.vlan === v.vlan ? " active" : "");
      c.setAttribute("aria-pressed", state.vlan === v.vlan);
      c.innerHTML = `<span class="sw" style="background:${vlanColor(v.vlan)}"></span>${esc(v.vlan || "?")} <span class="n">${v.online}/${v.n}</span>`;
      c.title = `${v.online} online of ${v.n} devices`;
      c.onclick = () => { state.vlan = state.vlan === v.vlan ? "" : v.vlan; renderVlans(); renderTable(); syncUrl(); };
      box.appendChild(c);
    }
  }

  function filtered() {
    const q = state.q.trim().toLowerCase();
    const list = state.devices.filter(d => {
      if (state.vlan && d.vlan !== state.vlan) return false;
      switch (state.status) {
        case "new": if (!isNew(d)) return false; break;
        case "unacked": if (d.acked || d.baseline) return false; break;
        case "online": if (!d.online) return false; break;
        case "offline": if (d.online) return false; break;
        case "dynamic": if (d.lease_type !== "dynamic") return false; break;
        case "static": if (d.lease_type !== "static") return false; break;
        case "arp": if (d.lease_type) return false; break;
        case "wifi": if (!d.wifi_ssid) return false; break;
        case "wired": if (d.wifi_ssid || (d.link !== "wired" && !d.sw_port)) return false; break;
      }
      if (q) {
        const hay = `${d.name} ${d.hostname} ${d.ip} ${d.mac} ${d.vendor} ${d.vlan} ${d.note} ${whereText(d)} ${d.wifi_alias}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    const byVlanIp = (a, b) => (a.vlan || "").localeCompare(b.vlan || "") || ipKey(a.ip).localeCompare(ipKey(b.ip));
    const cmp = {
      // real newcomers first (newest on top), then the baseline devices grouped by network and address
      first_desc: (a, b) => (a.baseline - b.baseline) || (a.baseline ? byVlanIp(a, b) : (b.first_seen - a.first_seen) || byVlanIp(a, b)),
      last_desc: (a, b) => (b.online - a.online) || ((b.last_online || 0) - (a.last_online || 0)) || byVlanIp(a, b),
      name: (a, b) => label(a).localeCompare(label(b), undefined, { sensitivity: "base" }) || byVlanIp(a, b),
      ip: (a, b) => ipKey(a.ip).localeCompare(ipKey(b.ip)),
      vlan: byVlanIp,
      vendor: (a, b) => (a.vendor || "~").localeCompare(b.vendor || "~") || label(a).localeCompare(label(b)),
    }[state.sort] || byVlanIp;
    return list.sort(cmp);
  }

  function renderTable() {
    const list = filtered();
    const tb = $("#rows"); tb.innerHTML = "";
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
      nm.classList.toggle("unnamed", !d.name && !d.hostname);
      if (fresh) nm.insertAdjacentHTML("beforeend", '<span class="badge new">NEW</span>');
      else if (!d.acked && !d.baseline) nm.insertAdjacentHTML("beforeend", '<span class="badge base">not yet known</span>');
      const sub = [];
      if (d.name && d.hostname) sub.push(`<span class="host">${esc(d.hostname)}</span>`);
      if (d.vendor && d.vendor !== lbl) sub.push(esc(d.vendor));
      if (!sub.length && !d.name && !d.hostname) sub.push(`<span class="host">${esc(d.mac)}</span>`);
      $(".dev-sub", tr).innerHTML = sub.join(" · ");
      $(".dev-meta .ip", tr).textContent = d.ip || "–";
      const vm = $(".dev-meta .badge", tr); vm.textContent = d.vlan || "?"; vm.style.setProperty("--vc", vlanColor(d.vlan));
      $(".dev-meta .last", tr).textContent = d.online ? "online" : (d.last_online ? `last ${rel(d.last_online)}` : "offline");
      $(".dev-meta .where", tr).textContent = d.wifi_ssid ? `${d.wifi_ssid} @ ${d.wifi_ap || "?"}` : d.sw_port ? `${d.sw_port}${d.sw_via ? " → " + d.sw_via : ""}` : "";
      $(".c-where", tr).innerHTML = whereHtml(d, false);
      $(".c-ip", tr).textContent = d.ip || "–";
      const mac = $(".c-mac", tr); mac.textContent = d.mac;
      const vb = $(".c-vlan .badge", tr); vb.textContent = d.vlan || "?"; vb.style.setProperty("--vc", vlanColor(d.vlan));
      $(".c-type", tr).textContent = typeText(d);
      const fs = $(".c-first", tr); fs.textContent = d.baseline ? "since the start" : rel(d.first_seen); fs.title = d.baseline ? `Already present when leasewatch started (${abs(state.meta.baseline_ts)})` : abs(d.first_seen);
      if (isNew(d)) fs.classList.add("recent");
      const ls = $(".c-last", tr); ls.textContent = d.online ? "now" : (d.last_online ? rel(d.last_online) : "not since the start"); ls.title = d.last_online ? `last online ${abs(d.last_online)} · last listed by fw1 ${abs(d.last_seen)}` : `listed by fw1 but not seen on the wire since leasewatch started; last listed ${abs(d.last_seen)}`;
      const ack = $(".ack", tr);
      if (d.acked || d.baseline) ack.remove();
      else ack.onclick = ev => { ev.stopPropagation(); setFields(d.mac, { acked: true }); };
      tr.onclick = () => openDrawer(d.mac);
      tr.onkeydown = ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); openDrawer(d.mac); } };
      mac.onclick = ev => {
        ev.stopPropagation();
        navigator.clipboard?.writeText(d.mac).then(() => { mac.classList.add("copied"); mac.title = "copied"; setTimeout(() => { mac.classList.remove("copied"); mac.title = "click to copy"; }, 900); });
      };
      frag.appendChild(tr);
    }
    tb.appendChild(frag);
    $("#count").textContent = `${list.length} of ${state.devices.length}`;
    $("#empty").classList.toggle("hidden", list.length > 0);
    $("#emptyText").textContent = state.q || state.vlan ? "Nothing matches." : state.status === "unacked" ? "Every device is known." : state.status === "new" ? `No new devices in the last ${state.meta?.new_days ?? 7} days.` : "Nothing matches.";
    $("#emptyClear").classList.toggle("hidden", !(state.q || state.vlan || state.status !== "all"));
  }

  function renderEvents() {
    const ul = $("#events"); ul.innerHTML = "";
    if (!state.events.length) { ul.innerHTML = '<li><span class="t">–</span><span></span><span class="muted">No events yet. New devices, address changes and acknowledgements show up here.</span></li>'; return; }
    for (const e of state.events.slice(0, 60)) {
      const li = document.createElement("li");
      const who = e.name || e.hostname || e.mac;
      let detail = String(e.detail || "").replace(" -> ", " → ");
      if (e.kind === "new") detail = detail.replace(/\s*\([^)]*\)$/, "").split(" ").filter(w => w && w !== who).join(" ");
      li.innerHTML = `<span class="t" title="${abs(e.ts)}">${esc(abs(e.ts))}</span><span class="k ${esc(e.kind)}">${esc(kindText(e.kind))}</span><span><button class="who" data-mac="${esc(e.mac)}">${esc(who)}</button> <span class="muted">${esc(detail)}</span>${e.vlan ? ` <span class="badge vlan" style="--vc:${vlanColor(e.vlan)}">${esc(e.vlan)}</span>` : ""}</span>`;
      $(".who", li).onclick = () => openDrawer(e.mac);
      ul.appendChild(li);
    }
  }
  const kindText = k => ({ new: "new device", ip: "new IP", hostname: "hostname", vlan: "moved network", lease_type: "lease type", back: "back online", acked: "marked known", unacked: "marked unknown", port: "moved port", wifi: "moved Wi-Fi" }[k] || k);

  // ---------- drawer ----------
  async function openDrawer(mac) {
    state.open = mac; state.returnTo = document.activeElement;
    $("#drawer").classList.add("open"); $("#scrim").classList.add("show"); $("#drawer").setAttribute("aria-hidden", "false");
    await refreshDrawer(mac, true);
  }
  function closeDrawer() {
    if (!state.open) return;
    state.open = null; $("#drawer").classList.remove("open"); $("#scrim").classList.remove("show"); $("#drawer").setAttribute("aria-hidden", "true");
    state.returnTo?.focus?.();
  }

  async function refreshDrawer(mac, focus) {
    let r; try { r = await api(`/api/devices/${mac}`); } catch (e) { if (state.open === mac) $("#dBody").innerHTML = `<p>${esc(e.message)}</p>`; return; }
    if (state.open !== mac) return; // another device was opened while this one loaded
    const d = r.device;
    $("#dTitle").textContent = label(d);
    const b = $("#dBody");
    const nameVal = $("#fName", b)?.value, noteVal = $("#fNote", b)?.value, dirty = $("#fName", b) && (nameVal !== d.name || noteVal !== d.note);
    if (dirty && !focus) return; // don't clobber an edit in progress
    b.innerHTML = `
      <dl class="kv">
        <dt>Status</dt><dd><span class="online-dot ${d.online ? "on" : ""}"></span> ${d.online ? "online" : (d.last_online ? `offline · last online ${esc(rel(d.last_online))}` : "offline · not seen online since leasewatch started")}</dd>
        <dt>IP</dt><dd class="mono">${esc(d.ip || "–")}</dd>
        <dt>MAC</dt><dd class="mono">${esc(d.mac)}</dd>
        <dt>Hostname</dt><dd>${esc(d.hostname || "–")}</dd>
        <dt>Vendor</dt><dd>${esc(d.vendor || "unknown")}</dd>
        <dt>Network</dt><dd><span class="badge vlan" style="--vc:${vlanColor(d.vlan)}">${esc(d.vlan || "?")}</span> <span class="muted" title="fw1 interface">${esc(d.iface)}</span></dd>
        <dt>Type</dt><dd>${esc(typeText(d))} <span class="muted">· seen in ${esc(sourcesText(d.sources))}</span></dd>
        ${whereHtml(d, true) ? `<dt>Connected via</dt><dd>${whereHtml(d, true)}</dd>` : ""}${d.wifi_alias ? `<dt>UniFi name</dt><dd>${esc(d.wifi_alias)}</dd>` : ""}
        <dt>First seen</dt><dd>${d.baseline ? `since the start (${esc(abs(state.meta.baseline_ts))})` : esc(abs(d.first_seen))}${isNew(d) ? ' <span class="badge new">NEW</span>' : ""}</dd>
        <dt>Last online</dt><dd>${d.last_online ? esc(abs(d.last_online)) : "never"} <span class="muted">· last listed by fw1 ${esc(abs(d.last_seen))}</span></dd>
        <dt>Known</dt><dd>${d.acked ? `yes, marked ${esc(abs(d.acked_at))}` : "not yet"}</dd>
      </dl>
      <div class="form">
        <label>Name (what this device is)<input id="fName" maxlength="80" value="${esc(d.name)}" placeholder="e.g. Alex's iPad"></label>
        <label>Note<textarea id="fNote" rows="2" maxlength="1000" placeholder="where it lives, who owns it, anything useful">${esc(d.note)}</textarea></label>
        <div class="actions">
          <button class="btn ${d.acked ? "primary" : ""}" id="fSave">Save</button>
          <button class="btn ${d.acked ? "" : "primary"}" id="fAck">${d.acked ? "Mark unknown" : "Save & mark known"}</button>
          <span class="saved" id="fSaved"></span>
        </div>
      </div>
      <h3>History</h3>
      <ul class="tl">${r.history.map(h => `<li><span class="t">${esc(abs(h.ts))}</span><span class="mono">${esc(h.ip)}</span> ${esc(h.hostname || "")} <span class="badge vlan" style="--vc:${vlanColor(h.vlan)}">${esc(h.vlan)}</span> <span class="muted">${esc(h.lease_type)}</span></li>`).join("") || '<li class="none">No changes recorded</li>'}</ul>
      <h3>Events</h3>
      <ul class="tl">${r.events.map(e => `<li><span class="t">${esc(abs(e.ts))}</span><span class="k ${esc(e.kind)}">${esc(kindText(e.kind))}</span> <span class="muted">${esc(String(e.detail || "").replace(" -> ", " → "))}</span></li>`).join("") || '<li class="none">No events</li>'}</ul>`;
    $("#fSave").onclick = () => setFields(d.mac, { name: $("#fName").value, note: $("#fNote").value }, true);
    $("#fAck").onclick = () => setFields(d.mac, { acked: !d.acked, name: $("#fName").value, note: $("#fNote").value }, true);
    if (focus) $("#fName").focus();
  }

  async function setFields(mac, fields, fromDrawer) {
    try {
      await api(`/api/devices/${mac}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(fields) });
      await load();
      if (fromDrawer && state.open === mac) { await refreshDrawer(mac, true); const s = $("#fSaved"); if (s) { s.textContent = "saved"; setTimeout(() => { if (s.isConnected) s.textContent = ""; }, 1500); } }
    } catch (e) { showBanner(`Save failed: ${e.message}`); }
  }

  // ---------- url state ----------
  function syncUrl() {
    const p = new URLSearchParams();
    if (state.q) p.set("q", state.q); if (state.status !== "all") p.set("filter", state.status); if (state.vlan) p.set("vlan", state.vlan); if (state.sort !== "first_desc") p.set("sort", state.sort);
    history.replaceState(null, "", p.toString() ? `?${p}` : location.pathname);
  }
  function readUrl() {
    const p = new URLSearchParams(location.search);
    state.q = p.get("q") || ""; state.status = p.get("filter") || "all"; state.vlan = p.get("vlan") || ""; state.sort = p.get("sort") || "first_desc";
    $("#q").value = state.q; $("#fStatus").value = state.status; $("#sort").value = state.sort;
    if (!$("#fStatus").value) { state.status = "all"; $("#fStatus").value = "all"; }
    if (!$("#sort").value) { state.sort = "first_desc"; $("#sort").value = "first_desc"; }
  }
  function clearFilters() { state.q = ""; state.vlan = ""; state.status = "all"; $("#q").value = ""; $("#fStatus").value = "all"; renderCards(); renderVlans(); renderTable(); syncUrl(); }

  // ---------- wiring ----------
  $("#q").addEventListener("input", e => { state.q = e.target.value; renderTable(); syncUrl(); });
  $("#fStatus").addEventListener("change", e => { state.status = e.target.value; renderCards(); renderTable(); syncUrl(); });
  $("#sort").addEventListener("change", e => { state.sort = e.target.value; renderTable(); syncUrl(); });
  $$(".card[data-filter]").forEach(c => c.onclick = () => { state.status = state.status === c.dataset.filter ? "all" : c.dataset.filter; $("#fStatus").value = state.status; renderCards(); renderTable(); syncUrl(); });
  $("#emptyClear").onclick = clearFilters;
  $("#dClose").onclick = closeDrawer; $("#scrim").onclick = closeDrawer;
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && document.activeElement === $("#q") && state.q) { state.q = ""; $("#q").value = ""; renderTable(); syncUrl(); return; }
    if (e.key === "Escape") closeDrawer();
    if (e.key === "/" && !/input|textarea|select/i.test(document.activeElement.tagName)) { e.preventDefault(); $("#q").focus(); $("#q").select(); }
  });
  const store = { get: k => { try { return localStorage.getItem(k); } catch (_) { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch (_) {} } };
  const theme = store.get("theme"); if (theme) document.documentElement.dataset.theme = theme;
  $("#themeBtn").onclick = () => { const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); const next = cur === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = next; store.set("theme", next); };

  readUrl(); load();
  setInterval(load, 60000);
  setInterval(() => { if (state.meta && !state.apiDown) renderStatus(); }, 15000);
})();
