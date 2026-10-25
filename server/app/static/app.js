(() => {
  "use strict";
  const { el, icon, hostIcon, badge, chip, progress, checkbox, button, segmented, select, gauge, dialog, confirmDialog, toast } = window.UI;
  const T = (k, p) => window.I18N.t(k, p);
  const root = document.getElementById("root");

  // --- состояние --------------------------------------------------------------------------------
  let me = null;
  let hosts = [];
  let timer = null;
  let routeToken = 0;
  const selected = new Set();
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (_) { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) { /* не критично */ } },
  };
  const prefs = Object.assign({ view: "tiles", filter: "all", sort: "status", q: "" }, store.get("hd_prefs", {}));
  const savePrefs = () => store.set("hd_prefs", prefs);
  let theme = store.get("hd_theme", "auto");

  function applyTheme() {
    if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
    else document.documentElement.removeAttribute("data-theme");
  }
  applyTheme();

  // --- сеть --------------------------------------------------------------------------------------
  async function api(path, opts = {}) {
    const o = { credentials: "same-origin", ...opts };
    if (o.body && typeof o.body !== "string") {
      o.body = JSON.stringify(o.body);
      o.headers = { "Content-Type": "application/json", ...(o.headers || {}) };
    }
    let r;
    try { r = await fetch(path, o); } catch (_) { throw new Error(T("err.network")); }
    let data = null;
    try { data = await r.json(); } catch (_) { /* пустой ответ */ }
    if (r.status === 401 && path !== "/api/login" && path !== "/api/me") { me = null; renderAll(); throw new Error("auth"); }
    if (!r.ok) throw new Error((data && data.error) || "HTTP " + r.status);
    return data;
  }
  function fail(e) { if (e && e.message !== "auth") toast(T("err.generic", { m: e.message }), "error"); }

  // --- форматирование -------------------------------------------------------------------------------
  const loc = () => (window.I18N.lang === "ru" ? "ru-RU" : "en-GB");
  function ago(ts) {
    if (!ts) return T("common.never");
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return T("common.now");
    const rtf = new Intl.RelativeTimeFormat(loc(), { numeric: "auto" });
    if (s < 3600) return rtf.format(-Math.floor(s / 60), "minute");
    if (s < 86400) return rtf.format(-Math.floor(s / 3600), "hour");
    return rtf.format(-Math.floor(s / 86400), "day");
  }
  const fmtDate = (ts) => (ts ? new Date(ts * 1000).toLocaleString(loc(), { dateStyle: "medium", timeStyle: "short" }) : "—");
  function fmtUptime(bootStr) {
    const b = Number(bootStr);
    if (!b) return "";
    const sec = Math.max(0, Date.now() / 1000 - b);
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    const ru = window.I18N.lang === "ru";
    if (d > 0) return ru ? `${d} д ${h} ч` : `${d}d ${h}h`;
    if (h > 0) return ru ? `${h} ч ${m} мин` : `${h}h ${m}m`;
    return ru ? `${m} мин` : `${m}m`;
  }
  const gb = (bytes) => (bytes / 2 ** 30).toFixed(bytes / 2 ** 30 >= 100 ? 0 : 1);
  const SEV = { fail: 0, warn: 1, unknown: 2, ok: 3, info: 4 };

  const osLine = (i) => (i.os === "linux" ? i.os_version || "Linux" : [i.os, i.os_version].filter(Boolean).join(" "));
  function metricsOf(h) {
    const m = h.metrics;
    const fresh = !!m && h.online && Date.now() / 1000 - (h.metrics_at || 0) < 180;
    const diskCheck = (h.checks || []).find((c) => c.id === "disk");
    return {
      fresh, m,
      cpu: m ? m.cpu : null,
      mem: m && m.mem_total ? (m.mem_used / m.mem_total) * 100 : null,
      disk: m ? m.disk_pct : diskCheck ? diskCheck.num : null,
    };
  }

  // --- проверки: подписи и значения ------------------------------------------------------------------------
  const CHECK_ICON = { filevault: "lock", sip: "shield", gatekeeper: "shield", firewall: "flame", stealth: "eye", auto_check: "refresh",
    auto_critical: "refresh", updates: "download", screenlock: "lock", ssh: "key", mdm: "sliders", disk: "disk", platform: "info" };
  const checkLabel = (id) => (window.I18N.has("check." + id) ? T("check." + id) : id);
  function checkValue(c) {
    const v = c.value || "";
    if (v.startsWith("after:")) return T("val.after", { n: v.slice(6) });
    if (v === "used") return T("val.used", { n: Math.round(c.num || 0) });
    if (v === "available") return T("val.available", { n: c.num });
    if (v === "none") return T("val.none") + (c.num ? ` (${T("val.checked", { t: ago(c.num) })})` : "");
    if (v && window.I18N.has("val." + v)) return T("val." + v);
    return v || (c.status === "unknown" ? T("status.unknown") : "");
  }
  function checkDetail(c) {
    if (c.id === "disk" && c.detail) return T("val.free", { n: c.detail });
    return c.detail || "";
  }

  // --- CSV ----------------------------------------------------------------------------------------------------
  function csvCell(v) {
    let s = v == null ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // защита от формул при открытии в Excel/Numbers
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function downloadCsv(name, rows) {
    const text = "﻿" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
    const url = URL.createObjectURL(new Blob([text], { type: "text/csv;charset=utf-8" }));
    const a = el("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast(T("csv.exported", { f: name }));
  }
  const stamp = () => new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const safeName = (s) => String(s).replace(/[^\w.-]+/g, "_").slice(0, 60) || "host";

  function exportFleet(list) {
    const rows = [[T("hosts.col.name"), T("hosts.col.status"), T("status.online"), T("info.os"), T("info.os_version"), T("info.model"), T("info.chip"), T("info.memory"),
      T("hosts.col.cpu") + " %", T("hosts.col.mem") + " %", T("hosts.col.disk") + " %", T("status.ok"), T("status.warn"), T("status.fail"),
      T("host.tab.software"), T("hosts.col.seen"), T("info.agent")]];
    for (const h of list) {
      const x = metricsOf(h), i = h.info || {};
      const r = (n) => (n == null ? "" : Math.round(n));
      rows.push([h.name, T("status." + h.status), h.online ? T("common.yes") : T("common.no"), i.os, i.os_version, i.model, i.chip, i.memory,
        r(x.cpu), r(x.mem), r(x.disk), h.counts.ok, h.counts.warn, h.counts.fail, h.software_count == null ? "" : h.software_count,
        h.last_seen ? new Date(h.last_seen * 1000).toISOString() : "", h.agent_version]);
    }
    downloadCsv(`hostdeck-hosts-${stamp()}.csv`, rows);
  }

  async function exportHost(h, software) {
    let sw = software;
    if (!sw) { try { sw = (await api(`/api/hosts/${h.id}/software`)).items; } catch (e) { fail(e); return; } }
    const rows = [[T("csv.section"), T("csv.key"), T("csv.value"), T("csv.status"), T("csv.detail")]];
    const sec = (k) => T("csv.sec." + k);
    const i = h.info || {};
    rows.push([sec("host"), T("hosts.col.name"), h.name, "", ""]);
    rows.push([sec("host"), T("hosts.col.status"), T("status." + h.status), h.online ? T("status.online") : T("status.offline"), fmtDate(h.last_seen)]);
    for (const k of ["os", "os_version", "build", "model", "chip", "memory", "arch", "hostname", "console_user", "agent"]) if (i[k]) rows.push([sec("host"), T("info." + k), i[k], "", ""]);
    if (i.boot_time) rows.push([sec("host"), T("info.boot_time"), new Date(Number(i.boot_time) * 1000).toISOString(), "", ""]);
    for (const c of (h.checks || [])) rows.push([sec("check"), checkLabel(c.id), checkValue(c), T("status." + c.status), checkDetail(c)]);
    for (const s of sw) rows.push([sec("software"), s.n, s.v, T("sw.src." + s.s), s.p]);
    downloadCsv(`hostdeck-${safeName(h.name)}-${stamp()}.csv`, rows);
  }

  // --- оболочка: шапка ----------------------------------------------------------------------------------------------
  function topbar(route) {
    const nav = (href, key, ic, active) => el("a", { href, class: "nav-item" + (active ? " active" : ""), "aria-current": active ? "page" : null }, icon(ic, 17), el("span", {}, T(key)));
    return el("header", { class: "topbar" },
      el("a", { class: "brand", href: "#/" }, el("img", { class: "logo-img", src: "/static/logo.svg", alt: "", width: 32, height: 32 }), el("span", {}, "HostDeck")),
      el("nav", { class: "nav", "aria-label": T("top.menu") },
        nav("#/", "nav.home", "home", route.name === "home"),
        nav("#/hosts", "nav.hosts", "grid", route.name === "hosts" || route.name === "host"),
        me && me.role === "admin" ? nav("#/audit", "nav.audit", "book", route.name === "audit") : null),
      el("span", { class: "spacer" }),
      segmented([
        { value: "auto", icon: "auto", label: T("top.theme.auto") },
        { value: "light", icon: "sun", label: T("top.theme.light") },
        { value: "dark", icon: "moon", label: T("top.theme.dark") },
      ], theme, (v) => { theme = v; store.set("hd_theme", v); applyTheme(); }, T("top.theme")),
      select([{ value: "ru", label: "Русский" }, { value: "en", label: "English" }], window.I18N.lang,
        (v) => { window.I18N.setLang(v); renderAll(); }, { icon: "globe", label: T("top.lang"), cls: "lang" }),
      me ? el("span", { class: "who", title: me.role }, icon("key", 15), el("span", {}, me.name)) : null,
      me ? button("", { icon: "logout", title: T("top.logout"), kind: "ghost", onclick: async () => { try { await api("/api/logout", { method: "POST", body: {} }); } catch (_) { /* уже вышли */ } me = null; renderAll(); } }) : null);
  }

  // --- вход -----------------------------------------------------------------------------------------------------------
  function loginView() {
    const err = el("div", { class: "form-error", role: "alert" });
    const name = el("input", { id: "u", class: "input", autocomplete: "username", required: true, placeholder: T("login.name"), "aria-label": T("login.name") });
    const pw = el("input", { id: "p", class: "input", type: "password", autocomplete: "current-password", required: true, placeholder: T("login.password"), "aria-label": T("login.password") });
    const form = el("form", { class: "login-card", onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      try {
        me = await api("/api/login", { method: "POST", body: { name: name.value, password: pw.value } });
        location.hash = location.hash && location.hash !== "#/login" ? location.hash : "#/";
        renderAll();
      } catch (ex) { err.textContent = ex.message; }
    } },
      el("img", { class: "logo-img big", src: "/static/logo.svg", alt: "HostDeck", width: 76, height: 76 }),
      el("h1", {}, T("login.title")), el("p", { class: "muted" }, T("login.sub")),
      name, pw, err, button(T("login.submit"), { type: "submit", kind: "primary wide" }));
    setTimeout(() => name.focus(), 30);
    return el("main", { class: "login-wrap" }, form);
  }

  // --- обзор ------------------------------------------------------------------------------------------------------------
  function stat(ic, value, label, tone) {
    return el("div", { class: "stat t-" + tone }, el("span", { class: "stat-ico" }, icon(ic, 20)), el("div", {}, el("div", { class: "stat-n" }, value), el("div", { class: "stat-l" }, label)));
  }
  function homeView() {
    const c = { hosts: hosts.length, online: hosts.filter((h) => h.online).length, fail: hosts.filter((h) => h.status === "fail").length, warn: hosts.filter((h) => h.status === "warn").length };
    const how = [["cpu", 1], ["refresh", 2], ["grid", 3]].map(([ic, n]) =>
      el("div", { class: "card how" }, el("span", { class: "how-ico" }, icon(ic, 22)), el("h3", {}, T(`home.how.${n}.t`)), el("p", { class: "muted" }, T(`home.how.${n}.d`))));
    const link = (href, ic, k, onclick) => el("a", { class: "card link-card", href, onclick }, el("span", { class: "how-ico" }, icon(ic, 20)),
      el("div", {}, el("div", { class: "link-t" }, T(k)), el("div", { class: "muted small" }, T(k + ".d"))), icon("chevron", 16, "go"));
    return el("main", { class: "page" },
      el("section", { class: "hero" },
        el("h1", {}, T("home.title")), el("p", { class: "lead" }, T("home.lead")),
        el("div", { class: "hero-cta" }, button(T("home.cta.hosts"), { kind: "primary", onclick: () => { location.hash = "#/hosts"; } }),
          me.role === "admin" ? button(T("home.cta.add"), { icon: "plus", onclick: addHostDialog }) : null)),
      el("section", { class: "stats" }, stat("server", c.hosts, T("home.stat.hosts"), "neutral"), stat("check", c.online, T("home.stat.online"), "ok"),
        stat("alert", c.warn, T("home.stat.warn"), "warn"), stat("x", c.fail, T("home.stat.problems"), "fail")),
      el("h2", { class: "sec" }, T("home.how.title")), el("section", { class: "grid3" }, how),
      el("section", { class: "split" },
        el("div", { class: "card" }, el("h2", { class: "sec in" }, T("home.start.title")),
          el("ol", { class: "steps" }, [1, 2, 3].map((n) => el("li", {}, el("span", { class: "step-n" }, n), el("span", {}, T("home.start." + n)))))),
        el("div", { class: "card" }, el("h2", { class: "sec in" }, T("home.legend.title")),
          el("div", { class: "legend" }, ["ok", "warn", "fail", "unknown"].map((s) => el("div", { class: "legend-row" }, badge(s, T("status." + s)),
            el("span", { class: "muted small" }, T("home.legend." + s))))))),
      el("h2", { class: "sec" }, T("home.links.title")),
      el("section", { class: "grid2" },
        link("#/hosts", "grid", "home.links.hosts"),
        me.role === "admin" ? link("#/hosts", "plus", "home.links.add", (e) => { e.preventDefault(); location.hash = "#/hosts"; addHostDialog(); }) : null,
        me.role === "admin" ? link("#/audit", "book", "home.links.audit") : null));
  }

  // --- список хостов ------------------------------------------------------------------------------------------------------------
  function visibleHosts() {
    const q = prefs.q.trim().toLowerCase();
    let list = hosts.filter((h) => {
      const i = h.info || {};
      if (q && !`${h.name} ${i.model || ""} ${i.os || ""} ${i.os_version || ""} ${i.chip || ""}`.toLowerCase().includes(q)) return false;
      switch (prefs.filter) {
        case "problems": return h.status === "fail";
        case "warn": return h.status === "warn";
        case "ok": return h.status === "ok";
        case "offline": return !h.online;
        default: return true;
      }
    });
    const cmp = {
      name: (a, b) => a.name.localeCompare(b.name, loc()),
      status: (a, b) => (SEV[a.status] ?? 9) - (SEV[b.status] ?? 9) || a.name.localeCompare(b.name, loc()),
      seen: (a, b) => (b.last_seen || 0) - (a.last_seen || 0),
    }[prefs.sort] || (() => 0);
    return list.sort(cmp);
  }

  function hostCard(h) {
    const x = metricsOf(h), i = h.info || {};
    const pct = (v) => (v == null ? "—" : Math.round(v) + "%");
    const cb = checkbox({ label: h.name, checked: selected.has(h.id), onchange: (on) => { on ? selected.add(h.id) : selected.delete(h.id); drawBulk(); card.classList.toggle("sel", on); } });
    const card = el("article", { class: "card host-card" + (selected.has(h.id) ? " sel" : "") + (h.online ? "" : " off"), tabindex: "0", role: "link", "aria-label": h.name,
      onclick: (e) => { if (!e.target.closest(".cb")) location.hash = "#/host/" + h.id; },
      onkeydown: (e) => { if (e.key === "Enter" && e.target === card) location.hash = "#/host/" + h.id; } },
      el("div", { class: "hc-top" }, el("label", { class: "cb-wrap" }, cb), el("span", { class: "avatar" }, icon(hostIcon(h), 24)),
        el("div", { class: "hc-title" }, el("h3", {}, h.name), el("div", { class: "muted small" }, [i.model, osLine(i)].filter(Boolean).join(" · "))),
        badge(h.status, T("status." + h.status))),
      el("div", { class: "chips" }, i.chip ? chip("cpu", i.chip) : null, i.memory ? chip("memory", i.memory) : null, chip(h.online ? "check" : "x", h.online ? T("status.online") : T("status.offline"), h.online ? "c-ok" : "c-off")),
      el("div", { class: "bars" },
        progress(x.cpu, { label: T("card.cpu"), text: pct(x.cpu) }), progress(x.mem, { label: T("card.mem"), text: pct(x.mem) }), progress(x.disk, { label: T("card.disk"), text: pct(x.disk) })),
      el("div", { class: "hc-foot muted small" }, el("span", {}, icon("clock", 14), " ", T("card.seen", { t: ago(h.last_seen) })),
        el("span", {}, T("card.checks", { ok: h.counts.ok, all: h.counts.ok + h.counts.warn + h.counts.fail + h.counts.unknown }))));
    return card;
  }

  function hostTable(list) {
    const all = checkbox({ label: T("hosts.selectall"), checked: list.length > 0 && list.every((h) => selected.has(h.id)), onchange: (on) => { list.forEach((h) => (on ? selected.add(h.id) : selected.delete(h.id))); drawHosts(); } });
    const pct = (v) => (v == null ? null : v);
    const rows = list.map((h) => {
      const x = metricsOf(h), i = h.info || {};
      const cb = checkbox({ label: h.name, checked: selected.has(h.id), onchange: (on) => { on ? selected.add(h.id) : selected.delete(h.id); drawBulk(); tr.classList.toggle("sel", on); } });
      const tr = el("tr", { class: (selected.has(h.id) ? "sel " : "") + (h.online ? "" : "off"), tabindex: "0",
        onclick: (e) => { if (!e.target.closest(".cb")) location.hash = "#/host/" + h.id; },
        onkeydown: (e) => { if (e.key === "Enter" && e.target === tr) location.hash = "#/host/" + h.id; } },
        el("td", { class: "c-cb" }, cb),
        el("td", {}, el("div", { class: "cell-host" }, el("span", { class: "avatar sm" }, icon(hostIcon(h), 18)),
          el("div", {}, el("div", { class: "strong" }, h.name), el("div", { class: "muted small" }, i.model || i.chip || "")))),
        el("td", {}, badge(h.status, T("status." + h.status))),
        el("td", { class: "hide-m" }, osLine(i)),
        el("td", { class: "hide-s" }, progress(pct(x.cpu), { text: x.cpu == null ? "—" : Math.round(x.cpu) + "%" })),
        el("td", { class: "hide-s" }, progress(pct(x.mem), { text: x.mem == null ? "—" : Math.round(x.mem) + "%" })),
        el("td", { class: "hide-s" }, progress(pct(x.disk), { text: x.disk == null ? "—" : Math.round(x.disk) + "%" })),
        el("td", { class: "muted small nowrap" }, el("span", { class: "dot " + (h.online ? "on" : "off") }), ago(h.last_seen)));
      return tr;
    });
    return el("div", { class: "card table-card" }, el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, el("th", { class: "c-cb" }, all), el("th", {}, T("hosts.col.name")), el("th", {}, T("hosts.col.status")), el("th", { class: "hide-m" }, T("hosts.col.os")),
        el("th", { class: "hide-s" }, T("hosts.col.cpu")), el("th", { class: "hide-s" }, T("hosts.col.mem")), el("th", { class: "hide-s" }, T("hosts.col.disk")), el("th", {}, T("hosts.col.seen")))),
      el("tbody", {}, rows)));
  }

  let hostsBox = null, bulkBox = null;
  function drawBulk() {
    if (!bulkBox) return;
    const n = [...selected].filter((id) => hosts.some((h) => h.id === id)).length;
    bulkBox.replaceChildren(...(n > 0 ? [el("div", { class: "bulk" }, el("span", { class: "bulk-n" }, T("hosts.selected", { n })),
      me.role !== "viewer" ? button(T("hosts.refresh.sel"), { icon: "refresh", onclick: bulkRefresh }) : null,
      button(T("hosts.export.sel"), { icon: "download", onclick: () => exportFleet(hosts.filter((h) => selected.has(h.id))) }),
      button("", { icon: "x", kind: "ghost", title: T("common.cancel"), onclick: () => { selected.clear(); drawHosts(); } }))] : []));
  }
  async function bulkRefresh() {
    const ids = [...selected];
    let ok = 0;
    for (const id of ids) { try { await api(`/api/hosts/${id}/refresh`, { method: "POST", body: {} }); ok++; } catch (e) { fail(e); } }
    toast(T("hosts.refresh.queued", { n: ok }));
  }
  function drawHosts() {
    if (!hostsBox) return;
    const list = visibleHosts();
    drawBulk();
    if (!hosts.length) {
      hostsBox.replaceChildren(el("div", { class: "empty" }, icon("server", 40), el("h3", {}, T("hosts.empty")), el("p", { class: "muted" }, T("hosts.empty.d")),
        me.role === "admin" ? button(T("hosts.add"), { icon: "plus", kind: "primary", onclick: addHostDialog }) : null));
    } else if (!list.length) {
      hostsBox.replaceChildren(el("div", { class: "empty" }, icon("search", 40), el("h3", {}, T("hosts.nomatch")), el("p", { class: "muted" }, T("hosts.nomatch.d"))));
    } else if (prefs.view === "list") {
      hostsBox.replaceChildren(hostTable(list));
    } else {
      hostsBox.replaceChildren(el("div", { class: "tiles" }, list.map(hostCard)));
    }
  }
  function hostsView() {
    const search = el("input", { class: "input search", type: "search", placeholder: T("hosts.search"), "aria-label": T("common.search"), value: prefs.q });
    search.addEventListener("input", () => { prefs.q = search.value; savePrefs(); drawHosts(); });
    const sel = checkbox({ label: T("hosts.selectall"), onchange: (on) => { const l = visibleHosts(); l.forEach((h) => (on ? selected.add(h.id) : selected.delete(h.id))); drawHosts(); } });
    hostsBox = el("div", { class: "hosts-box" });
    bulkBox = el("div", { class: "bulk-box" });
    const page = el("main", { class: "page" },
      el("div", { class: "page-head" }, el("h1", {}, T("hosts.title")), el("span", { class: "muted" }, hosts.length ? `(${hosts.length})` : ""), el("span", { class: "spacer" }),
        button(T("hosts.export"), { icon: "download", onclick: () => exportFleet(visibleHosts()) }),
        me.role === "admin" ? button(T("hosts.add"), { icon: "plus", kind: "primary", onclick: addHostDialog }) : null),
      el("div", { class: "toolbar" },
        el("div", { class: "search-wrap" }, icon("search", 16), search),
        select([{ value: "all", label: T("hosts.filter.all") }, { value: "problems", label: T("hosts.filter.problems"), icon: "x" }, { value: "warn", label: T("hosts.filter.warn"), icon: "alert" },
          { value: "ok", label: T("hosts.filter.ok"), icon: "check" }, { value: "offline", label: T("hosts.filter.offline"), icon: "clock" }], prefs.filter,
          (v) => { prefs.filter = v; savePrefs(); drawHosts(); }, { icon: "sliders", label: T("hosts.filter") }),
        select([{ value: "status", label: T("hosts.sort.status") }, { value: "name", label: T("hosts.sort.name") }, { value: "seen", label: T("hosts.sort.seen") }], prefs.sort,
          (v) => { prefs.sort = v; savePrefs(); drawHosts(); }, { caption: T("hosts.sort") + ":", label: T("hosts.sort") }),
        el("label", { class: "cb-line" }, sel, el("span", {}, T("hosts.selectall"))),
        el("span", { class: "spacer" }),
        segmented([{ value: "tiles", icon: "grid", label: T("hosts.view.tiles") }, { value: "list", icon: "list", label: T("hosts.view.list") }], prefs.view,
          (v) => { prefs.view = v; savePrefs(); drawHosts(); }, T("hosts.view.tiles"))),
      bulkBox, hostsBox);
    drawHosts();
    return page;
  }

  // --- диалог добавления хоста ----------------------------------------------------------------------------------------------------
  async function addHostDialog() {
    const nameIn = el("input", { class: "input", placeholder: T("add.name"), "aria-label": T("add.name"), maxlength: 60 });
    let osv = "mac";
    const termCb = checkbox({ label: T("add.terminal") });
    const osSel = select([{ value: "mac", label: T("add.os.mac"), icon: "laptop" }, { value: "macintel", label: T("add.os.macintel"), icon: "laptop" }, { value: "linux", label: T("add.os.linux"), icon: "server" }],
      osv, (v) => { osv = v; }, { label: T("add.os") });
    const body = el("div", { class: "form" }, el("label", { class: "field" }, el("span", {}, T("add.name")), nameIn),
      el("div", { class: "field" }, el("span", {}, T("add.os")), osSel),
      el("label", { class: "cb-line" }, termCb, el("span", {}, T("add.terminal"))), el("p", { class: "muted small" }, T("add.token.hint")));
    let created = false;
    await dialog({
      title: T("add.title"), icon: "plus", tone: "info", body, wide: true,
      buttons: [
        { text: T("common.close"), value: true },
        { text: T("add.create"), kind: "primary", keep: true, onclick: async (btn) => {
          if (created) return;
          btn.disabled = true;
          try {
            const r = await api("/api/enroll-tokens", { method: "POST", body: { label: nameIn.value } });
            created = true;
            const name = nameIn.value.trim();
            const bin = osv === "linux" ? "hostdeck-agent-linux-amd64" : osv === "macintel" ? "hostdeck-agent-darwin-amd64" : "hostdeck-agent-darwin-arm64";
            const tflag = termCb.checked;
            const cmd = osv === "linux"
              ? `sudo ./${bin} enroll -server ${location.origin} -token ${r.token}${name ? ` -name ${name}` : ""}${tflag ? " -terminal" : ""}\nsudo ./${bin} run`
              : `sudo ${tflag ? "HOSTDECK_TERMINAL=1 " : ""}./install-mac.sh ${location.origin} ${r.token}${name ? ` ${name}` : ""}`;
            const pre = el("pre", { class: "code" }, cmd);
            body.replaceChildren(el("h3", { class: "small-h" }, T("add.cmd.title")), pre, el("p", { class: "muted small" }, T("add.cmd.note")),
              el("div", { class: "row" }, button(T("common.copy"), { icon: "copy", onclick: async (e) => {
                try { await navigator.clipboard.writeText(cmd); toast(T("common.copied")); } catch (_) { const rg = document.createRange(); rg.selectNodeContents(pre); const s = getSelection(); s.removeAllRanges(); s.addRange(rg); }
              } })));
            btn.remove();
          } catch (e) { btn.disabled = false; fail(e); }
        } },
      ],
    });
  }

  // --- страница хоста -----------------------------------------------------------------------------------------------------------------
  let hostTab = "state";
  const swState = { q: "", src: "all", items: null, at: null, hostId: null };

  function gaugesRow(h) {
    const x = metricsOf(h), m = x.m;
    if (!m) return el("div", { class: "card empty-sm" }, icon("clock", 20), el("span", {}, T("host.metrics.none")));
    const stale = !x.fresh;
    const items = [
      gauge({ value: x.cpu, text: Math.round(x.cpu) + "%", title: T("gauge.cpu"), ico: "cpu", stale, sub: `${m.cores} ${window.I18N.lang === "ru" ? "ядер" : "cores"}` }),
      gauge({ value: x.mem, text: Math.round(x.mem || 0) + "%", title: T("gauge.mem"), ico: "memory", stale, sub: T("gauge.mem.sub", { u: gb(m.mem_used), t: gb(m.mem_total) }) }),
      gauge({ value: x.disk, text: Math.round(x.disk || 0) + "%", title: T("gauge.disk"), ico: "disk", stale, sub: T("gauge.disk.sub", { f: gb(m.disk_free) }) }),
    ];
    if (m.battery >= 0) {
      items.push(gauge({ value: m.battery, text: Math.round(m.battery) + "%", title: T("gauge.battery"), ico: "battery", stale,
        level: m.battery <= 15 && !m.battery_chrg ? "fail" : m.battery <= 30 && !m.battery_chrg ? "warn" : "ok",
        sub: m.battery_chrg ? T("gauge.battery.sub.chg") : T("gauge.battery.sub.dis") }));
    } else {
      const lp = Math.min(100, (m.load1 / Math.max(1, m.cores)) * 100);
      items.push(gauge({ value: lp, text: m.load1.toFixed(1), title: T("gauge.load"), ico: "refresh", stale, sub: T("gauge.load.sub", { v: m.load1.toFixed(2), c: m.cores }) }));
    }
    return el("div", null,
      el("div", { class: "gauges" }, items),
      stale ? el("p", { class: "muted small stale" }, icon("clock", 14), " ", T("host.stale") + " · " + ago(h.metrics_at)) : null,
      m.swap_pct > 0 ? el("div", { class: "swap" }, progress(m.swap_pct, { label: T("gauge.swap"), text: Math.round(m.swap_pct) + "%" })) : null);
  }

  function checksGrid(h) {
    const list = [...(h.checks || [])].sort((a, b) => (SEV[a.status] ?? 9) - (SEV[b.status] ?? 9));
    if (!list.length) return el("p", { class: "muted" }, T("common.none"));
    return el("div", { class: "checks" }, list.map((c) => {
      const det = checkDetail(c);
      return el("div", { class: "check s-" + c.status },
        el("span", { class: "check-ico" }, icon(CHECK_ICON[c.id] || "info", 20)),
        el("div", { class: "check-body" }, el("div", { class: "check-t" }, checkLabel(c.id)), el("div", { class: "check-v" }, checkValue(c)),
          c.id === "disk" && c.value === "used" ? progress(c.num, { level: c.status === "ok" ? "ok" : c.status }) : null,
          det ? el("div", { class: "check-d muted small" }, det) : null),
        badge(c.status, "", 18));
    }));
  }

  function stateTab(h) {
    return el("div", {}, el("h2", { class: "sec" }, T("host.gauges")), gaugesRow(h), el("h2", { class: "sec" }, T("host.checks")), checksGrid(h));
  }

  function detailsTab(h) {
    const i = h.info || {};
    const rows = [];
    for (const k of ["os", "os_version", "build", "model", "chip", "memory", "arch", "hostname", "console_user", "agent"]) if (i[k]) rows.push([T("info." + k), i[k]]);
    if (i.boot_time) rows.push([T("host.uptime"), fmtUptime(i.boot_time)], [T("info.boot_time"), fmtDate(Number(i.boot_time))]);
    rows.push([T("info.seen"), fmtDate(h.last_seen)], [T("info.created"), h.id]);
    return el("div", { class: "card table-card" }, el("table", { class: "tbl kv" }, el("tbody", {}, rows.map(([k, v]) => el("tr", {}, el("th", {}, k), el("td", {}, v))))));
  }

  function swTable() {
    const q = swState.q.trim().toLowerCase();
    const items = (swState.items || []).filter((s) => (swState.src === "all" || s.s === swState.src) && (!q || s.n.toLowerCase().includes(q)));
    const shown = items.slice(0, 500);
    return { items, node: el("div", { class: "card table-card" }, el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, el("th", {}, T("sw.col.name")), el("th", {}, T("sw.col.version")), el("th", {}, T("sw.col.source")), el("th", { class: "hide-m" }, T("sw.col.path")))),
      el("tbody", {}, shown.map((s) => el("tr", {}, el("td", { class: "strong" }, s.n), el("td", {}, s.v), el("td", {}, chip(s.s === "app" ? "apps" : "download", T("sw.src." + s.s))),
        el("td", { class: "muted small hide-m mono" }, s.p)))))), more: items.length > shown.length };
  }
  function softwareTab(h) {
    const wrap = el("div", {});
    const body = el("div", {});
    const draw = () => {
      if (swState.items == null) { body.replaceChildren(el("p", { class: "muted" }, T("common.loading"))); return; }
      if (!swState.items.length) {
        body.replaceChildren(el("div", { class: "empty" }, icon("apps", 40), el("h3", {}, T("sw.none")), el("p", { class: "muted" }, T("sw.none.d"))));
        return;
      }
      const t = swTable();
      count.textContent = T("sw.show", { n: Math.min(500, t.items.length) }) + (t.more ? ` / ${t.items.length}` : "");
      body.replaceChildren(t.node);
    };
    const count = el("span", { class: "muted small" });
    const search = el("input", { class: "input", type: "search", placeholder: T("sw.search"), "aria-label": T("sw.search"), value: swState.q });
    search.addEventListener("input", () => { swState.q = search.value; draw(); });
    const srcs = ["all", "app", "brew", "cask", "pkg"].map((s) => ({ value: s, label: T("sw.src." + s) }));
    wrap.append(
      el("div", { class: "toolbar" }, el("div", { class: "search-wrap" }, icon("search", 16), search),
        select(srcs, swState.src, (v) => { swState.src = v; draw(); }, { icon: "sliders", label: T("sw.source") }), count, el("span", { class: "spacer" }),
        el("span", { class: "muted small" }, swState.at ? T("sw.updated", { t: ago(swState.at) }) : ""),
        me.role !== "viewer" ? button(T("sw.refresh"), { icon: "refresh", onclick: async () => { try { await api(`/api/hosts/${h.id}/software/refresh`, { method: "POST", body: {} }); toast(T("sw.queued")); } catch (e) { fail(e); } } }) : null),
      body);
    draw();
    return wrap;
  }
  async function loadSoftware(h) {
    try {
      const r = await api(`/api/hosts/${h.id}/software`);
      swState.items = r.items; swState.at = r.at; swState.hostId = h.id;
    } catch (e) { fail(e); swState.items = []; }
  }

  let hostBox = null, curHost = null;
  function drawHostBody() {
    if (!hostBox || !curHost) return;
    const h = curHost;
    const tabs = [["state", "host.tab.state", "cpu"], ["software", "host.tab.software", "apps"], ["details", "host.tab.details", "info"]];
    if (me.role === "admin") tabs.push(["terminal", "host.tab.terminal", "terminal"]);
    const content = hostTab === "software" ? softwareTab(h) : hostTab === "details" ? detailsTab(h) : hostTab === "terminal" && me.role === "admin" ? terminalTab(h) : stateTab(h);
    hostBox.replaceChildren(
      el("div", { class: "tabs", role: "tablist" }, tabs.map(([k, key, ic]) => el("button", { role: "tab", class: "tab" + (hostTab === k ? " active" : ""), "aria-selected": String(hostTab === k),
        onclick: async () => { hostTab = k; if (k === "software" && swState.hostId !== h.id) { swState.items = null; drawHostBody(); await loadSoftware(h); } drawHostBody(); } },
        icon(ic, 16), el("span", {}, T(key))))),
      content);
  }
  function hostView(id) {
    const head = el("div", { class: "page-head host-head" });
    hostBox = el("div", { class: "host-body" });
    curHost = null;
    const page = el("main", { class: "page" }, el("a", { class: "back", href: "#/hosts" }, icon("chevron", 16, "back-ico"), T("common.back")), head, hostBox);
    (async () => {
      try {
        const h = await api("/api/hosts/" + id);
        curHost = h;
        const x = h.info || {};
        document.title = h.name + " — HostDeck";
        head.replaceChildren(
          el("span", { class: "avatar lg" }, icon(hostIcon(h), 30)),
          el("div", { class: "host-title" }, el("h1", {}, h.name), el("div", { class: "muted" }, [x.model, osLine(x), x.chip].filter(Boolean).join(" · "))),
          badge(h.status, T("status." + h.status), 16),
          chip(h.online ? "check" : "x", h.online ? T("status.online") : T("status.offline"), h.online ? "c-ok" : "c-off"),
          el("span", { class: "spacer" }),
          me.role !== "viewer" ? button(T("host.refresh"), { icon: "refresh", onclick: async () => { try { await api(`/api/hosts/${id}/refresh`, { method: "POST", body: {} }); toast(T("host.refresh.queued")); } catch (e) { fail(e); } } }) : null,
          me.role === "admin" ? button(T("host.console"), { icon: "terminal", onclick: () => { hostTab = "terminal"; drawHostBody(); } }) : null,
          button(T("host.export"), { icon: "download", onclick: () => exportHost(curHost, swState.hostId === id && swState.items ? swState.items : null) }),
          me.role === "admin" ? button("", { icon: "trash", kind: "danger-ghost", title: T("host.delete"), onclick: async () => {
            const ok = await confirmDialog({ title: T("host.delete.title", { name: h.name }), body: T("host.delete.body"), ok: T("common.delete") });
            if (!ok) return;
            try { await api("/api/hosts/" + id, { method: "DELETE" }); toast(T("host.deleted")); location.hash = "#/hosts"; } catch (e) { fail(e); }
          } }) : null);
        if (hostTab === "software" && swState.hostId !== id) await loadSoftware(h);
        drawHostBody();
      } catch (e) {
        if (e.message !== "auth") hostBox.replaceChildren(el("div", { class: "empty" }, icon("alert", 40), el("h3", {}, e.message)));
      }
    })();
    return page;
  }

  // --- терминал (root) ---------------------------------------------------------------------------------------------
  const term = { hostId: null, sid: null, emu: null, es: null, state: "idle", screen: null, input: null, sendQ: Promise.resolve(), buf: "", timer: null, raf: 0, cols: 100, rows: 28 };
  function termDispose() {
    if (term.es) { term.es.close(); term.es = null; }
    if (term.sid && term.state !== "closed") { try { fetch(`/api/term/${term.sid}/close`, { method: "POST", credentials: "same-origin", keepalive: true, headers: { "Content-Type": "application/json" }, body: "{}" }); } catch (_) { /* уходим со страницы */ } }
    Object.assign(term, { hostId: null, sid: null, emu: null, state: "idle", screen: null, input: null, buf: "" });
  }
  function termRender() {
    if (term.raf || !term.emu || !term.screen) return;
    term.raf = requestAnimationFrame(() => {
      term.raf = 0;
      const sc = term.screen, near = sc.scrollHeight - sc.scrollTop - sc.clientHeight < 40;
      term.emu.renderInto(sc, term.state === "open");
      if (near) sc.scrollTop = sc.scrollHeight;
    });
  }
  function termSend(s) {
    term.buf += s;
    if (term.timer) return;
    term.timer = setTimeout(() => {
      const d = term.buf; term.buf = ""; term.timer = null;
      const sid = term.sid;
      // запросы идут строго по очереди, иначе ввод может прийти в другом порядке
      term.sendQ = term.sendQ.then(() => api(`/api/term/${sid}/input`, { method: "POST", body: { d } })).catch(() => {});
    }, 8);
  }
  function termMeasure() {
    const probe = el("span", { class: "tl", style: { position: "absolute", visibility: "hidden", whiteSpace: "pre" } }, "M".repeat(50));
    term.screen.append(probe);
    const w = probe.getBoundingClientRect().width / 50 || 8, avail = term.screen.clientWidth - 28;
    probe.remove();
    term.cols = Math.max(40, Math.min(200, Math.floor(avail / w)));
  }
  async function termStart(h) {
    const ok = await confirmDialog({ title: T("term.confirm.title", { name: h.name }), body: T("term.confirm.body"), ok: T("term.confirm.ok"), icon: "terminal" });
    if (!ok) return;
    if (term.es) { term.es.close(); term.es = null; }
    termMeasure();
    term.state = "connecting"; term.hostId = h.id;
    term.emu = new window.HDTerm.Emu(term.cols, term.rows, termRender);
    drawHostBody();
    let r;
    try { r = await api(`/api/hosts/${h.id}/term`, { method: "POST", body: { cols: term.cols, rows: term.rows } }); }
    catch (e) { term.state = "idle"; fail(e); drawHostBody(); return; }
    term.sid = r.sid; term.sendQ = Promise.resolve();
    const es = new EventSource(`/api/term/${r.sid}/stream`);
    term.es = es;
    es.onmessage = (m) => {
      if (term.state === "connecting") { term.state = "open"; drawHostBody(); }
      const bin = atob(m.data), bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      term.emu.write(bytes);
    };
    es.addEventListener("exit", () => { term.state = "closed"; es.close(); term.es = null; term.emu.write(new TextEncoder().encode("\r\n\x1b[2m[" + T("term.state.closed") + "]\x1b[0m\r\n")); drawHostBody(); });
    setTimeout(() => term.input && term.input.focus(), 50);
  }
  async function termStop() {
    if (!term.sid) return;
    try { await api(`/api/term/${term.sid}/close`, { method: "POST", body: {} }); } catch (e) { fail(e); }
  }
  function termScreen() {
    if (term.screen) return term.screen;
    term.screen = el("div", { class: "term-screen", tabindex: "-1" });
    term.input = el("textarea", { class: "term-input", autocapitalize: "off", autocomplete: "off", spellcheck: "false", "aria-label": T("host.tab.terminal") });
    term.input.addEventListener("keydown", (e) => {
      if (term.state !== "open") return;
      const seq = window.HDTerm.keySeq(e, term.emu.appCursor);
      if (seq) { e.preventDefault(); termSend(seq); }
    });
    term.input.addEventListener("input", () => {
      const v = term.input.value; term.input.value = "";
      if (term.state === "open" && v) termSend(v.replace(/\r?\n/g, "\r"));
    });
    term.screen.addEventListener("mouseup", () => { if (!String(getSelection()).length) term.input.focus(); });
    return term.screen;
  }
  function terminalTab(h) {
    const info = h.info || {};
    if (!h.online && term.state !== "open") return el("div", { class: "card empty-sm" }, icon("clock", 20), el("span", {}, T("term.offline")));
    if (info.terminal !== "on" && term.state === "idle") {
      return el("div", { class: "card" }, el("div", { class: "empty-sm" }, icon("lock", 22), el("strong", {}, T("term.disabled.t"))), el("p", { class: "muted" }, T("term.disabled.d")),
        el("pre", { class: "code" }, T("term.disabled.cmd1") + "\n" + T("term.disabled.cmd2")));
    }
    const st = term.hostId === h.id ? term.state : "idle";
    const tone = { idle: "unknown", connecting: "warn", open: "ok", closed: "unknown" }[st];
    const bar = el("div", { class: "toolbar" }, badge(tone, T("term.state." + st)), el("span", { class: "spacer" }),
      st === "open" ? button(T("term.clear"), { icon: "x", onclick: () => { term.emu.reset(); term.emu.scroll = []; termRender(); term.input.focus(); termSend("\x0c"); } }) : null,
      st === "open" || st === "connecting" ? button(T("term.close"), { icon: "logout", kind: "danger-ghost", onclick: termStop }) : button(st === "closed" ? T("term.reconnect") : T("term.open"), { icon: "terminal", kind: "primary", onclick: () => termStart(h) }));
    const screen = termScreen();
    screen.classList.toggle("live", st === "open");
    screen.style.height = `calc(${term.rows} * 1.28em + 28px)`;
    if (st === "idle" && term.emu == null) screen.replaceChildren();
    return el("div", { class: "term-wrap" }, el("div", { class: "term-warn" }, icon("alert", 18), el("span", {}, T("term.warn"))), bar,
      el("div", { class: "term-box" }, screen, term.input), el("p", { class: "muted small" }, T("term.hint") + " " + T("term.idle")));
  }

  // --- журнал --------------------------------------------------------------------------------------------------------------------------------
  function auditView() {
    const box = el("div", {});
    const page = el("main", { class: "page" }, el("div", { class: "page-head" }, el("h1", {}, T("audit.title"))), box);
    api("/api/audit").then((rows) => {
      if (!rows.length) { box.replaceChildren(el("p", { class: "muted" }, T("audit.empty"))); return; }
      const nm = (id) => { const h = hosts.find((x) => x.id === id); return h ? h.name : id || ""; };
      box.replaceChildren(el("div", { class: "card table-card" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, ["time", "actor", "host", "action", "detail"].map((k) => el("th", {}, T("audit.col." + k))))),
        el("tbody", {}, rows.map((r) => el("tr", {}, el("td", { class: "nowrap muted small" }, fmtDate(r.ts)), el("td", {}, r.actor), el("td", {}, nm(r.host)), el("td", {}, r.action), el("td", { class: "muted small" }, r.detail || "")))))));
    }).catch(fail);
    return page;
  }

  // --- маршрутизация ------------------------------------------------------------------------------------------------------------------------
  function parseRoute() {
    const h = location.hash.replace(/^#/, "") || "/";
    const p = h.split("/").filter(Boolean);
    if (!p.length) return { name: "home" };
    if (p[0] === "hosts") return { name: "hosts" };
    if (p[0] === "host" && p[1]) return { name: "host", id: p[1] };
    if (p[0] === "audit") return { name: "audit" };
    return { name: "home" };
  }
  const TITLES = { home: "nav.home", hosts: "nav.hosts", audit: "nav.audit" };

  async function refreshHosts() {
    try { hosts = await api("/api/hosts"); } catch (e) { fail(e); }
  }
  function clearTimer() { if (timer) { clearInterval(timer); timer = null; } }

  async function renderAll() {
    clearTimer();
    const my = ++routeToken;
    window.UI.closeSelect();
    document.documentElement.lang = window.I18N.lang;
    if (!me) {
      try { me = await api("/api/me"); } catch (_) { me = null; }
      if (my !== routeToken) return;
    }
    if (!me) {
      document.title = T("login.title") + " — HostDeck";
      root.replaceChildren(topbar({ name: "login" }), loginView());
      return;
    }
    const route = parseRoute();
    if (term.hostId && !(route.name === "host" && route.id === term.hostId)) termDispose();
    if (route.name !== "host") await refreshHosts();
    if (my !== routeToken) return;
    document.title = (TITLES[route.name] ? T(TITLES[route.name]) + " — " : "") + "HostDeck";
    let view;
    switch (route.name) {
      case "hosts": view = hostsView(); break;
      case "host": view = hostView(route.id); break;
      case "audit": view = me.role === "admin" ? auditView() : homeView(); break;
      default: view = homeView();
    }
    root.replaceChildren(topbar(route), view);
    window.scrollTo(0, 0);
    // автообновление: данные обновляем, не перерисовывая страницу целиком (сохраняются поиск, выбор, вкладка)
    timer = setInterval(async () => {
      if (document.hidden || document.querySelector(".veil")) return;
      if (route.name === "hosts") { await refreshHosts(); drawHosts(); }
      else if (route.name === "host") {
        try { curHost = await api("/api/hosts/" + route.id); if (hostTab !== "terminal") drawHostBody(); } catch (_) { /* повторим в следующий раз */ }
      }
    }, 15000);
  }

  window.addEventListener("hashchange", renderAll);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") window.UI.closeSelect(); });
  renderAll();
})();
