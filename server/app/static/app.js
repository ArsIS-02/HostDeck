(() => {
  "use strict";
  const { el, svg, icon, hostIcon, badge, chip, progress, checkbox, button, segmented, select, gauge, dialog, confirmDialog, toast, tip } = window.UI;
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
  const CHECK_ICON = { timemachine: "clock", guest: "key", autologin: "key", admins: "key", sharing_screen: "eye", sharing_files: "server", sharing_remote: "eye", airdrop: "globe", xprotect: "shield", profiles: "sliders", sysext: "apps", display_sleep: "clock", screensaver: "lock", uid0: "key", empty_pw: "key", sudo_nopasswd: "key", pw_policy: "key", ports: "globe", sysctl: "sliders", tmp_mount: "disk", smart: "disk", audit_rules: "book", log_forward: "book", sec_updates: "shield", integrity: "shield", freeipa: "server", certs: "lock", selinux: "shield", iptables: "list", sshd: "key", pkg_updates: "download", reboot: "refresh", auditd: "book", time_sync: "clock", failed_units: "alert", luks: "lock", filevault: "lock", sip: "shield", gatekeeper: "shield", firewall: "flame", stealth: "eye", auto_check: "refresh",
    auto_critical: "refresh", updates: "download", screenlock: "lock", ssh: "key", mdm: "sliders", disk: "disk", platform: "info" };
  const checkLabel = (id) => (window.I18N.has("check." + id) ? T("check." + id) : id);
  function checkValue(c) {
    const v = c.value || "";
    if (v.startsWith("after:")) return T("val.after", { n: v.slice(6) });
    if (v === "backup_at" || v === "updated_at") return T("val." + v, { t: ago(c.num) });
    if (v === "used") return T("val.used", { n: Math.round(c.num || 0) });
    if (v === "available") return T("val.available", { n: c.num });
    if (v === "none") return T("val.none") + (c.num ? ` (${T("val.checked", { t: ago(c.num) })})` : "");
    if (v && window.I18N.has("val." + v)) return T("val." + v, { n: c.num });
    return v || (c.status === "unknown" ? T("status.unknown") : "");
  }
  function checkDetail(c) {
    if (c.id === "disk" && c.detail) return T("val.free", { n: c.detail });
    return c.detail || "";
  }



  // Значок ОС: если в static/os лежат свои файлы (apple.svg / tux.svg, либо .png), показываем их, иначе обычный значок устройства.
  // Список файлов спрашиваем у сервера один раз, чтобы браузер не получал 404 за отсутствующими.
  let osLogos = {};
  async function loadOsLogos() { try { osLogos = await (await fetch("/api/os-logos")).json(); } catch (_) { osLogos = {}; } }
  function osMark(h, size) {
    const os = `${h.os || ""} ${(h.info && h.info.os) || ""}`.toLowerCase();
    const base = os.includes("linux") ? "tux" : /mac|darwin/.test(os) ? "apple" : null;
    const url = base && osLogos[base];
    if (!url) return icon(hostIcon(h), size);
    return el("span", { class: "os-logo logo-mark", style: { width: size + "px", height: size + "px" } },
      el("img", { src: url, alt: "", width: size, height: size, draggable: "false" }));
  }

  function avatar(h, cls, size) {
    const m = osMark(h, size);
    return el("span", { class: `avatar ${cls}${m.classList.contains("logo-mark") ? " logo" : ""}`.trim() }, m);
  }

  // --- справка по проверкам и инструкция администратора (тексты в help.js) ---------------------------------------------------------
  // блок команды в подсказке: текст выделяется мышью целиком, рядом кнопка «Копировать»
  async function copyText(text, node) {
    try { await navigator.clipboard.writeText(text); toast(T("common.copied")); return; } catch (_) { /* нет доступа к буферу: запасной путь ниже */ }
    try {
      const ta = el("textarea", { class: "copy-tmp", "aria-hidden": "true" }); ta.value = text; document.body.append(ta); ta.select();
      const okc = document.execCommand("copy"); ta.remove();
      if (okc) { toast(T("common.copied")); return; }
    } catch (_) { /* выделяем текст блока, пользователь скопирует сам */ }
    if (node) { const rg = document.createRange(); rg.selectNodeContents(node); const sl = getSelection(); sl.removeAllRanges(); sl.addRange(rg); }
  }
  function cmdBlock(text) {
    const pre = el("pre", {}, text);
    return el("div", { class: "cmd-wrap" }, pre, el("button", { class: "cmd-copy", type: "button", title: T("common.copy"), "aria-label": T("common.copy"),
      onclick: (e) => { e.stopPropagation(); copyText(text, pre); } }, icon("copy", 14), el("span", {}, T("common.copy"))));
  }

  function checkTip(c, h) {
    const H = window.HELP.get(), U = H.ui, lin = h && (h.os || "").toLowerCase() === "linux";
    const info = (lin && H.checksLinux[c.id]) || H.checks[c.id];
    const val = checkValue(c), det = checkDetail(c);
    const kids = [el("div", { class: "tip-h" }, el("b", {}, checkLabel(c.id)), badge(c.status, T("status." + c.status), 14))];
    kids.push(el("div", { class: "now s-" + c.status }, el("b", {}, U.now + ": "), val || T("status." + c.status), det && c.id !== "disk" ? ` · ${det}` : ""));
    if (info) {
      kids.push(el("h4", {}, U.what), el("p", {}, info.what));
      if (c.status === "ok") { kids.push(el("p", { class: "run" }, U.ok)); }
      else {
        if (info.risk) kids.push(el("h4", {}, (c.status === "info" || c.status === "na") ? U.info : U.risk), el("p", {}, info.risk));
        if (c.status === "unknown") kids.push(el("h4", {}, U.unknown), el("p", {}, H.unknown));
        if (info.fix && info.fix.length && c.status !== "info" && c.status !== "na") kids.push(el("h4", {}, U.fix), el("ul", {}, info.fix.map((x) => el("li", {}, x))));
        // команды под конкретную проблему (имена файлов, служб, портов из результата); если подборки нет — общая команда из справки
        const dyn = window.HELP.cmdFor ? window.HELP.cmdFor(c, h) : null;
        const blocks = dyn || [info.cmd, info.cmd2].filter(Boolean);
        if (blocks.length && c.status !== "info" && c.status !== "na") {
          kids.push(el("h4", {}, dyn ? U.cmd + " · " + U.cmd_for : U.cmd), blocks.map((b) => cmdBlock(b)));
          kids.push(el("p", { class: "run" }, U.run));
        }
      }
    } else if (c.status === "unknown") kids.push(el("h4", {}, U.unknown), el("p", {}, H.unknown));
    return el("div", {}, kids);
  }

  function guideDialog() {
    const G = window.HELP.get().guide;
    const body = el("div", { class: "guide" }, G.sections.map((s) => el("section", {}, el("h3", {}, s.h),
      (s.p || []).map((t) => el("p", {}, t)),
      s.ol ? el("ol", {}, s.ol.map((t) => el("li", {}, t))) : null,
      s.ul ? el("ul", {}, s.ul.map((t) => el("li", {}, t))) : null)));
    return dialog({ title: G.title, icon: "book", tone: "info", body, wide: true, cls: "guide-dlg", buttons: [{ text: T("common.close"), value: true, kind: "primary" }] });
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
        nav("#/apps", "nav.apps", "apps", route.name === "apps"),
        nav("#/report", "nav.report", "shield", route.name === "report"),
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
          me.role === "admin" ? button(T("home.cta.add"), { icon: "plus", onclick: addHostDialog }) : null,
          me.role === "admin" ? button(T("home.cta.guide"), { icon: "book", onclick: guideDialog }) : null)),
      el("section", { class: "stats" }, stat("server", c.hosts, T("home.stat.hosts"), "neutral"), stat("check", c.online, T("home.stat.online"), "ok"),
        stat("alert", c.warn, T("home.stat.warn"), "warn"), stat("x", c.fail, T("home.stat.problems"), "fail")),
      expiringCard(),
      me.role === "admin" ? backupCard() : null,
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
        me.role === "admin" ? link("#/audit", "book", "home.links.audit") : null,
        me.role === "admin" ? link("#/", "book", "home.links.guide", (e) => { e.preventDefault(); guideDialog(); }) : null));
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
      el("div", { class: "hc-top" }, el("label", { class: "cb-wrap" }, cb), avatar(h, "", 28),
        el("div", { class: "hc-title" }, el("h3", {}, h.name), el("div", { class: "muted small" }, [i.model, osLine(i)].filter(Boolean).join(" · "))),
        badge(h.status, T("status." + h.status))),
      el("div", { class: "chips" }, i.chip ? chip("cpu", i.chip) : null, i.memory ? chip("memory", i.memory) : null, chip(h.online ? "check" : "x", h.online ? T("status.online") : T("status.offline"), h.online ? "c-ok" : "c-off")),
      el("div", { class: "bars" },
        progress(x.cpu, { label: T("card.cpu"), text: pct(x.cpu) }), progress(x.mem, { label: T("card.mem"), text: pct(x.mem) }), progress(x.disk, { label: T("card.disk"), text: pct(x.disk) })),
      el("div", { class: "hc-foot muted small" }, el("span", {}, icon("clock", 14), " ", T("card.seen", { t: ago(h.last_seen) })),
        el("span", {}, T("card.checks", { ok: h.counts.ok, all: h.counts.ok + h.counts.warn + h.counts.fail + h.counts.unknown })),
        me.role === "admin" ? button("", { icon: "trash", kind: "danger-ghost", title: T("host.delete"), onclick: (e) => { e.stopPropagation(); deleteHosts([h]); } }) : null));
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
        el("td", {}, el("div", { class: "cell-host" }, avatar(h, "sm", 22),
          el("div", {}, el("div", { class: "strong" }, h.name), el("div", { class: "muted small" }, i.model || i.chip || "")))),
        el("td", {}, badge(h.status, T("status." + h.status))),
        el("td", { class: "hide-m" }, osLine(i)),
        el("td", { class: "hide-s" }, progress(pct(x.cpu), { text: x.cpu == null ? "—" : Math.round(x.cpu) + "%" })),
        el("td", { class: "hide-s" }, progress(pct(x.mem), { text: x.mem == null ? "—" : Math.round(x.mem) + "%" })),
        el("td", { class: "hide-s" }, progress(pct(x.disk), { text: x.disk == null ? "—" : Math.round(x.disk) + "%" })),
        el("td", { class: "muted small nowrap" }, el("span", { class: "dot " + (h.online ? "on" : "off") }), ago(h.last_seen)),
        me.role === "admin" ? el("td", { class: "c-act" }, button("", { icon: "trash", kind: "danger-ghost", title: T("host.delete"), onclick: (e) => { e.stopPropagation(); deleteHosts([h]); } })) : null);
      return tr;
    });
    return el("div", { class: "card table-card" }, el("table", { class: "tbl" },
      el("thead", {}, el("tr", {}, el("th", { class: "c-cb" }, all), el("th", {}, T("hosts.col.name")), el("th", {}, T("hosts.col.status")), el("th", { class: "hide-m" }, T("hosts.col.os")),
        el("th", { class: "hide-s" }, T("hosts.col.cpu")), el("th", { class: "hide-s" }, T("hosts.col.mem")), el("th", { class: "hide-s" }, T("hosts.col.disk")), el("th", {}, T("hosts.col.seen")), me.role === "admin" ? el("th", { class: "c-act" }) : null)),
      el("tbody", {}, rows)));
  }

  // --- удаление хостов (из списка, плиток и панели выбранных) ---------------------------------------------------------------------------
  async function deleteHosts(list) {
    if (!list.length) return;
    const names = list.slice(0, 8).map((h) => el("li", {}, h.name));
    const body = el("div", {}, list.length > 1 ? el("ul", { class: "del-list" }, names, list.length > 8 ? el("li", { class: "muted" }, "…") : null) : null, el("p", {}, T("hosts.delete.body")));
    const yes = await dialog({ title: list.length === 1 ? T("hosts.delete.one", { name: list[0].name }) : T("hosts.delete.title", { n: list.length }), icon: "trash", tone: "danger", body,
      buttons: [{ text: T("common.cancel"), value: false }, { text: T("common.delete"), value: true, kind: "danger" }] });
    if (yes !== true) return;
    try {
      const r = await api("/api/hosts/delete", { method: "POST", body: { ids: list.map((h) => h.id) } });
      list.forEach((h) => selected.delete(h.id));
      toast(T("hosts.deleted", { n: r.deleted }));
      await refreshHosts();
      drawHosts();
    } catch (e) { fail(e); }
  }

  let hostsBox = null, bulkBox = null;
  function drawBulk() {
    if (!bulkBox) return;
    const n = [...selected].filter((id) => hosts.some((h) => h.id === id)).length;
    bulkBox.replaceChildren(...(n > 0 ? [el("div", { class: "bulk" }, el("span", { class: "bulk-n" }, T("hosts.selected", { n })),
      me.role !== "viewer" ? button(T("hosts.refresh.sel"), { icon: "refresh", onclick: bulkRefresh }) : null,
      me.role !== "viewer" ? button(T("hosts.profile.sel"), { icon: "sliders", onclick: () => bulkProfile(hosts.filter((h) => selected.has(h.id))) }) : null,
      me.role !== "viewer" ? button(T("hosts.exc.sel"), { icon: "shield", onclick: () => bulkException(hosts.filter((h) => selected.has(h.id))) }) : null,
      button(T("hosts.export.sel"), { icon: "download", onclick: () => exportFleet(hosts.filter((h) => selected.has(h.id))) }),
      me.role === "admin" ? button(T("hosts.update.sel"), { icon: "refresh", onclick: () => updateAgents(hosts.filter((h) => selected.has(h.id))) }) : null,
      me.role === "admin" ? button(T("hosts.delete.sel"), { icon: "trash", kind: "danger-ghost", onclick: () => deleteHosts(hosts.filter((h) => selected.has(h.id))) }) : null,
      button("", { icon: "x", kind: "ghost", title: T("common.cancel"), onclick: () => { selected.clear(); drawHosts(); } }))] : []));
  }
  // Групповые операции: профиль и исключение сразу для нескольких выбранных хостов
  async function bulkProfile(list) {
    if (!list.length) return;
    const sel = el("select", { class: "input", "aria-label": T("profile.cap") }, ["server", "laptop", "lab"].map((v) => el("option", { value: v }, T("profile." + v))));
    const body = el("div", { class: "form" }, el("p", {}, T("bulk.profile.body", { n: list.length })), el("label", {}, T("profile.cap")), sel,
      el("p", { class: "muted small" }, T("profile.hint")));
    const yes = await dialog({ title: T("hosts.profile.sel"), icon: "sliders", tone: "info", body, buttons: [{ text: T("common.cancel"), value: false }, { text: T("bulk.apply"), value: true, kind: "primary" }] });
    if (!yes) return;
    try { const r = await api("/api/hosts/profile", { method: "POST", body: { ids: list.map((h) => h.id), profile: sel.value } }); toast(T("bulk.done", { n: r.updated })); try { hosts = await api("/api/hosts"); } catch (_) { /* список обновится при следующем опросе */ } drawHosts(); } catch (e) { fail(e); }
  }
  async function bulkException(list) {
    if (!list.length) return;
    // какие проверки сейчас не в порядке хотя бы у одного из выбранных хостов
    let details = [];
    try { details = await Promise.all(list.map((h) => api("/api/hosts/" + h.id))); } catch (e) { fail(e); return; }
    const found = new Map();
    details.forEach((d) => (d.checks || []).forEach((c) => { if (["warn", "fail", "unknown"].includes(c.raw_status)) found.set(c.id, (found.get(c.id) || 0) + 1); }));
    if (!found.size) { toast(T("bulk.exc.none")); return; }
    const chk = el("select", { class: "input", "aria-label": T("exc.check") }, [...found.entries()].sort((a, b) => b[1] - a[1]).map(([id, n]) => el("option", { value: id }, `${checkLabel(id)} (${n})`)));
    const reason = el("input", { type: "text", class: "input", maxlength: "300", placeholder: T("exc.reason.ph"), "aria-label": T("exc.reason") });
    const days = el("select", { class: "input", "aria-label": T("exc.days") }, [[0, T("exc.forever")], [30, "30"], [90, "90"], [365, "365"]].map(([v, t]) => el("option", { value: String(v) }, v ? T("exc.days.n", { n: t }) : t)));
    const body = el("div", { class: "form" }, el("p", {}, T("bulk.exc.body", { n: list.length })), el("label", {}, T("exc.check")), chk, el("label", {}, T("exc.reason")), reason, el("label", {}, T("exc.days")), days);
    const yes = await dialog({ title: T("hosts.exc.sel"), icon: "shield", tone: "info", body, buttons: [{ text: T("common.cancel"), value: false }, { text: T("exc.add"), value: true, kind: "primary" }] });
    if (!yes) return;
    try { const r = await api("/api/hosts/exceptions", { method: "POST", body: { ids: list.map((h) => h.id), check: chk.value, reason: reason.value, days: Number(days.value) || null } }); toast(T("bulk.done", { n: r.updated })); try { hosts = await api("/api/hosts"); } catch (_) { /* список обновится при следующем опросе */ } drawHosts(); } catch (e) { fail(e); }
  }
  // Резервная копия базы: скачать и проверить, что копия открывается и совпадает с рабочей
  function backupCard() {
    const msg = el("p", { class: "muted small", role: "status" });
    const dl = button(T("bak.download"), { icon: "download", onclick: async () => {
      try {
        const r = await fetch("/api/backup", { credentials: "same-origin" });
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.status);
        const blob = await r.blob(), a = el("a", { href: URL.createObjectURL(blob), download: (r.headers.get("content-disposition") || "").match(/filename="?([^";]+)/)?.[1] || "hostdeck.db" });
        document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
        msg.textContent = T("bak.saved");
      } catch (e) { fail(e); }
    } });
    const ck = button(T("bak.check"), { icon: "check", onclick: async () => {
      msg.textContent = T("common.loading");
      try {
        const r = await api("/api/backup/check", { method: "POST", body: {} });
        msg.textContent = r.ok ? T("bak.ok", { s: Math.max(1, Math.round(r.size / 1024)), h: r.counts.hosts, u: r.counts.users }) : T("bak.bad", { i: r.integrity });
        toast(r.ok ? T("bak.ok.short") : T("bak.bad.short"));
      } catch (e) { msg.textContent = ""; fail(e); }
    } });
    return el("section", { class: "card" }, el("h2", { class: "sec in" }, T("bak.title")), el("p", { class: "muted small" }, T("bak.sub")), el("div", { class: "hero-cta" }, dl, ck), msg);
  }

  // Обзор: исключения, срок которых истекает или истёк, чтобы замечание не вернулось неожиданно
  function expiringCard() {
    const box = el("section", { class: "card exp", hidden: true });
    api("/api/exceptions?days=7").then((list) => {
      if (!list.length) return;
      box.hidden = false;
      box.replaceChildren(el("h2", { class: "sec in" }, T("exp.title")), el("p", { class: "muted small" }, T("exp.sub")),
        el("ul", { class: "exp-list" }, list.map((x) => el("li", {}, el("a", { href: "#/host/" + x.host_id }, x.host), " · ", el("b", {}, checkLabel(x.check)), " · ",
          el("span", { class: x.expired ? "exp-late" : "" }, x.expired ? T("exp.expired", { d: new Date(x.expires * 1000).toLocaleDateString(loc(), { day: "numeric", month: "short" }) }) : T("exp.until", { d: new Date(x.expires * 1000).toLocaleDateString(loc(), { day: "numeric", month: "short" }) })),
          el("span", { class: "muted" }, " — " + x.reason)))));
    }).catch(() => {});
    return box;
  }

  // Обновление агентов с веб-интерфейса: сервер ставит хостам команду, а хост скачивает нового агента с сервера, сверяет сумму и перезапускается.
  // Работает только на хостах, где обновление разрешено при установке (флаг HOSTDECK_AUTOUPDATE=1).
  async function updateAgents(list) {
    if (!list.length) return;
    // все хосты уже на актуальной версии: диалог не нужен, достаточно уведомления
    if (!list.some((h) => h.update_available)) { toast(T("update.uptodate")); return; }
    list = list.filter((h) => h.update_available);
    const can = list.filter((h) => (h.info || {}).auto_update === "on"), cannot = list.filter((h) => (h.info || {}).auto_update !== "on");
    const nm = (l) => el("ul", { class: "del-list" }, l.slice(0, 8).map((h) => el("li", {}, `${h.name} (${h.agent_version || "?"}${h.agent_latest ? " → " + h.agent_latest : ""})`)), l.length > 8 ? el("li", { class: "muted" }, "…") : null);
    const body = el("div", {},
      can.length ? el("div", {}, el("p", {}, T("update.body")), nm(can)) : null,
      cannot.length ? el("div", {}, el("p", { class: "muted" }, T("update.cannot")), nm(cannot), el("p", { class: "muted small" }, T("update.enable.cmd"))) : null);
    if (!can.length) {
      const r = await dialog({ title: T("update.title"), icon: "download", tone: "info", body, buttons: [{ text: T("common.close"), value: false }, { text: T("update.open.add"), value: "add", kind: "primary" }] });
      if (r === "add") addHostDialog();
      return;
    }
    const yes = await dialog({ title: T("update.title"), icon: "download", tone: "info", body,
      buttons: [{ text: T("common.cancel"), value: false }, { text: T("update.ok"), value: true, kind: "primary" }] });
    if (yes !== true) return;
    try {
      const r = await api("/api/hosts/update", { method: "POST", body: { ids: can.map((h) => h.id) } });
      toast(T("update.queued", { n: r.queued }));
    } catch (e) { fail(e); }
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
    const termCb = checkbox({ label: T("add.terminal") });
    const updCb = checkbox({ label: T("add.autoupdate") });
    const body = el("div", { class: "form" }, el("label", { class: "field" }, el("span", {}, T("add.name")), nameIn),
      el("label", { class: "cb-line" }, termCb, el("span", {}, T("add.terminal"))),
      el("label", { class: "cb-line" }, updCb, el("span", {}, T("add.autoupdate"))), el("p", { class: "muted small" }, T("add.token.hint")));
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
            const caSha = r.install_sha256 ? r.ca_sha256 : null;
            const caCb = caSha ? checkbox({ label: T("add.ca"), checked: true }) : null;
            // upd=true — команда обновления уже установленного агента: без токена и имени, сразу с разрешением обновлений из веб-интерфейса
            const build = (upd = false) => {
              const o = location.origin, tf = upd ? "HOSTDECK_AUTOUPDATE=1 " : (termCb.checked ? "HOSTDECK_TERMINAL=1 " : "") + (updCb.checked ? "HOSTDECK_AUTOUPDATE=1 " : "");
              const tail = upd ? "" : ` ${r.token}${name ? ` ${name}` : ""}`;
              if (caCb && caCb.checked) {
                // CA и скрипт скачиваются без проверки канала: подлинность доказывают отпечатки из этой (авторизованной) страницы.
                // Скрипт содержит контрольные суммы агентов, а регистрацию с токеном делает сам агент с проверкой по CA.
                const h = (v) => `"$( (sha256sum || shasum -a 256) < "${v}" 2>/dev/null | cut -d' ' -f1)"`;
                return `f=$(mktemp) && s=$(mktemp) && curl -fsSLk ${o}/ca.pem -o "$f" && curl -fsSLk ${o}/install.sh -o "$s" && [ ${h("$f")} = ${caSha} ] && [ ${h("$s")} = ${r.install_sha256} ] && sudo ${tf}HOSTDECK_CA="$f" bash "$s"${tail}`;
              }
              return `curl -fsSL ${o}/install.sh | sudo ${tf}bash -s --${tail}`;
            };
            let cmd = build();
            const pre = el("pre", { class: "code" }, cmd);
            const upre = el("pre", { class: "code" }, build(true));
            const refresh = () => { cmd = build(); pre.textContent = cmd; upre.textContent = build(true); };
            updCb.addEventListener("change", refresh); termCb.addEventListener("change", refresh);
            if (caCb) caCb.addEventListener("change", refresh);
            body.replaceChildren(el("h3", { class: "small-h" }, T("add.cmd.title")), pre,
              caCb ? el("label", { class: "cb-line" }, caCb, el("span", {}, T("add.ca"))) : null, el("p", { class: "muted small" }, T("add.cmd.note")),
              el("div", { class: "row" }, button(T("common.copy"), { icon: "copy", onclick: async (e) => {
                try { await navigator.clipboard.writeText(cmd); toast(T("common.copied")); } catch (_) { const rg = document.createRange(); rg.selectNodeContents(pre); const s = getSelection(); s.removeAllRanges(); s.addRange(rg); }
              } })),
              el("h3", { class: "small-h" }, T("add.upd.title")), upre, el("p", { class: "muted small" }, T("add.upd.note")),
              el("div", { class: "row" }, button(T("common.copy"), { icon: "copy", onclick: async () => {
                try { await navigator.clipboard.writeText(build(true)); toast(T("common.copied")); } catch (_) { const rg = document.createRange(); rg.selectNodeContents(upre); const s = getSelection(); s.removeAllRanges(); s.addRange(rg); }
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
  const ctrState = { q: "", f: "all" };

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

  async function addException(h, c) {
    const reason = el("input", { type: "text", class: "input", maxlength: "300", placeholder: T("exc.reason.ph"), "aria-label": T("exc.reason") });
    const days = el("select", { class: "input", "aria-label": T("exc.days") }, [[0, T("exc.forever")], [30, "30"], [90, "90"], [365, "365"]].map(([v, t]) => el("option", { value: String(v) }, v ? T("exc.days.n", { n: t }) : t)));
    const body = el("div", { class: "form" }, el("p", {}, T("exc.body", { c: checkLabel(c.id) })), el("label", {}, T("exc.reason")), reason, el("label", {}, T("exc.days")), days);
    const yes = await dialog({ title: T("exc.title"), icon: "shield", tone: "info", body, buttons: [{ text: T("common.cancel"), value: false }, { text: T("exc.add"), value: true, kind: "primary" }] });
    if (!yes) return;
    try {
      await api(`/api/hosts/${h.id}/exceptions`, { method: "POST", body: { check: c.id, reason: reason.value, days: Number(days.value) || null } });
      toast(T("exc.saved")); renderAll();
    } catch (e) { fail(e); }
  }
  async function removeException(h, c) {
    try { await api(`/api/hosts/${h.id}/exceptions/${encodeURIComponent(c.id)}`, { method: "DELETE" }); toast(T("exc.removed")); renderAll(); } catch (e) { fail(e); }
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
          det ? el("div", { class: "check-d muted small" }, det) : null,
          c.exception ? el("div", { class: "check-d muted small" }, T("exc.note", { r: c.exception.reason }) + (c.exception.expires ? " · " + T("exc.until", { d: new Date(c.exception.expires * 1000).toLocaleDateString(window.I18N.lang || undefined) }) : "")) : null,
          c.since && c.raw_status !== "ok" && c.raw_status !== "info" ? el("div", { class: "check-d muted small" }, T("hist.since", { d: new Date(c.since * 1000).toLocaleDateString(loc(), { day: "numeric", month: "short" }) })) : null,
          c.relaxed ? el("div", { class: "check-d muted small" }, T("exc.relaxed", { p: T("profile." + h.profile) })) : null,
          me.role !== "viewer" && (c.exception || ["warn", "fail", "unknown"].includes(c.raw_status) && !c.relaxed)
            ? el("div", { class: "check-act" }, button(c.exception ? T("exc.remove") : T("exc.add"), { onclick: () => c.exception ? removeException(h, c) : addException(h, c) })) : null),
        tip(badge(c.status, "", 18), () => checkTip(c, h)));
    }));
  }

  // --- история: график соответствия и смены статусов ---------------------------------------------------------------------------------------
  const histState = { days: 90 };
  const STATUS_COLOR = { ok: "var(--ok)", warn: "var(--warn)", fail: "var(--fail)", unknown: "var(--unk)", info: "var(--info)", na: "var(--unk)" };
  function historyChart(points, days) {
    const W = 720, H = 180, L = 36, R = 10, Tp = 10, B = 24, now = Date.now() / 1000, t0 = now - days * 86400;
    const x = (t) => L + ((t - t0) / (now - t0)) * (W - L - R), y = (v) => Tp + (1 - v / 100) * (H - Tp - B);
    const pts = points.filter((p) => p.idx != null);
    const g = [];
    [0, 50, 100].forEach((v) => g.push(svg("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), stroke: "var(--line, #8884)", "stroke-width": 1, "stroke-dasharray": v === 50 ? "3 4" : "" }), svg("text", { x: L - 6, y: y(v) + 4, "text-anchor": "end", "font-size": 11, fill: "var(--muted)" }, String(v))));
    for (let i = 0; i <= 3; i++) { const t = t0 + (i / 3) * (now - t0); g.push(svg("text", { x: x(t), y: H - 6, "text-anchor": i === 0 ? "start" : i === 3 ? "end" : "middle", "font-size": 11, fill: "var(--muted)" }, new Date(t * 1000).toLocaleDateString(loc(), { day: "numeric", month: "short" }))); }
    if (pts.length) {
      // ступенчатая линия: значение держится до следующей точки
      let d = `M${x(Math.max(pts[0].ts, t0))},${y(pts[0].idx)}`;
      pts.forEach((p, i) => { d += ` L${x(p.ts)},${y(i ? pts[i - 1].idx : p.idx)} L${x(p.ts)},${y(p.idx)}`; });
      d += ` L${x(now)},${y(pts[pts.length - 1].idx)}`;
      g.push(svg("path", { d, fill: "none", stroke: "var(--accent, #0a84ff)", "stroke-width": 2, "stroke-linejoin": "round" }));
      pts.forEach((p) => g.push(svg("circle", { cx: x(p.ts), cy: y(p.idx), r: 3, fill: STATUS_COLOR[p.worst] || "var(--unk)" }, svg("title", {}, `${fmtDate(p.ts)} · ${T("host.index", { n: p.idx })}`))));
    }
    return svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "hist-chart", role: "img", "aria-label": T("hist.chart") }, g);
  }
  function historyTab(h) {
    const box = el("div", { class: "hist" });
    const draw = async () => {
      box.replaceChildren(el("p", { class: "muted" }, T("common.loading")));
      try {
        const d = await api(`/api/hosts/${h.id}/history?days=${histState.days}`);
        const rows = d.changes.map((c) => el("tr", {}, el("td", {}, fmtDate(c.ts)), el("td", {}, checkLabel(c.check)),
          el("td", {}, badge(c.from || "unknown", T("status." + (c.from || "unknown")), 14), " → ", badge(c.to, T("status." + c.to), 14)),
          el("td", { class: "muted" }, c.detail || "")));
        box.replaceChildren(
          el("div", { class: "hist-bar" }, el("h2", { class: "sec" }, T("hist.chart")),
            select([30, 90, 365].map((v) => ({ value: String(v), label: T("hist.days", { n: v }) })), String(histState.days), (v) => { histState.days = Number(v); draw(); }, { icon: "clock", label: T("hist.range") })),
          d.points.length ? historyChart(d.points, d.days) : el("p", { class: "muted" }, T("hist.nopoints")),
          el("h2", { class: "sec" }, T("hist.changes")),
          rows.length ? el("div", { class: "table-wrap" }, el("table", { class: "table" }, el("thead", {}, el("tr", {}, ["hist.col.time", "hist.col.check", "hist.col.change", "hist.col.detail"].map((k) => el("th", {}, T(k))))), el("tbody", {}, rows))) : el("p", { class: "muted" }, T("hist.nochanges")));
      } catch (e) { box.replaceChildren(el("p", { class: "muted" }, String(e.message || e))); }
    };
    draw();
    return box;
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

  // --- вкладка «Контейнеры» ----------------------------------------------------------------------------
  const ctrWants = (c) => c.restart === "always" || c.restart === "unless-stopped";
  // уровень замечания по контейнеру: red — перезапускается по кругу, warn — остановлен с ошибкой, нездоров, не стартовал; "" — всё в порядке
  function ctrLevel(c) {
    if (c.state === "restarting") return "red";
    if (c.state === "running") return c.health === "unhealthy" ? "warn" : "";
    return ctrWants(c) && (c.exit !== 0 || c.state === "created") ? "warn" : "";
  }
  function containersTab(h) {
    const all = h.containers || [];
    const envOf = (c) => c.runtime + (c.owner ? "@" + c.owner : "");
    const envsByName = {};
    for (const c of all) (envsByName[c.name] = envsByName[c.name] || new Set()).add(envOf(c));
    const body = el("div", {});
    const count = el("span", { class: "muted small" });
    const draw = () => {
      const q = ctrState.q.trim().toLowerCase();
      let rows = all.filter((c) => (ctrState.f === "all" || (ctrState.f === "running" ? c.state === "running" : ctrState.f === "stopped" ? c.state !== "running" : ctrLevel(c) !== ""))
        && (!q || [c.name, c.image, c.owner, c.runtime, ...(c.ports || [])].join(" ").toLowerCase().includes(q)));
      const rank = (c) => (ctrLevel(c) === "red" ? 0 : ctrLevel(c) === "warn" ? 1 : c.state === "running" ? 3 : 2);
      rows = rows.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
      count.textContent = rows.length === all.length ? "" : `${rows.length} / ${all.length}`;
      if (!rows.length) { body.replaceChildren(el("div", { class: "empty" }, icon("box", 40), el("h3", {}, T("ctr.nomatch")))); return; }
      body.replaceChildren(el("div", { class: "card table-card" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, el("th", {}, T("ctr.col.name")), el("th", {}, T("ctr.col.env")), el("th", {}, T("ctr.col.state")), el("th", { class: "hide-m" }, T("ctr.col.restart")), el("th", { class: "hide-m" }, T("ctr.col.ports")), el("th", { class: "hide-m" }, T("ctr.col.up")))),
        el("tbody", {}, rows.map((c) => {
          const lv = ctrLevel(c);
          const stTone = c.state === "running" ? (c.health === "unhealthy" ? "c-warn" : "c-ok") : c.state === "restarting" ? "c-fail" : lv === "warn" ? "c-warn" : "c-off";
          const stText = T("ctr.st." + c.state) !== "ctr.st." + c.state ? T("ctr.st." + c.state) : c.state;
          return el("tr", { class: lv ? "ctr-bad" + (lv === "red" ? " ctr-red" : "") : "" },
            el("td", {}, el("span", { class: "ctr-name" }, c.name), c.image ? el("span", { class: "ctr-img" }, c.image) : null,
              envsByName[c.name].size > 1 ? chip("alert", T("ctr.dup"), "c-warn") : null),
            el("td", {}, chip(c.runtime === "docker" ? "server" : "box", T("ctr.rt." + c.runtime) + (c.owner ? " · " + c.owner : (c.runtime === "podman" ? " · root" : "")), "")),
            el("td", {}, chip(null, stText + (c.state !== "running" && c.state !== "created" && c.exit ? ` · ${T("ctr.exit", { n: c.exit })}` : ""), stTone),
              c.health === "unhealthy" ? el("span", { class: "muted small" }, " " + T("ctr.unhealthy")) : null),
            el("td", { class: "hide-m muted small" }, c.restart && c.restart !== "no" ? c.restart : "—"),
            el("td", { class: "hide-m" }, c.ports && c.ports.length ? el("div", { class: "ctr-ports" }, c.ports.map((p) => el("div", {}, p))) : el("span", { class: "muted" }, "—")),
            el("td", { class: "hide-m muted small" }, c.started ? ago(c.started) : "—"));
        })))));
    };
    const search = el("input", { class: "input", type: "search", placeholder: T("ctr.search"), "aria-label": T("ctr.search"), value: ctrState.q });
    search.addEventListener("input", () => { ctrState.q = search.value; draw(); });
    const filters = ["all", "running", "stopped", "problem"].map((f) => ({ value: f, label: T("ctr.f." + f) }));
    const bad = all.filter((c) => ctrLevel(c) !== "").length, run = all.filter((c) => c.state === "running").length;
    const wrap = el("div", {});
    if (!all.length) {
      wrap.append(el("div", { class: "empty" }, icon("box", 40), el("h3", {}, T("ctr.none")), el("p", { class: "muted" }, T("ctr.none.d"))));
      return wrap;
    }
    wrap.append(
      el("div", { class: "ctr-sum" }, chip("box", T("ctr.sum", { r: run, n: all.length }), run === all.length ? "c-ok" : ""), bad ? chip("alert", T("ctr.sum.bad", { n: bad }), "c-warn") : null,
        el("span", { class: "spacer" }), el("span", { class: "muted small" }, h.posture_at ? T("ctr.updated", { t: ago(h.posture_at) }) : "")),
      el("div", { class: "toolbar" }, el("div", { class: "search-wrap" }, icon("search", 16), search),
        select(filters, ctrState.f, (v) => { ctrState.f = v; draw(); }, { icon: "sliders", label: T("ctr.filter") }), count),
      body);
    draw();
    return wrap;
  }

  let hostBox = null, curHost = null;
  function drawHostBody() {
    if (!hostBox || !curHost) return;
    const h = curHost;
    const tabs = [["state", "host.tab.state", "cpu"], ["software", "host.tab.software", "apps"]];
    if (h.containers_count != null) tabs.push(["containers", "host.tab.containers", "box"]);
    tabs.push(["history", "host.tab.history", "clock"], ["details", "host.tab.details", "info"]);
    if (me.role === "admin") tabs.push(["terminal", "host.tab.terminal", "terminal"]);
    const content = hostTab === "software" ? softwareTab(h) : hostTab === "containers" && h.containers_count != null ? containersTab(h) : hostTab === "history" ? historyTab(h) : hostTab === "details" ? detailsTab(h) : hostTab === "terminal" && me.role === "admin" ? terminalTab(h) : stateTab(h);
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
        head.replaceChildren(...[
          avatar(h, "lg", 38),
          el("div", { class: "host-title" }, el("h1", {}, h.name), el("div", { class: "muted" }, [x.model, osLine(x), x.chip].filter(Boolean).join(" · "))),
          badge(h.status, T("status." + h.status), 16),
          chip(h.online ? "check" : "x", h.online ? T("status.online") : T("status.offline"), h.online ? "c-ok" : "c-off"),
          h.index != null ? chip("shield", T("host.index", { n: h.index }), h.index >= 90 ? "c-ok" : h.index >= 70 ? "c-warn" : "c-off") : null,
          me.role !== "viewer"
            ? select(["server", "laptop", "lab"].map((v) => ({ value: v, label: T("profile." + v) })), h.profile, async (v) => { try { await api(`/api/hosts/${id}/profile`, { method: "POST", body: { profile: v } }); toast(T("profile.saved")); renderAll(); } catch (e) { fail(e); } }, { caption: T("profile.cap") })
            : chip("sliders", T("profile." + h.profile), ""),
          h.update_available ? chip("download", T("host.update.avail", { v: h.agent_latest }), "c-warn") : (h.agent_version ? chip("check", T("host.update.current"), "c-ok") : null),
          el("span", { class: "spacer" }),
          me.role !== "viewer" ? button(T("host.refresh"), { icon: "refresh", onclick: async () => { try { await api(`/api/hosts/${id}/refresh`, { method: "POST", body: {} }); toast(T("host.refresh.queued")); } catch (e) { fail(e); } } }) : null,
          me.role === "admin" ? button(T("host.update"), { icon: "download", kind: h.update_available ? "primary" : "", onclick: () => updateAgents([h]) }) : null,
          button(T("host.export"), { icon: "download", onclick: () => exportHost(curHost, swState.hostId === id && swState.items ? swState.items : null) }),
          me.role === "admin" ? button("", { icon: "trash", kind: "danger-ghost", title: T("host.delete"), onclick: async () => {
            const ok = await confirmDialog({ title: T("host.delete.title", { name: h.name }), body: T("host.delete.body"), ok: T("common.delete") });
            if (!ok) return;
            try { await api("/api/hosts/" + id, { method: "DELETE" }); toast(T("host.deleted")); location.hash = "#/hosts"; } catch (e) { fail(e); }
          } }) : null].filter(Boolean));
        if (hostTab === "software" && swState.hostId !== id) await loadSoftware(h);
        drawHostBody();
      } catch (e) {
        if (e.message !== "auth") hostBox.replaceChildren(el("div", { class: "empty" }, icon("alert", 40), el("h3", {}, e.message)));
      }
    })();
    return page;
  }

  // --- терминал (root) ---------------------------------------------------------------------------------------------
  const term = { sel: "", hostId: null, sid: null, emu: null, es: null, state: "idle", screen: null, input: null, sendQ: Promise.resolve(), buf: "", timer: null, raf: 0, cols: 100, rows: 28 };
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
    // Выделенный текст запоминаем сразу: терминал перерисовывается при каждом выводе, и выделение иначе пропадает.
    const selText = () => String(getSelection() || "") || term.sel || "";
    const doCopy = async () => {
      const t = selText(); if (!t) return false;
      try { await navigator.clipboard.writeText(t); toast(T("common.copied")); } catch (_) { /* остаётся системное копирование */ }
      return true;
    };
    const doPaste = (text) => { if (term.state === "open" && text) termSend(text.replace(/\r\n|\n/g, "\r")); };
    const onKey = async (e) => {
      if (term.state !== "open") return;
      const k = (e.key || "").toLowerCase(), cmd = e.metaKey, ctl = e.ctrlKey && !e.altKey;
      // копирование: Cmd+C, Ctrl+Shift+C, а Ctrl+C — только если что-то выделено (иначе это прерывание команды)
      if ((cmd && k === "c") || (ctl && e.shiftKey && k === "c") || (ctl && !e.shiftKey && k === "c" && selText())) {
        if (selText()) { e.preventDefault(); await doCopy(); term.sel = ""; term.input.focus(); return; }
      }
      // вставка: Cmd+V, Ctrl+V, Ctrl+Shift+V — отдаём браузеру, текст придёт в событии paste
      if ((cmd || ctl) && k === "v") { term.input.focus(); return; }
      if (cmd) return;
      const seq = window.HDTerm.keySeq(e, term.emu.appCursor);
      // начали печатать: выделение больше не нужно, фокус возвращаем в поле ввода, символ отправляем сами (чтобы не потерять первый)
      const hadSel = !!String(getSelection() || "");
      if (hadSel) getSelection().removeAllRanges();
      if (hadSel || e.target !== term.input) term.input.focus();
      if (seq) { e.preventDefault(); term.sel = ""; termSend(seq); }
      else if ((hadSel || e.target !== term.input) && e.key.length === 1 && !ctl && !e.altKey) { e.preventDefault(); term.sel = ""; termSend(e.key); }
    };
    term.input.addEventListener("keydown", onKey);
    term.screen.addEventListener("keydown", onKey);
    term.input.addEventListener("input", () => {
      const v = term.input.value; term.input.value = "";
      if (term.state === "open" && v) { term.sel = ""; termSend(v.replace(/\r?\n/g, "\r")); }
    });
    for (const t of [term.input, term.screen]) {
      t.addEventListener("paste", (e) => { e.preventDefault(); doPaste((e.clipboardData && e.clipboardData.getData("text")) || ""); });
      t.addEventListener("copy", (e) => { const x = selText(); if (x && e.clipboardData) { e.preventDefault(); e.clipboardData.setData("text/plain", x); } });
    }
    term.screen.addEventListener("mouseup", () => {
      term.sel = String(getSelection() || "");
      if (!term.sel) term.input.focus();
    });
    // вставка средней кнопкой мыши (как в обычных терминалах Linux)
    term.screen.addEventListener("auxclick", async (e) => {
      if (e.button !== 1) return;
      e.preventDefault();
      try { doPaste(await navigator.clipboard.readText()); } catch (_) { /* нет разрешения на чтение буфера */ }
    });
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
  // --- журнал действий: лента понятных событий -------------------------------------------------------------------------------------------
  const AUDIT = {
    "login": { ic: "key", tone: "info", cat: "access" }, "login-failed": { ic: "alert", tone: "warn", cat: "access" },
    "refresh": { ic: "refresh", tone: "", cat: "requests" }, "software-refresh": { ic: "apps", tone: "", cat: "requests" },
    "term-open": { ic: "terminal", tone: "warn", cat: "console" }, "term-closed": { ic: "terminal", tone: "", cat: "console" }, "term-denied": { ic: "x", tone: "fail", cat: "console" },
    "host-deleted": { ic: "trash", tone: "fail", cat: "hosts" }, "enroll-token-created": { ic: "plus", tone: "info", cat: "hosts" },
    "enroll-rejected": { ic: "x", tone: "fail", cat: "hosts" }, "enrolled": { ic: "check", tone: "ok", cat: "hosts" },
    "admin-created": { ic: "key", tone: "info", cat: "access" },
    "agent-update": { ic: "download", tone: "info", cat: "hosts" }, "agent-updated": { ic: "check", tone: "ok", cat: "hosts" },
    "agent-update-failed": { ic: "x", tone: "fail", cat: "hosts" }, "agent-update-current": { ic: "check", tone: "", cat: "hosts" },
  };
  function fmtDur(sec) {
    if (sec < 60) return `${sec} ${T("u.s")}`;
    if (sec < 3600) return `${Math.floor(sec / 60)} ${T("u.min")} ${sec % 60} ${T("u.s")}`;
    return `${Math.floor(sec / 3600)} ${T("u.h")} ${Math.floor((sec % 3600) / 60)} ${T("u.min")}`;
  }
  function fmtBytes(n) {
    if (n < 1024) return `${n} ${T("u.b")}`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} ${T("u.kb")}`;
    return `${(n / 1048576).toFixed(1)} ${T("u.mb")}`;
  }
  function auditActor(r) { return r.actor === "agent" ? T("audit.actor.agent") : r.actor === "system" ? T("audit.actor.system") : r.actor || "—"; }
  function auditDetail(r) {
    const d = r.detail || "";
    switch (r.action) {
      case "login": case "term-open": case "enroll-rejected": return d ? T("audit.d.from", { ip: d }) : "";
      case "login-failed": return [r.actor ? T("audit.d.tried", { name: r.actor }) : "", d ? T("audit.d.from", { ip: d }) : ""].filter(Boolean).join(", ");
      case "term-denied": return d.includes("не разрешена") ? T("audit.d.term_off") : d;
      case "term-closed": {
        const m = d.match(/^(\d+) с, ввод (\d+) Б, вывод (\d+) Б(?:, ошибка: (.*))?$/);
        if (!m) return d;
        return T("audit.d.session", { t: fmtDur(+m[1]), i: fmtBytes(+m[2]), o: fmtBytes(+m[3]) }) + (m[4] ? ", " + T("audit.d.error", { e: m[4] }) : "");
      }
      case "enrolled": return "";
      case "admin-created": return d ? T("audit.d.name", { n: d }) : "";
      case "enroll-token-created": return d ? T("audit.d.label", { n: d }) : "";
      default: return d;
    }
  }
  function dayLabel(ts) {
    const d = new Date(ts * 1000), n = new Date();
    const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const diff = Math.round((day(n) - day(d)) / 86400000);
    if (diff === 0) return T("audit.today");
    if (diff === 1) return T("audit.yesterday");
    return d.toLocaleDateString(loc(), { weekday: "long", day: "numeric", month: "long", year: d.getFullYear() === n.getFullYear() ? undefined : "numeric" });
  }
  function auditView() {
    const st = { cat: "all", q: "", limit: 200, rows: [], more: false };
    const list = el("div", {});
    const search = el("input", { class: "input search", type: "search", placeholder: T("audit.search"), "aria-label": T("audit.search") });
    const draw = () => {
      const q = st.q.trim().toLowerCase();
      const rows = st.rows.filter((r) => {
        const a = AUDIT[r.action];
        if (st.cat !== "all" && (!a || a.cat !== st.cat)) return false;
        if (!q) return true;
        return `${T("audit.act." + r.action)} ${auditActor(r)} ${r.host_name || ""} ${auditDetail(r)}`.toLowerCase().includes(q);
      });
      if (!rows.length) { list.replaceChildren(el("div", { class: "empty" }, icon("book", 36), el("p", { class: "muted" }, st.rows.length ? T("audit.none") : T("audit.empty")))); return; }
      const out = []; let last = null, group = null;
      for (const r of rows) {
        const lbl = dayLabel(r.ts);
        if (lbl !== last) { last = lbl; out.push(el("h3", { class: "log-day" }, lbl)); group = el("div", { class: "card log-card" }); out.push(group); }
        const a = AUDIT[r.action] || { ic: "info", tone: "" };
        const det = auditDetail(r);
        const sub = [T("audit.by", { who: auditActor(r) }), det].filter(Boolean).join(" · ");
        group.append(el("div", { class: "log-row" },
          el("span", { class: "log-ico" + (a.tone ? " s-" + a.tone : "") }, icon(a.ic, 18)),
          el("div", { class: "log-body" },
            el("div", { class: "log-t" }, window.I18N.has("audit.act." + r.action) ? T("audit.act." + r.action) : r.action,
              r.host_name ? el("span", { class: "log-host" }, icon("server", 13), r.host_name) : null),
            el("div", { class: "muted small log-s" }, sub)),
          el("time", { class: "log-time muted small", title: fmtDate(r.ts) }, new Date(r.ts * 1000).toLocaleTimeString(loc(), { hour: "2-digit", minute: "2-digit" }))));
      }
      if (st.more) out.push(el("div", { class: "log-more" }, button(T("audit.more"), { onclick: () => { st.limit += 200; load(); } })));
      list.replaceChildren(...out);
    };
    const load = () => api(`/api/audit?limit=${st.limit}`).then((d) => { st.rows = d.rows; st.more = d.more; draw(); }).catch(fail);
    search.addEventListener("input", () => { st.q = search.value; draw(); });
    const page = el("main", { class: "page" }, el("div", { class: "page-head" }, el("h1", {}, T("audit.title"))), el("p", { class: "muted" }, T("audit.sub")),
      el("div", { class: "toolbar" }, el("div", { class: "search-wrap" }, icon("search", 16), search),
        select(["all", "access", "hosts", "console", "requests"].map((k) => ({ value: k, label: T("audit.cat." + k) })), st.cat, (v) => { st.cat = v; draw(); }, { icon: "sliders", label: T("audit.cat.all") })),
      list);
    load();
    return page;
  }

  // --- печатный отчёт «Состояние парка» -----------------------------------------------------------------------------------------------
  function reportView() {
    const page = el("main", { class: "page report" }, el("p", { class: "muted" }, T("common.loading")));
    api("/api/report").then((d) => {
      const hs = d.hosts, idxs = hs.map((h) => h.index).filter((v) => v != null);
      const avg = idxs.length ? Math.round(idxs.reduce((a, b) => a + b, 0) / idxs.length) : null;
      const date = (t) => new Date(t * 1000).toLocaleDateString(loc(), { day: "numeric", month: "short", year: "numeric" });
      const th = (keys) => el("thead", {}, el("tr", {}, keys.map((k) => el("th", {}, T(k)))));
      const sections = hs.map((h) => {
        const bad = (h.checks || []).filter((c) => ["fail", "warn", "unknown"].includes(c.status));
        return el("section", { class: "rep-host" },
          el("h2", {}, h.name, " ", badge(h.status, T("status." + h.status), 16)),
          el("p", { class: "muted small" }, [[(h.info || {}).model, (h.info || {}).os].filter(Boolean).join(" · "), T("profile.cap") + ": " + T("profile." + h.profile), h.index != null ? T("host.index", { n: h.index }) : null, h.posture_at ? T("rep.data", { t: fmtDate(h.posture_at) }) : T("rep.nodata")].filter(Boolean).join(" · ")),
          bad.length ? el("table", { class: "table" }, th(["rep.col.check", "rep.col.status", "rep.col.value", "rep.col.detail"]),
            el("tbody", {}, bad.map((c) => el("tr", {}, el("td", {}, checkLabel(c.id)), el("td", {}, badge(c.status, T("status." + c.status), 14)), el("td", {}, checkValue(c)),
              el("td", { class: "muted" }, [checkDetail(c), c.since ? T("hist.since", { d: date(c.since) }) : ""].filter(Boolean).join(" · ")))))) : el("p", {}, T("rep.clean")),
          (h.exceptions_list || []).length ? el("div", {}, el("h3", {}, T("rep.exc")),
            el("table", { class: "table" }, th(["rep.col.check", "rep.col.reason", "rep.col.who", "rep.col.until"]),
              el("tbody", {}, h.exceptions_list.map((x) => el("tr", {}, el("td", {}, checkLabel(x.check)), el("td", {}, x.reason), el("td", {}, x.actor || ""), el("td", {}, x.expires ? date(x.expires) : T("exc.forever"))))))) : null);
      });
      page.replaceChildren(
        el("div", { class: "page-head" }, el("div", {}, el("h1", {}, T("rep.title")), el("p", { class: "muted" }, T("rep.generated", { t: fmtDate(d.generated) }))),
          el("span", { class: "spacer" }), el("span", { class: "no-print" }, button(T("rep.print"), { icon: "download", kind: "primary", onclick: () => window.print() }))),
        el("p", {}, T("rep.summary", { n: hs.length, ok: hs.filter((h) => h.status === "ok").length, warn: hs.filter((h) => h.status === "warn").length, fail: hs.filter((h) => h.status === "fail").length }) + (avg != null ? " · " + T("rep.avg", { n: avg }) : "")),
        el("table", { class: "table rep-sum" }, th(["rep.col.host", "rep.col.os", "profile.cap", "rep.col.index", "rep.col.status", "rep.col.exc"]),
          el("tbody", {}, hs.map((h) => el("tr", {}, el("td", {}, h.name), el("td", {}, (h.info || {}).os || h.os || ""), el("td", {}, T("profile." + h.profile)), el("td", {}, h.index != null ? h.index + "%" : "—"),
            el("td", {}, badge(h.status, T("status." + h.status), 14)), el("td", {}, String(h.exceptions)))))),
        ...sections);
    }).catch((e) => page.replaceChildren(el("p", { class: "muted" }, String(e.message || e))));
    return page;
  }

  // --- поиск ПО по всему парку -----------------------------------------------------------------------------------------
  const appsState = { q: "", older: "", src: "all" };
  function appsView() {
    const page = el("main", { class: "page apps" });
    const body = el("div", {}), count = el("span", { class: "muted small" }), note = el("span", { class: "muted small" });
    let data = null, seq = 0, tm = null;
    const SHOW = 100;
    const csv = () => {
      if (!data) return;
      const rows = [[T("apps.col.app"), T("apps.col.version"), T("apps.col.source"), T("apps.col.host")]];
      for (const a of data.apps) for (const v of a.versions) for (const h of v.hosts) rows.push([a.name, v.v, a.sources.map((x) => T("sw.src." + x)).join(", "), h.name]);
      downloadCsv(`hostdeck-software-${stamp()}.csv`, rows);
    };
    const draw = () => {
      if (!data) { body.replaceChildren(el("p", { class: "muted" }, T("common.loading"))); return; }
      note.textContent = T("apps.nodata", { a: data.hosts_with_data, b: data.hosts_total });
      count.textContent = T("apps.found", { n: data.apps.length + (data.truncated ? "+" : "") });
      if (!data.apps.length) {
        body.replaceChildren(el("div", { class: "empty" }, icon("apps", 40), el("h3", {}, T("apps.none")), el("p", { class: "muted" }, T("apps.none.d"))));
        return;
      }
      const shown = data.apps.slice(0, SHOW);
      body.replaceChildren(...shown.map((a) => el("div", { class: "card app-card" },
        el("div", { class: "app-head" }, el("strong", {}, a.name), ...a.sources.map((x) => chip(x === "app" ? "apps" : "download", T("sw.src." + x))), el("span", { class: "spacer" }), el("span", { class: "muted small" }, T("apps.hosts", { n: a.hosts }))),
        el("div", { class: "app-vers" }, ...a.versions.map((v) => el("div", { class: "app-ver" }, el("span", { class: "mono ver" }, v.v || "—"),
          el("span", { class: "app-hosts" }, ...v.hosts.map((h) => el("a", { class: "chip host-chip", href: "#/host/" + h.id }, h.name)))))))),
        ...(data.apps.length > SHOW || data.truncated ? [el("p", { class: "muted small" }, T("apps.more", { n: SHOW }))] : []));
    };
    const load = async () => {
      const my = ++seq;
      const qs = new URLSearchParams({ q: appsState.q.trim(), older: appsState.older.trim(), src: appsState.src });
      try {
        const r = await api("/api/software/search?" + qs.toString());
        if (my !== seq) return;
        data = r;
      } catch (e) { if (my === seq) { fail(e); data = { apps: [], hosts_total: 0, hosts_with_data: 0 }; } }
      draw();
    };
    const later = () => { clearTimeout(tm); tm = setTimeout(load, 250); };
    const q = el("input", { class: "input", type: "search", placeholder: T("apps.q"), "aria-label": T("apps.q"), value: appsState.q });
    q.addEventListener("input", () => { appsState.q = q.value; later(); });
    const older = el("input", { class: "input narrow", type: "text", placeholder: T("apps.older"), "aria-label": T("apps.older"), value: appsState.older });
    older.addEventListener("input", () => { appsState.older = older.value; later(); });
    const srcs = ["all", "app", "brew", "cask", "pkg"].map((s) => ({ value: s, label: T("sw.src." + s) }));
    page.append(
      el("div", { class: "page-head" }, el("div", {}, el("h1", {}, T("apps.title")), el("p", { class: "muted" }, T("apps.sub")))),
      el("div", { class: "toolbar" }, el("div", { class: "search-wrap" }, icon("search", 16), q), older,
        select(srcs, appsState.src, (v) => { appsState.src = v; load(); }, { icon: "sliders", label: T("sw.source") }), count, el("span", { class: "spacer" }), note,
        button(T("apps.csv"), { icon: "download", onclick: csv })),
      body);
    draw();
    load();
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
    if (p[0] === "report") return { name: "report" };
    if (p[0] === "apps") return { name: "apps" };
    return { name: "home" };
  }
  const TITLES = { home: "nav.home", hosts: "nav.hosts", audit: "nav.audit", report: "nav.report", apps: "nav.apps" };

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
      case "report": view = reportView(); break;
      case "apps": view = appsView(); break;
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
  loadOsLogos().then(renderAll);
})();
