(() => {
  "use strict";
  const app = document.getElementById("app");
  const top = document.getElementById("top");
  let me = null;
  let timer = null;

  // --- помощники ---------------------------------------------------------
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else if (v === true) n.setAttribute(k, "");
      else if (v !== false && v != null) n.setAttribute(k, v);
    }
    for (const k of kids.flat()) {
      if (k == null || k === false) continue;
      n.append(k.nodeType ? k : document.createTextNode(String(k)));
    }
    return n;
  }
  async function api(path, opts = {}) {
    const o = { credentials: "same-origin", ...opts };
    if (o.body && typeof o.body !== "string") {
      o.body = JSON.stringify(o.body);
      o.headers = { "Content-Type": "application/json", ...(o.headers || {}) };
    }
    const r = await fetch(path, o);
    let data = null;
    try { data = await r.json(); } catch (_) { /* пустой ответ */ }
    if (r.status === 401 && path !== "/api/login") { me = null; showLogin(); throw new Error("auth"); }
    if (!r.ok) throw new Error((data && data.error) || "HTTP " + r.status);
    return data;
  }
  function ago(ts) {
    if (!ts) return "никогда";
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return "только что";
    if (s < 3600) return Math.floor(s / 60) + " мин назад";
    if (s < 86400) return Math.floor(s / 3600) + " ч назад";
    return Math.floor(s / 86400) + " д назад";
  }
  const STATUS_RU = { ok: "в порядке", warn: "внимание", fail: "проблема", unknown: "нет данных", info: "справка" };
  const INFO_LABELS = {
    os: "Система", os_version: "Версия", build: "Сборка", model: "Модель", chip: "Процессор", memory: "Память",
    arch: "Архитектура", uptime: "Аптайм", console_user: "Пользователь у экрана", hostname: "Имя хоста", agent: "Агент",
  };
  const SEVERITY = { fail: 0, warn: 1, unknown: 2, ok: 3, info: 4 };

  function setTitle(t) { document.title = t ? t + " — HostDeck" : "HostDeck"; }
  function clearTimer() { if (timer) { clearInterval(timer); timer = null; } }

  // --- вход ------------------------------------------------------------------
  function showLogin() {
    clearTimer();
    top.hidden = true;
    setTitle("Вход");
    const err = el("div", { class: "error" });
    const name = el("input", { id: "u", autocomplete: "username", required: true });
    const pw = el("input", { id: "p", type: "password", autocomplete: "current-password", required: true });
    const form = el("form", { class: "login panel", onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      try {
        me = await api("/api/login", { method: "POST", body: { name: name.value, password: pw.value } });
        start();
      } catch (ex) { err.textContent = ex.message; pw.value = ""; }
    } },
      el("h1", {}, "HostDeck"), el("p", { class: "sub" }, "Парк хостов лаборатории"),
      el("label", { for: "u" }, "Имя пользователя"), name,
      el("label", { for: "p" }, "Пароль"), pw, err,
      el("button", { class: "btn", type: "submit" }, "Войти"));
    app.replaceChildren(form);
    name.focus();
  }

  // --- парк хостов ---------------------------------------------------------------
  function chip(cls, text) { return el("span", { class: "chip " + cls }, text); }

  function hostCard(h) {
    const cls = ["card"];
    if (!h.online) cls.push("offline"); else cls.push("s-" + h.status);
    const i = h.info || {};
    const meta = [i.os ? i.os + (i.os_version ? " " + i.os_version : "") : h.os, i.chip || i.model].filter(Boolean).join(" · ");
    const chips = [];
    if (h.counts.fail) chips.push(chip("fail", "проблем: " + h.counts.fail));
    if (h.counts.warn) chips.push(chip("warn", "внимание: " + h.counts.warn));
    if (h.counts.unknown) chips.push(chip("", "нет данных: " + h.counts.unknown));
    if (h.status === "ok" && h.online) chips.push(chip("ok", "всё в порядке"));
    if (!h.posture_at) chips.length = 0, chips.push(chip("", "ждём первый отчёт"));
    return el("a", { class: cls.join(" "), href: "#/host/" + encodeURIComponent(h.id) },
      el("h3", {}, el("span", { class: "dot" + (h.online ? " on" : "") }), h.name),
      el("div", { class: "meta" }, meta || "—"),
      el("div", { class: "chips" }, chips),
      el("div", { class: "meta", style: "margin:10px 0 0" },
        (h.online ? "на связи" : "не на связи, был " + ago(h.last_seen)) + (i.uptime ? " · аптайм " + i.uptime : "")));
  }

  async function showFleet() {
    clearTimer();
    setTitle("Парк хостов");
    const wrap = el("div");
    app.replaceChildren(el("h1", {}, "Парк хостов"), el("p", { class: "sub", id: "sum" }, "Загрузка…"), wrap);
    async function load() {
      let hosts;
      try { hosts = await api("/api/hosts"); } catch (e) { if (e.message !== "auth") wrap.replaceChildren(el("div", { class: "error" }, e.message)); return; }
      const online = hosts.filter((h) => h.online).length;
      const bad = hosts.filter((h) => h.online && (h.status === "fail" || h.status === "warn")).length;
      document.getElementById("sum").textContent = hosts.length
        ? `Хостов: ${hosts.length}, на связи: ${online}, требуют внимания: ${bad}`
        : "Хостов пока нет.";
      wrap.replaceChildren(hosts.length
        ? el("div", { class: "grid" }, hosts.map(hostCard))
        : el("div", { class: "empty" }, "Нажмите «Добавить хост» и выполните команду на Mac."));
    }
    await load();
    timer = setInterval(load, 15000);
  }

  // --- карточка хоста ------------------------------------------------------------
  async function showHost(id) {
    clearTimer();
    const box = el("div");
    app.replaceChildren(el("a", { class: "back", href: "#/" }, "← Парк хостов"), box);
    async function load() {
      let h;
      try { h = await api("/api/hosts/" + encodeURIComponent(id)); }
      catch (e) { if (e.message !== "auth") box.replaceChildren(el("p", { class: "error" }, e.message)); return; }
      setTitle(h.name);
      const info = Object.entries(h.info || {}).filter(([, v]) => v).map(([k, v]) =>
        el("tr", {}, el("th", { class: "check-label" }, INFO_LABELS[k] || k), el("td", {}, v)));
      const checks = [...h.checks].sort((a, b) => (SEVERITY[a.status] ?? 9) - (SEVERITY[b.status] ?? 9)).map((c) =>
        el("tr", {}, el("td", { class: "check-label" }, c.label),
          el("td", {}, el("span", { class: "badge " + c.status }, STATUS_RU[c.status] || c.status)),
          el("td", {}, c.value || "", c.detail ? el("div", { class: "detail" }, c.detail) : null)));
      const canRefresh = me && (me.role === "operator" || me.role === "admin");
      const refresh = el("button", { class: "btn", onclick: async (e) => {
        e.target.disabled = true;
        try { await api("/api/hosts/" + encodeURIComponent(id) + "/refresh", { method: "POST", body: {} }); } catch (_) { /* показано ниже */ }
        setTimeout(load, 3000); setTimeout(load, 8000);
        e.target.textContent = "Запрошено…";
      } }, "Обновить сейчас");
      const del = me && me.role === "admin" ? el("button", { class: "btn ghost danger", onclick: async () => {
        if (!confirm("Удалить хост «" + h.name + "» из HostDeck? Агент на нём перестанет подключаться.")) return;
        await api("/api/hosts/" + encodeURIComponent(id), { method: "DELETE" });
        location.hash = "#/";
      } }, "Удалить") : null;
      box.replaceChildren(
        el("div", { class: "row" }, el("h1", { style: "margin:0" }, h.name),
          chip(h.online ? "ok" : "", h.online ? "на связи" : "не на связи"),
          el("span", { class: "spacer", style: "flex:1" }), canRefresh ? refresh : null, del),
        el("p", { class: "sub" }, "Отчёт получен: " + ago(h.posture_at) + " · последний сигнал: " + ago(h.last_seen) +
          (h.agent_version ? " · агент " + h.agent_version : "")),
        el("div", { class: "panel" }, el("h2", {}, "Состояние"),
          h.checks.length ? el("table", {}, checks) : el("div", { class: "empty" }, "Отчёта ещё нет.")),
        el("div", { class: "panel" }, el("h2", {}, "О хосте"), el("table", {}, info)));
    }
    await load();
    timer = setInterval(load, 20000);
  }

  // --- журнал --------------------------------------------------------------------
  async function showAudit() {
    clearTimer();
    setTitle("Журнал");
    if (!me || me.role !== "admin") { app.replaceChildren(el("p", { class: "error" }, "Только для администратора")); return; }
    const rows = await api("/api/audit");
    app.replaceChildren(el("h1", {}, "Журнал событий"), el("p", { class: "sub" }, "Последние 200 записей"),
      el("div", { class: "panel" }, el("table", {},
        el("tr", {}, el("th", {}, "Время"), el("th", {}, "Кто"), el("th", {}, "Действие"), el("th", {}, "Хост"), el("th", {}, "Детали")),
        rows.map((r) => el("tr", {}, el("td", {}, new Date(r.ts * 1000).toLocaleString("ru-RU")), el("td", {}, r.actor || ""),
          el("td", {}, r.action), el("td", {}, r.host || ""), el("td", {}, r.detail || ""))))));
  }

  // --- добавление хоста ----------------------------------------------------------
  function addHostDialog() {
    const label = el("input", { placeholder: "например, MacMiniM2" });
    const out = el("div");
    const close = () => bg.remove();
    const make = el("button", { class: "btn", onclick: async () => {
      try {
        const r = await api("/api/enroll-tokens", { method: "POST", body: { label: label.value } });
        const name = label.value.trim();
        const cmd = `sudo ./hostdeck-agent enroll -server ${location.origin} -token ${r.token}` + (name ? ` -name ${name}` : "");
        out.replaceChildren(el("p", {}, "Выполните на хосте. Токен одноразовый и действует 24 часа, больше он нигде не показывается:"),
          el("pre", {}, cmd));
        make.disabled = true;
      } catch (e) { out.replaceChildren(el("p", { class: "error" }, e.message)); }
    } }, "Создать токен");
    const bg = el("div", { class: "modal-bg", onclick: (e) => { if (e.target === bg) close(); } },
      el("div", { class: "modal" }, el("h2", {}, "Добавить хост"),
        el("label", {}, "Имя хоста (необязательно)"), label, out,
        el("div", { class: "row", style: "margin:14px 0 0" }, make, el("button", { class: "btn ghost", onclick: close }, "Закрыть"))));
    document.body.append(bg);
    label.focus();
  }

  // --- маршрутизация -------------------------------------------------------------
  function route() {
    if (!me) return;
    const h = location.hash || "#/";
    document.getElementById("nav-fleet").classList.toggle("active", h === "#/" || h.startsWith("#/host"));
    document.getElementById("nav-audit").classList.toggle("active", h === "#/audit");
    const m = h.match(/^#\/host\/(.+)$/);
    if (m) showHost(decodeURIComponent(m[1]));
    else if (h === "#/audit") showAudit().catch(() => {});
    else showFleet();
  }
  function start() {
    top.hidden = false;
    document.getElementById("who").textContent = me.name + " (" + me.role + ")";
    document.getElementById("add-host").hidden = me.role !== "admin";
    document.getElementById("nav-audit").hidden = me.role !== "admin";
    route();
  }
  document.getElementById("logout").addEventListener("click", async () => {
    try { await api("/api/logout", { method: "POST", body: {} }); } catch (_) { /* уже вышли */ }
    me = null; showLogin();
  });
  document.getElementById("add-host").addEventListener("click", addHostDialog);
  window.addEventListener("hashchange", route);
  api("/api/me").then((m) => { me = m; start(); }).catch(() => showLogin());
})();
