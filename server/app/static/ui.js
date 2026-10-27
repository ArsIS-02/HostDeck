// Компоненты интерфейса: элементы, иконки, выпадающий список, переключатели, приборы, диалоги.
(() => {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v;
      else if (k === "style" && typeof v === "object") Object.assign(n.style, v);
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else if (v === true) n.setAttribute(k, "");
      else if (v !== false && v != null) n.setAttribute(k, v);
    }
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      n.append(k.nodeType ? k : document.createTextNode(String(k)));
    }
    return n;
  }
  function svg(tag, attrs, ...kids) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    for (const k of kids.flat()) if (k) n.append(k);
    return n;
  }

  // --- иконки (24×24, контур) ---------------------------------------------------------
  const P = {
    laptop: ["M5 6.5A1.5 1.5 0 0 1 6.5 5h11A1.5 1.5 0 0 1 19 6.5V15H5z", "M3 18.5h18l-1.2-2.2a1 1 0 0 0-.9-.5H5.1a1 1 0 0 0-.9.5z"],
    mini: ["M4 11.5A1.5 1.5 0 0 1 5.5 10h13a1.5 1.5 0 0 1 1.5 1.5v3a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 14.5z", "M16.5 13h.01"],
    desktop: ["M4 5.5A1.5 1.5 0 0 1 5.5 4h13A1.5 1.5 0 0 1 20 5.5v9a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 14.5z", "M9 20h6", "M12 16v4"],
    server: ["M5 5.5A1.5 1.5 0 0 1 6.5 4h11A1.5 1.5 0 0 1 19 5.5v3A1.5 1.5 0 0 1 17.5 10h-11A1.5 1.5 0 0 1 5 8.5z", "M5 15.5A1.5 1.5 0 0 1 6.5 14h11a1.5 1.5 0 0 1 1.5 1.5v3a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 18.5z", "M8 7h.01", "M8 17h.01"],
    shield: ["M12 3l7 2.8v5.4c0 4.3-2.9 7.8-7 9.8-4.1-2-7-5.5-7-9.8V5.8z", "M9 12l2.2 2.2L15.5 10"],
    lock: ["M6.5 11h11A1.5 1.5 0 0 1 19 12.5v6a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 18.5v-6A1.5 1.5 0 0 1 6.5 11z", "M8 11V8a4 4 0 0 1 8 0v3"],
    flame: ["M12 3c.5 3-2.5 4.5-2.5 7.5A2.5 2.5 0 0 0 12 13c0-1.5 1.5-2 1.5-3.5 2.2 1.3 3.5 3.3 3.5 5.5a5 5 0 0 1-10 0c0-3 2-4.5 3-6.5.8-1.5 1.8-3 2-5.5z"],
    eye: ["M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z", "M12 14.8a2.8 2.8 0 1 0 0-5.6 2.8 2.8 0 0 0 0 5.6z"],
    refresh: ["M20 11a8 8 0 0 0-14.5-4M4 5v3.5h3.5", "M4 13a8 8 0 0 0 14.5 4M20 19v-3.5h-3.5"],
    download: ["M12 4v11", "M7.5 11L12 15.5 16.5 11", "M5 19.5h14"],
    trash: ["M5 7h14", "M10 7V5h4v2", "M7 7l.8 12h8.4L17 7", "M10 11v5M14 11v5"],
    plus: ["M12 5v14M5 12h14"],
    search: ["M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13z", "M20 20l-4.8-4.8"],
    grid: ["M5 5h5.5v5.5H5z", "M13.5 5H19v5.5h-5.5z", "M5 13.5h5.5V19H5z", "M13.5 13.5H19V19h-5.5z"],
    list: ["M8.5 6.5H19M8.5 12H19M8.5 17.5H19", "M5 6.5h.01M5 12h.01M5 17.5h.01"],
    sun: ["M12 16.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9z", "M12 3v1.5M12 19.5V21M3 12h1.5M19.5 12H21M5.6 5.6l1 1M17.4 17.4l1 1M5.6 18.4l1-1M17.4 6.6l1-1"],
    moon: ["M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"],
    auto: ["M12 20a8 8 0 1 0 0-16 8 8 0 0 0 0 16z", "M12 4v16"],
    globe: ["M12 20.5a8.5 8.5 0 1 0 0-17 8.5 8.5 0 0 0 0 17z", "M3.5 12h17", "M12 3.5c2.5 2.3 3.7 5.1 3.7 8.5s-1.2 6.2-3.7 8.5c-2.5-2.3-3.7-5.1-3.7-8.5S9.5 5.8 12 3.5z"],
    check: ["M5 12.5l4.5 4.5L19 7.5"],
    alert: ["M12 4l9 15.5H3z", "M12 10v4.5", "M12 17.5h.01"],
    x: ["M6 6l12 12M18 6L6 18"],
    info: ["M12 20.5a8.5 8.5 0 1 0 0-17 8.5 8.5 0 0 0 0 17z", "M12 11v5", "M12 8h.01"],
    minus: ["M12 20.5a8.5 8.5 0 1 0 0-17 8.5 8.5 0 0 0 0 17z", "M8.5 12h7"],
    help: ["M12 20.5a8.5 8.5 0 1 0 0-17 8.5 8.5 0 0 0 0 17z", "M9.6 9.6a2.5 2.5 0 0 1 4.8.9c0 1.7-2.4 2.1-2.4 3.5", "M12 16.8h.01"],
    chevron: ["M7 10l5 5 5-5"],
    cpu: ["M8 7h8a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1z", "M10 10h4v4h-4z", "M10 4v3M14 4v3M10 17v3M14 17v3M4 10h3M4 14h3M17 10h3M17 14h3"],
    memory: ["M4 8.5A1.5 1.5 0 0 1 5.5 7h13A1.5 1.5 0 0 1 20 8.5v6a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 14.5z", "M8 16v2.5M12 16v2.5M16 16v2.5", "M8 10.5v2M12 10.5v2M16 10.5v2"],
    disk: ["M4 12.5l2.2-6A1.5 1.5 0 0 1 7.6 5.5h8.8a1.5 1.5 0 0 1 1.4 1l2.2 6", "M4 12.5V17a1.5 1.5 0 0 0 1.5 1.5h13A1.5 1.5 0 0 0 20 17v-4.5z", "M16.5 15.5h.01"],
    battery: ["M4 9.5A1.5 1.5 0 0 1 5.5 8h11A1.5 1.5 0 0 1 18 9.5v5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 14.5z", "M20 11v2"],
    clock: ["M12 20.5a8.5 8.5 0 1 0 0-17 8.5 8.5 0 0 0 0 17z", "M12 7.5V12l3 2"],
    logout: ["M10 5H6.5A1.5 1.5 0 0 0 5 6.5v11A1.5 1.5 0 0 0 6.5 19H10", "M14.5 8l4 4-4 4", "M18.5 12H9.5"],
    box: ["M12 3l8 4.5v9L12 21l-8-4.5v-9z", "M4 7.5l8 4.5 8-4.5", "M12 12v9"],
    apps: ["M5 5h5v5H5z", "M14 5h5v5h-5z", "M5 14h5v5H5z", "M16.5 14v5M14 16.5h5"],
    copy: ["M9 9h9.5A1.5 1.5 0 0 1 20 10.5V19a1.5 1.5 0 0 1-1.5 1.5H10A1.5 1.5 0 0 1 8.5 19v-9.5", "M15 9V6.5A1.5 1.5 0 0 0 13.5 5H5.5A1.5 1.5 0 0 0 4 6.5v8A1.5 1.5 0 0 0 5.5 16H8.5"],
    key: ["M8.5 15a4 4 0 1 1 3.8-5.2L20 10v3h-2v2h-3v-2h-2.7A4 4 0 0 1 8.5 15z"],
    book: ["M5 5.5A1.5 1.5 0 0 1 6.5 4H19v14.5H6.5A1.5 1.5 0 0 0 5 20z", "M5 20a1.5 1.5 0 0 0 1.5 1.5H19"],
    home: ["M4 11l8-6.5 8 6.5", "M6 9.5V19a1 1 0 0 0 1 1h3.5v-5h3v5H17a1 1 0 0 0 1-1V9.5"],
    terminal: ["M4 6.5A1.5 1.5 0 0 1 5.5 5h13A1.5 1.5 0 0 1 20 6.5v11a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 17.5z", "M8 10l3 2-3 2", "M13 15h4"],
    sliders: ["M5 7h9M18 7h1M5 17h1M10 17h9", "M16 7m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0", "M8 17m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0"],
  };
  function icon(name, size = 18, cls = "") {
    const s = svg("svg", { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor", "stroke-width": "1.7", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: "ico " + cls });
    for (const d of P[name] || P.help) s.append(svg("path", { d }));
    return s;
  }
  function hostIcon(h) {
    const m = ((h.info && h.info.model) || "").toLowerCase();
    if ((h.os || "").toLowerCase() === "linux") return "server";
    if (m.includes("book")) return "laptop";
    if (m.includes("mini")) return "mini";
    return "desktop";
  }

  // --- простые элементы -------------------------------------------------------------------
  const STATUS_ICON = { ok: "check", warn: "alert", fail: "x", unknown: "help", info: "info", na: "minus" };
  function badge(status, text, size = 14) {
    return el("span", { class: "badge s-" + status }, icon(STATUS_ICON[status] || "help", size), text ? el("span", {}, text) : null);
  }
  function chip(iconName, text, cls = "") {
    return el("span", { class: "chip " + cls }, iconName ? icon(iconName, 14) : null, el("span", {}, text));
  }
  function progress(pct, opts = {}) {
    const v = Math.max(0, Math.min(100, pct == null ? 0 : pct));
    const lvl = opts.level || (pct == null ? "none" : v >= 90 ? "fail" : v >= 75 ? "warn" : "ok");
    const bar = el("div", { class: "bar l-" + lvl, role: "progressbar", "aria-valuemin": 0, "aria-valuemax": 100, "aria-valuenow": Math.round(v), "aria-label": opts.label || "" },
      el("div", { class: "bar-fill", style: { width: v + "%" } }));
    if (!opts.text) return bar;
    return el("div", { class: "bar-row" }, opts.label ? el("span", { class: "bar-label" }, opts.label) : null, bar, el("span", { class: "bar-val" }, opts.text));
  }
  function checkbox(opts = {}) {
    const input = el("input", { type: "checkbox", class: "cb", "aria-label": opts.label || "" });
    input.checked = !!opts.checked;
    if (opts.onchange) input.addEventListener("change", () => opts.onchange(input.checked));
    return input;
  }
  function button(text, opts = {}) {
    const b = el("button", { type: opts.type || "button", class: "btn " + (opts.kind || "") + (opts.icon && !text ? " icon-only" : "") , title: opts.title || "", "aria-label": opts.title || text || "" },
      opts.icon ? icon(opts.icon, opts.iconSize || 16) : null, text ? el("span", {}, text) : null);
    if (opts.onclick) b.addEventListener("click", opts.onclick);
    if (opts.disabled) b.disabled = true;
    return b;
  }
  function segmented(items, value, onchange, label) {
    const root = el("div", { class: "seg", role: "radiogroup", "aria-label": label || "" });
    const btns = items.map((it) => {
      const b = el("button", { type: "button", role: "radio", class: "seg-item", title: it.label, "aria-label": it.label, "aria-checked": String(it.value === value) },
        it.icon ? icon(it.icon, 16) : null, it.text ? el("span", {}, it.text) : null);
      b.addEventListener("click", () => {
        btns.forEach((x, i) => x.setAttribute("aria-checked", String(items[i].value === it.value)));
        onchange(it.value);
      });
      root.append(b);
      return b;
    });
    return root;
  }

  // --- выпадающий список ---------------------------------------------------------------------
  let openSelect = null;
  function closeSelect() { if (openSelect) { openSelect(); openSelect = null; } }
  document.addEventListener("click", (e) => { if (openSelect && !e.target.closest(".select")) closeSelect(); });

  function select(items, value, onchange, opts = {}) {
    let cur = value;
    const label = el("span", { class: "select-text" });
    const btn = el("button", { type: "button", class: "select-btn", "aria-haspopup": "listbox", "aria-expanded": "false", "aria-label": opts.label || "" },
      opts.icon ? icon(opts.icon, 16) : null, opts.caption ? el("span", { class: "select-cap" }, opts.caption) : null, label, icon("chevron", 16, "select-chev"));
    const list = el("ul", { class: "select-list", role: "listbox", hidden: true, tabindex: "-1" });
    const root = el("div", { class: "select " + (opts.cls || "") }, btn, list);
    let hi = 0;
    function render() {
      list.replaceChildren(...items.map((it, i) => {
        const li = el("li", { role: "option", class: "select-opt" + (it.value === cur ? " sel" : "") + (i === hi ? " hi" : ""), "aria-selected": String(it.value === cur), "data-i": i },
          it.icon ? icon(it.icon, 16) : null, el("span", {}, it.label), it.value === cur ? icon("check", 16, "select-tick") : null);
        li.addEventListener("click", (e) => { e.stopPropagation(); pick(i); });
        li.addEventListener("mousemove", () => { if (hi !== i) { hi = i; mark(); } });
        return li;
      }));
      const c = items.find((x) => x.value === cur) || items[0];
      label.textContent = c ? c.label : "";
    }
    function mark() { [...list.children].forEach((li, i) => li.classList.toggle("hi", i === hi)); }
    function open() {
      closeSelect();
      hi = Math.max(0, items.findIndex((x) => x.value === cur));
      render();
      list.hidden = false;
      btn.setAttribute("aria-expanded", "true");
      root.classList.add("open");
      openSelect = close;
    }
    function close() { list.hidden = true; btn.setAttribute("aria-expanded", "false"); root.classList.remove("open"); }
    function pick(i) {
      cur = items[i].value; render(); close(); openSelect = null; btn.focus();
      onchange(cur);
    }
    btn.addEventListener("click", (e) => { e.stopPropagation(); list.hidden ? open() : (close(), (openSelect = null)); });
    btn.addEventListener("keydown", (e) => {
      const isOpen = !list.hidden;
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        if (!isOpen) return open();
        hi = (hi + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length; mark();
      } else if ((e.key === "Enter" || e.key === " ") && isOpen) {
        e.preventDefault(); pick(hi);
      } else if (e.key === "Escape" && isOpen) {
        e.stopPropagation(); close(); openSelect = null;
      }
    });
    render();
    root.setValue = (v) => { cur = v; render(); };
    return root;
  }

  // --- стрелочный прибор ------------------------------------------------------------------------
  const A0 = -135, A1 = 135; // углы от вертикали, градусы
  function polar(cx, cy, r, deg) {
    const a = ((deg - 90) * Math.PI) / 180;
    return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  }
  function arc(cx, cy, r, d0, d1) {
    const [x0, y0] = polar(cx, cy, r, d0), [x1, y1] = polar(cx, cy, r, d1);
    return `M${x0.toFixed(2)} ${y0.toFixed(2)}A${r} ${r} 0 ${d1 - d0 > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
  }
  // opts: {value (0..100|null), title, text, sub, level, ico, stale}. У результата есть метод update(opts): прибор меняется на месте, стрелка и дуга движутся плавно.
  function gauge(opts) {
    const cx = 100, cy = 100, r = 74;
    const s = svg("svg", { viewBox: "0 0 200 162", class: "gauge-svg", role: "img" });
    s.append(svg("path", { d: arc(cx, cy, r, A0, A1), class: "g-track", fill: "none", "stroke-width": "12", "stroke-linecap": "round" }));
    const valArc = svg("path", { d: arc(cx, cy, r, A0, A1), class: "g-val", fill: "none", "stroke-width": "12", "stroke-linecap": "round", pathLength: "100", "stroke-dasharray": "0 100" });
    s.append(valArc);
    for (let i = 0; i <= 10; i++) {
      const d = A0 + (A1 - A0) * (i / 10), major = i % 5 === 0;
      const [x0, y0] = polar(cx, cy, r - 12, d), [x1, y1] = polar(cx, cy, r - (major ? 21 : 17), d);
      s.append(svg("line", { x1: x0.toFixed(1), y1: y0.toFixed(1), x2: x1.toFixed(1), y2: y1.toFixed(1), class: "g-tick" + (major ? " major" : "") }));
    }
    const needle = svg("g", { class: "g-needle" }, svg("path", { d: `M${cx - 3} ${cy}L${cx} ${cy - 58}L${cx + 3} ${cy}Z`, class: "g-hand" }));
    const val = svg("text", { x: cx, y: 144, "text-anchor": "middle", class: "g-text" });
    s.append(needle, svg("circle", { cx, cy, r: 7, class: "g-hub" }), svg("circle", { cx, cy, r: 2.6, class: "g-hub-in" }), val);
    const title = el("span", { class: "g-title" }, opts.ico ? icon(opts.ico, 15) : null, opts.title);
    const sub = el("span", { class: "g-sub" });
    const fig = el("figure", { class: "gauge" }, s, el("figcaption", {}, title, sub));
    fig.update = (o) => {
      const has = o.value != null && !o.stale;
      const v = Math.max(0, Math.min(100, o.value == null ? 0 : o.value));
      const lvl = !has ? "none" : o.level || (v >= 90 ? "fail" : v >= 75 ? "warn" : "ok");
      s.setAttribute("class", "gauge-svg l-" + lvl);
      s.setAttribute("aria-label", `${o.title}: ${o.text}`);
      const ang = A0 + (A1 - A0) * ((has ? v : 0) / 100);
      needle.style.transform = `rotate(${has ? ang : A0}deg)`;
      valArc.setAttribute("stroke-dasharray", `${has && v > 0.5 ? v : 0} 100`);
      val.textContent = has ? o.text : "—";
      sub.textContent = o.sub || "";
      fig.classList.toggle("off", !has);
    };
    fig.update(opts);
    return fig;
  }

  // Мини-график значений 0..100 за период [t0, t1]; spark.set(points, t0, t1), points = [[t, value|null], ...]
  function spark() {
    const W = 200, H = 38;
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "spark", preserveAspectRatio: "none", "aria-hidden": "true" });
    const area = svg("path", { class: "sp-area", d: "" }), line = svg("path", { class: "sp-line", d: "", fill: "none" });
    root.append(svg("line", { x1: 0, y1: H - 0.5, x2: W, y2: H - 0.5, class: "sp-base" }), area, line);
    const wrap = el("div", { class: "spark-box" }, root);
    const cap = el("span", { class: "sp-max" });
    wrap.append(cap);
    wrap.set = (pts, t0, t1) => {
      const ok = pts.filter((p) => p[1] != null && p[0] >= t0 && p[0] <= t1);
      if (ok.length < 2) { line.setAttribute("d", ""); area.setAttribute("d", ""); cap.textContent = ""; return; }
      const mx = Math.max(...ok.map((p) => p[1])), top = Math.min(100, Math.max(25, Math.ceil((mx * 1.15) / 25) * 25));
      const X = (t) => ((t - t0) / (t1 - t0)) * W, Y = (v) => H - 2 - (Math.min(v, top) / top) * (H - 6);
      // разрыв (хост был выключен) рисуем разрывом линии: больше 5 минут, а на длинных периодах больше 1/40 периода
      const gap = Math.max(300, (t1 - t0) / 40);
      let d = "", dArea = "", prevT = null, seg = [];
      const flush = () => {
        if (seg.length > 1) { d += "M" + seg.map(([x, y]) => x.toFixed(1) + " " + y.toFixed(1)).join("L"); dArea += `M${seg[0][0].toFixed(1)} ${H}L` + seg.map(([x, y]) => x.toFixed(1) + " " + y.toFixed(1)).join("L") + `L${seg[seg.length - 1][0].toFixed(1)} ${H}Z`; }
        seg = [];
      };
      for (const p of ok) { if (prevT != null && p[0] - prevT > gap) flush(); seg.push([X(p[0]), Y(p[1])]); prevT = p[0]; }
      flush();
      line.setAttribute("d", d); area.setAttribute("d", dArea);
      cap.textContent = top + "%";
    };
    return wrap;
  }

  // --- диалоги и уведомления -------------------------------------------------------------------------
  let modalDepth = 0;
  // dialog({title, body (Node), buttons:[{text, kind, value, keep}], wide}) -> Promise<value>
  function dialog(opts) {
    return new Promise((resolve) => {
      const prev = document.activeElement;
      const titleId = "dlg-t-" + Math.random().toString(36).slice(2, 7);
      const done = (val) => { document.removeEventListener("keydown", onKey, true); veil.classList.add("out"); setTimeout(() => veil.remove(), 160); modalDepth--; if (prev && prev.focus) prev.focus(); resolve(val); };
      const btns = (opts.buttons || [{ text: window.I18N.t("common.close"), value: true, kind: "primary" }]).map((b) => {
        const x = button(b.text, { kind: b.kind || "", onclick: () => { if (b.keep) b.onclick && b.onclick(x); else done(b.value); } });
        return x;
      });
      const box = el("div", { class: "dialog" + (opts.wide ? " wide" : "") + (opts.cls ? " " + opts.cls : ""), role: "dialog", "aria-modal": "true", "aria-labelledby": titleId },
        el("div", { class: "dialog-head" }, opts.icon ? el("span", { class: "dialog-ico k-" + (opts.tone || "info") }, icon(opts.icon, 22)) : null,
          el("h2", { id: titleId }, opts.title)),
        opts.body ? el("div", { class: "dialog-body" }, opts.body) : null,
        el("div", { class: "dialog-foot" }, btns));
      const veil = el("div", { class: "veil" }, box);
      veil.addEventListener("mousedown", (e) => { if (e.target === veil && opts.dismiss !== false) done(undefined); });
      function onKey(e) {
        if (e.key === "Escape" && opts.dismiss !== false) { e.stopPropagation(); done(undefined); }
        else if (e.key === "Tab") {
          const f = [...box.querySelectorAll("button, input, select, a[href], textarea, [tabindex]:not([tabindex='-1'])")].filter((n) => !n.disabled && n.offsetParent !== null);
          if (!f.length) return;
          const first = f[0], last = f[f.length - 1];
          if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
          else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
      }
      document.addEventListener("keydown", onKey, true);
      modalDepth++;
      document.body.append(veil);
      const focusTarget = box.querySelector("[autofocus], input") || btns[btns.length - 1];
      setTimeout(() => focusTarget && focusTarget.focus(), 30);
    });
  }

  // --- всплывающая подсказка: по наведению, фокусу и касанию; её содержимое можно выделять и копировать -------------------------------
  let tipBox = null, tipTarget = null, tipTimer = 0, tipPinned = false, tipHover = false;
  function tipHide() {
    clearTimeout(tipTimer);
    tipPinned = false; tipHover = false;
    if (tipBox) { tipBox.remove(); tipBox = null; }
    if (tipTarget) { tipTarget.removeAttribute("aria-describedby"); tipTarget = null; }
  }
  let tipShownAt = 0;
  function tipPlace() {
    if (!tipBox || !tipTarget) return;
    const r = tipTarget.getBoundingClientRect(), b = tipBox.getBoundingClientRect(), vw = document.documentElement.clientWidth, vh = window.innerHeight, gap = 8;
    let top = r.bottom + gap;
    if (top + b.height > vh - 8 && r.top - gap - b.height > 8) top = r.top - gap - b.height;   // не помещается снизу — показать сверху
    top = Math.max(8, Math.min(top, vh - b.height - 8));
    const left = Math.max(8, Math.min(r.left + r.width / 2 - b.width / 2, vw - b.width - 8));
    tipBox.style.top = top + "px"; tipBox.style.left = left + "px";
  }
  function tipShow(target, build) {
    tipHide();
    const id = "tip-" + Math.random().toString(36).slice(2, 7);
    tipBox = el("div", { class: "tip", role: "tooltip", id }, build());
    // подсказку можно «закрепить»: нажатие внутри неё (выделение текста, кнопка «Копировать») отменяет автозакрытие;
    // закрывается она по Esc, по кнопке × или по щелчку вне подсказки
    const closeBtn = el("button", { class: "tip-x", type: "button", "aria-label": window.I18N.t("common.close"), title: window.I18N.t("common.close") }, "×");
    closeBtn.addEventListener("click", (e) => { e.stopPropagation(); tipHide(); });
    tipBox.prepend(closeBtn);
    tipBox.addEventListener("pointerdown", () => { tipPinned = true; tipBox && tipBox.classList.add("pinned"); clearTimeout(tipTimer); });
    tipBox.addEventListener("mouseenter", () => { tipHover = true; clearTimeout(tipTimer); });
    tipBox.addEventListener("mouseleave", () => {
      tipHover = false;
      if (tipPinned) return;
      tipTimer = setTimeout(() => { const sel = window.getSelection && window.getSelection(); if (!(sel && !sel.isCollapsed && tipBox && tipBox.contains(sel.anchorNode))) tipHide(); }, 180);
    });
    document.body.append(tipBox);
    tipTarget = target; target.setAttribute("aria-describedby", id);
    tipShownAt = performance.now();
    tipPlace();
    tipBox.classList.add("on");
  }
  function tip(target, build) {
    target.classList.add("has-tip");
    target.setAttribute("tabindex", "0"); target.setAttribute("role", "button");
    target.setAttribute("aria-label", window.I18N.t("tip.aria"));
    target.addEventListener("mouseenter", () => { clearTimeout(tipTimer); tipTimer = setTimeout(() => tipShow(target, build), 120); });
    target.addEventListener("mouseleave", () => { clearTimeout(tipTimer); tipTimer = setTimeout(() => { if (!tipPinned && !tipHover) tipHide(); }, 180); });
    target.addEventListener("focus", () => tipShow(target, build));
    target.addEventListener("blur", () => { tipTimer = setTimeout(() => { if (!tipPinned && !tipHover) tipHide(); }, 120); });
    target.addEventListener("click", (e) => { e.stopPropagation(); if (tipTarget === target) tipHide(); else tipShow(target, build); });   // касание на телефоне
    target.addEventListener("keydown", (e) => { if (e.key === "Escape") tipHide(); });
    return target;
  }
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") tipHide(); });
  // Прокрутка закрывает подсказку, кроме прокрутки внутри неё. Сразу после показа (фокус с клавиатуры сам прокручивает страницу
  // к элементу) подсказку не закрываем, а переставляем к элементу.
  document.addEventListener("scroll", (e) => {
    if (tipBox && e.target instanceof Node && tipBox.contains(e.target)) return;
    if (tipPinned) return;   // закреплённая подсказка остаётся на месте при прокрутке страницы
    if (tipBox && performance.now() - tipShownAt < 400) { tipPlace(); return; }
    tipHide();
  }, true);   // прокрутка внутри самой подсказки её не закрывает
  document.addEventListener("click", (e) => { if (tipBox && !tipBox.contains(e.target) && !(tipTarget && tipTarget.contains(e.target))) tipHide(); });
  async function confirmDialog({ title, body, ok, tone = "danger", icon: ic = "alert" }) {
    const T = window.I18N.t;
    const r = await dialog({ title, icon: ic, tone, body: el("p", {}, body),
      buttons: [{ text: T("common.cancel"), value: false }, { text: ok, value: true, kind: tone === "danger" ? "danger" : "primary" }] });
    return r === true;
  }
  function toast(text, kind = "ok") {
    let host = document.getElementById("toasts");
    if (!host) { host = el("div", { id: "toasts", "aria-live": "polite" }); document.body.append(host); }
    const n = el("div", { class: "toast k-" + kind }, icon(kind === "error" ? "alert" : "check", 18), el("span", {}, text));
    host.append(n);
    setTimeout(() => { n.classList.add("out"); setTimeout(() => n.remove(), 250); }, kind === "error" ? 6000 : 3200);
  }

  window.UI = { el, svg, icon, hostIcon, badge, chip, progress, checkbox, button, segmented, select, gauge, spark, dialog, confirmDialog, toast, closeSelect, tip, tipHide };
})();
