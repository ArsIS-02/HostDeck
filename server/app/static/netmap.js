// Сетевая карта: граф связей между хостами (силовая раскладка, перетаскивание, масштаб) и топология подсетей.
// Данные присылают агенты пассивно (интерфейсы, ARP, соединения); интерфейс ничего не сканирует.
(() => {
  "use strict";
  const { el, svg, icon, chip, button, segmented, select, dialog, toast, checkbox } = window.UI;
  const T = (k, p) => window.I18N.t(k, p);
  const CMD = "sudo /usr/local/bin/hostdeck-agent set -network on && sudo systemctl restart hostdeck-agent";
  const CATS = ["admin", "web", "infra", "logs", "db", "mail", "files", "mon", "other"];
  const COLOR = { admin: "#bf5af2", web: "#0a84ff", infra: "#30b0c7", logs: "#ff9f0a", db: "#ff375f", mail: "#a2845e", files: "#5e5ce6", mon: "#34c759", other: "#8e8e93" };
  const S = { tab: "map", fam: "4", hours: 24, ext: "group", off: new Set(), hideDev: false, q: "" }; // состояние страницы живёт, пока открыта вкладка браузера
  const num = (n) => Number(n).toLocaleString(window.I18N.lang === "ru" ? "ru-RU" : "en-GB");

  const hint = (title, text, cmd) => el("div", { class: "card ctr-hint ctr-hint-off" }, icon("lock", 18),
    el("div", {}, el("strong", {}, title), el("p", { class: "muted small" }, text), cmd ? el("pre", { class: "code" }, cmd) : null));

  function table(head, rows, cls = "") {
    return el("div", { class: "tbl-wrap" }, el("table", { class: "tbl " + cls },
      el("thead", {}, el("tr", {}, head.map((h) => el("th", { class: h[1] || "" }, h[0])))),
      el("tbody", {}, rows)));
  }

  // --- подпись устройства ------------------------------------------------------------------------------------------------------------------
  async function labelDialog(ctx, ip, name, note) {
    const nm = el("input", { class: "input", value: name || "", maxlength: 80, placeholder: T("net.label.ph"), "aria-label": T("net.label.name") });
    const nt = el("input", { class: "input", value: note || "", maxlength: 300, "aria-label": T("net.label.note") });
    const body = el("div", { class: "form" }, el("label", { class: "field" }, el("span", {}, T("net.label.name")), nm), el("label", { class: "field" }, el("span", {}, T("net.label.note")), nt),
      el("p", { class: "muted small" }, T("net.label.hint")));
    setTimeout(() => nm.focus(), 50);
    const ok = await dialog({ title: T("net.label.title", { ip }), icon: "sliders", tone: "info", body,
      buttons: [{ text: T("common.cancel"), value: false }, { text: T("bulk.apply"), value: true, kind: "primary" }] });
    if (ok !== true) return false;
    try {
      await ctx.api("/api/network/label", { method: "POST", body: { ip, name: nm.value, note: nt.value } });
      toast(T(nm.value.trim() ? "net.label.saved" : "net.label.removed"));
      return true;
    } catch (e) { ctx.fail(e); return false; }
  }

  // --- граф ------------------------------------------------------------------------------------------------------------------
  function buildPairs(links) {
    const pairs = new Map();
    for (const l of links) {
      const k = l.from < l.to ? l.from + "\u0000" + l.to : l.to + "\u0000" + l.from;
      let p = pairs.get(k);
      if (!p) { p = { a: l.from < l.to ? l.from : l.to, b: l.from < l.to ? l.to : l.from, items: [], n: 0, ab: false, ba: false }; pairs.set(k, p); }
      p.items.push(l); p.n += l.n;
      if (l.from === p.a) p.ab = true; else p.ba = true;
    }
    for (const p of pairs.values()) { p.items.sort((x, y) => y.n - x.n); p.cat = p.items[0].cat; }
    return [...pairs.values()];
  }

  function nodeIcon(n) {
    if (n.kind === "internet") return "globe";
    if (n.kind === "host") return (n.os || "").toLowerCase() === "linux" ? "server" : "desktop";
    return "sliders";
  }
  const nodeR = (n) => (n.kind === "host" ? 21 : n.kind === "internet" ? 22 : n.kind === "external" ? 11 : 16);
  const IPLIKE = /^[0-9a-f:.]+$/i;
  // короткое имя для подписи: домен отрезается (полное имя видно в подсказке и панели)
  function shortName(n) {
    let t = n.name;
    if (n.kind === "host" && !IPLIKE.test(t) && t.includes(".")) t = t.split(".")[0];
    return t.length > 16 ? t.slice(0, 15) + "…" : t;
  }
  function zoneTitle(z) {
    if (z === "ext") return T("net.zone.ext");
    if (z === "none") return T("net.zone.none", { f: S.fam === "6" ? "IPv6" : "IPv4" });
    return z;
  }

  // Раскладка по зонам: каждая подсеть — своя рамка, внутри узлы сеткой (хосты с агентом, затем устройства); внешние адреса отдельной зоной.
  // Раскладка детерминирована, поэтому карта не «прыгает» при обновлении и не превращается в клубок при десятках хостов.
  function layout(nodes, zones, W) {
    const CW = 118, CH = 92, PAD = 18, TITLE = 30, GAP = 22;
    const order = { host: 0, device: 1, internet: 2, external: 3 };
    const boxes = zones.map((z) => {
      const list = nodes.filter((n) => n.zone === z).sort((x, y) => order[x.kind] - order[y.kind] || x.name.localeCompare(y.name, undefined, { numeric: true }));
      const cols = Math.max(1, Math.min(z === "ext" ? 8 : 6, Math.ceil(Math.sqrt(list.length * 1.5))));
      const rows = Math.ceil(list.length / cols);
      return { z, list, cols, w: cols * CW + PAD * 2, h: rows * CH + TITLE + PAD, x: 0, y: 0 };
    }).filter((b) => b.list.length);
    const maxW = Math.max(W - 40, 560);
    let x = 20, y = 20, rowH = 0, totalW = 0;
    for (const b of boxes) {
      if (x > 20 && x + b.w > maxW) { x = 20; y += rowH + GAP; rowH = 0; }
      b.x = x; b.y = y; x += b.w + GAP; rowH = Math.max(rowH, b.h); totalW = Math.max(totalW, b.x + b.w);
      b.list.forEach((n, i) => { n.x = b.x + PAD + (i % b.cols) * CW + CW / 2; n.y = b.y + TITLE + Math.floor(i / b.cols) * CH + CH / 2 - 10; });
    }
    return { boxes, w: totalW + 20, h: y + rowH + 20 };
  }

  function graph(ctx, data, box, panel, selectState) {
    // хосты без адресов этого семейства (например, без IPv6) на графе не рисуются: их число показано над ним
    const nodes = data.nodes.filter((n) => n.zone !== "none" && !(S.hideDev && (n.kind === "device" || n.kind === "external")));
    const ids = new Set(nodes.map((n) => n.id));
    const links = data.links.filter((l) => !S.off.has(l.cat) && ids.has(l.from) && ids.has(l.to));
    const pairs = buildPairs(links);
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const W = Math.max(520, box.clientWidth || 900);
    const q = S.q.trim().toLowerCase();
    const match = (n) => !q || n.name.toLowerCase().includes(q) || (n.ips || []).some((i) => i.includes(q));
    const zones = data.zones.filter((z) => nodes.some((n) => n.zone === z));
    const lay = layout(nodes, zones, W);
    const H = Math.round(Math.max(420, Math.min(900, lay.h * Math.min(1, W / lay.w) + 10)));
    for (const n of nodes) { const d = graph.pos.get(n.id); if (d) { n.x = d.x; n.y = d.y; } }

    const view = { k: 1, x: 0, y: 0 };
    const root = svg("svg", { class: "nm-svg", viewBox: `0 0 ${W} ${H}`, width: "100%", height: H, role: "img", "aria-label": T("net.title") });
    const defs = svg("defs", {});
    for (const c of CATS) defs.append(svg("marker", { id: "nm-arr-" + c, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 5, markerHeight: 5, orient: "auto-start-reverse" }, svg("path", { d: "M0 1l9 4-9 4z", fill: COLOR[c] })));
    const vp = svg("g", { class: "nm-vp" });
    const gz = svg("g", {}), gl = svg("g", {}), gn = svg("g", {});
    vp.append(gz, gl, gn);
    root.append(svg("rect", { class: "nm-bg", x: 0, y: 0, width: W, height: H, fill: "transparent" }), defs, vp);
    for (const b of lay.boxes) {
      const t = svg("text", { class: "nm-zone-t", x: b.x + 16, y: b.y + 21 });
      t.textContent = zoneTitle(b.z);
      const c = svg("text", { class: "nm-zone-c", x: b.x + b.w - 16, y: b.y + 21, "text-anchor": "end" });
      c.textContent = T("net.zone.n", { n: b.list.length });
      gz.append(svg("g", { class: "nm-zone k-" + (b.z === "ext" || b.z === "none" ? b.z : "lan") }, svg("rect", { x: b.x, y: b.y, width: b.w, height: b.h, rx: 16 }), t, c));
    }
    const apply = () => vp.setAttribute("transform", `translate(${view.x} ${view.y}) scale(${view.k})`);
    // связь — лёгкая дуга: пары, идущие через соседние узлы, не сливаются в одну прямую
    const path = (p) => {
      const a = byId.get(p.a), b = byId.get(p.b), dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
      const off = Math.min(60, d * 0.14), cx = (a.x + b.x) / 2 - (dy / d) * off, cy = (a.y + b.y) / 2 + (dx / d) * off;
      const t = (px, py, r) => { const ux = px - cx, uy = py - cy, l = Math.sqrt(ux * ux + uy * uy) || 1; return [px - (ux / l) * r, py - (uy / l) * r]; };
      const [x1, y1] = t(a.x, a.y, nodeR(a) + 4), [x2, y2] = t(b.x, b.y, nodeR(b) + 4);
      return `M${x1} ${y1} Q${cx} ${cy} ${x2} ${y2}`;
    };
    const elems = pairs.map((p) => {
      const w = Math.min(5, 1 + Math.log2(p.n + 1) * 0.7);
      const sv = p.items.slice(0, 6).map((l) => `${l.service}:${l.port}`).join(", ");
      const line = svg("path", { class: "nm-link", fill: "none", stroke: COLOR[p.cat], "stroke-width": w, "marker-end": p.ab ? `url(#nm-arr-${p.cat})` : null, "marker-start": p.ba ? `url(#nm-arr-${p.cat})` : null });
      const hit = svg("path", { class: "nm-hit", fill: "none", stroke: "transparent", "stroke-width": 14 });
      const g = svg("g", { class: "nm-pair", tabindex: 0, role: "button", "aria-label": `${byId.get(p.a).name} ↔ ${byId.get(p.b).name}: ${sv}` }, svg("title", {}, `${byId.get(p.a).name} ↔ ${byId.get(p.b).name}\n${sv}`), line, hit);
      g.addEventListener("click", (e) => { e.stopPropagation(); selectState.set({ pair: p }); });
      g.addEventListener("keydown", (e) => { if (e.key === "Enter") selectState.set({ pair: p }); });
      gl.append(g);
      return { p, line, hit, g };
    });
    let paintFn = () => {};
    const nelems = nodes.map((n) => {
      const r = nodeR(n);
      const cls = "nm-node k-" + n.kind + (n.kind === "host" && !n.online ? " off" : "") + (n.kind === "host" && !n.collecting ? " nocol" : "");
      const g = svg("g", { class: cls, tabindex: 0, role: "button", "aria-label": n.name });
      const ic = icon(nodeIcon(n), r * 0.95); ic.setAttribute("x", -r * 0.475); ic.setAttribute("y", -r * 0.475);
      const lab = svg("text", { class: "nm-label", y: r + 14, "text-anchor": "middle" });
      lab.textContent = shortName(n);
      g.append(svg("title", {}, n.name + (n.ips && n.ips.length ? "\n" + n.ips.slice(0, 6).join(", ") : "")), svg("circle", { r }), n.kind === "external" ? null : ic, lab);
      let moved = false;
      g.addEventListener("pointerenter", () => { if (!selectState.cur) paintFn({ node: n }); });
      g.addEventListener("pointerleave", () => paintFn(selectState.cur));
      g.addEventListener("pointerdown", (e) => {
        e.stopPropagation(); g.setPointerCapture(e.pointerId); moved = false;
        const move = (ev) => {
          const rc = root.getBoundingClientRect(), sx = W / rc.width;
          n.x = ((ev.clientX - rc.left) * sx - view.x) / view.k; n.y = ((ev.clientY - rc.top) * sx - view.y) / view.k; moved = true; place();
        };
        const up = () => { g.removeEventListener("pointermove", move); g.removeEventListener("pointerup", up); if (moved) graph.pos.set(n.id, { x: n.x, y: n.y }); else selectState.set({ node: n }); };
        g.addEventListener("pointermove", move); g.addEventListener("pointerup", up);
      });
      g.addEventListener("keydown", (e) => { if (e.key === "Enter") selectState.set({ node: n }); });
      gn.append(g);
      return { n, g };
    });
    const place = () => {
      for (const { n, g } of nelems) g.setAttribute("transform", `translate(${n.x} ${n.y})`);
      for (const { p, line, hit } of elems) { const d = path(p); line.setAttribute("d", d); hit.setAttribute("d", d); }
    };
    place();
    // выделение, наведение и поиск: не относящееся к выбранному гасится
    const paint = (sel) => {
      const near = new Set();
      if (sel && sel.node) { near.add(sel.node.id); for (const p of pairs) { if (p.a === sel.node.id) near.add(p.b); if (p.b === sel.node.id) near.add(p.a); } }
      if (sel && sel.pair) { near.add(sel.pair.a); near.add(sel.pair.b); }
      for (const { n, g } of nelems) {
        g.classList.toggle("dim", (!!sel && !!(sel.node || sel.pair) && !near.has(n.id)) || !match(n));
        g.classList.toggle("sel", !!sel && !!sel.node && sel.node.id === n.id);
        g.classList.toggle("near", !!sel && near.has(n.id) && n.kind === "external");
      }
      for (const { p, g } of elems) {
        g.classList.toggle("dim", !!sel && ((sel.node && p.a !== sel.node.id && p.b !== sel.node.id) || (sel.pair && sel.pair !== p)));
        g.classList.toggle("hot", !!sel && ((sel.node && (p.a === sel.node.id || p.b === sel.node.id)) || sel.pair === p));
      }
    };
    paintFn = paint;
    // масштаб и сдвиг
    const toWorld = (ev) => { const rc = root.getBoundingClientRect(), sx = W / rc.width; return { x: (ev.clientX - rc.left) * sx, y: (ev.clientY - rc.top) * sx }; };
    const zoomAt = (f, cx, cy) => {
      const k = Math.max(0.25, Math.min(3.5, view.k * f)), r = k / view.k;
      view.x = cx - (cx - view.x) * r; view.y = cy - (cy - view.y) * r; view.k = k; apply();
    };
    root.addEventListener("wheel", (e) => { e.preventDefault(); const c = toWorld(e); zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, c.x, c.y); }, { passive: false });
    root.addEventListener("pointerdown", (e) => {
      if (e.target !== root && !e.target.classList.contains("nm-bg") && !e.target.closest(".nm-zone")) return;
      root.setPointerCapture(e.pointerId); const s0 = toWorld(e), v0 = { x: view.x, y: view.y }; let moved = false;
      const move = (ev) => { const c = toWorld(ev); view.x = v0.x + c.x - s0.x; view.y = v0.y + c.y - s0.y; moved = true; apply(); };
      const up = () => { root.removeEventListener("pointermove", move); root.removeEventListener("pointerup", up); if (!moved) selectState.set(null); };
      root.addEventListener("pointermove", move); root.addEventListener("pointerup", up);
    });
    const fit = () => {
      const k = Math.max(0.25, Math.min(1.4, Math.min(W / lay.w, H / lay.h)));
      view.k = k; view.x = (W - lay.w * k) / 2; view.y = Math.max(0, (H - lay.h * k) / 2); apply();
    };
    fit();
    return { el: root, paint, byId, pairs, zoom: (f) => zoomAt(f, W / 2, H / 2), fit, stop: () => {} };
  }
  graph.pos = new Map();

  // --- панель справа -------------------------------------------------------------------------------------------------------------
  function panel(ctx, data, g, sel) {
    const box = el("aside", { class: "card nm-panel", "aria-live": "polite" });
    const name = (id) => (g.byId.get(id) || { name: id }).name;
    const linkRow = (l, self) => {
      const out = self ? l.from === self : null;
      return el("tr", {},
        self ? el("td", { class: "nowrap", title: T(out ? "net.dir.out" : "net.dir.in") }, out ? "→" : "←") : null,
        self ? el("td", {}, name(out ? l.to : l.from)) : el("td", {}, name(l.from) + " → " + name(l.to)),
        el("td", {}, el("div", { class: "nowrap" }, el("span", { class: "nm-dot", style: { background: COLOR[l.cat] } }), l.service, el("span", { class: "muted mono" }, " :" + l.port)),
          l.procs.length ? el("div", { class: "muted small" }, l.procs.join(", ")) : null),
        el("td", { class: "num", title: l.peers > 1 ? T("net.peers", { n: l.peers }) : "" }, num(l.n)));
    };
    const head = (self) => [self ? [""] : null, [T("net.col.peer")], [T("net.col.service")], [T("net.col.cnt"), "num"]].filter(Boolean);
    const draw = (s) => {
      if (!s) { box.replaceChildren(el("p", { class: "muted small" }, T("net.help")), legend()); return; }
      if (s.pair) {
        box.replaceChildren(el("h3", {}, name(s.pair.a) + " ↔ " + name(s.pair.b)), table(head(null), s.pair.items.map((l) => linkRow(l, null)), "compact"), legend());
        return;
      }
      const n = s.node, mine = data.links.filter((l) => (l.from === n.id || l.to === n.id) && !S.off.has(l.cat));
      const kids = [el("div", { class: "nm-pt" }, el("h3", {}, n.name), chip(null, T("net.node." + n.kind), n.kind === "host" ? (n.online ? "c-ok" : "c-off") : ""))];
      if (n.kind === "host" && !n.online) kids.push(el("p", { class: "muted small" }, T("net.node.offline")));
      if (n.kind === "host" && !n.collecting) kids.push(el("p", { class: "muted small" }, T("net.node.nocollect")));
      if (n.ips && n.ips.length) kids.push(el("p", { class: "small" }, el("span", { class: "muted" }, T("net.node.ips") + ": "), el("span", { class: "mono" }, n.ips.slice(0, 8).join(", ") + (n.kind === "internet" && n.count > n.ips.length ? " …" : ""))));
      if (n.kind === "host") kids.push(el("div", {}, button(T("net.node.open"), { icon: "chevron", onclick: () => { location.hash = "#/host/" + encodeURIComponent(n.id); } })));
      if (n.kind === "device" && ctx.me.role !== "viewer") kids.push(el("div", {}, button(T("net.topo.rename"), { icon: "sliders", onclick: async () => { if (await labelDialog(ctx, n.ips[0], n.labeled ? n.name : "", "")) ctx.reload(); } })));
      kids.push(el("h4", {}, T("net.node.links")), mine.length ? table(head(n.id), mine.slice(0, 80).map((l) => linkRow(l, n.id)), "compact") : el("p", { class: "muted small" }, T("net.node.none")));
      box.replaceChildren(...kids, legend());
    };
    const legend = () => {
      const have = {};
      for (const l of data.links) have[l.cat] = (have[l.cat] || 0) + 1;
      return el("div", { class: "nm-legend" }, CATS.filter((c) => have[c]).map((c) => el("button", { type: "button", class: "nm-cat" + (S.off.has(c) ? " off" : ""), "aria-pressed": String(!S.off.has(c)),
        onclick: () => { if (S.off.has(c)) S.off.delete(c); else S.off.add(c); ctx.redraw(); } }, el("span", { class: "nm-dot", style: { background: COLOR[c] } }), T("net.cat." + c), el("span", { class: "muted small" }, " " + have[c]))));
    };
    return { el: box, draw, legend };
  }

  // --- страница -------------------------------------------------------------------------------------------------------------
  function page(ctx) {
    const root = el("main", { class: "page netmap" });
    const body = el("div", {});
    let data = null, topo = null, sig = "", timer = null, gobj = null;
    const sel = { cur: null, set: (v) => { sel.cur = v; if (gobj) gobj.paint(v); pan && pan.draw(v); } };
    let pan = null;

    const load = async (force) => {
      try {
        const [m, t] = await Promise.all([ctx.api(`/api/network/map?hours=${S.hours}&external=${S.ext}&family=${S.fam}`), ctx.api("/api/network/topology?family=" + S.fam)]);
        const s = JSON.stringify([S.tab, S.fam, S.hours, S.ext, m.nodes.map((n) => [n.id, n.name, n.online]), m.links.map((l) => [l.from, l.to, l.port, l.n]), t.subnets.map((x) => [x.cidr, x.devices.map((d) => d.name)])]);
        data = m; topo = t;
        if (force || s !== sig) { sig = s; draw(); }
      } catch (e) { ctx.fail(e); }
    };
    ctx.reload = () => load(true);
    ctx.redraw = () => draw();

    const toolbar = () => {
      const left = [
        segmented([{ value: "map", text: T("net.tab.map"), icon: "network" }, { value: "topo", text: T("net.tab.topo"), icon: "grid" }], S.tab, (v) => { S.tab = v; sel.cur = null; draw(); }, T("net.title")),
      ];
      left.push(segmented([{ value: "4", text: "IPv4" }, { value: "6", text: "IPv6" }], S.fam, (v) => { S.fam = v; sel.cur = null; graph.pos.clear(); load(true); }, T("net.fam")));
      if (S.tab === "map") {
        const search = el("input", { class: "input nm-search", type: "search", placeholder: T("net.search"), "aria-label": T("net.search"), value: S.q });
        search.addEventListener("input", () => { S.q = search.value; if (gobj) gobj.paint(sel.cur); });
        left.push(select([1, 24, 168].map((h) => ({ value: h, label: T("net.h." + h) })), S.hours, (v) => { S.hours = Number(v); load(true); }, { icon: "clock", caption: T("net.hours") }),
          select([{ value: "group", label: T("net.ext.group") }, { value: "ip", label: T("net.ext.ip") }], S.ext, (v) => { S.ext = v; load(true); }, { icon: "globe", caption: T("net.ext") }),
          el("label", { class: "cb-line" }, checkbox({ label: T("net.hide.dev"), checked: S.hideDev, onchange: (v) => { S.hideDev = v; draw(); } }), el("span", {}, T("net.hide.dev"))),
          search);
      }
      left.push(el("span", { class: "spacer" }));
      if (S.tab === "map") left.push(button("", { icon: "plus", title: T("net.zoom.in"), kind: "ghost", onclick: () => gobj && gobj.zoom(1.25) }), button("", { icon: "minus", title: T("net.zoom.out"), kind: "ghost", onclick: () => gobj && gobj.zoom(0.8) }), button("", { icon: "grid", title: T("net.zoom.fit"), kind: "ghost", onclick: () => gobj && gobj.fit() }));
      if (ctx.me.role !== "viewer") left.push(button(T("net.refresh"), { icon: "refresh", onclick: async () => {
        try { const r = await ctx.api("/api/network/refresh", { method: "POST", body: {} }); toast(r.queued ? T("net.refresh.queued", { n: r.queued }) : T("net.refresh.none"), r.queued ? "ok" : "error"); if (r.queued) setTimeout(() => load(true), 4000); } catch (e) { ctx.fail(e); } } }));
      return el("div", { class: "toolbar" }, left);
    };

    const emptyHint = () => el("div", { class: "card" }, el("div", { class: "empty" }, icon("network", 40), el("h3", {}, T("net.empty.t")), el("p", {}, T("net.empty.d")), el("pre", { class: "code" }, CMD)));

    const draw = () => {
      if (gobj) gobj.stop();
      gobj = null; pan = null;
      const head = el("div", { class: "page-head" }, el("h1", {}, T("net.title")), el("span", { class: "spacer" }),
        topo ? chip("network", T("net.collecting", { n: topo.collecting, m: topo.hosts }), topo.collecting ? "c-ok" : "") : null);
      if (!data) { body.replaceChildren(head, el("p", { class: "muted" }, T("common.loading"))); return; }
      const collecting = data.nodes.some((n) => n.kind === "host" && n.collecting);
      const parts = [head, el("p", { class: "muted lead-sm" }, T("net.sub"))];
      if (!collecting) { body.replaceChildren(...parts, emptyHint()); return; }
      parts.push(toolbar());
      const noAddr = data.nodes.filter((n) => n.zone === "none");
      if (noAddr.length) parts.push(el("p", { class: "muted small", title: noAddr.map((n) => n.name).join(", ") }, T("net.noaddr", { n: noAddr.length, f: S.fam === "6" ? "IPv6" : "IPv4" })));
      if (S.tab === "topo") { body.replaceChildren(...parts, topoView(ctx, topo)); return; }
      const wrap = el("div", { class: "nm-wrap" });
      const gbox = el("div", { class: "card nm-graph" });
      const dummy = { nodes: data.nodes, links: data.links };
      body.replaceChildren(...parts, wrap);
      wrap.append(gbox);
      gobj = graph(ctx, data, gbox, null, sel);
      pan = panel(ctx, dummy, gobj, sel);
      gbox.append(gobj.el);
      if (!data.links.length) gbox.append(el("p", { class: "muted small nm-note" }, T("net.nolinks")));
      wrap.append(pan.el);
      pan.draw(sel.cur); gobj.paint(sel.cur);
    };

    root.append(body);
    draw();
    load(true);
    timer = setInterval(() => { if (!root.isConnected) { clearInterval(timer); return; } if (!document.hidden && !document.querySelector(".veil")) load(false); }, 30000);
    return root;
  }

  // --- топология --------------------------------------------------------------------------------------------------------------
  function topoView(ctx, topo) {
    if (!topo.subnets.length) return el("div", { class: "card" }, el("div", { class: "empty" }, icon("network", 40), el("h3", {}, T("net.topo.none")), S.fam === "6" ? el("p", {}, T("net.v6.note")) : null));
    return el("div", { class: "nm-subnets" }, S.fam === "6" ? el("p", { class: "muted small" }, T("net.v6.note")) : null, topo.subnets.map((s) => {
      const roles = (list, key) => list.length ? el("p", { class: "small" }, el("span", { class: "muted" }, T(key) + ": "), list.map((g, i) => [i ? ", " : "", el("span", { class: "mono" }, g.ip), g.host ? " (" + g.host + ")" : "", el("span", { class: "muted" }, " · " + T("net.topo.by", { n: g.by }))])) : null;
      const devs = s.devices.length ? table([[T("net.col.addr")], [T("net.col.mac")], [T("net.col.name")], [T("net.topo.seen", { n: "" }).replace(/:?\s*$/, "")], [""]],
        s.devices.map((d) => el("tr", {},
          el("td", { class: "mono nowrap" }, d.ip, d.gateway ? " " : null, d.gateway ? chip(null, T("net.topo.gw"), "c-warn") : null, d.dns ? chip(null, "DNS", "") : null),
          el("td", { class: "mono small" }, d.mac || "—"),
          el("td", {}, d.name ? el("strong", {}, d.name) : el("span", { class: "muted" }, "—"), d.note ? el("div", { class: "muted small" }, d.note) : null),
          el("td", { class: "small" }, d.seen_by.join(", ")),
          el("td", { class: "num" }, ctx.me.role !== "viewer" ? button(T("net.topo.rename"), { icon: "sliders", kind: "ghost", onclick: async () => { if (await labelDialog(ctx, d.ip, d.name, d.note)) ctx.reload(); } }) : null)))) : el("p", { class: "muted small" }, T("net.topo.nodev"));
      return el("section", { class: "card nm-subnet" },
        el("div", { class: "nm-pt" }, icon("network", 20), el("h3", { class: "mono" }, s.cidr), chip(null, T("net.topo.hosts") + ": " + s.hosts.length, "")),
        roles(s.gateways, "net.topo.gw"), roles(s.dns, "net.topo.dns"),
        table([[T("net.col.peer")], [T("net.col.addr")], [T("net.col.iface")], [T("net.col.mac")]], s.hosts.map((h) => el("tr", { tabindex: 0, onclick: () => { location.hash = "#/host/" + encodeURIComponent(h.id); } },
          el("td", {}, el("strong", {}, h.name)), el("td", { class: "mono" }, h.ip), el("td", { class: "mono small" }, h.iface), el("td", { class: "mono small" }, h.mac || "—")))),
        el("h4", {}, T("net.topo.dev")), el("p", { class: "muted small" }, T("net.topo.dev.d")), devs);
    }));
  }

  // --- вкладка «Сеть» на странице хоста ------------------------------------------------------------------------------------------------
  function hostTab(ctx, h) {
    const wrap = el("div", { class: "nm-host" });
    const on = (h.info || {}).network === "on";
    if (!ctx.vAtLeast(h.agent_version, [0, 9, 0])) { wrap.append(ctx.me.role === "admin" ? el("div", { class: "card ctr-hint" }, icon("download", 18), el("span", {}, T("net.old"))) : el("p", { class: "muted" }, T("net.old"))); return wrap; }
    if (!on) { wrap.append(ctx.me.role === "admin" ? hint(T("net.off.t"), T("net.off.d"), CMD) : el("p", { class: "muted" }, T("net.off.t"))); return wrap; }
    wrap.append(el("p", { class: "muted" }, T("common.loading")));
    (async () => {
      let v;
      try { v = await ctx.api(`/api/hosts/${h.id}/network`); } catch (e) { ctx.fail(e); return; }
      if (!wrap.isConnected && !wrap.parentNode) { /* вкладку уже закрыли — всё равно заполним, элемент мог быть ещё не вставлен */ }
      if (!v.at) { wrap.replaceChildren(el("p", { class: "muted" }, T("net.host.none"))); return; }
      const who = (ip) => (v.hosts[ip] && v.hosts[ip] !== h.name ? v.hosts[ip] : v.labels[ip] || "");
      const priv = (a) => a !== "127.0.0.1" && a !== "::1";
      const row = (c) => el("tr", {},
        el("td", { class: "nowrap" }, c.dir === "out" ? "→ " : "← ", el("span", { class: "muted small" }, T(c.dir === "out" ? "net.dir.out" : "net.dir.in"))),
        el("td", {}, el("span", { class: "mono" }, c.peer), who(c.peer) ? el("span", { class: "muted small" }, " " + who(c.peer)) : null),
        el("td", {}, c.service), el("td", { class: "num mono" }, String(c.port)), el("td", { class: "small" }, c.proc || "—"), el("td", { class: "num" }, String(c.n)));
      wrap.replaceChildren(
        el("div", { class: "nm-pt" }, el("span", { class: "muted small" }, T("net.host.updated", { t: ctx.fmtDate(v.at) })),
          v.gateways.length ? chip(null, T("net.host.gw") + ": " + v.gateways.join(", "), "") : null, v.dns.length ? chip(null, T("net.host.dns") + ": " + v.dns.join(", "), "") : null),
        el("section", { class: "card" }, el("h3", {}, T("net.host.conns")), v.conns.length ? table([[T("net.col.dir")], [T("net.col.peer")], [T("net.col.service")], [T("net.col.port"), "num"], [T("net.col.proc")], [T("net.col.n"), "num"]], v.conns.map(row), "compact") : el("p", { class: "muted small" }, T("net.host.noconn"))),
        el("section", { class: "card" }, el("h3", {}, T("net.host.listen")), v.listen.length ? table([[T("net.col.port"), "num"], [T("net.col.service")], [T("net.col.addr")], [T("net.col.proc")]], v.listen.map((l) => el("tr", {},
          el("td", { class: "num mono" }, String(l.port)), el("td", {}, l.service), el("td", { class: "mono small" }, l.addr || "*", " ", el("span", { class: "muted" }, priv(l.addr) ? "· " + T("net.host.public") : "· " + T("net.host.local"))), el("td", { class: "small" }, l.proc || "—"))), "compact") : el("p", { class: "muted small" }, "—")),
        el("section", { class: "card" }, el("h3", {}, T("net.host.neigh")), v.neigh.length ? table([[T("net.col.addr")], [T("net.col.mac")], [T("net.col.iface")], [T("net.col.name")]], v.neigh.map((n) => el("tr", {}, el("td", { class: "mono" }, n.ip), el("td", { class: "mono small" }, n.mac), el("td", { class: "mono small" }, n.dev || "—"), el("td", {}, who(n.ip) || "—"))), "compact") : el("p", { class: "muted small" }, "—")),
        el("section", { class: "card" }, el("h3", {}, T("net.host.ifaces")), table([[T("net.col.iface")], [T("net.col.addr")], [T("net.col.mac")]], v.ifaces.map((i) => el("tr", {}, el("td", { class: "mono" }, i.name, i.virtual ? el("span", { class: "muted small" }, " · " + T("net.host.virtual")) : null, i.up ? null : el("span", { class: "muted small" }, " · down")), el("td", { class: "mono small" }, i.addrs.join(", ") || "—"), el("td", { class: "mono small" }, i.mac || "—"))), "compact")));
    })();
    return wrap;
  }

  window.NetMap = { page, hostTab };
})();
