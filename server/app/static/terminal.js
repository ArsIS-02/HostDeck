// Небольшой эмулятор терминала (VT100/xterm-подмножество) без внешних библиотек.
// Поддержано: цвета SGR (16/256/truecolor), перемещение курсора, стирание, вставка/удаление строк и знаков,
// альтернативный экран (less, vim, top), прокрутка. Мышь и нестандартные режимы игнорируются.
(() => {
  "use strict";
  const PAL = ["#000000", "#cd3131", "#0dbc79", "#e5e510", "#2472c8", "#bc3fbc", "#11a8cd", "#e5e5e5",
    "#666666", "#f14c4c", "#23d18b", "#f5f543", "#3b8eea", "#d670d6", "#29b8db", "#ffffff"];
  function color256(n) {
    if (n < 16) return PAL[n];
    if (n < 232) { n -= 16; const c = [0, 95, 135, 175, 215, 255]; return `rgb(${c[Math.floor(n / 36)]},${c[Math.floor(n / 6) % 6]},${c[n % 6]})`; }
    const g = 8 + (n - 232) * 10; return `rgb(${g},${g},${g})`;
  }
  const blank = () => ({ c: " ", fg: null, bg: null, b: 0, u: 0, r: 0, d: 0 });

  class Emu {
    constructor(cols, rows, onDirty) {
      this.cols = cols; this.rows = rows; this.onDirty = onDirty;
      this.dec = new TextDecoder("utf-8");
      this.scroll = []; this.maxScroll = 3000;
      this.screen = this.newScreen(); this.saved = null; this.alt = false;
      this.cx = 0; this.cy = 0; this.wrapPending = false; this.sv = null;
      this.pen = { fg: null, bg: null, b: 0, u: 0, r: 0, d: 0 };
      this.state = 0; this.buf = ""; this.appCursor = false; this.title = "";
    }
    newRow() { return Array.from({ length: this.cols }, blank); }
    newScreen() { return Array.from({ length: this.rows }, () => this.newRow()); }
    reset() { this.screen = this.newScreen(); this.cx = this.cy = 0; this.pen = { fg: null, bg: null, b: 0, u: 0, r: 0, d: 0 }; }
    write(bytes) {
      const s = this.dec.decode(bytes, { stream: true });
      for (const ch of s) this.put(ch);
      this.onDirty();
    }
    lineFeed() {
      if (this.cy === this.rows - 1) {
        const row = this.screen.shift();
        if (!this.alt) { this.scroll.push(row); if (this.scroll.length > this.maxScroll) this.scroll.shift(); }
        this.screen.push(this.newRow());
      } else this.cy++;
    }
    cell(ch) {
      return { c: ch, fg: this.pen.fg, bg: this.pen.bg, b: this.pen.b, u: this.pen.u, r: this.pen.r, d: this.pen.d };
    }
    print(ch) {
      if (this.wrapPending) { this.cx = 0; this.lineFeed(); this.wrapPending = false; }
      this.screen[this.cy][this.cx] = this.cell(ch);
      if (this.cx === this.cols - 1) this.wrapPending = true; else this.cx++;
    }
    put(ch) {
      const code = ch.codePointAt(0);
      switch (this.state) {
        case 0:
          if (ch === "\x1b") this.state = 1;
          else if (ch === "\n" || ch === "\x0b" || ch === "\x0c") { this.lineFeed(); this.wrapPending = false; }
          else if (ch === "\r") { this.cx = 0; this.wrapPending = false; }
          else if (ch === "\b") { if (this.cx > 0) this.cx--; this.wrapPending = false; }
          else if (ch === "\t") { this.cx = Math.min(this.cols - 1, (this.cx + 8) & ~7); this.wrapPending = false; }
          else if (code >= 32 && code !== 127) this.print(ch);
          break;
        case 1: // после ESC
          if (ch === "[") { this.state = 2; this.buf = ""; }
          else if (ch === "]") { this.state = 3; this.buf = ""; }
          else if (ch === "(" || ch === ")" || ch === "#" || ch === "%") this.state = 4;
          else {
            this.state = 0;
            if (ch === "M") { if (this.cy > 0) this.cy--; else { this.screen.pop(); this.screen.unshift(this.newRow()); } }
            else if (ch === "7") this.sv = [this.cx, this.cy];
            else if (ch === "8" && this.sv) [this.cx, this.cy] = this.sv;
            else if (ch === "c") this.reset();
            else if (ch === "E") { this.cx = 0; this.lineFeed(); }
          }
          break;
        case 2: // CSI
          if (code >= 0x40 && code <= 0x7e) { this.state = 0; this.csi(this.buf, ch); }
          else this.buf += ch;
          break;
        case 3: // OSC до BEL или ESC \
          if (ch === "\x07") { this.state = 0; this.osc(this.buf); }
          else if (ch === "\x1b") this.state = 5;
          else this.buf += ch;
          break;
        case 5: this.state = 0; this.osc(this.buf); if (ch !== "\\") this.put(ch); break;
        case 4: this.state = 0; break; // выбор набора символов — игнорируем
        default: this.state = 0;
      }
    }
    osc(s) { if (/^[02];/.test(s)) this.title = s.slice(2); }
    clampX() { this.cx = Math.max(0, Math.min(this.cols - 1, this.cx)); }
    clampY() { this.cy = Math.max(0, Math.min(this.rows - 1, this.cy)); }
    csi(buf, fin) {
      const priv = /^[?>!]/.test(buf) ? buf[0] : "";
      const p = buf.replace(/^[?>!]/, "").split(";").map((x) => (x === "" ? 0 : parseInt(x, 10) || 0));
      const n = (d = 1) => (p[0] > 0 ? p[0] : d);
      this.wrapPending = false;
      switch (fin) {
        case "A": this.cy -= n(); this.clampY(); break;
        case "B": case "e": this.cy += n(); this.clampY(); break;
        case "C": case "a": this.cx += n(); this.clampX(); break;
        case "D": this.cx -= n(); this.clampX(); break;
        case "E": this.cy += n(); this.cx = 0; this.clampY(); break;
        case "F": this.cy -= n(); this.cx = 0; this.clampY(); break;
        case "G": case "`": this.cx = n() - 1; this.clampX(); break;
        case "d": this.cy = n() - 1; this.clampY(); break;
        case "H": case "f": this.cy = (p[0] || 1) - 1; this.cx = (p[1] || 1) - 1; this.clampX(); this.clampY(); break;
        case "J": {
          const m = p[0] || 0;
          if (m === 0) { this.eraseLine(this.cy, this.cx, this.cols); for (let y = this.cy + 1; y < this.rows; y++) this.eraseLine(y, 0, this.cols); }
          else if (m === 1) { for (let y = 0; y < this.cy; y++) this.eraseLine(y, 0, this.cols); this.eraseLine(this.cy, 0, this.cx + 1); }
          else { for (let y = 0; y < this.rows; y++) this.eraseLine(y, 0, this.cols); if (m === 3) this.scroll = []; }
          break;
        }
        case "K": {
          const m = p[0] || 0;
          if (m === 0) this.eraseLine(this.cy, this.cx, this.cols); else if (m === 1) this.eraseLine(this.cy, 0, this.cx + 1); else this.eraseLine(this.cy, 0, this.cols);
          break;
        }
        case "L": for (let i = 0; i < n(); i++) { this.screen.splice(this.cy, 0, this.newRow()); this.screen.pop(); } break;
        case "M": for (let i = 0; i < n(); i++) { this.screen.splice(this.cy, 1); this.screen.push(this.newRow()); } break;
        case "P": { const r = this.screen[this.cy]; r.splice(this.cx, n()); while (r.length < this.cols) r.push(blank()); break; }
        case "@": { const r = this.screen[this.cy]; for (let i = 0; i < n(); i++) r.splice(this.cx, 0, blank()); r.length = this.cols; break; }
        case "X": this.eraseLine(this.cy, this.cx, Math.min(this.cols, this.cx + n())); break;
        case "S": for (let i = 0; i < n(); i++) { this.screen.shift(); this.screen.push(this.newRow()); } break;
        case "T": for (let i = 0; i < n(); i++) { this.screen.pop(); this.screen.unshift(this.newRow()); } break;
        case "m": this.sgr(p.length ? p : [0]); break;
        case "s": this.sv = [this.cx, this.cy]; break;
        case "u": if (this.sv) [this.cx, this.cy] = this.sv; break;
        case "h": case "l": this.mode(priv, p, fin === "h"); break;
        default: break; // r (область прокрутки), n, c и прочее — не нужны
      }
    }
    mode(priv, p, on) {
      if (priv !== "?") return;
      for (const m of p) {
        if (m === 1) this.appCursor = on;
        else if (m === 1049 || m === 47 || m === 1047) {
          if (on && !this.alt) { this.saved = [this.screen, this.cx, this.cy]; this.alt = true; this.screen = this.newScreen(); this.cx = this.cy = 0; }
          else if (!on && this.alt) { [this.screen, this.cx, this.cy] = this.saved; this.alt = false; }
        }
      }
    }
    eraseLine(y, x0, x1) { const r = this.screen[y]; for (let x = x0; x < x1; x++) r[x] = blank(); }
    sgr(p) {
      for (let i = 0; i < p.length; i++) {
        const v = p[i], pen = this.pen;
        if (v === 0) Object.assign(pen, { fg: null, bg: null, b: 0, u: 0, r: 0, d: 0 });
        else if (v === 1) pen.b = 1; else if (v === 2) pen.d = 1; else if (v === 4) pen.u = 1; else if (v === 7) pen.r = 1;
        else if (v === 22) { pen.b = 0; pen.d = 0; } else if (v === 24) pen.u = 0; else if (v === 27) pen.r = 0;
        else if (v >= 30 && v <= 37) pen.fg = PAL[v - 30]; else if (v === 39) pen.fg = null;
        else if (v >= 40 && v <= 47) pen.bg = PAL[v - 40]; else if (v === 49) pen.bg = null;
        else if (v >= 90 && v <= 97) pen.fg = PAL[v - 90 + 8]; else if (v >= 100 && v <= 107) pen.bg = PAL[v - 100 + 8];
        else if (v === 38 || v === 48) {
          const key = v === 38 ? "fg" : "bg";
          if (p[i + 1] === 5) { pen[key] = color256(p[i + 2] | 0); i += 2; }
          else if (p[i + 1] === 2) { pen[key] = `rgb(${p[i + 2] | 0},${p[i + 3] | 0},${p[i + 4] | 0})`; i += 4; }
        }
      }
    }
    // Рендер: строки прокрутки + экран; группируем соседние ячейки с одинаковым стилем
    renderInto(box, showCursor) {
      const all = this.alt ? this.screen : this.scroll.concat(this.screen);
      const frag = document.createDocumentFragment();
      const cursorRow = (this.alt ? 0 : this.scroll.length) + this.cy;
      all.forEach((row, y) => {
        const line = document.createElement("div");
        line.className = "tl";
        let last = row.length;
        while (last > 0 && row[last - 1].c === " " && !row[last - 1].bg && !row[last - 1].r) last--;
        if (showCursor && y === cursorRow) last = Math.max(last, this.cx + 1);
        let span = null, key = "";
        for (let x = 0; x < last; x++) {
          const c = row[x], cur = showCursor && y === cursorRow && x === this.cx;
          const k = `${c.fg}|${c.bg}|${c.b}|${c.u}|${c.r}|${c.d}|${cur ? 1 : 0}`;
          if (!span || k !== key) {
            span = document.createElement("span"); key = k;
            let fg = c.fg, bg = c.bg;
            if (c.r) [fg, bg] = [bg || "var(--term-bg)", fg || "var(--term-fg)"];
            if (fg) span.style.color = fg;
            if (bg) span.style.background = bg;
            if (c.b) span.style.fontWeight = "700";
            if (c.u) span.style.textDecoration = "underline";
            if (c.d) span.style.opacity = ".6";
            if (cur) span.className = "tcur";
            line.append(span);
          }
          span.textContent += c.c;
        }
        if (!line.firstChild) line.textContent = "​";
        frag.append(line);
      });
      box.replaceChildren(frag);
    }
  }

  // Преобразование нажатия клавиши в последовательность байт терминала.
  function keySeq(e, appCursor) {
    const k = e.key;
    if (e.metaKey) return null; // Cmd+C / Cmd+V остаются браузеру
    const arrows = { ArrowUp: "A", ArrowDown: "B", ArrowRight: "C", ArrowLeft: "D", Home: "H", End: "F" };
    if (arrows[k]) {
      const mod = (e.shiftKey ? 1 : 0) + (e.altKey ? 2 : 0) + (e.ctrlKey ? 4 : 0);
      if (mod) return `\x1b[1;${mod + 1}${arrows[k]}`;
      return (appCursor ? "\x1bO" : "\x1b[") + arrows[k];
    }
    const map = { Enter: "\r", Backspace: "\x7f", Tab: e.shiftKey ? "\x1b[Z" : "\t", Escape: "\x1b", Delete: "\x1b[3~", PageUp: "\x1b[5~", PageDown: "\x1b[6~", Insert: "\x1b[2~",
      F1: "\x1bOP", F2: "\x1bOQ", F3: "\x1bOR", F4: "\x1bOS", F5: "\x1b[15~", F6: "\x1b[17~", F7: "\x1b[18~", F8: "\x1b[19~", F9: "\x1b[20~", F10: "\x1b[21~", F11: "\x1b[23~", F12: "\x1b[24~" };
    if (map[k]) return (e.altKey ? "\x1b" : "") + map[k];
    if (e.ctrlKey && !e.altKey && k.length === 1) {
      const c = k.toLowerCase().charCodeAt(0);
      if (c >= 97 && c <= 122) return String.fromCharCode(c - 96);
      if (k === " " || k === "@") return "\x00";
      if (k === "[") return "\x1b"; if (k === "\\") return "\x1c"; if (k === "]") return "\x1d";
    }
    if (e.altKey && !e.ctrlKey && k.length === 1) return "\x1b" + k;
    return undefined; // обычный символ придёт через событие input
  }

  window.HDTerm = { Emu, keySeq };
})();
