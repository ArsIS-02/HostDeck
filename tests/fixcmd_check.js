// Проверка подбора команд под проблему: node tests/fixcmd_check.js
global.window = { HELP: {} };
require("../server/app/static/fixcmd.js");
const f = window.HELP.cmdFor, bad = [];
const must = (name, r, re) => { if (!r || !re.test(r.join("\n"))) bad.push(name); };
must("certs: имя файла из результата", f({ id: "certs", status: "fail", value: "expired", detail: "abc (postfix.pem) — 2026-06-25" }), /-name postfix\.pem/);
must("ports: порты из результата", f({ id: "ports", status: "warn", detail: "tcp/25 master" }), /:\(25\)/);
must("sysctl: нужное значение", f({ id: "sysctl", status: "warn", detail: "fs.suid_dumpable=2 (нужно =0)" }), /fs\.suid_dumpable=0/);
must("failed_units: имя службы", f({ id: "failed_units", status: "warn", detail: "postfix.service" }), /journalctl -u postfix\.service/);
must("admins: без текущего пользователя", f({ id: "admins", status: "warn", detail: "igor, bob" }, { info: { console_user: "igor" } }), /-d bob/);
if (f({ id: "admins", status: "warn", detail: "igor, bob" }, { info: { console_user: "igor" } }).join().includes("-d igor")) bad.push("admins: удалил бы текущего");
if (f({ id: "certs", status: "ok", detail: "x (a.pem)" })) bad.push("для «в порядке» команд быть не должно");
if (f({ id: "firewall", status: "fail" })) bad.push("без подборки — общая команда из справки");
const inj = f({ id: "failed_units", status: "warn", detail: "a;rm -rf /" });
if (inj && /rm -rf \/(\s|$)/.test(inj.join("\n").replace(/'[^']*'/g, ""))) bad.push("подстановка не экранирована");
console.log(bad.length ? "FAIL: " + bad.join("; ") : "OK: подбор команд под проблему"); process.exit(bad.length ? 1 : 0);
