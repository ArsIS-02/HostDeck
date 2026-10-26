// Команды исправления «под проблему»: по результату проверки (значение и подробности) подставляются реальные имена
// файлов, служб, пользователей, портов и дисков. Если для проверки такой подборки нет, интерфейс берёт общую команду из help.js.
// Возвращает массив блоков команд или null. Все команды выполняются на хосте от администратора.
(() => {
  "use strict";
  const list = (s) => String(s || "").split(/\s*[,;]\s*/).map((x) => x.replace(/\s*…$/, "").trim()).filter(Boolean);
  // безопасная подстановка в shell: только простые имена, остальное в одинарные кавычки
  const q = (s) => (/^[\w@%+=:,./-]+$/.test(s) ? s : "'" + String(s).replace(/'/g, "'\\''") + "'");
  const uniq = (a) => [...new Set(a)];

  const F = {
    // ---------- Linux ----------
    certs(c) {
      const files = uniq([...String(c.detail || "").matchAll(/\(([^)]+\.(?:pem|crt|cer))\)/g)].map((m) => m[1]));
      const dirs = "/etc/letsencrypt/live /etc/pki/tls/certs /etc/pki/ca-trust/source/anchors /usr/local/share/ca-certificates /etc/ipa /var/lib/ipa/certs";
      if (!files.length) return null;
      const out = [];
      files.slice(0, 3).forEach((f) => {
        out.push(`# где лежит и когда истекает ${f}\nsudo find ${dirs} -name ${q(f)} 2>/dev/null | while read p; do echo "== $p"; sudo openssl x509 -in "$p" -noout -subject -issuer -enddate; done`);
      });
      out.push("# продление: Let's Encrypt (проверка, затем реальное)\nsudo certbot renew --dry-run && sudo certbot renew");
      out.push("# FreeIPA / certmonger: какие сертификаты отслеживаются и в каком они состоянии\nsudo getcert list | grep -E 'Request ID|status|expires|certificate:'");
      if (files.some((f) => /postfix|dovecot|mail/i.test(f))) out.push("# после замены сертификата почтовой службы\nsudo systemctl reload postfix 2>/dev/null; sudo systemctl reload dovecot 2>/dev/null");
      return out;
    },
    uid0(c) {
      const us = list(c.detail).filter((u) => u !== "root");
      if (!us.length) return null;
      return [us.map((u) => `getent passwd ${q(u)}; sudo last -n 5 ${q(u)}`).join("\n"),
        "# если учётная запись лишняя: заблокировать и лишить оболочки (UID потом задайте вручную)\n" + us.map((u) => `sudo passwd -l ${q(u)} && sudo usermod -s /sbin/nologin ${q(u)}`).join("\n")];
    },
    empty_pw(c) {
      const us = list(c.detail);
      if (!us.length) return null;
      return [us.map((u) => `sudo passwd -l ${q(u)}`).join("\n") + "\n# затем задайте пароль или ключ:\n" + us.map((u) => `sudo passwd ${q(u)}`).join("\n")];
    },
    sudo_nopasswd() {
      return ["sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/", "# правка файла из списка (проверка синтаксиса встроена)\nsudo visudo -f /etc/sudoers.d/ИМЯ_ФАЙЛА"];
    },
    ports(c) {
      const items = list(c.detail).map((x) => x.match(/^(tcp|udp)6?\/(\d+)(?:\s+(\S+))?/)).filter(Boolean);
      if (!items.length) return null;
      const re = uniq(items.map((m) => m[2])).join("|");
      const out = [`sudo ss -tulpn | grep -E ':(${re})\\b'`];
      const procs = uniq(items.map((m) => m[3]).filter(Boolean));
      if (procs.length) out.push("# какой службе принадлежит процесс\n" + procs.map((p) => `systemctl status $(pgrep -o -x ${q(p)}) --no-pager | head -3`).join("\n") + "\n# если служба не нужна: остановить и убрать из автозапуска\nsudo systemctl disable --now ИМЯ_СЛУЖБЫ");
      out.push("# если порт нужен, но закрыть его снаружи\n" + items.map((m) => `sudo firewall-cmd --permanent --remove-port=${m[2]}/${m[1]}`).join("\n") + "\nsudo firewall-cmd --reload");
      out.push("# если порт нужен — добавьте его в \"allowed_ports\" в настройках агента\nsudo nano /etc/hostdeck/agent.json   # \"allowed_ports\": [22, 443]\nsudo systemctl restart hostdeck-agent");
      return out;
    },
    sysctl(c) {
      const rows = list(c.detail).map((x) => x.match(/^([\w.]+)=(-?\d+) \(нужно [=≥](\d+)\)/) || x.match(/^([\w.]+)=(-?\d+) \(need [=≥](\d+)\)/)).filter(Boolean);
      if (!rows.length) return null;
      return [rows.map((m) => `sudo sysctl -w ${m[1]}=${m[3]}`).join("\n"),
        "# сохранить после перезагрузки\n" + "printf '" + rows.map((m) => `${m[1]} = ${m[3]}\\n`).join("") + "' | sudo tee /etc/sysctl.d/99-hostdeck.conf\nsudo sysctl --system"];
    },
    tmp_mount(c) {
      if (c.value === "tmp_not_separate") return ["findmnt /tmp /var/tmp", "# вариант: /tmp в памяти с нужными опциями\nsudo systemctl enable --now tmp.mount\nsudo systemctl edit tmp.mount   # [Mount] Options=mode=1777,strictatime,nosuid,nodev,noexec"];
      const paths = uniq([...String(c.detail || "").matchAll(/(\/(?:var\/)?tmp):/g)].map((m) => m[1]));
      if (!paths.length) return null;
      return [paths.map((p) => `sudo mount -o remount,nosuid,nodev,noexec ${p}`).join("\n"), "# постоянно: добавьте nosuid,nodev,noexec в опции этих строк\nsudo vi /etc/fstab && sudo mount -a"];
    },
    smart(c) {
      const ds = list(c.detail).filter((d) => /^[\w-]+$/.test(d));
      if (!ds.length) return null;
      return [ds.map((d) => `sudo smartctl -a /dev/${d} | grep -Ei 'result|reallocated|pending|uncorrect|error'`).join("\n"),
        "# срочно: копия данных, затем замена диска\n" + ds.map((d) => `sudo smartctl -t short /dev/${d}`).join("\n")];
    },
    failed_units(c) {
      const us = list(c.detail).filter((u) => /\.(service|socket|timer|mount|path)$/.test(u) || /^[\w@.-]+$/.test(u));
      if (!us.length) return null;
      return [us.map((u) => `sudo systemctl status ${q(u)} --no-pager -l | head -20\nsudo journalctl -u ${q(u)} -n 30 --no-pager`).join("\n"),
        "# после устранения причины\n" + us.map((u) => `sudo systemctl reset-failed ${q(u)} && sudo systemctl restart ${q(u)}`).join("\n")];
    },
    pkg_updates(c) {
      const ns = list(c.detail).filter((n) => /^[\w.+:@-]+$/.test(n));
      if (!ns.length) return null;
      const l = ns.join(" ");
      return [`sudo dnf upgrade -y ${l} 2>/dev/null || sudo apt-get install -y --only-upgrade ${l}`, "# всё сразу\nsudo dnf upgrade -y 2>/dev/null || sudo apt-get update && sudo apt-get upgrade -y"];
    },
    sec_updates(c) {
      const ns = list(c.detail).filter((n) => /^[\w.+:@-]+$/.test(n));
      return ["sudo dnf upgrade --security -y 2>/dev/null || (sudo apt-get update && sudo apt-get upgrade -y)" , ns.length ? `sudo dnf updateinfo list security 2>/dev/null | grep -E '${ns.map((n) => n.replace(/[.+]/g, "\\$&")).join("|")}'` : null].filter(Boolean);
    },
    selinux(c) {
      if (c.value === "permissive") return ["sudo ausearch -m avc -ts recent | tail -20", "sudo setenforce 1\nsudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"];
      if (c.value === "off") return ["sestatus", "sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config\nsudo touch /.autorelabel && sudo reboot   # первая загрузка с перемаркировкой идёт долго"];
      return null;
    },
    freeipa(c) {
      const d = c.detail ? ` ${q(c.detail)}` : "";
      if (c.value === "sssd_down") return ["sudo systemctl status sssd --no-pager | head -15\nsudo journalctl -u sssd -n 40 --no-pager", "sudo systemctl enable --now sssd"];
      if (c.value === "no_keytab") return ["sudo klist -k /etc/krb5.keytab", "# keytab нет — хост выпал из домена: повторный ввод\nsudo ipa-client-install --force-join"];
      if (c.value === "ipa_offline") return [`sudo sssctl domain-status${d}`, "# сервер FreeIPA недоступен: проверка сети и времени\nping -c 2 ipa.$(hostname -d)\nchronyc tracking", "sudo sss_cache -E && sudo systemctl restart sssd"];
      return null;
    },
    // ---------- macOS ----------
    timemachine(c) {
      if (c.value === "not_configured") return ["tmutil destinationinfo", "sudo tmutil setdestination /Volumes/ИМЯ_ДИСКА\nsudo tmutil enable"];
      if (c.value === "no_backups") return ["tmutil destinationinfo", "sudo tmutil startbackup --block"];
      return ["tmutil destinationinfo\ntmutil latestbackup", "sudo tmutil startbackup --block"];
    },
    admins(c, h) {
      const me = (h && h.info && h.info.console_user) || "";
      const us = list(c.detail).filter((u) => u !== me);
      if (!us.length) return null;
      return [us.map((u) => `dscl . -read /Users/${q(u)} RealName UniqueID`).join("\n"), "# если права администратора не нужны\n" + us.map((u) => `sudo dseditgroup -o edit -d ${q(u)} -t user admin`).join("\n")];
    },
    updates(c) {
      const ts = list(c.detail);
      if (!ts.length) return null;
      return ["softwareupdate --list", ts.map((t) => `sudo softwareupdate --install ${q(t)} --agree-to-license`).join("\n") + "\n# с перезагрузкой, если нужна: добавьте --restart"];
    },
  };

  window.HELP.cmdFor = (c, h) => {
    const f = F[c.id];
    if (!f || c.status === "ok" || c.status === "info") return null;
    try { const r = f(c, h); return r && r.length ? r : null; } catch (_) { return null; }
  };
})();
