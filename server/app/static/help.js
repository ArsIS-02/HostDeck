// Справка: что означает каждая проверка, чем опасно отклонение и как его исправить; инструкция администратора.
// Тексты лежат отдельно от интерфейса, чтобы их было удобно править. Команды выполняются на самом хосте с правами администратора
// (их можно вставить в «Консоль» карточки хоста, если на нём разрешена консоль).
(() => {
  "use strict";
  const FW = "/usr/libexec/ApplicationFirewall/socketfilterfw";
  const PREF = "/Library/Preferences/com.apple.SoftwareUpdate";

  const ru = {
    checks: {
      firewall: {
        what: "Встроенный брандмауэр macOS. Он решает, каким программам разрешены входящие сетевые подключения.",
        risk: "Без брандмауэра любая программа, слушающая порт, доступна из локальной сети (общий Wi-Fi, гостевая сеть, VPN).",
        fix: ["Системные настройки → Сеть → Брандмауэр → включить (в macOS 12 и старше: Конфиденциальность и безопасность → Брандмауэр)."],
        cmd: `sudo ${FW} --setglobalstate on`,
      },
      stealth: {
        what: "«Режим невидимки» — опция брандмауэра. Включённый, он заставляет Mac молчать в ответ на ping (ICMP) и на попытки подключиться к закрытым портам, поэтому сканеры портов и случайные «стуки» в сеть не видят, что хост вообще есть.",
        risk: "Выключенный режим — это не поломка, а компромисс: Mac отвечает на ping и сканирование. Для ноутбука в чужой Wi-Fi лучше включить. Для сервера, который вы пингуете системой мониторинга, режим оставляют выключенным, иначе ping-проверки покажут «недоступен».",
        fix: ["Системные настройки → Сеть → Брандмауэр → Параметры… → «Включить режим невидимки». Работает, только если включён сам брандмауэр."],
        cmd: `sudo ${FW} --setstealthmode on`,
      },
      filevault: {
        what: "FileVault шифрует весь диск. Без пароля пользователя данные нельзя прочитать, даже вынув накопитель.",
        risk: "При потере или краже Mac содержимое диска доступно любому, у кого есть физический доступ.",
        fix: ["Системные настройки → Конфиденциальность и безопасность → FileVault → «Включить». Обязательно сохраните ключ восстановления в надёжном месте.", "Шифрование идёт в фоне, пока Mac работает."],
        cmd: "sudo fdesetup enable",
      },
      sip: {
        what: "SIP (System Integrity Protection) не даёт менять системные файлы и процессы даже root-у.",
        risk: "Отключённая защита позволяет вредоносной программе с правами root внедриться в систему.",
        fix: ["Перезагрузитесь в режим восстановления (Apple silicon: зажмите кнопку питания, «Параметры»; Intel: Cmd+R), откройте Утилиты → Терминал и выполните команду ниже, затем перезагрузитесь."],
        cmd: "csrutil enable",
      },
      gatekeeper: {
        what: "Gatekeeper проверяет подпись и нотаризацию программ, скачанных из интернета, прежде чем их запустить.",
        risk: "Выключенный Gatekeeper разрешает запуск любых неподписанных программ без предупреждения.",
        fix: ["Системные настройки → Конфиденциальность и безопасность → «Разрешить программы из»: App Store или App Store и проверенных разработчиков."],
        cmd: "sudo spctl --global-enable",
        cmd2: "sudo spctl --master-enable   # для macOS 14 и старше",
      },
      auto_check: {
        what: "Автоматическая проверка обновлений: macOS сама сверяется с серверами Apple.",
        risk: "«Не задано» означает, что параметр не записан в настройках. На практике macOS в таком случае проверяет обновления по умолчанию, поэтому это скорее замечание, чем проблема. «Выключено» — настоящая проблема: об обновлениях вы узнаете только вручную.",
        fix: ["Системные настройки → Основные → Обновление ПО → кнопка (i) у «Автоматические обновления» → «Проверять наличие обновлений»."],
        cmd: `sudo defaults write ${PREF} AutomaticCheckEnabled -bool true`,
      },
      auto_critical: {
        what: "Автоматическая установка файлов безопасности и срочных исправлений («Быстрые меры безопасности»).",
        risk: "Срочные исправления уязвимостей придут с задержкой, пока вы не поставите их вручную.",
        fix: ["Системные настройки → Основные → Обновление ПО → (i) → «Устанавливать файлы данных системы и обновления безопасности»."],
        cmd: `sudo defaults write ${PREF} CriticalUpdateInstall -bool true`,
      },
      updates: {
        what: "Есть ли для Mac непоставленные обновления macOS и программ Apple. Проверку агент запускает в фоне, она может идти несколько минут.",
        risk: "Пока обновления не установлены, известные уязвимости остаются открытыми. «Проверка выполняется» — просто подождите. «Не удалось» — Mac не достучался до серверов Apple (сеть, DNS, прокси); подсказка обновится при следующем опросе.",
        fix: ["Системные настройки → Основные → Обновление ПО → «Обновить».", "Список ожидающих обновлений указан в подробностях карточки."],
        cmd: "sudo softwareupdate -i -a",
      },
      screenlock: {
        what: "Через сколько после засыпания или заставки экран блокируется и требует пароль.",
        risk: "Если пароль не требуется сразу, любой, кто подошёл к оставленному Mac, получает доступ к сессии.",
        fix: ["Системные настройки → Экран блокировки → «Запрашивать пароль после начала заставки или выключения дисплея» → «Сразу»."],
      },
      ssh: {
        what: "Удалённый вход (SSH) позволяет подключаться к Mac по сети из терминала.",
        risk: "Это справочная отметка, а не ошибка. Включённый SSH нужен администратору, но расширяет поверхность атаки: ограничьте доступ нужными пользователями и входите по ключам.",
        fix: ["Не нужен — отключите: Системные настройки → Основные → Общий доступ → «Удалённый вход».", "Нужен — оставьте включённым и в том же окне («i») ограничьте список пользователей."],
        cmd: "sudo systemsetup -setremotelogin off",
      },
      mdm: {
        what: "Управляется ли Mac через MDM (централизованное управление устройствами организации).",
        risk: "Это справочная отметка. Для домашнего Mac без MDM «не зарегистрирован» — нормально.",
        fix: [],
      },
      disk: {
        what: "Сколько места занято на системном диске. Предупреждение с 85%, ошибка с 95%.",
        risk: "Когда диск почти полон, macOS замедляется, не может ставить обновления и создавать снимки Time Machine, а приложения теряют данные при записи.",
        fix: ["Системные настройки → Основные → Хранилище: освободите место рекомендациями macOS.", "Найдите самые тяжёлые каталоги командой ниже и удалите ненужное (старые образы, кэши, загрузки).", "Локальные снимки Time Machine: tmutil listlocalsnapshots /"],
        cmd: "du -xhd1 /Users | sort -h | tail -15",
      },
      platform: {
        what: "Для этой операционной системы агент собирает только базовые данные и метрики. Проверки безопасности macOS здесь не применяются.",
        risk: "", fix: [],
      },
    },
    unknown: "Данные не получены: команда проверки завершилась ошибкой или параметр не задан. Причина показана в карточке ниже названия. Обычно помогает кнопка «Обновить» в шапке хоста. Если ошибка повторяется, проверьте журнал агента: /var/log/hostdeck-agent.log.",
    ui: { what: "Что это", risk: "Почему это важно", fix: "Как исправить", cmd: "Команда (на хосте, от администратора)", unknown: "Почему нет данных", now: "Сейчас",
          run: "Команды можно выполнить в «Консоли» карточки хоста, если на нём разрешена консоль.", ok: "Всё в порядке, менять ничего не нужно.", info: "Справочная информация.",
          hint: "Подсказка", close: "Закрыть" },
    guide: {
      title: "Инструкция администратора",
      sections: [
        { h: "Роли и вход", p: ["В HostDeck предусмотрены роли: администратор, оператор и наблюдатель. Только администратор добавляет и удаляет хосты, выдаёт токены, открывает консоль и видит журнал.",
          "Первый администратор создаётся при первом запуске сервера из пароля в секрете (HOSTDECK_ADMIN_PASSWORD_FILE). Пароль нигде не хранится в открытом виде. Веб-интерфейс сейчас не управляет другими пользователями."] },
        { h: "Подключение хоста", ol: ["Главная или «Хосты» → «Добавить хост». Введите имя (необязательно) и, если нужна консоль, отметьте флажок.", "Нажмите «Создать токен». Токен одноразовый и действует 24 часа.",
          "Скопируйте команду и выполните её на хосте в терминале (спросит пароль sudo этого хоста). Хост скачает установщик и агента с этого сервера, проверит контрольные суммы и зарегистрируется.",
          "Если сервер подписан внутренним CA, оставьте включённым флажок про CA: сертификат скачивается и сверяется по отпечатку из этой страницы. В системное хранилище он не добавляется.",
          "Через минуту хост появится в списке. Пока в списке нет — смотрите «Если хост не появился»."] },
        { h: "Консоль с правами root", p: ["Консоль открывается кнопкой «Консоль» в карточке хоста. Она включена только при двойном разрешении: вы вошли как администратор и агент на хосте установлен с разрешением консоли (HOSTDECK_TERMINAL=1 в команде, флажок в окне добавления).",
          "Оболочка работает от root. Сессия закрывается после 15 минут простоя, на хост допускается не больше двух. В журнал пишутся открытие, закрытие и отказы; сами команды не записываются, потому что в них бывают пароли.",
          "Чтобы выключить консоль на хосте, переустановите агента командой без флага или поправьте allow_terminal в его конфиге."] },
        { h: "Что показывает карточка", ul: ["Приборы: процессор, память, диск, нагрузка (или батарея у ноутбука) и своп. Обновляются раз в минуту; если данные устарели, это видно по значку часов.",
          "Проверки безопасности: наведите курсор на значок статуса справа, и появится подсказка, что проверка значит и как исправить проблему.",
          "ПО: список установленных программ собирается раз в сутки и по кнопке «Обновить». Выгрузка в CSV включает метаданные и ПО."] },
        { h: "Если хост не появился или «не на связи»", ul: ["Хост считается недоступным, если не опрашивал сервер больше 90 секунд.", "На macOS: tail -n 50 /var/log/hostdeck-agent.log и sudo launchctl print system/local.hostdeck.agent. На Linux: journalctl -u hostdeck-agent -n 50.",
          "Ошибка сертификата в журнале: сервер подписан CA, которому агент не доверяет. Переустановите агента командой с включённым флажком CA.", "Агент использует исходящие подключения HTTPS к серверу; входящие порты на хосте открывать не нужно."] },
        { h: "Обновление и удаление агента", ul: ["Обновить: возьмите команду из окна «Добавить хост» и удалите в конце токен и имя. Останется команда обновления: настройки и регистрация сохраняются. Без внутреннего CA подойдёт и короткая: curl -fsSL https://СЕРВЕР/install.sh | sudo bash -s --",
          "Удалить: sudo ./scripts/uninstall.sh на хосте, затем удалите хост в карточке («Удалить»). Удаление хоста в интерфейсе останавливает его агента."] },
        { h: "Сервер: обслуживание", ul: ["Данные лежат в томе hostdeck-data (/data/hostdeck.db). Резервная копия: podman volume export hostdeck-data -o hostdeck-data.tar.",
          "Обновить сервер: пересобрать образ (podman build) и systemctl --user restart hostdeck. Агенты переподключатся сами.", "Журнал контейнера: journalctl --user -u hostdeck -f. Журнал действий пользователей — раздел «Журнал» в верхнем меню."] },
        { h: "Безопасность", ul: ["Работайте только по HTTPS. Агент по голому HTTP не подключается (кроме localhost).", "Токены одноразовые и хранятся в виде хешей. Ключ хоста выдаётся при регистрации и отзывается удалением хоста.",
          "Корневая консоль даёт полный контроль над хостом: включайте её только там, где она нужна, и ограничивайте число администраторов."] },
      ],
    },
  };

  const en = {
    checks: {
      firewall: {
        what: "The built-in macOS firewall. It decides which apps may accept incoming network connections.",
        risk: "Without it, any app that listens on a port is reachable from the local network (shared Wi-Fi, guest network, VPN).",
        fix: ["System Settings → Network → Firewall → turn on (macOS 12 and earlier: Privacy & Security → Firewall)."],
        cmd: `sudo ${FW} --setglobalstate on`,
      },
      stealth: {
        what: "Stealth mode is a firewall option. When on, the Mac stays silent to ping (ICMP) and to connection attempts on closed ports, so port scanners and random probes cannot tell the host is there.",
        risk: "Off is a trade-off, not a failure: the Mac answers ping and scans. Turn it on for a laptop on untrusted Wi-Fi. Keep it off for a server you ping from monitoring, otherwise ping checks will report it as down.",
        fix: ["System Settings → Network → Firewall → Options… → “Enable stealth mode”. It only works while the firewall itself is on."],
        cmd: `sudo ${FW} --setstealthmode on`,
      },
      filevault: {
        what: "FileVault encrypts the whole disk. Without the user's password the data cannot be read, even with the drive removed.",
        risk: "If the Mac is lost or stolen, anyone with physical access can read the disk.",
        fix: ["System Settings → Privacy & Security → FileVault → Turn On. Keep the recovery key somewhere safe.", "Encryption runs in the background while the Mac is on."],
        cmd: "sudo fdesetup enable",
      },
      sip: {
        what: "SIP (System Integrity Protection) stops anyone, root included, from modifying system files and processes.",
        risk: "With SIP off, malware running as root can embed itself in the system.",
        fix: ["Boot into Recovery (Apple silicon: hold the power button, Options; Intel: Cmd+R), open Utilities → Terminal, run the command below and restart."],
        cmd: "csrutil enable",
      },
      gatekeeper: {
        what: "Gatekeeper checks the signature and notarization of downloaded apps before they run.",
        risk: "With Gatekeeper off, unsigned apps run without any warning.",
        fix: ["System Settings → Privacy & Security → “Allow applications from”: App Store, or App Store and identified developers."],
        cmd: "sudo spctl --global-enable",
        cmd2: "sudo spctl --master-enable   # macOS 14 and earlier",
      },
      auto_check: {
        what: "Automatic update check: macOS contacts Apple's servers on its own.",
        risk: "“Not set” means the key is not written in preferences. macOS checks by default in that case, so this is a note rather than a problem. “Off” is a real problem: you only learn about updates by hand.",
        fix: ["System Settings → General → Software Update → (i) next to Automatic Updates → “Check for updates”."],
        cmd: `sudo defaults write ${PREF} AutomaticCheckEnabled -bool true`,
      },
      auto_critical: {
        what: "Automatic installation of security responses and system data files (rapid security fixes).",
        risk: "Urgent vulnerability fixes arrive late, until you install them by hand.",
        fix: ["System Settings → General → Software Update → (i) → “Install Security Responses and system files”."],
        cmd: `sudo defaults write ${PREF} CriticalUpdateInstall -bool true`,
      },
      updates: {
        what: "Whether macOS or Apple software updates are waiting to be installed. The agent runs the check in the background; it can take a few minutes.",
        risk: "Until updates are installed, known vulnerabilities stay open. “Checking” — just wait. “Failed” — the Mac could not reach Apple (network, DNS, proxy); the hint refreshes on the next poll.",
        fix: ["System Settings → General → Software Update → Update.", "The list of pending updates is in the host's details."],
        cmd: "sudo softwareupdate -i -a",
      },
      screenlock: {
        what: "How soon after sleep or the screen saver the screen locks and asks for a password.",
        risk: "If the password is not required immediately, anyone walking up to an unattended Mac gets into the session.",
        fix: ["System Settings → Lock Screen → “Require password after screen saver begins or display is turned off” → Immediately."],
      },
      ssh: {
        what: "Remote Login (SSH) lets you connect to the Mac over the network from a terminal.",
        risk: "This is informational, not an error. SSH is useful to an administrator but widens the attack surface: limit it to the users who need it and use keys.",
        fix: ["Not needed — turn it off: System Settings → General → Sharing → Remote Login.", "Needed — keep it on and limit the allowed users in the same pane (“i”)."],
        cmd: "sudo systemsetup -setremotelogin off",
      },
      mdm: {
        what: "Whether the Mac is managed through MDM (centralized device management for an organization).",
        risk: "Informational. For a home Mac without MDM, “not enrolled” is normal.",
        fix: [],
      },
      disk: {
        what: "How much of the system disk is used. Warning from 85%, error from 95%.",
        risk: "A nearly full disk slows macOS, blocks updates and Time Machine snapshots, and apps may lose data when saving.",
        fix: ["System Settings → General → Storage: free space with macOS recommendations.", "Find the heaviest folders with the command below and remove what you do not need (old images, caches, downloads).", "Local Time Machine snapshots: tmutil listlocalsnapshots /"],
        cmd: "du -xhd1 /Users | sort -h | tail -15",
      },
      platform: {
        what: "On this operating system the agent collects only basic data and metrics. The macOS security checks do not apply here.",
        risk: "", fix: [],
      },
    },
    unknown: "No data: the check command failed or the setting is not defined. The reason is shown on the card under the title. The Refresh button in the host header usually helps. If it keeps failing, look at the agent log: /var/log/hostdeck-agent.log.",
    ui: { what: "What it is", risk: "Why it matters", fix: "How to fix", cmd: "Command (on the host, as administrator)", unknown: "Why there is no data", now: "Now",
          run: "You can run the commands in the host's Console, if the console is enabled there.", ok: "All good, nothing to change.", info: "For information.",
          hint: "Hint", close: "Close" },
    guide: {
      title: "Administrator guide",
      sections: [
        { h: "Roles and sign-in", p: ["HostDeck has three roles: administrator, operator and viewer. Only an administrator adds and removes hosts, issues tokens, opens the console and sees the audit log.",
          "The first administrator is created on the first start from the password in the secret (HOSTDECK_ADMIN_PASSWORD_FILE). The password is never stored in clear text. The web UI does not manage other users yet."] },
        { h: "Connecting a host", ol: ["Home or Hosts → Add a host. Enter a name (optional) and tick the box if you want the console.", "Click Create token. The token is single-use and valid for 24 hours.",
          "Copy the command and run it in a terminal on the host (it will ask for that host's sudo password). The host downloads the installer and the agent from this server, verifies the checksums and enrolls.",
          "If the server uses an internal CA, keep the CA box ticked: the certificate is downloaded and checked against the fingerprint from this page. It is not added to the system trust store.",
          "The host shows up in the list within a minute. If it does not, see “If a host does not appear”."] },
        { h: "Root console", p: ["The console opens with the Console button on the host's card. It needs two permissions: you are signed in as an administrator, and the agent was installed with the console allowed (HOSTDECK_TERMINAL=1 in the command, the box in the Add dialog).",
          "The shell runs as root. A session closes after 15 minutes idle, and at most two are allowed per host. The audit log records open, close and denied attempts; the commands themselves are not recorded, as they may contain passwords.",
          "To disable the console on a host, reinstall the agent with the command without the flag or change allow_terminal in its config."] },
        { h: "What the card shows", ul: ["Gauges: CPU, memory, disk, load (or battery on a laptop) and swap. Refreshed every minute; stale data is marked with a clock.",
          "Security checks: hover the status icon on the right to see what the check means and how to fix a problem.",
          "Software: the installed-apps list is collected daily and on Refresh. The CSV export includes metadata and software."] },
        { h: "If a host does not appear or is offline", ul: ["A host is offline if it has not polled the server for more than 90 seconds.", "macOS: tail -n 50 /var/log/hostdeck-agent.log and sudo launchctl print system/local.hostdeck.agent. Linux: journalctl -u hostdeck-agent -n 50.",
          "A certificate error in the log means the server's CA is not trusted by the agent. Reinstall the agent with the CA box ticked.", "The agent only makes outgoing HTTPS connections to the server; no inbound ports are needed on the host."] },
        { h: "Updating and removing the agent", ul: ["Update: take the command from the Add a host dialog and delete the token and name at the end. What is left is the update command: settings and enrollment are kept. Without an internal CA the short one works too: curl -fsSL https://SERVER/install.sh | sudo bash -s --",
          "Remove: sudo ./scripts/uninstall.sh on the host, then delete the host in its card (Delete). Deleting the host in the UI stops its agent."] },
        { h: "Server maintenance", ul: ["Data lives in the hostdeck-data volume (/data/hostdeck.db). Backup: podman volume export hostdeck-data -o hostdeck-data.tar.",
          "To update the server: rebuild the image (podman build) and systemctl --user restart hostdeck. Agents reconnect on their own.", "Container log: journalctl --user -u hostdeck -f. User activity is in the Audit log in the top menu."] },
        { h: "Security", ul: ["Use HTTPS only. The agent will not connect over plain HTTP (except localhost).", "Tokens are single-use and stored as hashes. A host key is issued at enrollment and revoked by deleting the host.",
          "The root console gives full control of a host: enable it only where needed and keep the number of administrators small."] },
      ],
    },
  };
  window.HELP = { ru, en, get: () => window.HELP[window.I18N.lang] || ru };
})();
