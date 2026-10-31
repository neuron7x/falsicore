"""Operator interpretation of findings and coverage codes (Ukrainian).

Every rule the collectors can emit has an entry; a test enforces completeness.
Each entry separates what was observed from what it could mean, states the
uncertainty, and proposes only non-destructive next steps. Priority orders
review effort; it is not a probability of compromise.
"""
from __future__ import annotations

import re

# priority: P1 review first, P2 review soon, P3 context/hardening.
RULES: dict[str, dict[str, str]] = {
    "EXECUTABLE_IN_VOLATILE_PATH": {
        "priority": "P1",
        "observed": "Процес виконується з тимчасового каталогу (/tmp, /var/tmp, /dev/shm).",
        "benign": "Збірка чи тест розробника, інсталятор, AppImage, розпакований оновлювач.",
        "uncertainty": "Розташування не доводить шкідливості; знімок не показує, хто й навіщо запустив процес.",
        "action": "Зіставити PID, батьківський процес і хеш виконуваного файла з власними діями; зберегти копію файла до будь-яких змін.",
    },
    "DELETED_RUNNING_EXECUTABLE": {
        "priority": "P2",
        "observed": "Виконуваний файл процесу видалено з диска, а процес ще працює.",
        "benign": "Найчастіше — оновлення пакета без перезапуску програми.",
        "uncertainty": "Також типова техніка приховування; без контексту оновлення не розрізнити.",
        "action": "Перевірити, чи було нещодавнє оновлення цього пакета; за потреби перезапустити програму після збереження доказів.",
    },
    "ROOT_RUNNING_USER_PATH": {
        "priority": "P1",
        "observed": "Процес root виконує файл із каталогу, доступного звичайному користувачеві.",
        "benign": "Ручний запуск власного скрипта через sudo, нестандартна установка.",
        "uncertainty": "Може бути шляхом підвищення привілеїв; знімок не показує, як файл туди потрапив.",
        "action": "Встановити власника файла, час зміни та походження; не запускати файл повторно.",
    },
    "TEMP_PROCESS_PUBLIC_EGRESS": {
        "priority": "P1",
        "observed": "Процес із тимчасового каталогу має з'єднання з публічною адресою.",
        "benign": "Тестовий клієнт, сервер розробки, інструмент оновлення.",
        "uncertainty": "Один знімок з'єднання; призначення адреси локально не встановлюється.",
        "action": "Зберегти адресу з private_index.json локально, зіставити з власними діями; не надсилати її стороннім сервісам без потреби.",
    },
    "UNSAFE_BROWSER_LAUNCH_FLAG": {
        "priority": "P2",
        "observed": "Браузер запущено з прапорцями, що послаблюють ізоляцію або дають зовнішнє керування.",
        "benign": "Автоматизація (Playwright, Puppeteer, Selenium, тестові агенти) запускає браузер саме з --no-sandbox і --remote-debugging-pipe.",
        "uncertainty": "--remote-debugging-pipe — канал лише до процесу-запускача, не мережевий порт; порт існує тільки з --remote-debugging-port і перевіряється за таблицею сокетів.",
        "action": "Подивитися батьківський процес у спостереженні: якщо це ваш інструмент автоматизації — очікувано; якщо невідомий — зберегти дані процесу й закрити той екземпляр браузера.",
    },
    "POWERFUL_BROWSER_EXTENSION": {
        "priority": "P2",
        "observed": "Розширення заявляє дозволи, що дають доступ до вмісту сторінок, вкладок, cookie або налагодження.",
        "benign": "Менеджери паролів, блокувальники реклами, інструменти розробника та агенти легітимно потребують широких дозволів.",
        "uncertainty": "Заявлений дозвіл — це можливість, а не зафіксована дія; назва не підтверджує видавця.",
        "action": "Звірити ID, версію й джерело встановлення з тим, що ви свідомо ставили; невідоме — вимкнути в браузері після збереження звіту.",
    },
    "POWERFUL_FIREFOX_EXTENSION": {
        "priority": "P2",
        "observed": "Доповнення Firefox має дозволи на широкий доступ до сторінок чи мережевих запитів.",
        "benign": "Вбудовані системні доповнення Firefox (location app-builtin/app-system) і відомі розширення.",
        "uncertainty": "Дозвіл не є поведінкою; стан підпису показує лише відповідність перевірці Mozilla.",
        "action": "Звірити ID, джерело (location) і підпис; невідоме доповнення — вимкнути в about:addons після збереження звіту.",
    },
    "NATIVE_HOST_OUTSIDE_STANDARD_PATH": {
        "priority": "P2",
        "observed": "Native messaging host — програма поза браузером, яку розширення можуть викликати — лежить у каталозі, доступному на запис користувачу.",
        "benign": "Багато легітимних інструментів (менеджери паролів, агенти, IDE) ставлять host у домашній каталог.",
        "uncertainty": "Розташування — не вторгнення; важливо, яким розширенням дозволено виклик і чи файл очікуваний.",
        "action": "Звірити ім'я host, дозволені розширення й хеш виконуваного файла з встановленим вами ПЗ.",
    },
    "INVALID_EXTENSION_MANIFEST": {
        "priority": "P3",
        "observed": "Маніфест розширення не вдалося прочитати як коректний JSON.",
        "benign": "Пошкоджене чи частково оновлене розширення.",
        "uncertainty": "Дозволи цього розширення не оцінено.",
        "action": "Перевірити розширення в інтерфейсі браузера.",
    },
    "BROWSER_ENTERPRISE_POLICY": {
        "priority": "P2",
        "observed": "Знайдено політику керування браузером, яка може примусово встановлювати розширення.",
        "benign": "Корпоративне або дистрибутивне керування.",
        "uncertainty": "Політика може бути легітимною або механізмом закріплення.",
        "action": "З'ясувати, хто встановив політику і чи вона очікувана.",
    },
    "REMOTE_ACCESS_PORT_EXPOSED": {
        "priority": "P2",
        "observed": "Служба віддаленого доступу (SSH/RDP/VNC/ADB) слухає не лише на loopback.",
        "benign": "Свідомо увімкнений SSH чи віддалений робочий стіл.",
        "uncertainty": "Доступність з мережі залежить від фаєрвола й маршрутизатора; це не перевіряється.",
        "action": "Переконатися, що служба потрібна; якщо ні — вимкнути її штатними засобами після збереження звіту.",
    },
    "REMOTE_AUTHENTICATION_REVIEW": {
        "priority": "P3",
        "observed": "У журналі є успішні входи через SSH.",
        "benign": "Ваші власні сесії.",
        "uncertainty": "Журнал локальний і може бути змінений привілейованим нападником.",
        "action": "Звірити час і джерела входів з власними сесіями.",
    },
    "SUSPICIOUS_SHELL_INIT": {
        "priority": "P1",
        "observed": "Файл ініціалізації оболонки містить синтаксис запуску з тимчасового шляху, завантаження в оболонку або декодування в оболонку.",
        "benign": "Власні налаштування, інсталятори (rustup, nvm), тимчасові експерименти.",
        "uncertainty": "Це статичний збіг синтаксису, не факт виконання; аналізатор — підмножина Bash.",
        "action": "Відкрити файл локально на вказаних рядках; не виконувати рядок і не пересилати вміст у чат.",
    },
    "SUSPICIOUS_SYSTEMD_EXECUTION": {
        "priority": "P1",
        "observed": "Юніт systemd запускає програму з тимчасового шляху або завантажений скрипт.",
        "benign": "Самописна службова автоматизація.",
        "uncertainty": "Статичний збіг; чи юніт активний — окреме питання.",
        "action": "Перевірити `systemctl status` цього юніта, власника і час зміни файла; не запускати вручну.",
    },
    "SYSTEMD_SYMLINK_TO_TEMP": {
        "priority": "P1",
        "observed": "Посилання на службу systemd веде в тимчасовий каталог.",
        "benign": "Рідко буває легітимним.",
        "uncertainty": "Ціль могла вже зникнути.",
        "action": "Зберегти посилання й ціль, з'ясувати походження.",
    },
    "SUSPICIOUS_CRON_EXECUTION": {
        "priority": "P1",
        "observed": "Системне завдання cron містить ризикований шаблон запуску.",
        "benign": "Адміністративна автоматизація.",
        "uncertainty": "Статичний збіг синтаксису.",
        "action": "Перевірити файл, власника, час зміни та пов'язані події в журналі.",
    },
    "SUSPICIOUS_USER_CRONTAB": {
        "priority": "P1",
        "observed": "Crontab користувача містить ризикований шаблон запуску.",
        "benign": "Власні заплановані скрипти.",
        "uncertainty": "Статичний збіг синтаксису.",
        "action": "Переглянути `crontab -l` локально; не виконувати рядок.",
    },
    "SUSPICIOUS_AUTOSTART": {
        "priority": "P1",
        "observed": "Запис автозапуску робочого столу посилається на ризикований запуск.",
        "benign": "Самописний автозапуск.",
        "uncertainty": "Статичний збіг; Hidden/OnlyShowIn можуть вимикати запис.",
        "action": "Переглянути .desktop-файл локально, з'ясувати походження.",
    },
    "SYSTEM_LOADER_PRELOAD": {
        "priority": "P1",
        "observed": "Налаштовано /etc/ld.so.preload — бібліотеки, що підвантажуються в кожен процес.",
        "benign": "Профілювальники, сумісність, деякі безпекові агенти.",
        "uncertainty": "Класичний механізм user-space руткітів; живий знімок не довіряє ураженій системі.",
        "action": "Зберегти файл, визначити пакет-власник бібліотек; за підозри — офлайн-аналіз диска.",
    },
    "INSECURE_PACKAGE_SOURCE_SETTING": {
        "priority": "P2",
        "observed": "Налаштування джерел пакетів вимикає перевірку підпису або транспорту (apt trusted=yes/Allow-Insecure, dnf gpgcheck=0/sslverify=0, pacman SigLevel Never/TrustAll, apk --allow-untrusted).",
        "benign": "Локальне тестове дзеркало, тимчасове налагодження.",
        "uncertainty": "Дає змогу підмінити пакети в дорозі; саме налаштування не є вторгненням.",
        "action": "З'ясувати, навіщо джерело так налаштоване; виправити після збереження доказів.",
    },
    "PACKAGE_FILE_DRIFT": {
        "priority": "P1",
        "observed": "Вміст встановлених НЕ-конфігураційних файлів пакетів відрізняється від записів бази пакетів (dpkg, rpm, pacman або apk).",
        "benign": "Ручні правки, локальні збірки поверх пакета, перерване оновлення, prelink.",
        "uncertainty": "Зміна бінарних файлів пакета — класична ознака підміни; привілейований нападник може змінити і файли, і записи бази.",
        "action": "Подивитися перелік у package_integrity (system scope дає повний); перевстановити пакет лише після збереження доказів.",
    },
    "PACKAGE_CONFFILE_CHANGED": {
        "priority": "P3",
        "observed": "Конфігураційні файли відрізняються від версій із пакетів.",
        "benign": "Звичайні налаштування системи адміністратором.",
        "uncertainty": "Зміна конфігурації може як бути нормою, так і послаблювати захист.",
        "action": "Переглянути змінені конфіги, якщо їх не правили свідомо.",
    },
    "PACKAGE_FILES_MISSING": {
        "priority": "P3",
        "observed": "Файлів, записаних за встановленими пакетами, немає на диску.",
        "benign": "Залишки старих ядер (/lib/modules/<версія>), path-exclude у dpkg, ручне прибирання.",
        "uncertainty": "Відсутність файла не є зміною вмісту; зрідка це сліди заметання.",
        "action": "Подивитися missing_by_prefix; модулі старих ядер прибираються штатним видаленням відповідних пакетів.",
    },
    "PACKAGE_METADATA_DRIFT": {
        "priority": "P3",
        "observed": "У пакетних файлів змінено права, власника, розмір або ціль посилання, хоча вміст збігається із записом.",
        "benign": "Локальне посилення/послаблення прав адміністратором, системи з prelink або IMA.",
        "uncertainty": "Доданий setuid або змінений власник бінарника — ознака підвищення привілеїв; сам факт змін без вмісту — контекст.",
        "action": "Порівняти права файлів із записами пакета (rpm -V, mtree); повернути штатні права після збереження доказів.",
    },
    "SSH_DIRECTORY_OVERPERMISSIVE": {
        "priority": "P3",
        "observed": "Каталог ~/.ssh доступний іншим користувачам.",
        "benign": "Помилка налаштування прав.",
        "uncertainty": "Налаштування захисту, не ознака вторгнення.",
        "action": "Обмежити права до 700 після збереження звіту.",
    },
    "SSH_AUTHORIZED_KEYS_PERMISSIONS": {
        "priority": "P3",
        "observed": "Файл authorized_keys має надто широкі права.",
        "benign": "Помилка налаштування прав.",
        "uncertainty": "Інший користувач міг би додати ключ.",
        "action": "Перевірити перелік ключів і обмежити права до 600.",
    },
    "SUDO_NOPASSWD_RULE": {
        "priority": "P3",
        "observed": "Є правило sudo без пароля.",
        "benign": "Свідоме налаштування для автоматизації.",
        "uncertainty": "Розширює наслідки компрометації облікового запису.",
        "action": "Переконатися, що правило потрібне і обмежене конкретними командами.",
    },
}

DEFAULT_RULE = {
    "priority": "P2",
    "observed": "Евристичне спостереження без окремого опису.",
    "benign": "Невідомо.",
    "uncertainty": "Потребує ручної перевірки.",
    "action": "Перевірити локально за джерелом у private_index.json.",
}

REASONS_UA: dict[str, str] = {
    "PERMISSION_DENIED": "немає доступу до частини власної цілі перевірки",
    "TOOL_MISSING": "потрібна утиліта не встановлена",
    "TOOL_FAILED": "команда-проба завершилась помилкою",
    "TIMEOUT": "команда-проба не вклалась у час",
    "INPUT_TRUNCATED": "вхідні дані обрізано за обмеженням розміру",
    "ENUMERATION_LIMIT": "досягнуто ліміт кількості об'єктів профілю",
    "BUDGET_EXHAUSTED": "вичерпано загальний час сканування",
    "PARSE_UNSUPPORTED": "синтаксис поза підтримуваною підмножиною аналізатора",
    "MALFORMED_INPUT": "дані не вдалося розібрати",
    "HISTORY_UNAVAILABLE": "запитана історія не збережена або не повернута",
    "SYMLINK_NOT_FOLLOWED": "посилання за межі оглянутих каталогів не відкривалось",
    "ATTRIBUTION_UNAVAILABLE": "об'єкт не вдалося пов'язати з процесом",
    "READ_FAILED": "неочікувана помилка читання",
    "PROFILE_EXCLUDED": "виключено обраним профілем",
    "COLLECTOR_ERROR": "збій колектора; його спостереження відкинуто",
    "OTHER_ACCOUNTS_NOT_VISIBLE": "об'єкти інших облікових записів невидимі в user scope",
    "REQUIRES_SYSTEM_SCOPE": "ця частина виконується лише з --scope system",
    "NOT_IN_PROFILE": "ця частина виконується лише в глибшому профілі",
    "SOURCE_VANISHED": "об'єкт зник між переліком і читанням",
    "PACKAGE_ATTESTED_NOT_PARSED": "файл root збігається із записом dpkg; складний синтаксис не розбирався (довіра до пакета)",
}

_CONTROL = re.compile("[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\\u202a-\\u202e\\u2066-\\u2069]")


def rule(name: str) -> dict[str, str]:
    return RULES.get(name, DEFAULT_RULE)


def terminal_safe(value: object, limit: int = 300) -> str:
    """Neutralise terminal control and bidi characters from untrusted strings."""
    text = str(value)[:limit]
    return _CONTROL.sub(lambda m: "\\x%02x" % ord(m.group(0)) if ord(m.group(0)) < 0x100 else "\\u%04x" % ord(m.group(0)), text)


def codes_ua(codes: dict) -> str:
    return "; ".join(f"{REASONS_UA.get(k, k)} ({k}×{v})" for k, v in sorted(codes.items())) or "—"


def identity_line(finding: dict) -> str:
    """One-line private attribution: who/what the finding is about.

    Total on any JSON-shaped finding: a malformed evidence block yields an
    empty line, never an exception (an explain/verify path must not crash).
    """
    ev = finding.get("evidence", {})
    if not isinstance(ev, dict):
        return ""
    ext = ev.get("extension")
    if isinstance(ext, dict):
        parts = [f"{ext.get('name', 'UNKNOWN')} {ext.get('version', '')}".strip(),
                 f"id={ext.get('extension_id', 'UNKNOWN')}", f"увімкнено={ext.get('enabled', 'UNKNOWN')}"]
        for key, label in (("install_location", "джерело"), ("from_webstore", "з магазину"),
                           ("signed_state", "підпис")):
            if key in ext:
                parts.append(f"{label}={ext[key]}")
        if ext.get("native_hosts_allowing"):
            parts.append("native host=" + ",".join(ext["native_hosts_allowing"]))
        return "; ".join(terminal_safe(p, 120) for p in parts)
    if "host_name" in ev:
        exe = ev.get("executable", {})
        return terminal_safe(f"браузер={ev.get('manifest_owner', '?')}; host={ev['host_name']}; дозволені розширення={','.join(ev.get('allowed_extensions', [])) or '—'}; "
                             f"файл={exe.get('status', 'UNKNOWN')} uid={exe.get('owner_uid', '?')} sha256={str(exe.get('sha256', '?'))[:16]}", 300)
    observations = finding.get("observations") or []
    if isinstance(observations, list) and observations and isinstance(observations[0], dict):
        o = observations[0]
        parent = o.get("parent", {}) if isinstance(o.get("parent"), dict) else {}
        line = (f"pid={o.get('pid')} ppid={o.get('ppid')} uid={o.get('uid')} exe={o.get('exe_name')} "
                f"батько={parent.get('exe_name', '?')} старт={o.get('start_ticks')} час={o.get('observed_utc')}")
        if ev.get("debug_channel"):
            line += f"; debug={ev['debug_channel']}" + (f":{ev.get('debug_port')} {ev.get('debug_port_listener')}" if ev.get("debug_port") else "")
        return terminal_safe(line, 300)
    locations = ev.get("locations")
    if isinstance(locations, list) and locations:
        lines = ",".join(str(x.get("line", "?")) for x in locations if isinstance(x, dict))
        return terminal_safe("файл=" + str(ev.get("file_name", "?")) + "; рядки=" + lines, 200)
    return ""
