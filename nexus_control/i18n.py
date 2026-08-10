"""Минимальный i18n: en (msgid) / ru без gettext."""

from __future__ import annotations

from typing import Iterable

LOCALES: tuple[str, ...] = ("en", "ru")
DEFAULT_LOCALE = "ru"

_locale: str = DEFAULT_LOCALE

# msgid = English; только ru нуждается в таблице.
_MESSAGES: dict[str, dict[str, str]] = {
    "ru": {
        # Bindings / footer
        "Quit": "Выход",
        "Language": "Язык",
        "Refresh": "Обновить",
        "Filter": "Фильтр",
        "Next": "Далее",
        "Previous": "Назад",
        "To list": "К списку",
        "Open": "Открыть",
        "Logout": "Выйти",
        "Help": "Справка",
        "Close filter": "Закрыть фильтр",
        "Back": "Назад",
        "Expand": "Раскрыть",
        "Mark": "Отметить",
        "Unmark": "Снять отметки",
        "Download": "Скачать",
        "Verify": "Verify",
        "Download all": "Скачать всё",
        "Verify all": "Verify всё",
        "Report": "Отчёт",
        "Scanners": "Сканеры",
        "Cancel": "Отмена",
        "Confirm": "Подтвердить",
        "Yes": "Да",
        "No": "Нет",
        "OK": "OK",
        "Close": "Закрыть",
        "Save": "Сохранить",
        # Status / screens
        "Connecting…": "Подключение…",
        "Filter repositories…": "Фильтр репозиториев…",
        "Filter assets…": "Фильтр ассетов…",
        "Loading repositories…": "Загрузка репозиториев…",
        "Authentication error": "Ошибка аутентификации",
        "Network error": "Сетевая ошибка",
        "Nexus API error": "Ошибка Nexus API",
        "Unexpected error": "Неожиданная ошибка",
        "Connected to {url} as {user} — {count} repositories": (
            "Подключено к {url} как {user} — репозиториев: {count}"
        ),
        "Loaded {count} repositories": "Загружено репозиториев: {count}",
        "SSL/TLS certificate error": "Ошибка сертификата SSL/TLS",
        "SSL certificate error:": "Ошибка SSL-сертификата:",
        "Do you want to disable SSL/TLS validation?": (
            "Хотите ли вы отключить валидацию SSL/TLS?"
        ),
        "Failed to update config": "Не удалось обновить конфиг",
        "SSL/TLS verification disabled (nexus_verify_ssl=false); retrying…": (
            "Проверка SSL/TLS отключена (nexus_verify_ssl=false); повторный запрос…"
        ),
        "Certificate verification error": "Ошибка проверки сертификата",
        "Name": "Имя",
        "Format": "Формат",
        "Type": "Тип",
        "Support": "Поддержка",
        "URL": "URL",
        "Attributes": "Атрибуты",
        "Idle": "Ожидание",
        "Selection cleared": "Выделение снято",
        "Cancel requested…": "Отмена запрошена…",
        "Busy; wait for the current job.": "Занято; дождитесь текущей задачи.",
        "Loading assets for {name}…": "Загрузка ассетов для {name}…",
        "Listing assets…": "Загрузка списка ассетов…",
        "Listing assets… {count} (page {page})": (
            "Загрузка ассетов… {count} (стр. {page})"
        ),
        "Listing in background — browse as folders appear…": (
            "Фоновая загрузка — можно листать дерево по мере появления папок…"
        ),
        "Building tree…": "Построение дерева…",
        "Ready — {count} assets": "Готово — ассетов: {count}",
        "Ready — {count} tags": "Готово — тегов: {count}",
        "Loaded {count} assets from cache ({age}s old)": (
            "Загружено ассетов из кэша: {count} (возраст {age} с)"
        ),
        "Cache is {age}s old — refreshing from Nexus in background…": (
            "Кэш устарел ({age} с) — обновление из Nexus в фоне…"
        ),
        "Background refresh… {count} (page {page})": (
            "Фоновое обновление… {count} (стр. {page})"
        ),
        "Background refresh done — {count} assets": (
            "Фоновое обновление готово — ассетов: {count}"
        ),
        "Failed to load assets": "Не удалось загрузить ассеты",
        "Repository is empty (no assets).": "Репозиторий пуст (нет ассетов).",
        "Loaded {count} assets": "Загружено ассетов: {count}",
        "Unsupported repository: asset tree is built from paths best-effort.": (
            "Частично поддерживаемый репозиторий: дерево строится по путям best-effort."
        ),
        "Docker registry not exposed; set NEXUS_DOCKER_REGISTRY=host:port in config.toml or env.": (
            "Docker registry не доступен; задайте NEXUS_DOCKER_REGISTRY=host:port "
            "в config.toml или env."
        ),
        "Loaded {count} docker tags (adapter view)": (
            "Загружено docker-тегов: {count} (adapter view)"
        ),
        "download marked": "скачать отмеченное",
        "download": "скачать",
        "verify marked": "verify отмеченного",
        "verify": "verify",
        "download ALL": "скачать ВСЁ",
        "verify ALL": "verify ВСЁ",
        "No report yet. Run verify first.": (
            "Отчёта ещё нет. Сначала выполните verify."
        ),
        "Scan history": "История сканирований",
        "all repositories": "все репозитории",
        "No scan history yet.": "Истории сканирований пока нет.",
        "History": "История",
        "Open": "Открыть",
        "When": "Когда",
        "Repo": "Репо",
        "Source": "Источник",
        "Total": "Всего",
        "Copied": "Скопировано",
        "Skipped": "Пропущено",
        "Run id": "Run id",
        "Could not load run {run_id}.": "Не удалось загрузить прогон {run_id}.",
        "Open scan history": "Открыть историю сканирований",
        "Scanners: {names}": "Сканеры: {names}",
        "Another job is running.": "Уже выполняется другая задача.",
        "Nothing to do": "Нечего делать",
        "No assets marked/selected or repository is empty.": (
            "Нет отмеченных/выбранных ассетов или репозиторий пуст."
        ),
        "Marked nodes: {count}": "Отмечено узлов: {count}",
        "Confirm {action}": "Подтвердить: {action}",
        "Starting…": "Запуск…",
        "Done — PASS={passed} FAIL={failed} ERROR={errors} copied={copied}": (
            "Готово — PASS={passed} FAIL={failed} ERROR={errors} скопировано={copied}"
        ),
        "Finished scanned={scanned} PASS={passed} FAIL={failed} ERROR={errors} copied={copied}": (
            "Завершено scanned={scanned} PASS={passed} FAIL={failed} "
            "ERROR={errors} скопировано={copied}"
        ),
        "Failed": "Ошибка",
        "Pipeline failed": "Ошибка pipeline",
        "Language: {locale}": "Язык: {locale}",
        # Confirm body
        "Action: {action}": "Действие: {action}",
        "Items: {count}": "Элементов: {count}",
        "Scanners: {scanners}": "Сканеры: {scanners}",
        "Approx. size: {size}": "Примерно размер: {size}",
        "Download path: {path}": "Путь загрузки: {path}",
        "Verified path: {path}": "Путь verified: {path}",
        "Proceed?": "Продолжить?",
        "unknown": "неизвестно",
        "none": "нет",
        # Modals
        "Keyboard shortcuts": "Горячие клавиши",
        "Scanners": "Сканеры",
        "Vulnerability scanners": "Сканеры уязвимостей",
        "Enable one or both. Verify copies to *-verified only if all enabled scanners PASS.": (
            "Включите один или оба. Verify копирует в *-verified только если "
            "все включённые сканеры дали PASS."
        ),
        "Select at least one scanner.": "Выберите хотя бы один сканер.",
        "Upload verified": "Загрузить verified",
        "Upload": "Загрузить",
        "Upload target repository": "Целевой репозиторий для upload",
        (
            "Hosted repository name in Nexus. Default is <source>-verified. "
            "Existing repo of the same format will be reused."
        ): (
            "Имя hosted-репозитория в Nexus. По умолчанию <source>-verified. "
            "Существующий репозиторий того же format будет переиспользован."
        ),
        "Repository name": "Имя репозитория",
        "Asset": "Ассет",
        "Scan": "Скан",
        "Vulns": "Уязв.",
        "Crit": "Crit",
        "High": "High",
        "Med": "Med",
        "Low": "Low",
        "Verdict": "Вердикт",
        "Verified": "Verified",
        "Creating repository if missing…": "Создание репозитория при отсутствии…",
        "Upload finished ({created}): uploaded={uploaded} skipped={skipped} failed={failed}": (
            "Upload завершён ({created}): uploaded={uploaded} "
            "skipped={skipped} failed={failed}"
        ),
        "created": "создан",
        "existing": "существующий",
        "Upload failed:": "Ошибка upload:",
        # Help
        "Repositories": "Репозитории",
        "Assets": "Ассеты",
        "Selection rules": "Правила выбора",
        "Quit the application": "Выход из приложения",
        "Refresh repository list": "Обновить список репозиториев",
        "Filter by name": "Фильтр по имени",
        "From filter to repository list": "Из фильтра к списку репозиториев",
        "From filter to asset tree": "Из фильтра к дереву ассетов",
        "Open assets": "Открыть ассеты",
        "Logout (clear Nexus session and encrypted credentials)": (
            "Выйти (сброс Nexus-сессии и encrypted credentials)"
        ),
        "Show this help": "Показать эту справку",
        "Toggle UI language (en/ru)": "Переключить язык UI (en/ru)",
        "Back to repositories": "Назад к репозиториям",
        "Refresh assets": "Обновить ассеты",
        "Filter tree": "Фильтр дерева",
        "Expand / collapse": "Раскрыть / свернуть",
        "Mark / unmark (● marked, ○ not)": "Отметить / снять (● отмечено, ○ нет)",
        "Clear all marks": "Снять все отметки",
        "Download marked (or node under cursor)": (
            "Скачать отмеченное (или узел под курсором)"
        ),
        "Verify marked (download + scanners + copy PASS)": (
            "Verify отмеченного (download + сканеры + copy PASS)"
        ),
        "Download entire repository": "Скачать весь репозиторий",
        "Verify entire repository": "Verify весь репозиторий",
        "Open last report": "Открыть последний отчёт",
        "Scanners (grype / trivy / both)": "Сканеры (grype / trivy / оба)",
        "Scanners (grype / trivy / osv)": "Сканеры (grype / trivy / osv)",
        "Enable one or more. Verify copies to *-verified only if all "
        "enabled scanners PASS.": (
            "Включите один или несколько. Verify копирует в *-verified "
            "только если все включённые сканеры дали PASS."
        ),
        "Space on file/image marks one asset": (
            "Space на файле / образе — отметить один ассет"
        ),
        "Space on folder marks the whole branch (recursive on download/verify)": (
            "Space на папке — отметить всю ветку (рекурсивно при download/verify)"
        ),
        "Mark several nodes, then press d or v": (
            "Можно отметить несколько узлов, затем нажать d или v"
        ),
        "Without marks, d / v use the node under the cursor": (
            "Без отметок d / v работают для узла под курсором"
        ),
        "D / V always mean the entire repository": "D / V — всегда весь репозиторий",
        "s enables/disables Grype and/or Trivy; PASS only if all enabled PASS": (
            "s — включить/выключить Grype и/или Trivy; PASS только если все включённые PASS"
        ),
        # Wizard / credentials
        "nexus-control — first-run setup": "nexus-control — первоначальная настройка",
        "Config will be saved to: {path}": "Конфиг будет сохранён в: {path}",
        (
            "Username/password are not stored here — you will be prompted next "
            "(encrypted vault until session TTL)."
        ): (
            "Username/password здесь не сохраняются — запрос будет следующим "
            "(encrypted vault до TTL сессии)."
        ),
        "Language / Язык [ru/en]": "Language / Язык [ru/en]",
        "Nexus URL [{default}]": "Nexus URL [{default}]",
        "Verify TLS certificates? [Y/n]": "Проверять TLS-сертификаты? [Y/n]",
        "Scanners (grype, trivy, or both) [grype]": (
            "Сканеры (grype, trivy или оба) [grype]"
        ),
        "Scanners (grype, trivy, osv — comma-separated) [grype]": (
            "Сканеры (grype, trivy, osv — через запятую) [grype]"
        ),
        "Wrote {path}": "Записано {path}",
        "Nexus authentication": "Аутентификация Nexus",
        (
            "Credentials are stored encrypted until the Nexus session expires "
            "(see NEXUS_SESSION_TTL / {vault})."
        ): (
            "Учётные данные хранятся зашифрованно до истечения Nexus-сессии "
            "(см. NEXUS_SESSION_TTL / {vault})."
        ),
        "Username": "Имя пользователя",
        "Password: ": "Пароль: ",
        "Username is required": "Требуется имя пользователя",
        "Password is required": "Требуется пароль",
    }
}


def normalize_locale(code: str | None) -> str:
    raw = (code or DEFAULT_LOCALE).strip().lower().replace("_", "-")
    if raw.startswith("ru"):
        return "ru"
    if raw.startswith("en"):
        return "en"
    if raw in LOCALES:
        return raw
    return DEFAULT_LOCALE


def get_locale() -> str:
    return _locale


def set_locale(code: str) -> str:
    """Установить текущую локаль; вернуть нормализованный код."""
    global _locale
    _locale = normalize_locale(code)
    return _locale


def toggle_locale() -> str:
    """Переключить en ↔ ru."""
    return set_locale("en" if _locale == "ru" else "ru")


def _(message: str, **kwargs: object) -> str:
    """Перевести msgid; для en вернуть как есть. Поддержка ``str.format`` kwargs."""
    if _locale != "en":
        translated = _MESSAGES.get(_locale, {}).get(message, message)
    else:
        translated = message
    if kwargs:
        try:
            return translated.format(**kwargs)
        except (KeyError, ValueError):
            return translated
    return translated


def available_locales() -> Iterable[str]:
    return LOCALES
