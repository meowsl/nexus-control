# nexus-tui

Production-ready **Textual** TUI для **Nexus Sonatype CE**: просмотр репозиториев и ассетов, скачивание артефактов, сканирование через **Grype** и копирование только чистых (без уязвимостей) результатов в локальную verified-директорию.

```bash
python -m nexus_tui
```

Быстрый старт: см. [QUICKSTART.md](QUICKSTART.md).

---

## Возможности

- Загрузка конфигурации из `.env` / переменных окружения ОС (приоритет у ОС)
- Клиент Nexus REST API (`httpx`) с Basic Auth
- Локальный кэш сессии (`~/.cache/nexus-tui/session.json`) с TTL — без лишних проверок авторизации
- Список репозиториев с фильтром и обновлением
- Дерево ассетов по полю Nexus `path` (раскрытие / сворачивание / фильтр)
- Docker-репозитории через адаптер тегов (Registry v2 API + fallback по assets)
- Мультивыбор ассетов/папок (Space), затем download или verify; либо действие на весь репозиторий
- Фоновые workers для сети, скачивания, Grype и копирования (UI не блокируется)
- Потоковое скачивание с защитой от path traversal
- Локальный Grype или fallback через Docker-образ
- Строгая политика verify: в `<repo>-verified` копируются **только** ассеты с нулём уязвимостей
- Ротация логов в файл + панель логов в TUI (секреты маскируются)

---

## Архитектура

```
nexus_tui/
  config.py          # pydantic-settings
  models.py          # доменные dataclasses
  logging_setup.py
  nexus/             # REST-клиент, кэш сессии, парсеры
  services/          # downloader, grype, verifier, docker, pipeline
  ui/                # экраны / виджеты / кейбинды Textual
  utils/             # safe_path, fs, subprocess, tree_builder
```

Слои разделены: UI вызывает сервисы; сервисы используют Nexus-клиент; безопасность путей — в `utils/safe_path.py`.

---

## Требования

- **Python 3.13+**
- Целевая среда — **Linux** (TUI + POSIX-права). На Windows возможны unit-тесты и ограниченный UI
- Доступный **Nexus Repository CE** с REST API (`/service/rest/v1`)
- **grype** в `PATH` **или** Docker (для fallback `anchore/grype`)
- Опционально для docker-репозиториев: **skopeo** (предпочтительно) или **docker** CLI

---

## Установка

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# опционально editable-установка:
pip install -e .
```

---

## Настройка

```bash
cp .env.example .env
# заполнить NEXUS_URL; username/password лучше вводить при запуске
```

### Обязательные переменные

| Переменная | Описание |
|------------|----------|
| `NEXUS_URL` | Базовый URL Nexus, например `http://localhost:8081` |

### Учётные данные

| Переменная | Описание |
|------------|----------|
| `NEXUS_USERNAME` / `NEXUS_PASSWORD` | Опционально. Если не заданы — prompt при старте (TTY). Для CI задайте в env. |

После успешного логина пароль хранится **зашифрованно** (Fernet) в `NEXUS_CACHE_DIR/credentials.vault` только до `expires_at` Nexus-сессии (`NEXUS_SESSION_TTL`). В `session.json` пароля нет. Сброс: клавиша `L` (Logout) или истечение TTL.

### Важные опциональные

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `NEXUS_VERIFY_SSL` | `true` | `false` только для self-signed TLS в лаборатории (будет warning) |
| `NEXUS_SESSION_TTL` | `3600` | TTL кэша сессии (секунды) |
| `NEXUS_CACHE_DIR` | `~/.cache/nexus-tui` | Каталог кэша сессии (режим 700) |
| `NEXUS_DOCKER_REGISTRY` | _(пусто)_ | Переопределение docker connector `host:port` |
| `DOWNLOAD_ROOT` | `~/nexus-automation/downloads` | Скачанные артефакты |
| `REPORTS_ROOT` | `~/nexus-automation/reports` | JSON/TXT отчёты Grype |
| `VERIFIED_ROOT` | `~/nexus-automation` | Родитель каталогов `<repo>-verified/` |
| `GRYPE_USE_DOCKER` | `auto` | `auto` / `true` / `false` |
| `GRYPE_DOCKER_IMAGE` | `anchore/grype:latest` | Образ для docker-fallback |
| `OVERWRITE_DOWNLOADS` | `false` | Force-перекачка; иначе skip по checksum, mismatch → overwrite |
| `OVERWRITE_VERIFIED` | `false` | Перезаписывать в verified |
| `LOG_FILE` | `~/nexus-automation/logs/nexus-tui.log` | Ротируемый лог |

Все пути с `~` раскрываются через `Path.expanduser()`. Каталоги downloads / reports / verified / logs создаются при старте.

Полные комментарии по каждой переменной — в `.env.example`.

---

## Запуск

```bash
python -m nexus_tui
# или
nexus-tui          # после pip install -e .
# или
python main.py
```

### Пример использования

1. Запустите TUI против вашего Nexus.
2. На экране репозиториев: фильтр `/`, обновление `r`, открытие `Enter`.
3. В дереве ассетов выберите файл или директорию.
4. Space — отметить нужные файлы/папки; `v` — download → Grype → copy PASS в verified (`d` — только download).
5. Нажмите `V` для того же сценария по **всему** репозиторию.
6. Изучите модальное окно результатов; позже `o` откроет последний отчёт.

---

## Кейбинды

### Репозитории

| Клавиша | Действие |
|---------|----------|
| `q` | Выход |
| `r` | Обновить список |
| `/` | Фильтр по имени |
| `Enter` | Открыть ассеты |
| `?` | Справка |

### Ассеты

| Клавиша | Действие |
|---------|----------|
| `Esc` / `q` | Назад |
| `r` | Обновить ассеты |
| `/` | Фильтр дерева |
| `Enter` | Раскрыть / свернуть |
| `d` | Скачать выбранное |
| `s` | Скачать + просканировать выбранное |
| `v` | Скачать + просканировать + verify выбранное |
| `D` | Скачать **весь** репозиторий |
| `S` | Просканировать **весь** репозиторий |
| `V` | Verify **всего** репозитория |
| `o` | Открыть последний отчёт |
| `?` | Справка |

**Правила выбора**

- Файл / образ → только этот элемент  
- Директория → все вложенные ассеты  
- `D` / `S` / `V` → всегда весь репозиторий  

---

## Где лежат файлы

При значениях по умолчанию, пользователь `alice`, репозиторий `my-repo`:

| Тип | Путь |
|-----|------|
| Downloads | `/home/alice/nexus-automation/downloads/my-repo/...` |
| Reports | `/home/alice/nexus-automation/reports/my-repo/...grype.json` |
| Verified | `/home/alice/nexus-automation/my-repo-verified/...` |
| Manifest | `/home/alice/nexus-automation/my-repo-verified/verified-manifest.json` |
| Logs | `/home/alice/nexus-automation/logs/nexus-tui.log` |
| Session | `~/.cache/nexus-tui/session.json` |

Docker-образы сохраняются как:

`downloads/<repo>/images/<tag-safe>.tar`

---

## Кэш сессии

1. При старте читается `NEXUS_CACHE_DIR/session.json`.
2. Кэш принимается только если совпадают `schema_version`, `nexus_url`, `username` / `config_hash` и `expires_at` ещё в будущем.
3. Выполняется probe: `GET /service/rest/v1/repositories`.
4. Если OK — сессия переиспользуется. При 401/403 кэш инвалидируется, выполняетсяется одна повторная авторизация; при повторном отказе — понятная ошибка пользователю.
5. Пароль **никогда** не сохраняется. Права файла `600`, каталога `700` (best-effort на POSIX).
6. Во время работы при 401/403: invalidate → re-auth один раз → retry.

Если Nexus поддерживает только Basic Auth (типичный CE), кэш всё равно хранит факт успешной проверки на TTL `NEXUS_SESSION_TTL`.

---

## Grype и Docker-fallback

Порядок выбора:

1. Локальный `GRYPE_BINARY`, если найден и `GRYPE_USE_DOCKER` не принудительно `true`
2. Иначе `docker run` образа `GRYPE_DOCKER_IMAGE`, если режим `auto`/`true` и docker доступен
3. Иначе понятная ошибка в UI / логах

Docker-grype монтирует только `DOWNLOAD_ROOT` (ro) и `REPORTS_ROOT` (rw) — не весь home. Без privileged. Docker socket **не** монтируется (сканируются локальные `file:` / `docker-archive:`).

**Политика вердикта (строгая):** любая уязвимость (включая Low / Negligible) → `FAIL` → не копируется в verified. Пустой список → `PASS`.

---

## Docker-репозитории

- Теги показываются под виртуальным узлом `images/` (не сырые blob/manifest paths).
- Источник тегов: Docker Registry v2 `GET /v2/<repo>/tags/list`, если известен host/port connector (`NEXUS_DOCKER_REGISTRY` или `attributes.docker.httpPort/httpsPort`).
- Fallback: вывод тегов из путей ассетов с `/manifests/<tag>`.
- Pull: **skopeo** `copy` с временным auth-файлом (режим 600), иначе **docker** `pull` + `save` с временным `DOCKER_CONFIG` — пароль не передаётся в argv.

---

## Допущения (Assumptions)

1. Nexus CE доступен по `NEXUS_URL` и отдаёт REST v1.
2. Основная авторизация — **HTTP Basic**; cookies сохраняются, если сервер их выставляет.
3. Docker connector в лабораториях часто на отдельном HTTP-порту; задайте `NEXUS_DOCKER_REGISTRY`, если автоопределение не сработало.
4. Имя verified-каталога: `<repository>-verified` под `VERIFIED_ROOT` (без хардкода `/home/...`).
5. При повторной загрузке локальный файл сверяется с remote checksum (`sha256` → `sha1` → `md5`); совпадение → skip, расхождение → перекачка. После скачивания mismatch → download `ERROR` (для blob-ассетов). Для npm package-root/metadata Nexus часто отдаёт sha1, не совпадающий с телом ответа — там checksum не hard-fail, skip идёт по неизменности remote identity в sidecar. `OVERWRITE_DOWNLOADS=true` форсирует перекачку.
6. Целевая ОС — Linux; биты прав на других платформах — best-effort.

---

## Ограничения текущей версии

- Upload verified создаёт hosted `<repo>-verified` **того же format**, что источник (npm/maven2/pypi/raw); npm metadata / non-package файлы при upload пропускаются
- Нет delete и произвольного admin write в Nexus
- Для docker нужны skopeo или docker CLI
- Очень большие репозитории загружают все ассеты в память для построения дерева (пагинация используется на проводе)
- Нет порога severity — по умолчанию строгий zero vulnerabilities

---

## Тесты

```bash
pytest
```

Офлайн unit-тесты покрывают кэш сессии, построение дерева, парсер Grype и safe paths.

---

## Troubleshooting

| Симптом | Что проверить |
|---------|----------------|
| Ошибка конфигурации при старте | Есть `.env`; заданы обязательные `NEXUS_*` |
| Auth failed | Логин/пароль; права пользователя на репозитории |
| Ошибки TLS | Self-signed в лаборатории → `NEXUS_VERIFY_SSL=false` (ожидается warning) |
| Пустые docker-теги | Задайте `NEXUS_DOCKER_REGISTRY=host:port` |
| Grype не найден | Установите grype **или** docker + образ `anchore/grype` |
| skopeo/docker pull падает | Auth к registry; для insecure HTTP помогает `NEXUS_VERIFY_SSL=false` |
| Путь отклонён | В path был `..` или абсолютный путь — пропуск из соображений безопасности |
| UI «зависает» | Не должен; проверьте панель логов / файл лога |

---

## Заметки по безопасности

- Пароль не пишется в кэш сессии, манифесты и отчёты
- Логи маскируют password / Authorization-подобные шаблоны
- Downloads ограничены `DOWNLOAD_ROOT`; verified — `VERIFIED_ROOT`
- Path traversal и абсолютные пути из API отклоняются
- Subprocess вызывается списками argv (`shell=False`)
- У скачанных файлов execute-биты снимаются best-effort
- Права кэша сессии ужесточаются на POSIX
- Временные auth-файлы docker/skopeo имеют режим `600` и удаляются вместе с temp-каталогом

---

## Структура проекта

```
nexus-automation/
├── nexus_tui/           # пакет приложения
├── tests/
├── .env.example
├── QUICKSTART.md
├── requirements.txt
├── pyproject.toml
├── main.py
└── README.md
```
