# nexus-control

Production-ready **Textual** TUI для **Nexus Sonatype CE**: просмотр репозиториев и ассетов, скачивание артефактов, сканирование через **Grype** и/или **Trivy** и копирование только чистых (без уязвимостей) результатов в локальную verified-директорию.

```bash
python -m nexus_control
```

Быстрый старт: см. [QUICKSTART.md](QUICKSTART.md).

---

## Возможности

- First-run wizard + XDG-конфиг (`~/.config/nexus-control/config.toml`) — запуск из любого каталога
- Клиент Nexus REST API (`httpx`) с Basic Auth
- Локальный кэш сессии (`~/.cache/nexus-control/session.json`) с TTL — без лишних проверок авторизации
- Список репозиториев с фильтром и обновлением
- Дерево ассетов по полю Nexus `path` (раскрытие / сворачивание / фильтр)
- Docker-репозитории через адаптер тегов (Registry v2 API + fallback по assets)
- Мультивыбор ассетов/папок (Space), затем download или verify; либо действие на весь репозиторий
- Фоновые workers для сети, скачивания, сканеров и копирования (UI не блокируется)
- Потоковое скачивание с защитой от path traversal
- Grype и/или Trivy (локально или Docker-fallback); в TUI — клавиша `s`
- Строгая политика verify: в `<repo>-verified` только если все включённые сканеры дали PASS
- Ротация логов в файл + панель логов в TUI (секреты маскируются)

---

## Архитектура

```
nexus_control/
  config.py          # pydantic-settings + XDG TOML
  config_wizard.py   # first-run setup
  models.py          # доменные dataclasses
  logging_setup.py
  cli/               # nexus-control-cli (repos / verify / upload)
  nexus/             # REST-клиент, кэш сессии, парсеры
  services/          # downloader, grype, trivy, verifier, docker, pipeline
  ui/                # экраны / виджеты / кейбинды Textual
  utils/             # safe_path, fs, subprocess, tree_builder
```

Слои разделены: UI вызывает сервисы; сервисы используют Nexus-клиент; безопасность путей — в `utils/safe_path.py`.

---

## Требования

- **Python 3.13+** (или `uv`, который подтянет нужный Python)
- Целевая среда — **Linux** (TUI + POSIX-права). На Windows возможны unit-тесты и ограниченный UI
- Доступный **Nexus Repository CE** с REST API (`/service/rest/v1`)
- **grype** и/или **trivy** в `PATH` **или** Docker (fallback `anchore/grype` / `aquasec/trivy`)
- Опционально для docker-репозиториев: **skopeo** (предпочтительно) или **docker** CLI

---

## Установка (рекомендуется)

```bash
# Нужен uv: https://docs.astral.sh/uv/
# ~/.local/bin должен быть в PATH
uv tool install git+https://github.com/meowsl/nexus-control.git@dev

nexus-control       # Textual TUI
nexus-control-cli   # headless verify/upload (cron / CI)
```

При первом запуске wizard спросит Nexus URL и сохранит
`~/.config/nexus-control/config.toml`. Затем — prompt логина/пароля
(encrypted vault до TTL сессии).

### CLI (автоматизация)

После установки доступен `nexus-control-cli` — тот же pipeline, что в TUI, без UI:

```bash
# Список репозиториев
nexus-control-cli repos

# Verify + upload в <repo>-verified
nexus-control-cli verify --repo maven-hosted --upload

# Только upload локального *-verified
nexus-control-cli upload --repo maven-hosted

# Smoke / узкий прогон
nexus-control-cli verify --repo maven-hosted --path-prefix com/example --limit 20 --json

# Параллельная загрузка/скан (по умолчанию pipeline_workers=4 в config)
nexus-control-cli verify --repo maven-hosted --workers 8
```

`--limit N` ограничивает только основные ассеты, которым действительно нужна
загрузка или перезагрузка из-за изменившегося checksum. Уже существующие
неизменённые файлы и checksum/signature sidecar'ы лимит не расходуют.

После полного PASS + verified copy рядом с локальным файлом сохраняется
`*.scan-checkpoint.json`. Пока checksum, локальный файл, набор/версия/настройки
сканеров не изменились и checkpoint моложе `scan_checkpoint_ttl` (по умолчанию
сутки), повторный CLI verify пропускает этот ассет. После TTL он сканируется
повторно для учёта обновлений vulnerability DB; `scan_checkpoint_ttl = 0`
полностью отключает такой skip.

Для cron/CI задайте `NEXUS_USERNAME` / `NEXUS_PASSWORD` (или один раз прогрейте vault в TTY). Пример:

```cron
0 3 * * * NEXUS_USERNAME=… NEXUS_PASSWORD=… nexus-control-cli verify --repo maven-hosted --upload >>/var/log/nexus-verify.log 2>&1
```

Docker-репозитории в CLI v1 не поддерживаются (используйте TUI).

### Разработка из клона

```bash
git clone https://github.com/meowsl/nexus-control.git
cd nexus-control
uv sync --extra dev
uv run nexus-control
uv run nexus-control-cli repos
```

Или классический venv:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
nexus-control
```

---

## Конфигурация

Приоритет (выше побеждает):

1. Переменные окружения ОС (`NEXUS_URL`, …)
2. Legacy `.env` в **текущем** каталоге (опционально)
3. `~/.config/nexus-control/config.toml` (или `$NEXUS_CONTROL_CONFIG`)
4. Значения по умолчанию

Переопределить путь к TOML: `export NEXUS_CONTROL_CONFIG=/path/to/config.toml`.

Пример TOML — [config.toml.example](config.toml.example).

### Обязательно

| Ключ / переменная | Описание |
|-------------------|----------|
| `nexus_url` / `NEXUS_URL` | Базовый URL Nexus, например `http://localhost:8081` |

При отсутствии URL и наличии TTY запускается first-run wizard.

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
| `NEXUS_CACHE_DIR` | `~/.cache/nexus-control` | Каталог кэша сессии (режим 700) |
| `NEXUS_DOCKER_REGISTRY` | _(пусто)_ | Переопределение docker connector `host:port` |
| `NEXUS_CONTROL_CONFIG` | `~/.config/nexus-control/config.toml` | Путь к TOML-конфигу |
| `DOWNLOAD_ROOT` | `~/nexus-control/downloads` | Скачанные артефакты |
| `REPORTS_ROOT` | `~/nexus-control/reports` | JSON/TXT отчёты (`grype_*` / `trivy_*`) |
| `VERIFIED_ROOT` | `~/nexus-control` | Родитель каталогов `<repo>-verified/` |
| `SCANNERS` | `grype` | Через запятую: `grype`, `trivy` (в TUI — клавиша `s`) |
| `GRYPE_USE_DOCKER` | `auto` | `auto` / `true` / `false` |
| `GRYPE_DOCKER_IMAGE` | `anchore/grype:latest` | Образ для docker-fallback |
| `TRIVY_USE_DOCKER` | `auto` | `auto` / `true` / `false` |
| `TRIVY_DOCKER_IMAGE` | `aquasec/trivy:latest` | Образ для docker-fallback |
| `OVERWRITE_DOWNLOADS` | `false` | Force-перекачка; иначе skip по checksum, mismatch → overwrite |
| `OVERWRITE_VERIFIED` | `false` | Перезаписывать в verified |
| `LOG_FILE` | `~/nexus-control/logs/nexus-control.log` | Ротируемый лог |

Все пути с `~` раскрываются через `Path.expanduser()`. Каталоги downloads / reports / verified / logs создаются при старте.

Legacy `.env` — см. [.env.example](.env.example). Для повседневного использования достаточно wizard / TOML.
---

## Запуск

```bash
python -m nexus_control
# или
nexus-control          # TUI после install
nexus-control-cli      # headless CLI
# или
python main.py
```

### Пример использования

1. Запустите TUI против вашего Nexus.
2. На экране репозиториев: фильтр `/`, обновление `r`, открытие `Enter`.
3. В дереве ассетов выберите файл или директорию.
4. `s` — выбрать сканеры (grype / trivy / оба). Space — отметить файлы/папки; `v` — download → scan → copy PASS в verified (`d` — только download).
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
| `d` | Скачать выбранное / отмеченное |
| `v` | Verify выбранного / отмеченного |
| `D` | Скачать **весь** репозиторий |
| `V` | Verify **всего** репозитория |
| `s` | Сканеры (grype / trivy / оба) |
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
| Downloads | `/home/alice/nexus-control/downloads/my-repo/...` |
| Reports | `/home/alice/nexus-control/reports/my-repo/grype_....json` / `trivy_....json` |
| Verified | `/home/alice/nexus-control/my-repo-verified/...` |
| Manifest | `/home/alice/nexus-control/my-repo-verified/verified-manifest.json` |
| Logs | `/home/alice/nexus-control/logs/nexus-control.log` |
| Session | `~/.cache/nexus-control/session.json` |

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

## Сканеры (Grype / Trivy) и Docker-fallback

Включённые сканеры задаются `SCANNERS` (по умолчанию `grype`) или в TUI клавишей `s`. При verify оба могут работать **параллельно**. Отчёты: `grype_<asset>.json|txt`, `trivy_<asset>.json|txt`.

Порядок выбора бэкенда (для каждого сканера отдельно):

1. Локальный бинарник, если найден и `*_USE_DOCKER` не принудительно `true`
2. Иначе `docker run` образа (`GRYPE_DOCKER_IMAGE` / `TRIVY_DOCKER_IMAGE`), если режим `auto`/`true` и docker доступен
3. Иначе понятная ошибка в UI / логах

Docker-сканеры монтируют только `DOWNLOAD_ROOT` (ro) и `REPORTS_ROOT` (rw) — не весь home. Без privileged. Docker socket **не** монтируется.

**Политика вердикта (строгая):** у каждого сканера любая уязвимость → `FAIL`. В verified копируется только если **все** включённые сканеры дали `PASS`.

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
| Grype/Trivy не найден | Установите бинарник **или** docker + образ; либо выключите сканер клавишей `s` |
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
nexus-control/
├── nexus_control/           # пакет приложения
├── tests/
├── .env.example
├── QUICKSTART.md
├── requirements.txt
├── pyproject.toml
├── main.py
└── README.md
```

---

## License

[MIT](LICENSE) — © 2026 meowsl
