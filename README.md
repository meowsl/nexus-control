# nexus-control

Production-ready **Textual** TUI для **Nexus Sonatype CE**: просмотр репозиториев и ассетов, скачивание артефактов, сканирование через **Grype**, **Trivy** и/или **OSV-Scanner** и копирование только чистых (без уязвимостей) результатов в локальную verified-директорию.

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
- Grype / Trivy / OSV-Scanner (локально или Docker-fallback); в TUI — клавиша `s`
- Строгая политика verify: в `<repo>-verified` только если все включённые сканеры дали PASS
- Ротация логов в файл + панель логов в TUI (секреты маскируются)

---

## Архитектура

Слои разделены: UI/CLI вызывают сервисы; сервисы используют Nexus-клиент; безопасность путей — в `utils/safe_path.py`.

```
UI (Textual) / CLI / scheduler  →  services (pipeline, scanners, verifier)
                                →  nexus (REST client, cache, credentials)
                                →  utils (safe_path, fs, hashing, …)
```

---

## Требования

- **Python 3.13+** (или `uv`, который подтянет нужный Python)
- Целевая среда — **Linux** (TUI + POSIX-права). На Windows возможны unit-тесты и ограниченный UI
- Доступный **Nexus Repository CE** с REST API (`/service/rest/v1`)
- **grype** / **trivy** / **osv-scanner** в `PATH` **или** Docker (fallback `anchore/grype` / `aquasec/trivy` / `ghcr.io/google/osv-scanner`)
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
# (только пути из последнего verified-manifest.json / PASS; stale на диске пропускаются)
nexus-control-cli upload --repo maven-hosted

# Smoke / узкий прогон
nexus-control-cli verify --repo maven-hosted --path-prefix com/example --limit 20 --json
nexus-control-cli verify --repo maven-hosted --scan-limit 20   # debug: max mains to verify

# Параллельная загрузка/скан (по умолчанию auto от CPU/RAM; или явный override)
nexus-control-cli verify --repo maven-hosted --workers 8 --max-scanner-procs 4

# История сканирований (последние verify из TUI / CLI / scheduler)
nexus-control-cli history
nexus-control-cli history --repo maven-hosted --limit 20
nexus-control-cli history show <run_id>
nexus-control-cli history show <run_id> --json

# Offline OSV vulnerability DB (для osv / nuget verify без remote API)
nexus-control-cli osv-db status
nexus-control-cli osv-db update --ecosystem NuGet
# cron example:
# 0 3 * * * nexus-control-cli osv-db update --ecosystem NuGet

# Webhook: POST JSON-сводки после verify (Bearer / Basic / custom header)
nexus-control-cli webhook configure
nexus-control-cli webhook status
nexus-control-cli webhook test
```

`--limit N` ограничивает только основные ассеты, которым действительно нужна
загрузка или перезагрузка из-за изменившегося checksum. Уже существующие
неизменённые файлы и checksum/signature sidecar'ы лимит не расходуют. Как только
найдено `N` таких main-ассетов, CLI останавливает pagination Nexus; частичный
список не сохраняется как полный asset cache. Companion sidecar'ы для PASS
запрашиваются напрямую по стандартным суффиксам, поэтому дочитывать весь
репозиторий ради них не требуется.

`--scan-limit N` — отдельный дебаг-лимит: в verify попадает не больше `N`
основных ассетов (с их sidecar'ами), независимо от того, нужна ли перезагрузка.
Удобно на больших репозиториях, когда `--limit` почти ничего не режет, потому
что локальный кэш уже заполнен. В scheduler: флаг `schedule run … --scan-limit`
или поле `scan_limit` в `schedule.toml`.

### Ресурсы (CPU / RAM / диск)

По умолчанию `pipeline_workers = 0` и `max_scanner_procs = 0` означают **auto**:
лимиты считаются от числа CPU и `MemAvailable` (~2 GiB на один concurrent
scanner, потолок 8). Явные значения в config / `--workers` /
`--max-scanner-procs` перекрывают auto. При старте verify печатается строка
`Resource limits: …`.

Глобальный семафор `max_scanner_procs` ограничивает одновременные процессы
сканеров across всех asset-workers (иначе `workers × scanners` легко
перегружает хост).

**Disk-pressure** (CLI / scheduler verify): при заполнении volume выше
`disk_high_watermark` (по умолчанию 80%) новые downloads паузятся →
сканируются уже локальные файлы → при `--upload` / `verify_upload` идёт
upload finished → downloads упаковываются в `archive_root` (`*.tar.gz`) и
удаляются с диска → при usage ≤ `disk_low_watermark` (70%) качание
возобновляется. Критический порог `disk_critical_watermark` (95%) —
ошибка без бесконечного цикла. Отключение: `disk_reclaim_enabled = false`.

**Verified без удвоения места:** по умолчанию `verified_link_mode=auto` —
PASS кладётся в `*-verified` через **hardlink** на том же volume (download и
verified — один inode). Перекачка через `.partial`+`replace` не портит
уже linked verified. Если hardlink невозможен (другой FS) — обычный copy.
Уже существующие полные копии не конвертируются сами: один раз
`OVERWRITE_VERIFIED=true` или удалить `*-verified` и перепрогнать verify.
При disk-pressure reclaim unlink download у hardlink'нутого PASS **не
освобождает** байты, пока жив путь в verified (nlink > 1) — это ожидаемо.

Жёсткий потолок снаружи процесса (рекомендуется для daemon):

```ini
# /etc/systemd/system/nexus-control-scheduler.service.d/override.conf
[Service]
MemoryMax=8G
CPUQuota=200%
```

После полного PASS + verified copy рядом с локальным файлом сохраняется
`*.scan-checkpoint.json`. Пока checksum, локальный файл, набор/версия/настройки
сканеров не изменились и checkpoint моложе `scan_checkpoint_ttl` (по умолчанию
сутки), повторный CLI verify пропускает этот ассет. После TTL он сканируется
повторно для учёта обновлений vulnerability DB; `scan_checkpoint_ttl = 0`
полностью отключает такой skip.

Каждый verify (TUI / CLI / scheduler) также пишет компактный snapshot в
`~/.cache/nexus-control/scan-history/` (index + `runs/*.json`). Хранится
последние `scan_history_keep` прогонов (по умолчанию 50; `0` = выкл).
В TUI: клавиша `h` — список; Enter — детали (как отчёт `o`). `o` без
in-memory отчёта открывает самый свежий disk-run для текущего репо.

### Планировщик (встроенный daemon)

Интерактивное меню для правил и локального демона (без systemd):

```bash
nexus-control-cli schedule              # меню: list/add/edit/remove/start/stop/status/run/login
nexus-control-cli schedule login        # сохранить зашифрованные креды для демона
nexus-control-cli schedule logout       # очистить сохранённые scheduler-креды
nexus-control-cli schedule start
nexus-control-cli schedule stop
nexus-control-cli schedule status
nexus-control-cli schedule status -m          # live progress (Ctrl+C)
nexus-control-cli schedule status -m --interval 0.5
nexus-control-cli schedule run nightly-core
```

Правила хранятся в `~/.config/nexus-control/schedule.toml` (или `$NEXUS_CONTROL_SCHEDULE`).
Одно правило = одно cron-расписание + список репозиториев.
В меню Add/Edit показывается шпаргалка по полям cron и пресеты
(`1` = каждый день 03:00, `2` = будни 03:00, …); можно ввести `help` или свой
5-field cron — перед сохранением CLI покажет ближайшие запуски.

```toml
[scheduler]
timezone = "local"   # timezone машины; или IANA, напр. Europe/Moscow
overlap = "queue"   # skip | queue | overlap (default: sequential catch-up queue)

[[rules]]
id = "nightly-core"
enabled = true
cron = "0 3 * * 1-5"
description = "Основные maven/npm"
repos = ["maven-hosted", "npm-hosted"]
action = "verify_upload"
# targets = { "maven-hosted" = "maven-hosted-verified", "npm-hosted" = "npm-clean" }

[[rules]]
id = "weekend-raw"
enabled = true
cron = "30 4 * * 6"
repos = ["raw-hosted", "pypi-hosted"]
action = "verify"
upload = true
```

Демон: pidfile в `NEXUS_CACHE_DIR/scheduler.pid`, лог — `scheduler.log` рядом с `LOG_FILE`.
Во время job демон пишет live-progress в `scheduler-state.json`; смотреть без логов:
`schedule status -m` / `--monitor` (обновление раз в `--interval` сек, по умолчанию 1).
Timezone по умолчанию — **локальный TZ машины** (`timezone = "local"`: `$TZ`,
`/etc/timezone`, `/etc/localtime`). Явный IANA в `schedule.toml` перекрывает его.
`SIGHUP` перечитывает `schedule.toml`. После reboot демон нужно стартовать снова
(`schedule start` или внешний `@reboot`).

По умолчанию `overlap = "queue"`: если слот правила уже наступил, а демон занят
другим job, правило встаёт в очередь и стартует сразу после текущего (последовательно).
Обработанные cron-слоты пишутся в `scheduler-state.json` (`last_fires`), поэтому
долгий скан в 02:00 не «съедает» задачу на 02:05.

Для daemon / `schedule start|run` **нет интерактивного prompt**. Задайте креды одним из способов:

1. `NEXUS_USERNAME` / `NEXUS_PASSWORD` в env или `.env`
2. Один раз: `nexus-control-cli schedule login` — пароль в `NEXUS_CACHE_DIR/credentials.scheduler.vault` (Fernet, `0o600`), без TTL сессии; сброс: `schedule logout`

Session vault TUI (`credentials.vault`, TTL `NEXUS_SESSION_TTL`) для демона **не** считается долгоживущим источником.

Альтернатива без встроенного демона — классический cron:

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

При отсутствии URL и наличии TTY запускается first-run wizard
(язык → Nexus URL → TLS → сканеры → **опционально DefectDojo**).

### Учётные данные

| Переменная | Описание |
|------------|----------|
| `NEXUS_USERNAME` / `NEXUS_PASSWORD` | Опционально. Если не заданы — prompt при старте (TTY). Для CI задайте в env. |

После успешного логина в TUI пароль хранится **зашифрованно** (Fernet) в `NEXUS_CACHE_DIR/credentials.vault` только до `expires_at` Nexus-сессии (`NEXUS_SESSION_TTL`). В `session.json` пароля нет. Сброс: клавиша `L` (Logout) или истечение TTL.

Для планировщика отдельно: `schedule login` → `credentials.scheduler.vault` (без TTL сессии).

### Важные опциональные

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `NEXUS_VERIFY_SSL` | `true` | `false` только для self-signed TLS в лаборатории (будет warning) |
| `NEXUS_SESSION_TTL` | `3600` | TTL кэша сессии (секунды) |
| `NEXUS_CACHE_DIR` | `~/.cache/nexus-control` | Каталог кэша сессии (режим 700) |
| `NEXUS_DOCKER_REGISTRY` | _(пусто)_ | Переопределение docker connector `host:port` |
| `NEXUS_CONTROL_CONFIG` | `~/.config/nexus-control/config.toml` | Путь к TOML-конфигу |
| `DOWNLOAD_ROOT` | `~/nexus-control/downloads` | Скачанные артефакты |
| `REPORTS_ROOT` | `~/nexus-control/reports` | JSON/TXT отчёты (`grype_*` / `trivy_*` / `osv_*`) |
| `VERIFIED_ROOT` | `~/nexus-control` | Родитель каталогов `<repo>-verified/` |
| `VERIFIED_LINK_MODE` | `auto` | `auto`: hardlink download→verified на том же volume (без удвоения байт), иначе copy; `copy`: всегда полная копия |
| `SCANNERS` | `grype` | Через запятую: `grype`, `trivy`, `osv` (в TUI — клавиша `s`) |
| `DEFECTDOJO_ENABLED` | `false` | После verify пушить FAIL findings в DefectDojo |
| `DEFECTDOJO_URL` | _(пусто)_ | Базовый URL, например `http://localhost:8080` |
| `DEFECTDOJO_API_KEY` | _(пусто)_ | API token (или encrypted vault) |
| `GRYPE_USE_DOCKER` | `auto` | `auto` / `true` / `false` |
| `GRYPE_DOCKER_IMAGE` | `anchore/grype:latest` | Образ для docker-fallback |
| `TRIVY_USE_DOCKER` | `auto` | `auto` / `true` / `false` |
| `TRIVY_DOCKER_IMAGE` | `aquasec/trivy:latest` | Образ для docker-fallback |
| `OSV_USE_DOCKER` | `auto` | `auto` / `true` / `false` |
| `OSV_DOCKER_IMAGE` | `ghcr.io/google/osv-scanner:latest` | Образ для docker-fallback |
| `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` | `~/.cache` (XDG) | Корень offline DB (`osv-scalibr/<Eco>/all.zip`) |
| `OVERWRITE_DOWNLOADS` | `false` | Force-перекачка; иначе skip по checksum, mismatch → overwrite |
| `OVERWRITE_VERIFIED` | `false` | Перезаписывать в verified |
| `SCAN_HISTORY_KEEP` | `50` | Сколько verify-прогонов хранить в истории; `0` = выкл |
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
4. `s` — выбрать сканеры (grype / trivy / osv). Space — отметить файлы/папки; `v` — download → scan → copy PASS в verified (`d` — только download).
5. Нажмите `V` для того же сценария по **всему** репозиторию.
6. Изучите модальное окно результатов; позже `o` / `h` — последний отчёт и история.

---

## Кейбинды

### Репозитории

| Клавиша | Действие |
|---------|----------|
| `q` | Выход |
| `r` | Обновить список |
| `/` | Фильтр по имени |
| `Enter` | Открыть ассеты |
| `h` | История сканирований |
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
| `s` | Сканеры (grype / trivy / osv) |
| `o` | Последний отчёт (память или disk history) |
| `h` | История сканирований (текущий репо) |
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
| Reports | `/home/alice/nexus-control/reports/my-repo/grype_....json` / `trivy_....json` / `osv_....json` |
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

## Сканеры (Grype / Trivy / OSV) и Docker-fallback

Включённые сканеры задаются `SCANNERS` (по умолчанию `grype`) или в TUI клавишей `s`. При verify включённые сканеры могут работать **параллельно**. Отчёты: `grype_<asset>.json|txt`, `trivy_<asset>.json|txt`, `osv_<asset>.json|txt`.

OSV-Scanner всегда запускается с `--experimental-plugins=directory,artifact` (presets для directory + artifact extractors). Доп. флаги — через `OSV_EXTRA_ARGS`.

**NuGet (`.nupkg`):** сырой archive osv-scanner не разбирает. Для nuget-ассетов nexus-control делает **identity-скан**: читает `.nuspec` → временный custom lockfile → `osv-scanner --lockfile osv-scanner:…`. Grype/Trivy для таких ассетов помечаются `SKIPPED` (не влияют на aggregate). Нужен локальный `osv-scanner` (или Docker-fallback).

**npm (`.tgz` / `.tar.gz`):** сырой tarball Trivy/Grype не видят как пакет (`trivy fs file.tgz` → 0 language files). Перед сканом читается `package/package.json` из архива и пишется временный `package-lock.json` (identity) — Trivy/Grype сканируют его и находят CVE пакета.

**OSV offline DB preflight:** если нужен osv (`--scanners osv` или nuget-репо), перед verify проверяется локальная offline DB под **ecosystem формата репо** (`pypi→PyPI`, `npm→npm`, `maven2→Maven`, `nuget→NuGet`, `rubygems→RubyGems`, `go→Go`, `apt→Debian`, `yum→Red Hat`). Путь: `~/.cache/osv-scalibr/<Eco>/all.zip`. Если DB нет — в TTY предложит скачать **только нужный** ecosystem; отказ / non-interactive → **сканирование отменяется** (без remote OSV API). raw/docker/helm/huggingface без package-ecosystem — preflight не блокирует. После успеха: `--offline --offline-vulnerabilities`. Обновление: `nexus-control-cli osv-db update --ecosystem PyPI`.

Порядок выбора бэкенда (для Grype / Trivy / osv-scanner CLI):

1. Локальный бинарник, если найден и `*_USE_DOCKER` не принудительно `true`
2. Иначе `docker run` образа (`GRYPE_DOCKER_IMAGE` / `TRIVY_DOCKER_IMAGE` / `OSV_DOCKER_IMAGE`), если режим `auto`/`true` и docker доступен
3. Иначе понятная ошибка в UI / логах

Docker-сканеры монтируют `DOWNLOAD_ROOT` (ro), `REPORTS_ROOT` (rw) и кэш offline OSV DB (rw). Без privileged. Docker socket **не** монтируется.

**Политика вердикта (строгая):** у каждого *участвующего* сканера любая уязвимость → `FAIL`. `SKIPPED` в aggregate не учитывается. В verified копируется только если итоговый вердикт `PASS`.

---

## DefectDojo

Опционально: после каждого verify (TUI / CLI / scheduler) findings с **FAIL**-ассетов уходят в DefectDojo как **Generic Findings Import** (`POST /api/v2/reimport-scan/`, `auto_create_context`).

- First-run wizard: «Включить DefectDojo?» → URL + API-ключ (ключ в `NEXUS_CACHE_DIR/defectdojo.vault`, не в TOML).
- Уже настроенный инстанс: `nexus-control-cli defectdojo configure` / `status` / `disable [--clear-vault]`.
- Env: `DEFECTDOJO_ENABLED`, `DEFECTDOJO_URL`, `DEFECTDOJO_API_KEY` (и опционально product/engagement names).
- Product по умолчанию `nexus-control`, engagement = имя Nexus-репозитория. Ошибка push не роняет verify (warning в лог).

API-ключ: в UI DefectDojo → профиль → **API Key**.

---

## Webhook

Опционально: после каждого verify (TUI / CLI / scheduler) nexus-control шлёт
**POST JSON** на ваш URL — сводка репозитория, totals, ассеты и уязвимости
(без native dumps сканеров). Ошибка доставки не роняет verify (warning в лог).

- First-run wizard: «Включить вебхук?» → URL + auth.
- Уже настроенный инстанс: `nexus-control-cli webhook configure` / `status` /
  `test` / `disable [--clear-vault]`.
- Auth: `none` | `bearer` (токен) | `basic` (логин/пароль) | `header` (свой
  заголовок, например `X-Api-Key`). Секреты — vault или env
  (`WEBHOOK_TOKEN`, `WEBHOOK_USERNAME`/`WEBHOOK_PASSWORD`, `WEBHOOK_HEADER_VALUE`),
  не TOML.
- Заголовки запроса: `Content-Type: application/json`,
  `User-Agent: nexus-control/<version>`, `X-Nexus-Control-Event: verify.completed`
  (для `webhook test` — `webhook.test`).

Тело `verify.completed` (сжато): `event`, `source`, `version`, `repository`,
времена, `cancelled`, `scanners`, `totals`, `assets[]` (`path`, `kind`,
`verdict`, `scans` с counts и до 20 CVE на сканер).

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

- Upload verified создаёт hosted `<repo>-verified` **того же format**, что источник (npm/maven2/pypi/raw); npm metadata / non-package файлы при upload пропускаются; заливаются только ассеты из последнего `verified-manifest.json` (PASS), stale-файлы в локальном `*-verified` не грузятся
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
| Grype/Trivy/OSV не найден | Установите бинарник **или** docker + образ; либо выключите сканер клавишей `s` |
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
├── main.py                      # тонкая обёртка: python main.py
├── pyproject.toml
├── requirements.txt
├── uv.lock
├── config.toml.example
├── schedule.toml.example        # пример правил планировщика
├── .env.example                 # legacy env
├── QUICKSTART.md
├── README.md
├── scripts/                     # вспомогательные скрипты
├── tests/                       # pytest
└── nexus_control/               # пакет приложения
    ├── app.py / __main__.py     # Textual TUI entry
    ├── config.py                # pydantic-settings + XDG TOML
    ├── config_wizard.py         # first-run setup
    ├── config_io.py / config_paths.py
    ├── models.py
    ├── logging_setup.py
    ├── i18n.py
    ├── cli/                     # nexus-control-cli
    │   ├── __main__.py          # argparse: repos / verify / upload / schedule / history
    │   ├── cmd_repos.py
    │   ├── cmd_verify.py        # download + scan + verified [+ upload]
    │   ├── cmd_upload.py        # upload локального *-verified без сканера
    │   ├── cmd_schedule.py      # интерактивное меню планировщика
    │   ├── cmd_history.py       # list/show scan history
    │   ├── cmd_osv_db.py        # offline OSV DB status/update
    │   ├── cmd_defectdojo.py    # DefectDojo configure/status/disable
    │   ├── cmd_webhook.py       # webhook configure/status/disable/test
    │   ├── assets.py            # listing / cache / inspect / checkpoints
    │   ├── progress.py
    │   └── bootstrap.py
    ├── integrations/            # DefectDojo, webhook
    │   ├── defectdojo.py
    │   └── webhook.py
    ├── scheduler/               # schedule.toml + daemon (pidfile/cron loop)
    │   ├── models.py / store.py / cronutil.py
    │   ├── daemon.py / jobs.py / pidfile.py / state.py
    │   └── paths.py
    ├── nexus/                   # REST-клиент Nexus
    │   ├── client.py
    │   ├── repositories.py / assets.py / uploads.py
    │   ├── session.py / credentials.py
    │   └── asset_cache.py
    ├── services/
    │   ├── pipeline.py          # download → scan → verified copy
    │   ├── downloader.py
    │   ├── grype_scanner.py / trivy_scanner.py / osv_scanner.py
    │   ├── scan_common.py / scan_checkpoint.py
    │   ├── scan_history.py      # index + run snapshots
    │   ├── verifier.py / verified_uploader.py
    │   └── docker_assets.py
    ├── ui/                      # экраны / виджеты / history / кейбинды Textual
    └── utils/                   # safe_path, fs, hashing, subprocess, tree_builder
```

---

## License

[MIT](LICENSE) — © 2026 meowsl
