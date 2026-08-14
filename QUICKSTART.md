# Быстрый старт — nexus-control

Краткая инструкция: установить → запустить → пользоваться.

Полное описание — в [README.md](README.md).

---

## 1. Требования

- Python 3.13+ **или** [uv](https://docs.astral.sh/uv/) (подтянет Python сам)
- Доступ к Nexus Sonatype CE
- Учётная запись с правами на чтение репозиториев/ассетов
- Для сканирования: `grype` / `trivy` / `osv-scanner` **или** Docker
- Для docker-репозиториев (опционально): `skopeo` или `docker`

---

## 2. Установка (рекомендуется)

```bash
# Убедитесь, что ~/.local/bin в PATH
uv tool install git+https://github.com/meowsl/nexus-control.git@dev
```

Запуск из **любого** каталога:

```bash
nexus-control
```

При первом запуске:

1. Wizard спросит Nexus URL (и опционально TLS / scanners)
2. Сохранит `~/.config/nexus-control/config.toml`
3. Спросит username/password (encrypted vault до TTL сессии)

Повторные запуски wizard не показывают.

### Разработка из клона

```bash
git clone https://github.com/meowsl/nexus-control.git
cd nexus-control
uv sync --extra dev
uv run nexus-control
```

---

## 3. Конфиг (если нужен вручную)

Обычно wizard достаточно. Ручной TOML:

```bash
mkdir -p ~/.config/nexus-control
cp config.toml.example ~/.config/nexus-control/config.toml
# отредактировать nexus_url
```

Или только env:

```bash
export NEXUS_URL=http://localhost:8081
nexus-control
```

Legacy `.env` в CWD всё ещё поддерживается (см. `.env.example`), но не обязателен.

Частые опции для лаборатории (env или TOML):

```toml
nexus_url = "http://localhost:8081"
nexus_verify_ssl = false
# nexus_docker_registry = "localhost:8082"
```

Пути по умолчанию:

| Назначение | Путь |
|------------|------|
| Config | `~/.config/nexus-control/config.toml` |
| Downloads | `~/nexus-control/downloads` |
| Reports | `~/nexus-control/reports` |
| Verified | `~/nexus-control/<repo>-verified` |
| Logs | `~/nexus-control/logs/nexus-control.log` |

---

## 4. Первый проход в TUI

### Экран репозиториев

1. Дождитесь загрузки списка.
2. При необходимости нажмите `/` и введите часть имени.
3. Выберите репозиторий стрелками и нажмите `Enter`.
4. Справка: `?`. Выход: `q`.

### Экран ассетов

1. Раскройте дерево (`Enter`).
2. `Space` — отметить файлы/папки (● / ○).
3. `s` — выбрать сканеры (grype / trivy / osv).
4. `d` — только скачать; `v` — download → scan → copy PASS в verified.
5. `D` / `V` — то же для **всего** репозитория.
6. `o` — последний отчёт.

---

## 5. Проверка

```bash
ls ~/.config/nexus-control/config.toml
ls ~/nexus-control/downloads/<repo>/
ls ~/nexus-control/reports/<repo>/
ls ~/nexus-control/<repo>-verified/
```

Критерий успеха:

- `nexus-control` запускается из `/tmp` или любого каталога
- список репозиториев загружается
- `PASS` копируется в verified, `FAIL`/`ERROR` — нет

---

## 6. Частые проблемы

| Проблема | Решение |
|----------|---------|
| `nexus-control: command not found` | Добавьте `~/.local/bin` в PATH |
| Нет конфига / NEXUS_URL | Запустите в TTY — сработает wizard; или `export NEXUS_URL=...` |
| Grype/Trivy не найден | Установите бинарник или Docker (`*_USE_DOCKER=auto`) |
| Self-signed TLS | `nexus_verify_ssl = false` в TOML или `NEXUS_VERIFY_SSL=false` |
| Docker-теги не находятся | Задайте `nexus_docker_registry` / `NEXUS_DOCKER_REGISTRY` |
