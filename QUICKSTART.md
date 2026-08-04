# Быстрый старт — nexus-control

Краткая инструкция, чтобы за 5 минут открыть TUI и прогнать сценарий download / verify.

Полное описание — в [README.md](README.md).

---

## 1. Требования

- Python 3.13+
- Доступ к Nexus Sonatype CE (`NEXUS_URL`)
- Учётная запись с правами на чтение репозиториев/ассетов
- Для сканирования: `grype` **или** Docker
- Для docker-репозиториев (опционально): `skopeo` или `docker`

---

## 2. Установка

```bash
git clone <repo-url> nexus-control
cd nexus-control

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

Альтернатива через `uv`:

```bash
uv sync --extra dev
```

---

## 3. Настройка `.env`

```bash
cp .env.example .env
```

Минимум, что нужно заполнить:

```env
NEXUS_URL=http://localhost:8081
NEXUS_USERNAME=admin
NEXUS_PASSWORD=your_password_here
```

Частые опции для лаборатории:

```env
# self-signed TLS
NEXUS_VERIFY_SSL=false

# docker connector, если теги не находятся автоматически
NEXUS_DOCKER_REGISTRY=localhost:8082
```

Остальные пути по умолчанию:

| Назначение | Путь |
|------------|------|
| Downloads | `~/nexus-control/downloads` |
| Reports | `~/nexus-control/reports` |
| Verified | `~/nexus-control/<repo>-verified` |
| Logs | `~/nexus-control/logs/nexus-control.log` |

---

## 4. Запуск

```bash
python -m nexus_control
```

или:

```bash
python main.py
```

При ошибке конфигурации приложение сразу завершится с понятным сообщением — проверьте `.env`.

---

## 5. Первый проход в TUI

### Экран репозиториев

1. Дождитесь загрузки списка.
2. При необходимости нажмите `/` и введите часть имени.
3. Выберите репозиторий стрелками и нажмите `Enter`.
4. Справка: `?`. Выход: `q`.

### Экран ассетов

1. Дерево строится из путей ассетов (для docker — список тегов).
2. Выберите файл или директорию.
3. Нажмите `v` — подтвердите операцию в модалке.
4. Следите за прогрессом и панелью Logs.
5. В итоге откроется таблица результатов: `PASS` / `FAIL` / `ERROR`.

Чистые артефакты (`PASS`) окажутся в:

```text
~/nexus-control/<имя-репозитория>-verified/
```

---

## 6. Основные клавиши

| Клавиша | Где | Действие |
|---------|-----|----------|
| `Enter` | репозитории | открыть ассеты |
| `/` | оба экрана | фильтр |
| `r` | оба экрана | обновить |
| `Space` | ассеты | отметить / снять отметку (файл или папка) |
| `u` | ассеты | снять все отметки |
| `d` | ассеты | скачать отмеченное (или узел под курсором) |
| `v` | ассеты | verify отмеченного (download + Grype + copy PASS) |
| `D` / `V` | ассеты | download / verify для **всего** репозитория |
| `o` | ассеты | последний отчёт |
| `Esc` / `q` | ассеты | назад |
| `?` | оба экрана | справка |

---

## 7. Проверка, что всё работает

После `v` / `V` проверьте:

```bash
# скачанные файлы
ls ~/nexus-control/downloads/<repo>/

# отчёты Grype
ls ~/nexus-control/reports/<repo>/

# только чистые артефакты
ls ~/nexus-control/<repo>-verified/

# лог
tail -n 50 ~/nexus-control/logs/nexus-control.log
```

Критерий успеха:

- TUI открывается
- список репозиториев загружается
- дерево ассетов видно
- выбранный ассет скачивается и сканируется
- `PASS` копируется в verified, `FAIL`/`ERROR` — нет

---

## 8. Частые проблемы

| Проблема | Решение |
|----------|---------|
| `Failed to load configuration` | Заполните `NEXUS_URL`, `NEXUS_USERNAME`, `NEXUS_PASSWORD` в `.env` |
| `Authentication failed` | Проверьте пароль и права пользователя |
| Ошибка TLS / certificate | Для лаборатории: `NEXUS_VERIFY_SSL=false` |
| `grype is not installed` | Установите grype или Docker (`GRYPE_USE_DOCKER=auto`) |
| Пустые docker-теги | Задайте `NEXUS_DOCKER_REGISTRY=host:port` |
| Нет skopeo/docker | Установите один из них для docker-репозиториев |

---

## 9. Тесты (опционально)

```bash
pytest
```

---

## 10. Что дальше

- Полные кейбинды, архитектура и security notes — [README.md](README.md)
- Все переменные окружения — [.env.example](.env.example)
