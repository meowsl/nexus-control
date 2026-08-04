"""Центральная документация по горячим клавишам для Footer / Help."""

from __future__ import annotations

REPO_BINDINGS = [
    ("q", "quit", "Выход"),
    ("r", "refresh", "Обновить"),
    ("slash", "search", "Фильтр"),
    ("enter", "open", "Открыть"),
    ("L", "logout", "Logout"),
    ("question_mark", "help", "Справка"),
]

ASSET_BINDINGS = [
    ("escape", "back", "Назад"),
    ("q", "back", "Назад"),
    ("r", "refresh", "Обновить"),
    ("slash", "search", "Фильтр"),
    ("enter", "toggle", "Раскрыть"),
    ("space", "toggle_mark", "Отметить"),
    ("u", "clear_marks", "Снять отметки"),
    ("d", "download_selected", "Скачать"),
    ("v", "verify_selected", "Verify"),
    ("D", "download_all", "Скачать всё"),
    ("V", "verify_all", "Verify всё"),
    ("o", "open_report", "Отчёт"),
    ("question_mark", "help", "Справка"),
]

HELP_TEXT = """
[b]Репозитории[/b]
  q           Выход
  r           Обновить список репозиториев
  /           Фильтр по имени
  Enter       Открыть ассеты
  L           Logout (сброс Nexus-сессии и encrypted credentials)
  ?           Справка

[b]Ассеты[/b]
  Esc / q     Назад к репозиториям
  r           Обновить ассеты
  /           Фильтр дерева
  Enter       Раскрыть / свернуть
  Space       Отметить / снять отметку (● отмечено, ○ нет)
  u           Снять все отметки
  d           Скачать отмеченное (или узел под курсором)
  v           Verify отмеченного (download + Grype + copy PASS)
  D           Скачать весь репозиторий
  V           Verify весь репозиторий
  o           Открыть последний отчёт
  ?           Справка

[b]Правила выбора[/b]
  • Space на файле / образе — отметить один ассет
  • Space на папке — отметить всю ветку (рекурсивно при download/verify)
  • Можно отметить несколько узлов, затем нажать d или v
  • Без отметок d / v работают для узла под курсором
  • D / V — всегда весь репозиторий
""".strip()
