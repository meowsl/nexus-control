"""Настройка логирования: ротируемый файл + опциональный обработчик для TUI."""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable

from nexus_control.utils.fs import ensure_parent_dir

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(authorization)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(bearer)\s+[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)(api[_-]?key)\s*[:=]\s*\S+"),
]


class SecretMaskingFilter(logging.Filter):
    """Скрывать типичные секреты в записях логов."""

    def __init__(self, extra_secrets: list[str] | None = None) -> None:
        super().__init__()
        self._extra = [s for s in (extra_secrets or []) if s and len(s) >= 3]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        masked = mask_secrets(msg, self._extra)
        if masked != msg:
            record.msg = masked
            record.args = ()
        return True


def mask_secrets(text: str, extra: list[str] | None = None) -> str:
    """Вернуть ``text`` с секретами, заменёнными на ``***``."""
    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(lambda m: f"{m.group(1)}=***", result)
    for secret in extra or []:
        if secret:
            result = result.replace(secret, "***")
    return result


class TuiLogHandler(logging.Handler):
    """Передавать записи логов в UI-колбэк (главный поток / message pump)."""

    def __init__(self, callback: Callable[[str], None]) -> None:
        super().__init__()
        self._callback = callback

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._callback(msg)
        except Exception:  # noqa: BLE001
            self.handleError(record)


class FlushingRotatingFileHandler(RotatingFileHandler):
    """Ротация + немедленный flush, чтобы ``tail -f`` видел строки во время job."""

    def _open(self):
        return open(
            self.baseFilename,
            self.mode,
            encoding=self.encoding,
            errors=self.errors,
            buffering=1,
        )

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        try:
            if self.stream is not None:
                self.stream.flush()
        except Exception:  # noqa: BLE001
            self.handleError(record)


def setup_logging(
    level: str,
    log_file: Path,
    password: str | None = None,
) -> logging.Logger:
    """Настроить корневой логгер с ротируемым файловым обработчиком.

    Возвращает логгер пакета ``nexus_control``.
    """
    ensure_parent_dir(log_file)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = FlushingRotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SecretMaskingFilter([password] if password else None))
    root.addHandler(file_handler)

    # Приглушить шумные библиотеки
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    pkg = logging.getLogger("nexus_control")
    pkg.debug("Logging initialized file=%s level=%s", log_file, level)
    return pkg


def attach_tui_handler(
    callback: Callable[[str], None],
    level: int = logging.INFO,
    password: str | None = None,
) -> TuiLogHandler:
    """Подключить обработчик, передающий логи в панель логов TUI."""
    handler = TuiLogHandler(callback)
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S")
    )
    handler.addFilter(SecretMaskingFilter([password] if password else None))
    logging.getLogger().addHandler(handler)
    return handler
