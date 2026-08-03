"""Вспомогательные функции файловой системы (создание каталогов, безопасные режимы, копирование)."""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def ensure_dir(path: Path, mode: int | None = None) -> Path:
    """Создать каталог (и родителей). Опционально задать Unix mode."""
    path.mkdir(parents=True, exist_ok=True)
    if mode is not None:
        _chmod_best_effort(path, mode)
    return path


def ensure_parent_dir(path: Path) -> Path:
    """Убедиться, что родительский каталог ``path`` существует."""
    parent = path.parent
    if parent and str(parent) not in {"", "."}:
        ensure_dir(parent)
    return parent


def _chmod_best_effort(path: Path, mode: int) -> None:
    """Установить права на POSIX; no-op / best-effort в остальных ОС."""
    try:
        os.chmod(path, mode)
    except OSError as exc:
        logger.debug("chmod %o on %s failed: %s", mode, path, exc)


def write_json(path: Path, data: Any, mode: int | None = None) -> None:
    """Записать JSON атомарно (temp + replace) с опциональным file mode."""
    ensure_parent_dir(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    text = json.dumps(data, indent=2, ensure_ascii=False, default=_json_default)
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    if mode is not None:
        _chmod_best_effort(path, mode)


def read_json(path: Path) -> Any:
    """Прочитать JSON-файл."""
    return json.loads(path.read_text(encoding="utf-8"))


def _json_default(obj: Any) -> Any:
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)!r} is not JSON serializable")


def copy_file(src: Path, dst: Path, overwrite: bool = False) -> tuple[bool, bool]:
    """Скопировать ``src`` в ``dst``.

    Возвращает ``(copied, skipped_existing)``.
    """
    ensure_parent_dir(dst)
    if dst.exists() and not overwrite:
        return False, True
    # Отказ следовать symlink-назначениям, выходящим за пределы (вызывающий должен проверить).
    if dst.is_symlink():
        dst.unlink()
    shutil.copy2(src, dst)
    return True, False


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def path_is_within(child: Path, parent: Path) -> bool:
    """Вернуть True, если resolved ``child`` находится внутри resolved ``parent``."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def disable_execute_bit_best_effort(path: Path) -> None:
    """По возможности сбросить execute-биты, чтобы скачанные артефакты нельзя было запустить."""
    try:
        mode = path.stat().st_mode
        new_mode = mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.chmod(path, new_mode)
    except OSError:
        pass
