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

from nexus_tui.utils.safe_path import ASSET_META_LEAF, resolve_storage_path

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


def prepare_asset_destination(dest: Path) -> Path:
    """Подготовить локальный путь артефакта с учётом npm file/dir конфликтов.

    1. Если ``dest`` уже каталог → писать в ``dest/(metadata)``.
    2. Если любой предок нужного родителя существует как *файл* → превратить
       его в каталог, перенеся содержимое в ``<file>/(metadata)``.
    3. Создать родительские каталоги.

    Returns:
        Итоговый путь для записи файла.
    """
    dest = resolve_storage_path(dest)
    _promote_file_ancestors(dest.parent)
    # После promote dest мог снова оказаться каталогом (редко) — пересчитать.
    dest = resolve_storage_path(dest)
    ensure_parent_dir(dest)
    return dest


def _promote_file_ancestors(directory: Path) -> None:
    """Сделать так, чтобы все предки ``directory`` были каталогами, не файлами."""
    if directory is None or str(directory) in {"", "."}:
        return
    # От корня к листу: короткие пути раньше длинных.
    chain: list[Path] = []
    cur = directory
    for _ in range(len(cur.parts) + 2):
        chain.append(cur)
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    chain.reverse()
    for node in chain:
        if node.exists() and node.is_file():
            _promote_file_to_directory(node)


def _promote_file_to_directory(file_path: Path) -> None:
    """Файл ``file_path`` → каталог; содержимое переносится в ``(metadata)``."""
    meta_dest = file_path / ASSET_META_LEAF
    sidecar = Path(str(file_path) + ".metadata.json")
    tmp = file_path.with_name(file_path.name + ".__promote__")
    try:
        if tmp.exists():
            if tmp.is_dir():
                shutil.rmtree(tmp)
            else:
                tmp.unlink()
        file_path.rename(tmp)
        file_path.mkdir(parents=False, exist_ok=False)
        tmp.rename(meta_dest)
        if sidecar.exists() and sidecar.is_file():
            try:
                sidecar.rename(file_path / f"{ASSET_META_LEAF}.metadata.json")
            except OSError as exc:
                logger.warning("Failed to move sidecar %s: %s", sidecar, exc)
    except OSError as exc:
        # Откатить tmp → file, если успели переименовать, но mkdir/rename упал.
        if tmp.exists() and not file_path.exists():
            try:
                tmp.rename(file_path)
            except OSError:
                pass
        raise OSError(
            f"Cannot prepare nested path: {file_path} is a file and could not be "
            f"promoted to a directory ({exc}). Check ownership/permissions."
        ) from exc
    logger.info(
        "Promoted file to directory for nested assets: %s -> %s",
        file_path,
        meta_dest,
    )


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
