"""Чтение и атомарная запись TOML-конфигурации."""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

import tomllib
import tomli_w

from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

# Секреты не должны попадать в config.toml из wizard / CLI configure.
SECRET_KEYS = frozenset(
    {
        "nexus_password",
        "nexus_username",
        "vk_teams_token",
        "defectdojo_api_key",
        "webhook_token",
        "webhook_username",
        "webhook_password",
        "webhook_header_value",
    }
)


def read_toml(path: Path) -> dict[str, Any]:
    """Прочитать TOML. Пустой/отсутствующий файл → ``{}``."""
    if not path.is_file():
        return {}
    if path.is_symlink():
        raise ValueError(f"Refusing to read symlink config: {path}")
    text = path.read_bytes()
    if not text.strip():
        return {}
    data = tomllib.loads(text.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("TOML root must be a table/object")
    return data


def peek_nexus_url_from_toml(path: Path) -> str | None:
    """Вернуть ``nexus_url`` из TOML или ``None``."""
    try:
        data = read_toml(path)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        logger.debug("Could not peek TOML %s: %s", path, exc)
        return None
    url = data.get("nexus_url")
    if url is None or not str(url).strip():
        return None
    return str(url).strip().rstrip("/")


def write_toml_atomic(path: Path, data: dict[str, Any], *, mode: int = 0o600) -> None:
    """Атомарно записать TOML: каталог ``0700``, файл ``mode`` (по умолчанию ``0600``).

    Не следует по symlink-назначению.
    """
    if path.exists() and path.is_symlink():
        raise ValueError(f"Refusing to write through symlink: {path}")

    ensure_dir(path.parent, mode=0o700)

    # Не записывать секреты из wizard/нормального пути.
    safe = {k: v for k, v in data.items() if k not in SECRET_KEYS}
    # Path → str для TOML
    serializable: dict[str, Any] = {}
    for key, value in safe.items():
        if isinstance(value, Path):
            serializable[key] = str(value)
        else:
            serializable[key] = value

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            tomli_w.dump(serializable, handle)
        os.chmod(tmp_path, mode)
        tmp_path.replace(path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    logger.info("Wrote config %s", path)


def update_toml_key(path: Path, key: str, value: Any, *, mode: int = 0o600) -> dict[str, Any]:
    """Прочитать TOML, выставить ``key=value`` и атомарно записать. Вернуть итоговый dict."""
    data = read_toml(path)
    data[key] = value
    write_toml_atomic(path, data, mode=mode)
    return data
