"""Пути XDG-конфигурации для nexus-control."""

from __future__ import annotations

import os
from pathlib import Path


CONFIG_DIR_NAME = "nexus-control"
CONFIG_FILENAME = "config.toml"
ENV_CONFIG_OVERRIDE = "NEXUS_CONTROL_CONFIG"


def config_dir() -> Path:
    """Каталог конфигурации: ``$XDG_CONFIG_HOME/nexus-control`` или ``~/.config/...``."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg:
        return Path(xdg).expanduser() / CONFIG_DIR_NAME
    return Path.home() / ".config" / CONFIG_DIR_NAME


def default_config_file() -> Path:
    """Путь к ``config.toml`` по умолчанию."""
    return config_dir() / CONFIG_FILENAME


def resolve_config_path(override: str | Path | None = None) -> Path:
    """Разрешить путь к TOML-конфигу.

    Приоритет:
    1. явный ``override`` (аргумент);
    2. ``$NEXUS_CONTROL_CONFIG``;
    3. XDG default.
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(ENV_CONFIG_OVERRIDE, "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return default_config_file().resolve()
