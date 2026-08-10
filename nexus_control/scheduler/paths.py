"""Пути schedule.toml, pidfile и state."""

from __future__ import annotations

import os
from pathlib import Path

from nexus_control.config_paths import config_dir

SCHEDULE_FILENAME = "schedule.toml"
ENV_SCHEDULE_OVERRIDE = "NEXUS_CONTROL_SCHEDULE"
PID_FILENAME = "scheduler.pid"
STATE_FILENAME = "scheduler-state.json"
LOCK_FILENAME = "scheduler.lock"


def default_schedule_file() -> Path:
    return config_dir() / SCHEDULE_FILENAME


def resolve_schedule_path(override: str | Path | None = None) -> Path:
    """Путь к schedule.toml.

    Приоритет: явный override → ``$NEXUS_CONTROL_SCHEDULE`` → XDG default.
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(ENV_SCHEDULE_OVERRIDE, "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return default_schedule_file().resolve()


def cache_dir_from_settings(cache_dir: Path) -> Path:
    return Path(cache_dir).expanduser().resolve()


def pid_path(cache_dir: Path) -> Path:
    return cache_dir_from_settings(cache_dir) / PID_FILENAME


def lock_path(cache_dir: Path) -> Path:
    return cache_dir_from_settings(cache_dir) / LOCK_FILENAME


def state_path(cache_dir: Path) -> Path:
    return cache_dir_from_settings(cache_dir) / STATE_FILENAME


def scheduler_log_path(log_file: Path) -> Path:
    """Лог демона рядом с основным лог-файлом."""
    base = Path(log_file).expanduser().resolve()
    return base.with_name("scheduler.log")
