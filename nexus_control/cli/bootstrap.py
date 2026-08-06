"""Bootstrap: settings, logging, Nexus client for CLI."""

from __future__ import annotations

import sys
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from nexus_control.config import ConfigError, Settings, load_settings
from nexus_control.i18n import set_locale
from nexus_control.logging_setup import setup_logging
from nexus_control.nexus.client import NexusClient
from nexus_control.nexus.credentials import resolve_runtime_credentials


@dataclass(slots=True)
class CliContext:
    settings: Settings
    client: NexusClient


def load_cli_settings(*, allow_prompt: bool | None = None) -> Settings:
    """Загрузить Settings и credentials.

    ``allow_prompt=None`` → prompt только если stdin — TTY.
    """
    cfg = load_settings()
    set_locale(cfg.locale)
    if allow_prompt is None:
        allow_prompt = sys.stdin.isatty()
    cfg = resolve_runtime_credentials(cfg, allow_prompt=allow_prompt)
    if not cfg.nexus_username or not cfg.nexus_password:
        raise ConfigError(
            "Nexus username/password are required. "
            "Set NEXUS_USERNAME/NEXUS_PASSWORD or run in a TTY to be prompted."
        )
    setup_logging(cfg.log_level, cfg.log_file, password=cfg.nexus_password)
    return cfg


@contextmanager
def open_cli_client(settings: Settings | None = None) -> Iterator[CliContext]:
    """Контекст с открытым ``NexusClient``."""
    cfg = settings or load_cli_settings()
    client = NexusClient(cfg)
    try:
        client.open()
        yield CliContext(settings=cfg, client=client)
    finally:
        client.close()
