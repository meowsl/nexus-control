"""Точка входа Textual-приложения и общий контекст выполнения."""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from typing import Any

from textual.app import App
from textual.binding import Binding

from nexus_control.config import ConfigError, Settings, load_settings
from nexus_control.config_io import update_toml_key
from nexus_control.config_paths import resolve_config_path
from nexus_control.logging_setup import attach_tui_handler, setup_logging
from nexus_control.nexus.client import NexusClient
from nexus_control.nexus.credentials import resolve_runtime_credentials
from nexus_control.ui.screens import RepositoriesScreen

logger = logging.getLogger(__name__)


class NexusControlApp(App[None]):
    """Основное Textual-приложение."""

    TITLE = "nexus-control"
    SUB_TITLE = "Nexus Sonatype CE browser / Grype verifier"
    CSS = """
    Screen {
        background: $background;
    }
    RichLog {
        background: $surface;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Выход", show=False),
    ]

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.client = NexusClient(settings)
        self._tui_log_handler: Any = None

    def on_mount(self) -> None:
        # Передавать логи приложения в RichLog активного экрана, если возможно.
        self._tui_log_handler = attach_tui_handler(
            self._forward_log,
            level=getattr(logging, self.settings.log_level, logging.INFO),
            password=self.settings.nexus_password,
        )
        self.push_screen(RepositoriesScreen())
        logger.info("nexus-control started settings=%s", self.settings.masked_dict())

    def on_unmount(self) -> None:
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            pass
        if self._tui_log_handler is not None:
            logging.getLogger().removeHandler(self._tui_log_handler)

    def ensure_client(self) -> NexusClient:
        """Открыть клиент Nexus при необходимости (безопасно вызывать из worker-потоков)."""
        self.client.open()
        return self.client

    def disable_ssl_verification(self, *, persist: bool = True) -> None:
        """Отключить проверку TLS в runtime и (опционально) записать в config.toml.

        Пересоздаёт HTTP-клиент, чтобы следующий запрос шёл с ``verify=False``.
        """
        import os

        self.settings.nexus_verify_ssl = False
        os.environ["NEXUS_VERIFY_SSL"] = "false"
        if persist:
            path = resolve_config_path()
            update_toml_key(path, "nexus_verify_ssl", False)
            logger.warning(
                "Wrote nexus_verify_ssl=false to %s after TLS certificate error",
                path,
            )
        else:
            logger.warning(
                "NEXUS_VERIFY_SSL disabled for this session after TLS certificate error"
            )
        self.client.close()

    def _forward_log(self, message: str) -> None:
        def _write() -> None:
            try:
                screen = self.screen
                log = screen.query_one("#log")
                log.write(message)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                # У экрана может не быть панели логов (модальные окна).
                pass

        # Неблокирующая доставка: blocking call_from_thread из worker + logging
        # из того же потока легко приводит к deadlock / обрыву UI-контекста.
        try:
            if (
                self._loop is not None
                and self._thread_id != threading.get_ident()
            ):
                async def _run() -> None:
                    with self._context():
                        _write()

                asyncio.run_coroutine_threadsafe(_run(), self._loop)
            else:
                _write()
        except Exception:  # noqa: BLE001
            try:
                _write()
            except Exception:  # noqa: BLE001
                pass


def run_app(settings: Settings | None = None) -> None:
    """Загрузить конфигурацию, разрешить credentials и запустить TUI."""
    try:
        cfg = settings or load_settings()
        # Prompt / vault / env — до старта Textual, пока есть TTY.
        if settings is None:
            cfg = resolve_runtime_credentials(cfg)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc

    if not cfg.nexus_username or not cfg.nexus_password:
        print(
            "Nexus username/password are required. "
            "Set NEXUS_USERNAME/NEXUS_PASSWORD or run in a TTY to be prompted.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    setup_logging(cfg.log_level, cfg.log_file, password=cfg.nexus_password)
    app = NexusControlApp(cfg)
    app.run()
