"""Точка входа Textual-приложения и общий контекст выполнения."""

from __future__ import annotations

import logging
import sys
from typing import Any

from textual.app import App
from textual.binding import Binding

from nexus_tui.config import ConfigError, Settings, load_settings
from nexus_tui.logging_setup import attach_tui_handler, setup_logging
from nexus_tui.nexus.client import NexusClient
from nexus_tui.ui.screens import RepositoriesScreen

logger = logging.getLogger(__name__)


class NexusTuiApp(App[None]):
    """Основное Textual-приложение."""

    TITLE = "nexus-tui"
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
        logger.info("nexus-tui started settings=%s", self.settings.masked_dict())

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

    def _forward_log(self, message: str) -> None:
        def _write() -> None:
            try:
                screen = self.screen
                log = screen.query_one("#log")
                log.write(message)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                # У экрана может не быть панели логов (модальные окна).
                pass

        try:
            self.call_from_thread(_write)
        except Exception:  # noqa: BLE001
            # Не в потоке / приложение ещё не запущено.
            try:
                _write()
            except Exception:  # noqa: BLE001
                pass


def run_app(settings: Settings | None = None) -> None:
    """Загрузить конфигурацию (при необходимости) и запустить TUI."""
    try:
        cfg = settings or load_settings()
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc

    setup_logging(cfg.log_level, cfg.log_file, password=cfg.nexus_password)
    app = NexusTuiApp(cfg)
    app.run()
