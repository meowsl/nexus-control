"""Tests for rotating file logging flush behaviour."""

from __future__ import annotations

import logging
from pathlib import Path

from nexus_control.logging_setup import FlushingRotatingFileHandler, setup_logging


def test_setup_logging_flushes_immediately(tmp_path: Path) -> None:
    log_file = tmp_path / "logs" / "app.log"
    pkg = setup_logging("INFO", log_file)
    try:
        pkg.info("hello-from-flush-test")
        text = log_file.read_text(encoding="utf-8")
        assert "hello-from-flush-test" in text
        root = logging.getLogger()
        assert any(isinstance(h, FlushingRotatingFileHandler) for h in root.handlers)
    finally:
        for handler in logging.getLogger().handlers[:]:
            handler.close()
        logging.getLogger().handlers.clear()
