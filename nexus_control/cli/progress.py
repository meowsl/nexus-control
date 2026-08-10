"""Progress callbacks for CLI (stderr)."""

from __future__ import annotations

import sys
import threading
import time
from typing import TextIO


class ProgressPrinter:
    """Печать прогресса pipeline/upload в stderr (throttled, thread-safe)."""

    def __init__(self, stream: TextIO | None = None, *, min_interval: float = 0.25) -> None:
        self.stream = stream or sys.stderr
        self.min_interval = min_interval
        self._last = 0.0
        self._lock = threading.Lock()
        self._line_open = False

    def status(self, message: str, *, final: bool = False) -> None:
        """Статус до pipeline (listing/inspect) — одна обновляемая строка."""
        with self._lock:
            now = time.monotonic()
            if not final and now - self._last < self.min_interval:
                return
            self._last = now
            text = message if len(message) <= 118 else message[:117] + "…"
            print(
                f"\r{text}".ljust(120),
                end="\n" if final else "",
                file=self.stream,
                flush=True,
            )
            self._line_open = not final

    def __call__(self, asset_path: str, progress: float, stage: str) -> None:
        with self._lock:
            now = time.monotonic()
            if progress < 1.0 and now - self._last < self.min_interval:
                return
            self._last = now
            pct = max(0, min(100, int(progress * 100)))
            path = asset_path if len(asset_path) <= 72 else "…" + asset_path[-71:]
            print(
                f"\r[{pct:3d}%] {stage}: {path}".ljust(120),
                end="",
                file=self.stream,
                flush=True,
            )
            self._line_open = progress < 1.0
            if progress >= 1.0:
                print(file=self.stream)
                self._line_open = False
