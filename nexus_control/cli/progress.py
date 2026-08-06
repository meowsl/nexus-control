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
            if progress >= 1.0:
                print(file=self.stream)
