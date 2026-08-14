"""Throttled progress writer into scheduler-state.json for ``status --monitor``."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from nexus_control.scheduler.state import SchedulerState, iso_now, save_state


class StateProgressSink:
    """Duck-type совместим с ``ProgressPrinter``: ``status()`` + ``__call__``."""

    def __init__(
        self,
        state_file: Path,
        state: SchedulerState,
        *,
        min_interval: float = 0.5,
    ) -> None:
        self.state_file = state_file
        self.state = state
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._last = 0.0

    def status(self, message: str, *, final: bool = False) -> None:
        with self._lock:
            now = time.monotonic()
            if not final and now - self._last < self.min_interval:
                return
            self._last = now
            text = message if len(message) <= 200 else message[:199] + "…"
            self.state.progress_message = text
            self.state.progress_stage = "status"
            self.state.progress_asset = ""
            if final:
                self.state.progress_pct = 1.0
            self.state.progress_updated_at = iso_now()
            save_state(self.state_file, self.state)

    def __call__(self, asset_path: str, progress: float, stage: str) -> None:
        with self._lock:
            now = time.monotonic()
            if progress < 1.0 and now - self._last < self.min_interval:
                return
            self._last = now
            pct = max(0.0, min(1.0, float(progress)))
            path = asset_path if len(asset_path) <= 120 else "…" + asset_path[-119:]
            self.state.progress_pct = pct
            self.state.progress_stage = str(stage or "")
            self.state.progress_asset = path
            self.state.progress_message = f"{stage}: {path}"
            self.state.progress_updated_at = iso_now()
            save_state(self.state_file, self.state)

    def clear(self) -> None:
        with self._lock:
            self.state.clear_progress()
            save_state(self.state_file, self.state)
