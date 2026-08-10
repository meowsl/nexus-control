"""Персистентный статус демона (last/next runs)."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nexus_control.utils.fs import ensure_parent_dir

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RuleRunRecord:
    rule_id: str
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    message: str = ""
    skipped: bool = False


@dataclass
class SchedulerState:
    started_at: str | None = None
    pid: int | None = None
    last_reload_at: str | None = None
    busy: bool = False
    current_rule: str | None = None
    current_repo: str | None = None
    last_runs: dict[str, RuleRunRecord] = field(default_factory=dict)
    next_fires: dict[str, str] = field(default_factory=dict)
    # Live progress for ``schedule status --monitor`` (daemon jobs).
    progress_pct: float | None = None
    progress_stage: str = ""
    progress_asset: str = ""
    progress_message: str = ""
    progress_updated_at: str | None = None

    def clear_progress(self) -> None:
        self.current_repo = None
        self.progress_pct = None
        self.progress_stage = ""
        self.progress_asset = ""
        self.progress_message = ""
        self.progress_updated_at = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "pid": self.pid,
            "last_reload_at": self.last_reload_at,
            "busy": self.busy,
            "current_rule": self.current_rule,
            "current_repo": self.current_repo,
            "last_runs": {
                key: asdict(value) for key, value in self.last_runs.items()
            },
            "next_fires": dict(self.next_fires),
            "progress_pct": self.progress_pct,
            "progress_stage": self.progress_stage,
            "progress_asset": self.progress_asset,
            "progress_message": self.progress_message,
            "progress_updated_at": self.progress_updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SchedulerState:
        last_runs: dict[str, RuleRunRecord] = {}
        raw_runs = data.get("last_runs") or {}
        if isinstance(raw_runs, dict):
            for key, value in raw_runs.items():
                if not isinstance(value, dict):
                    continue
                last_runs[str(key)] = RuleRunRecord(
                    rule_id=str(value.get("rule_id") or key),
                    started_at=value.get("started_at"),
                    finished_at=value.get("finished_at"),
                    exit_code=value.get("exit_code"),
                    message=str(value.get("message") or ""),
                    skipped=bool(value.get("skipped", False)),
                )
        next_fires = data.get("next_fires") or {}
        if not isinstance(next_fires, dict):
            next_fires = {}
        pct_raw = data.get("progress_pct")
        progress_pct: float | None
        try:
            progress_pct = float(pct_raw) if pct_raw is not None else None
        except (TypeError, ValueError):
            progress_pct = None
        return cls(
            started_at=data.get("started_at"),
            pid=data.get("pid"),
            last_reload_at=data.get("last_reload_at"),
            busy=bool(data.get("busy", False)),
            current_rule=data.get("current_rule"),
            current_repo=data.get("current_repo"),
            last_runs=last_runs,
            next_fires={str(k): str(v) for k, v in next_fires.items()},
            progress_pct=progress_pct,
            progress_stage=str(data.get("progress_stage") or ""),
            progress_asset=str(data.get("progress_asset") or ""),
            progress_message=str(data.get("progress_message") or ""),
            progress_updated_at=data.get("progress_updated_at"),
        )


def load_state(path: Path) -> SchedulerState:
    if not path.is_file():
        return SchedulerState()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read scheduler state %s: %s", path, exc)
        return SchedulerState()
    if not isinstance(data, dict):
        return SchedulerState()
    return SchedulerState.from_dict(data)


def save_state(path: Path, state: SchedulerState) -> None:
    ensure_parent_dir(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(state.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def iso_now() -> str:
    return _utcnow().isoformat()
