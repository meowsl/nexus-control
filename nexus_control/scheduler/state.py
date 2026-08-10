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
    last_runs: dict[str, RuleRunRecord] = field(default_factory=dict)
    next_fires: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "pid": self.pid,
            "last_reload_at": self.last_reload_at,
            "busy": self.busy,
            "current_rule": self.current_rule,
            "last_runs": {
                key: asdict(value) for key, value in self.last_runs.items()
            },
            "next_fires": dict(self.next_fires),
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
        return cls(
            started_at=data.get("started_at"),
            pid=data.get("pid"),
            last_reload_at=data.get("last_reload_at"),
            busy=bool(data.get("busy", False)),
            current_rule=data.get("current_rule"),
            last_runs=last_runs,
            next_fires={str(k): str(v) for k, v in next_fires.items()},
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
