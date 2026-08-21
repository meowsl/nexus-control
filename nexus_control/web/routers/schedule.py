"""Schedule rules in the console database."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from nexus_control.scheduler.cronutil import CronError, validate_cron
from nexus_control.web.db import get_db
from nexus_control.web.deps import current_session
from nexus_control.web.orm import AuthSession, ScheduleRuleRow

router = APIRouter(tags=["schedule"])


class RuleIn(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    cron: str = Field(min_length=1, max_length=64)
    repos: list[str] = Field(min_length=1)
    enabled: bool = True
    description: str = ""
    action: str = "verify_upload"
    upload: bool = False
    target: str = ""
    scanners: str = ""
    severity: str = ""
    path_prefixes: list[str] = Field(default_factory=list)
    excluded_prefixes: list[str] = Field(default_factory=list)
    scan_mode: str = "incremental"


def _rule_json(row: ScheduleRuleRow) -> dict:
    return {
        "id": row.id,
        "cron": row.cron,
        "repos": [p for p in row.repos.split(",") if p],
        "enabled": row.enabled,
        "description": row.description,
        "action": row.action,
        "upload": row.upload,
        "target": row.target,
        "scanners": row.scanners,
        "severity": row.severity,
        "path_prefixes": [p for p in row.path_prefixes.split(",") if p],
        "excluded_prefixes": [p for p in row.excluded_prefixes.split(",") if p],
        "scan_mode": row.scan_mode,
        "last_fire": row.last_fire,
    }


def _fill(row: ScheduleRuleRow, body: RuleIn) -> None:
    try:
        row.cron = validate_cron(body.cron)
    except CronError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if body.action not in {"verify", "upload", "verify_upload"}:
        raise HTTPException(status_code=400, detail="invalid action")
    if body.scan_mode not in {"incremental", "full"}:
        raise HTTPException(status_code=400, detail="invalid scan_mode")
    row.repos = ",".join(r.strip() for r in body.repos if r.strip())
    row.enabled = body.enabled
    row.description = body.description.strip()
    row.action = body.action
    row.upload = body.upload
    row.target = body.target.strip()
    row.scanners = body.scanners.strip()
    row.severity = body.severity.strip()
    row.path_prefixes = ",".join(body.path_prefixes)
    row.excluded_prefixes = ",".join(body.excluded_prefixes)
    row.scan_mode = body.scan_mode


@router.get("/schedule")
def list_rules(
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> list[dict]:
    rows = db.query(ScheduleRuleRow).order_by(ScheduleRuleRow.id.asc()).all()
    return [_rule_json(r) for r in rows]


@router.post("/schedule", status_code=201)
def create_rule(
    body: RuleIn,
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> dict:
    if db.get(ScheduleRuleRow, body.id):
        raise HTTPException(status_code=409, detail="rule id exists")
    row = ScheduleRuleRow(id=body.id.strip())
    _fill(row, body)
    db.add(row)
    db.flush()
    return _rule_json(row)


@router.put("/schedule/{rule_id}")
def update_rule(
    rule_id: str,
    body: RuleIn,
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> dict:
    row = db.get(ScheduleRuleRow, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="rule not found")
    _fill(row, body)
    db.flush()
    return _rule_json(row)


@router.delete("/schedule/{rule_id}")
def delete_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> dict[str, bool]:
    row = db.get(ScheduleRuleRow, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="rule not found")
    db.delete(row)
    return {"ok": True}
