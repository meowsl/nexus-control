"""Console status: Nexus URL, signed-in user, and DB counts."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from nexus_control.web.db import get_db
from nexus_control.web.deps import current_session
from nexus_control.web.integrations import runtime_settings, snapshot
from nexus_control.web.orm import AuthSession, Job, Label, ScheduleRuleRow

router = APIRouter(tags=["status"])


@router.get("/status")
def get_status(
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    settings = runtime_settings(db, run_wizard=False)
    integ = snapshot(db, settings)
    return {
        "nexus_url": settings.nexus_url,
        "username": session.username,
        "counts": {
            "labels": db.query(Label).count(),
            "jobs": (
                db.query(Job)
                .filter(Job.status.in_(("queued", "running")))
                .count()
            ),
            "schedule_rules": db.query(ScheduleRuleRow).count(),
        },
        "integrations": {
            "defectdojo": bool(integ["defectdojo"]["enabled"]),
            "webhook": bool(integ["webhook"]["enabled"]),
            "vk_teams": bool(integ["vk_teams"]["enabled"]),
        },
    }
