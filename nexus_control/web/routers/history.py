"""Scan history from existing disk snapshots."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from nexus_control.web.db import get_db
from nexus_control.web.deps import current_session, settings_for, unpack_creds
from nexus_control.web.orm import AuthSession

router = APIRouter(tags=["history"])


@router.get("/history")
def list_history(
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
    repo: str | None = None,
    limit: int = 50,
) -> list[dict]:
    from nexus_control.services.scan_history import list_runs

    user, password = unpack_creds(session.creds_blob)
    settings = settings_for(user, password, db=db)
    runs = list_runs(settings, repository=repo, limit=min(max(limit, 1), 200))
    return [
        {
            "run_id": r.run_id,
            "repository": r.repository,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
            "source": r.source,
            "scanners": r.scanners,
            "totals": {
                "scanned": r.totals.scanned,
                "passed": r.totals.passed,
                "failed": r.totals.failed,
                "errors": r.totals.errors,
                "checkpoint_skipped": r.totals.checkpoint_skipped,
            },
            "rule_id": r.rule_id,
        }
        for r in runs
    ]


@router.get("/history/{run_id}")
def show_history(
    run_id: str,
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    from nexus_control.services.scan_history import load_run

    user, password = unpack_creds(session.creds_blob)
    settings = settings_for(user, password, db=db)
    summary = load_run(settings, run_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="run not found")
    return {
        "run_id": run_id,
        "repository": summary.repository,
        "started_at": summary.started_at.isoformat(),
        "finished_at": (
            summary.finished_at.isoformat() if summary.finished_at else None
        ),
        "scanners": summary.scanners,
        "totals": {
            "scanned": summary.total_scanned,
            "passed": summary.total_passed,
            "failed": summary.total_failed,
            "errors": summary.total_errors,
            "copied": summary.total_copied,
        },
    }
