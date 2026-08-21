"""Queue verify jobs for the worker."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from nexus_control.web.db import get_db
from nexus_control.web.deps import current_session
from nexus_control.web.orm import AuthSession, Job

router = APIRouter(tags=["jobs"])


class JobIn(BaseModel):
    repository: str = Field(min_length=1, max_length=200)
    upload: bool = False
    scan_mode: str = "incremental"
    target: str = ""
    scanners: str = ""
    severity: str = ""
    path_prefixes: list[str] = Field(default_factory=list)
    excluded_prefixes: list[str] = Field(default_factory=list)


def _job_json(row: Job) -> dict:
    return {
        "id": row.id,
        "kind": row.kind,
        "repository": row.repository,
        "status": row.status,
        "scan_mode": row.scan_mode,
        "upload": row.upload,
        "progress": row.progress,
        "progress_text": row.progress_text,
        "error": row.error,
        "exit_code": row.exit_code,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }


@router.get("/jobs")
def list_jobs(
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> list[dict]:
    rows = db.query(Job).order_by(Job.created_at.desc()).limit(100).all()
    return [_job_json(r) for r in rows]


@router.get("/jobs/{job_id}")
def get_job(
    job_id: str,
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> dict:
    row = db.get(Job, job_id)
    if row is None:
        raise HTTPException(status_code=404, detail="job not found")
    return _job_json(row)


@router.post("/jobs", status_code=201)
def enqueue_job(
    body: JobIn,
    db: Session = Depends(get_db),
    session: AuthSession = Depends(current_session),
) -> dict:
    mode = body.scan_mode.strip().lower()
    if mode not in {"incremental", "full"}:
        raise HTTPException(status_code=400, detail="scan_mode must be incremental|full")
    row = Job(
        kind="verify",
        repository=body.repository.strip(),
        status="queued",
        scan_mode=mode,
        upload=body.upload,
        target=body.target.strip(),
        scanners=body.scanners.strip(),
        severity=body.severity.strip(),
        path_prefixes=",".join(body.path_prefixes),
        excluded_prefixes=",".join(body.excluded_prefixes),
        created_by=session.username,
        creds_blob=session.creds_blob,
    )
    db.add(row)
    db.flush()
    return _job_json(row)
