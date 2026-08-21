"""Background worker: queued verify jobs + DB schedule rules."""

from __future__ import annotations

import logging
import os
import time
from argparse import Namespace
from datetime import datetime, timezone

from croniter import croniter
from sqlalchemy.orm import Session

from nexus_control.cli.cmd_verify import run_verify
from nexus_control.scheduler.cronutil import resolve_tz
from nexus_control.web.db import SessionLocal, init_db
from nexus_control.web.deps import expand_repo_selectors, unpack_creds
from nexus_control.web.orm import Job, ScheduleRuleRow

logger = logging.getLogger(__name__)


class _JobProgress:
    def __init__(self, job_id: str) -> None:
        self.job_id = job_id

    def __call__(self, asset_path: str, progress: float, stage: str) -> None:
        self._write(float(progress), f"{stage} {asset_path}")

    def status(self, msg: str, final: bool = False) -> None:
        self._write(1.0 if final else None, msg)

    def _write(self, progress: float | None, text: str) -> None:
        db = SessionLocal()
        try:
            job = db.get(Job, self.job_id)
            if job is None:
                return
            if progress is not None:
                job.progress = max(0.0, min(1.0, progress))
            job.progress_text = text[:4000]
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("progress write failed")
        finally:
            db.close()


def _run_job(job: Job) -> int:
    prefixes = [p for p in job.path_prefixes.split(",") if p]
    excludes = [p for p in job.excluded_prefixes.split(",") if p]
    user, password = unpack_creds(job.creds_blob) if job.creds_blob else ("", "")
    db = SessionLocal()
    try:
        from nexus_control.web.integrations import runtime_settings

        settings = runtime_settings(db, username=user, password=password)
    finally:
        db.close()
    return run_verify(
        Namespace(
            repo=job.repository,
            scanners=job.scanners or None,
            severity=job.severity or None,
            upload=job.upload,
            target=job.target or None,
            path_prefix=prefixes or None,
            exclude_prefix=excludes or None,
            limit=None,
            scan_limit=None,
            workers=None,
            refresh=False,
            json=False,
            history_source=(
                "scheduler" if job.created_by.startswith("schedule:") else "web"
            ),
            history_rule_id=None,
            allow_prompt=False,
            on_progress=_JobProgress(job.id),
            scan_mode=job.scan_mode,
            settings=settings,
        )
    )


def _claim_job(db: Session) -> Job | None:
    row = (
        db.query(Job)
        .filter(Job.status == "queued")
        .order_by(Job.created_at.asc())
        .first()
    )
    if row is None:
        return None
    row.status = "running"
    row.started_at = datetime.now(timezone.utc)
    row.progress_text = "starting"
    db.commit()
    db.refresh(row)
    return row


def _finish(db: Session, job_id: str, code: int, error: str = "") -> None:
    job = db.get(Job, job_id)
    if job is None:
        return
    job.exit_code = code
    job.error = error[:4000]
    job.finished_at = datetime.now(timezone.utc)
    job.status = "success" if code == 0 else "failed"
    job.progress = 1.0
    db.commit()


def _fire_key(dt: datetime) -> str:
    return dt.strftime("%Y%m%d%H%M")


def _due_schedule(db: Session) -> None:
    tz = resolve_tz(os.environ.get("TZ") or "local")
    now = datetime.now(tz)
    rules = db.query(ScheduleRuleRow).filter(ScheduleRuleRow.enabled.is_(True)).all()
    for rule in rules:
        try:
            prev = croniter(rule.cron, now).get_prev(datetime)
            if prev.tzinfo is None:
                prev = prev.replace(tzinfo=now.tzinfo)
            key = _fire_key(prev)
            if rule.last_fire == key:
                continue
            if prev > now:
                continue
        except (ValueError, KeyError, TypeError) as exc:
            logger.error("schedule %s: %s", rule.id, exc)
            continue
        selectors = [p for p in rule.repos.split(",") if p]
        repos = expand_repo_selectors(db, selectors)
        creds = ""
        user = os.environ.get("NEXUS_USERNAME", "")
        password = os.environ.get("NEXUS_PASSWORD", "")
        if user and password:
            from nexus_control.web.deps import pack_creds

            creds = pack_creds(user, password)
        for repo in repos:
            db.add(
                Job(
                    kind="verify",
                    repository=repo,
                    status="queued",
                    scan_mode=rule.scan_mode,
                    upload=rule.action in {"verify_upload", "upload"} or rule.upload,
                    target=rule.target,
                    scanners=rule.scanners,
                    severity=rule.severity,
                    path_prefixes=rule.path_prefixes,
                    excluded_prefixes=rule.excluded_prefixes,
                    created_by=f"schedule:{rule.id}",
                    creds_blob=creds,
                )
            )
        rule.last_fire = key
        logger.info("Enqueued schedule %s for %s repos (slot %s)", rule.id, len(repos), key)
    db.commit()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    init_db()
    logger.info("Worker started")
    ticks = 0
    while True:
        job = None
        db = SessionLocal()
        try:
            job = _claim_job(db)
            if job is not None:
                job_id = job.id
                try:
                    code = _run_job(job)
                    _finish(db, job_id, code)
                except Exception as exc:  # noqa: BLE001
                    logger.exception("job %s crashed", job_id)
                    _finish(db, job_id, 1, str(exc))
            ticks += 1
            if ticks % 2 == 0:
                _due_schedule(db)
        except Exception:
            logger.exception("worker loop error")
            db.rollback()
        finally:
            db.close()
        if job is None:
            time.sleep(8)


if __name__ == "__main__":
    main()
