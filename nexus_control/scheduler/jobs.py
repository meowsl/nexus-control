"""In-process выполнение правил планировщика (verify / upload)."""

from __future__ import annotations

import logging
from argparse import Namespace
from typing import Callable

from nexus_control.cli.cmd_upload import run_upload
from nexus_control.cli.cmd_verify import run_verify
from nexus_control.scheduler.models import ScheduleRule

logger = logging.getLogger(__name__)

ProgressFn = Callable[[str, float, str], None]


def run_rule(rule: ScheduleRule) -> int:
    """Выполнить правило для всех repos; вернуть worst exit code."""
    if not rule.repos:
        logger.warning("Rule %s has no repos", rule.id)
        return 0

    worst = 0
    for repo in rule.repos:
        code = _run_repo(rule, repo)
        if code > worst:
            worst = code
    return worst


def _run_repo(rule: ScheduleRule, repo: str) -> int:
    target = rule.target_for(repo)
    logger.info(
        "Scheduler rule=%s repo=%s action=%s upload=%s target=%s",
        rule.id,
        repo,
        rule.action,
        rule.wants_upload(),
        target or f"{repo}-verified",
    )
    if rule.action == "upload" and not rule.wants_verify():
        return run_upload(
            Namespace(
                repo=repo,
                target=target,
                json=False,
                allow_prompt=False,
            )
        )

    if rule.wants_verify():
        code = run_verify(
            Namespace(
                repo=repo,
                scanners=rule.scanners,
                upload=rule.wants_upload(),
                target=target,
                path_prefix=rule.path_prefix,
                limit=rule.limit,
                workers=rule.workers,
                refresh=rule.refresh,
                json=False,
                history_source="scheduler",
                history_rule_id=rule.id,
                allow_prompt=False,
            )
        )
        return code

    # upload-only already handled; fallback
    return run_upload(
        Namespace(
            repo=repo,
            target=target,
            json=False,
            allow_prompt=False,
        )
    )
