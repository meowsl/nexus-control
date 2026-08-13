"""Load/save ``schedule.toml``."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from nexus_control.config_io import read_toml, write_toml_atomic
from nexus_control.scheduler.cronutil import (
    LOCAL_TIMEZONE,
    CronError,
    effective_timezone,
    resolve_tz,
    validate_cron,
)
from nexus_control.scheduler.models import (
    VALID_ACTIONS,
    VALID_OVERLAP,
    ScheduleConfig,
    ScheduleRule,
)
from nexus_control.scheduler.paths import resolve_schedule_path

logger = logging.getLogger(__name__)


class ScheduleStoreError(ValueError):
    """Ошибка чтения/валидации schedule.toml."""


def load_schedule(path: Path | None = None) -> ScheduleConfig:
    """Загрузить конфиг; отсутствующий файл → пустой ScheduleConfig."""
    resolved = resolve_schedule_path(path)
    if not resolved.is_file():
        return ScheduleConfig()
    try:
        data = read_toml(resolved)
    except (OSError, ValueError) as exc:
        raise ScheduleStoreError(f"Cannot read {resolved}: {exc}") from exc
    return parse_schedule_dict(data)


def save_schedule(config: ScheduleConfig, path: Path | None = None) -> Path:
    """Атомарно сохранить schedule.toml; вернуть путь."""
    resolved = resolve_schedule_path(path)
    validate_config(config)
    write_toml_atomic(resolved, config_to_dict(config), mode=0o600)
    logger.info("Wrote schedule config to %s (%d rules)", resolved, len(config.rules))
    return resolved


def parse_schedule_dict(data: dict[str, Any]) -> ScheduleConfig:
    sched = data.get("scheduler") or {}
    if sched is None:
        sched = {}
    if not isinstance(sched, dict):
        raise ScheduleStoreError("[scheduler] must be a table")

    # Пусто / отсутствует / local → timezone машины в runtime.
    raw_tz = sched.get("timezone")
    if raw_tz is None or str(raw_tz).strip() == "":
        timezone = LOCAL_TIMEZONE
    else:
        timezone = str(raw_tz).strip()
    try:
        # Validate now (resolves local → system).
        effective_timezone(timezone)
        resolve_tz(timezone)
    except CronError as exc:
        raise ScheduleStoreError(str(exc)) from exc

    overlap_raw = str(sched.get("overlap") or "queue").strip().lower()
    if overlap_raw not in VALID_OVERLAP:
        raise ScheduleStoreError(
            f"Invalid overlap={overlap_raw!r}; expected one of {sorted(VALID_OVERLAP)}"
        )

    rules_raw = data.get("rules") or []
    if not isinstance(rules_raw, list):
        raise ScheduleStoreError("[[rules]] must be an array of tables")

    rules: list[ScheduleRule] = []
    seen: set[str] = set()
    for index, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            raise ScheduleStoreError(f"rules[{index}] must be a table")
        rule = _parse_rule(item, index=index)
        if rule.id in seen:
            raise ScheduleStoreError(f"Duplicate rule id: {rule.id!r}")
        seen.add(rule.id)
        rules.append(rule)

    return ScheduleConfig(
        timezone=timezone,
        overlap=overlap_raw,  # type: ignore[arg-type]
        rules=rules,
    )


def validate_config(config: ScheduleConfig) -> None:
    try:
        resolve_tz(config.timezone)
    except CronError as exc:
        raise ScheduleStoreError(str(exc)) from exc
    if config.overlap not in VALID_OVERLAP:
        raise ScheduleStoreError(f"Invalid overlap={config.overlap!r}")
    seen: set[str] = set()
    for rule in config.rules:
        _validate_rule(rule)
        if rule.id in seen:
            raise ScheduleStoreError(f"Duplicate rule id: {rule.id!r}")
        seen.add(rule.id)


def config_to_dict(config: ScheduleConfig) -> dict[str, Any]:
    return {
        "scheduler": {
            "timezone": config.timezone,
            "overlap": config.overlap,
        },
        "rules": [_rule_to_dict(rule) for rule in config.rules],
    }


def _parse_rule(item: dict[str, Any], *, index: int) -> ScheduleRule:
    rule_id = str(item.get("id") or "").strip()
    if not rule_id:
        raise ScheduleStoreError(f"rules[{index}].id is required")

    cron_raw = str(item.get("cron") or "").strip()
    try:
        cron = validate_cron(cron_raw)
    except CronError as exc:
        raise ScheduleStoreError(f"rules[{index}] ({rule_id}): {exc}") from exc

    repos_raw = item.get("repos") or []
    if isinstance(repos_raw, str):
        repos = [p.strip() for p in repos_raw.split(",") if p.strip()]
    elif isinstance(repos_raw, list):
        repos = [str(p).strip() for p in repos_raw if str(p).strip()]
    else:
        raise ScheduleStoreError(f"rules[{index}].repos must be a list or string")
    if not repos:
        raise ScheduleStoreError(f"rules[{index}] ({rule_id}): repos must be non-empty")

    action = str(item.get("action") or "verify").strip().lower()
    if action not in VALID_ACTIONS:
        raise ScheduleStoreError(
            f"rules[{index}].action={action!r}; expected {sorted(VALID_ACTIONS)}"
        )

    workers = item.get("workers")
    if workers is not None:
        workers = int(workers)
        if workers < 1:
            raise ScheduleStoreError(f"rules[{index}].workers must be >= 1")

    limit = item.get("limit")
    if limit is not None:
        limit = int(limit)
        if limit < 1:
            raise ScheduleStoreError(f"rules[{index}].limit must be >= 1")

    scan_limit = item.get("scan_limit")
    if scan_limit is not None:
        scan_limit = int(scan_limit)
        if scan_limit < 1:
            raise ScheduleStoreError(f"rules[{index}].scan_limit must be >= 1")

    target = item.get("target")
    targets_raw = item.get("targets")
    scanners = item.get("scanners")
    path_prefix = item.get("path_prefix")

    targets = _parse_targets(targets_raw, rule_id=rule_id, index=index)
    legacy_target: str | None = None
    if target is not None and str(target).strip():
        legacy_target = str(target).strip()
        if "," in legacy_target:
            parts = [p.strip() for p in legacy_target.split(",") if p.strip()]
            if len(parts) == len(repos) and not targets:
                # Миграция со старого UX: "a-verified,b-verified" + repos=[a,b]
                targets = dict(zip(repos, parts, strict=True))
                logger.warning(
                    "rules[%d] (%s): migrated comma-separated target %r → targets=%s",
                    index,
                    rule_id,
                    legacy_target,
                    targets,
                )
                legacy_target = None
            else:
                raise ScheduleStoreError(
                    f"rules[{index}] ({rule_id}): 'target' must be a single repo name. "
                    "For several source repos use a targets table, e.g. "
                    'targets = {{ "test-raw" = "test-raw-verified", '
                    '"test-pypi" = "test-pypi-verified" }}'
                )
        elif len(repos) > 1 and not targets:
            raise ScheduleStoreError(
                f"rules[{index}] ({rule_id}): single 'target' cannot be used with "
                f"multiple repos={repos}. Set per-repo 'targets' or leave empty "
                "for <repo>-verified defaults."
            )

    return ScheduleRule(
        id=rule_id,
        cron=cron,
        repos=repos,
        enabled=bool(item.get("enabled", True)),
        description=str(item.get("description") or "").strip(),
        action=action,  # type: ignore[arg-type]
        upload=bool(item.get("upload", False)),
        targets=targets,
        target=legacy_target,
        scanners=str(scanners).strip() if scanners else None,
        path_prefix=str(path_prefix).strip() if path_prefix else None,
        workers=workers,
        limit=limit,
        scan_limit=scan_limit,
        refresh=bool(item.get("refresh", False)),
    )


def _parse_targets(
    raw: object,
    *,
    rule_id: str,
    index: int,
) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ScheduleStoreError(
            f"rules[{index}] ({rule_id}): targets must be a table "
            '(e.g. targets = {{ "repo" = "repo-verified" }})'
        )
    out: dict[str, str] = {}
    for key, value in raw.items():
        src = str(key).strip()
        dst = str(value).strip() if value is not None else ""
        if not src or not dst:
            raise ScheduleStoreError(
                f"rules[{index}] ({rule_id}): targets entries must be "
                "non-empty source = target"
            )
        if "," in dst:
            raise ScheduleStoreError(
                f"rules[{index}] ({rule_id}): target for {src!r} must be one "
                f"repository name, got {dst!r}"
            )
        out[src] = dst
    return out


def _validate_rule(rule: ScheduleRule) -> None:
    if not rule.id.strip():
        raise ScheduleStoreError("rule.id is required")
    try:
        validate_cron(rule.cron)
    except CronError as exc:
        raise ScheduleStoreError(f"rule {rule.id!r}: {exc}") from exc
    if not rule.repos:
        raise ScheduleStoreError(f"rule {rule.id!r}: repos must be non-empty")
    if rule.action not in VALID_ACTIONS:
        raise ScheduleStoreError(f"rule {rule.id!r}: invalid action")
    if rule.workers is not None and rule.workers < 1:
        raise ScheduleStoreError(f"rule {rule.id!r}: workers must be >= 1")
    if rule.limit is not None and rule.limit < 1:
        raise ScheduleStoreError(f"rule {rule.id!r}: limit must be >= 1")
    if rule.scan_limit is not None and rule.scan_limit < 1:
        raise ScheduleStoreError(f"rule {rule.id!r}: scan_limit must be >= 1")
    if rule.target and "," in rule.target:
        raise ScheduleStoreError(
            f"rule {rule.id!r}: 'target' must be a single name; use 'targets'"
        )
    if rule.target and len(rule.repos) > 1 and not rule.targets:
        raise ScheduleStoreError(
            f"rule {rule.id!r}: single 'target' with multiple repos; use 'targets'"
        )
    unknown = set(rule.targets) - set(rule.repos)
    if unknown:
        raise ScheduleStoreError(
            f"rule {rule.id!r}: targets keys not in repos: {sorted(unknown)}"
        )


def _rule_to_dict(rule: ScheduleRule) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": rule.id,
        "enabled": rule.enabled,
        "cron": rule.cron,
        "description": rule.description,
        "repos": list(rule.repos),
        "action": rule.action,
        "upload": rule.upload,
        "refresh": rule.refresh,
    }
    if rule.targets:
        data["targets"] = dict(rule.targets)
    elif rule.target:
        data["target"] = rule.target
    if rule.scanners:
        data["scanners"] = rule.scanners
    if rule.path_prefix:
        data["path_prefix"] = rule.path_prefix
    if rule.workers is not None:
        data["workers"] = rule.workers
    if rule.limit is not None:
        data["limit"] = rule.limit
    if rule.scan_limit is not None:
        data["scan_limit"] = rule.scan_limit
    return data
