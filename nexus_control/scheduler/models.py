"""Модель правил планировщика."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from nexus_control.scheduler.cronutil import LOCAL_TIMEZONE, effective_timezone

OverlapPolicy = Literal["skip", "queue", "overlap"]
RuleAction = Literal["verify", "upload", "verify_upload"]

VALID_OVERLAP: frozenset[str] = frozenset({"skip", "queue", "overlap"})
VALID_ACTIONS: frozenset[str] = frozenset({"verify", "upload", "verify_upload"})


@dataclass(slots=True)
class ScheduleRule:
    id: str
    cron: str
    repos: list[str]
    enabled: bool = True
    description: str = ""
    action: RuleAction = "verify"
    upload: bool = False
    # Per-source-repo upload target. Empty/missing → ``<repo>-verified``.
    targets: dict[str, str] = field(default_factory=dict)
    # Legacy single target (only for rules with one repo). Prefer ``targets``.
    target: str | None = None
    scanners: str | None = None
    path_prefix: str | None = None
    workers: int | None = None
    limit: int | None = None
    refresh: bool = False

    def wants_verify(self) -> bool:
        return self.action in {"verify", "verify_upload"}

    def wants_upload(self) -> bool:
        if self.action == "upload":
            return True
        if self.action == "verify_upload":
            return True
        return bool(self.upload)

    def target_for(self, repo: str) -> str | None:
        """Target Nexus repo for upload of ``repo``, or None → ``<repo>-verified``."""
        custom = self.targets.get(repo)
        if custom is not None and str(custom).strip():
            return str(custom).strip()
        if (
            self.target
            and len(self.repos) == 1
            and self.repos[0] == repo
            and "," not in self.target
        ):
            return self.target.strip()
        return None


@dataclass(slots=True)
class ScheduleConfig:
    timezone: str = LOCAL_TIMEZONE
    overlap: OverlapPolicy = "skip"
    rules: list[ScheduleRule] = field(default_factory=list)

    def resolved_timezone(self) -> str:
        """Timezone для cron: ``local`` → IANA с машины."""
        return effective_timezone(self.timezone)

    def get_rule(self, rule_id: str) -> ScheduleRule | None:
        needle = rule_id.strip()
        for rule in self.rules:
            if rule.id == needle:
                return rule
        return None

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id.strip()]
        return len(self.rules) < before

    def upsert_rule(self, rule: ScheduleRule) -> None:
        for index, existing in enumerate(self.rules):
            if existing.id == rule.id:
                self.rules[index] = rule
                return
        self.rules.append(rule)
