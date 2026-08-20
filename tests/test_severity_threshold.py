"""Fail-on-severity threshold for verify verdicts."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_control.config import Settings
from nexus_control.models import Severity, Verdict, Vulnerability
from nexus_control.scheduler.models import ScheduleRule
from nexus_control.scheduler.store import ScheduleStoreError, parse_schedule_dict, save_schedule
from nexus_control.services.grype_scanner import parse_grype_json
from nexus_control.services.scan_checkpoint import scan_policy_hash
from nexus_control.services.scan_common import (
    is_blocking_severity,
    parse_severity_threshold,
    verdict_from_vulnerabilities,
)


def _vuln(severity: Severity, vid: str = "CVE-1") -> Vulnerability:
    return Vulnerability(id=vid, severity=severity, package_name="pkg", package_version="1")


def test_parse_severity_threshold_aliases() -> None:
    assert parse_severity_threshold("HIGH") == "high"
    assert parse_severity_threshold(" Medium ") == "medium"
    assert parse_severity_threshold(None) == "negligible"
    assert parse_severity_threshold("") == "negligible"
    with pytest.raises(ValueError, match="severity must be"):
        parse_severity_threshold("urgent")


def test_unknown_is_always_blocking() -> None:
    assert is_blocking_severity(Severity.UNKNOWN, "critical") is True
    assert is_blocking_severity(Severity.LOW, "high") is False
    assert is_blocking_severity(Severity.HIGH, "high") is True
    assert is_blocking_severity(Severity.MEDIUM, "medium") is True
    assert is_blocking_severity(Severity.NEGLIGIBLE, "negligible") is True


def test_verdict_threshold_high_ignores_low_medium() -> None:
    vulns = [
        _vuln(Severity.LOW),
        _vuln(Severity.MEDIUM, "CVE-2"),
    ]
    assert verdict_from_vulnerabilities(vulns, "high") == Verdict.PASS
    assert verdict_from_vulnerabilities(vulns, "medium") == Verdict.FAIL
    assert verdict_from_vulnerabilities(vulns, "negligible") == Verdict.FAIL
    assert verdict_from_vulnerabilities(
        vulns + [_vuln(Severity.CRITICAL, "CVE-3")],
        "high",
    ) == Verdict.FAIL


def test_grype_parse_respects_severity_kwarg() -> None:
    payload = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-LOW", "severity": "Low"},
                "artifact": {"name": "x", "version": "1"},
            }
        ],
        "descriptor": {"name": "grype"},
    }
    strict = parse_grype_json(payload)
    assert strict.verdict == Verdict.FAIL
    assert strict.counts.low == 1
    relaxed = parse_grype_json(payload, severity="high")
    assert relaxed.verdict == Verdict.PASS
    assert relaxed.vulnerability_count == 1


def test_settings_severity_from_toml_alias(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "rp",
        verified_root=tmp_path / "vf",
        nexus_cache_dir=tmp_path / "cache",
        log_file=tmp_path / "app.log",
        fail_on_severity="HIGH",
    )
    assert settings.severity == "high"


def test_checkpoint_policy_hash_includes_severity(tmp_path: Path) -> None:
    base = dict(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "rp",
        verified_root=tmp_path / "vf",
        nexus_cache_dir=tmp_path / "cache",
        log_file=tmp_path / "app.log",
    )
    a = Settings(**base, severity="negligible")  # type: ignore[arg-type]
    b = Settings(**base, severity="high")  # type: ignore[arg-type]
    assert scan_policy_hash(a, ["grype"]) != scan_policy_hash(b, ["grype"])


def test_schedule_severity_roundtrip(tmp_path: Path) -> None:
    parsed = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "nightly",
                    "cron": "0 3 * * *",
                    "repos": ["maven-hosted"],
                    "severity": "High",
                }
            ]
        }
    )
    assert parsed.rules[0].severity == "high"
    out = tmp_path / "schedule.toml"
    save_schedule(parsed, out)
    assert 'severity = "high"' in out.read_text(encoding="utf-8")

    omitted = parse_schedule_dict(
        {"rules": [{"id": "x", "cron": "0 0 * * *", "repos": ["r"]}]}
    )
    assert omitted.rules[0].severity is None

    with pytest.raises(ScheduleStoreError, match="severity"):
        parse_schedule_dict(
            {
                "rules": [
                    {
                        "id": "bad",
                        "cron": "0 0 * * *",
                        "repos": ["r"],
                        "severity": "urgent",
                    }
                ]
            }
        )


def test_run_rule_passes_severity() -> None:
    from unittest.mock import patch

    from nexus_control.scheduler.jobs import run_rule

    rule = ScheduleRule(
        id="n",
        cron="0 0 * * *",
        repos=["r"],
        action="verify",
        severity="high",
    )
    with patch("nexus_control.scheduler.jobs.run_verify", return_value=0) as verify:
        assert run_rule(rule) == 0
    assert verify.call_args.args[0].severity == "high"
