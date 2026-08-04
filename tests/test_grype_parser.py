"""Модульные тесты парсера JSON Grype."""

from __future__ import annotations

import json

from nexus_tui.models import Severity, Verdict
from nexus_tui.services.grype_scanner import normalize_severity, parse_grype_json


MATCHES_JSON = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2024-0001",
                "severity": "Critical",
                "description": "bad",
                "fix": {"versions": ["1.2.3"]},
            },
            "artifact": {"name": "openssl", "version": "1.0.0"},
        },
        {
            "vulnerability": {"id": "CVE-2024-0002", "severity": "low"},
            "artifact": {"name": "leftpad", "version": "0.1"},
        },
    ],
    "descriptor": {"name": "grype"},
}


def test_parse_matches() -> None:
    result = parse_grype_json(MATCHES_JSON)
    assert result.verdict == Verdict.FAIL
    assert result.vulnerability_count == 2
    assert result.counts.critical == 1
    assert result.counts.low == 1
    assert result.vulnerabilities[0].id == "CVE-2024-0001"
    assert result.vulnerabilities[0].fix_version == "1.2.3"
    assert result.vulnerabilities[0].package_name == "openssl"


def test_empty_matches_is_pass() -> None:
    result = parse_grype_json({"matches": [], "descriptor": {"name": "grype"}})
    assert result.verdict == Verdict.PASS
    assert result.vulnerability_count == 0


def test_error_json_is_error() -> None:
    result = parse_grype_json({"error": "db not found"})
    assert result.verdict == Verdict.ERROR
    assert "db not found" in (result.error or "")


def test_invalid_json_is_error() -> None:
    result = parse_grype_json("{not-json")
    assert result.verdict == Verdict.ERROR


def test_severity_normalization() -> None:
    assert normalize_severity("critical") == Severity.CRITICAL
    assert normalize_severity("HIGH") == Severity.HIGH
    assert normalize_severity("moderate") == Severity.MEDIUM
    assert normalize_severity("weird") == Severity.UNKNOWN


def test_vulnerabilities_list_compat() -> None:
    payload = {
        "vulnerabilities": [
            {
                "id": "CVE-1",
                "severity": "Medium",
                "package": "foo",
                "version": "1",
            }
        ]
    }
    result = parse_grype_json(json.dumps(payload))
    assert result.verdict == Verdict.FAIL
    assert result.counts.medium == 1


def test_infer_scheme_distinguishes_npm_and_docker_archives() -> None:
    from pathlib import Path

    from nexus_tui.services.grype_scanner import _infer_scheme

    assert _infer_scheme(Path("lodash-4.17.15.tgz")) == "file"
    assert _infer_scheme(Path("pkg.tar.gz")) == "file"
    assert _infer_scheme(Path("image.tar")) == "docker-archive"
    assert _infer_scheme(Path("bundle.oci")) == "oci-archive"
