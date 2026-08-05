"""Модульные тесты парсера JSON Trivy и агрегации сканов."""

from __future__ import annotations

from nexus_control.models import ScanResult, ScanStatus, SeverityCounts, Verdict
from nexus_control.services.scan_common import aggregate_scan_results, parse_scanner_names
from nexus_control.services.trivy_scanner import parse_trivy_json


TRIVY_JSON = {
    "SchemaVersion": 2,
    "ArtifactName": "pkg.jar",
    "Results": [
        {
            "Target": "pkg.jar",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-9999",
                    "PkgName": "log4j",
                    "InstalledVersion": "2.14.0",
                    "FixedVersion": "2.17.0",
                    "Severity": "CRITICAL",
                    "Description": "bad",
                }
            ],
        }
    ],
}


def test_parse_trivy_vulns() -> None:
    result = parse_trivy_json(TRIVY_JSON)
    assert result.verdict == Verdict.FAIL
    assert result.scanner == "trivy"
    assert result.vulnerability_count == 1
    assert result.counts.critical == 1
    assert result.vulnerabilities[0].id == "CVE-2024-9999"
    assert result.vulnerabilities[0].fix_version == "2.17.0"
    assert result.vulnerabilities[0].package_name == "log4j"


def test_parse_trivy_clean() -> None:
    result = parse_trivy_json(
        {"SchemaVersion": 2, "ArtifactName": "x", "Results": []}
    )
    assert result.verdict == Verdict.PASS
    assert result.vulnerability_count == 0


def test_parse_trivy_null_vulns() -> None:
    result = parse_trivy_json(
        {
            "SchemaVersion": 2,
            "Results": [{"Target": "a", "Vulnerabilities": None}],
        }
    )
    assert result.verdict == Verdict.PASS


def test_aggregate_requires_all_pass() -> None:
    fail_counts = SeverityCounts(critical=1)
    scans = {
        "grype": ScanResult(
            status=ScanStatus.SUCCESS,
            verdict=Verdict.PASS,
            scanner="grype",
        ),
        "trivy": ScanResult(
            status=ScanStatus.SUCCESS,
            verdict=Verdict.FAIL,
            scanner="trivy",
            counts=fail_counts,
        ),
    }
    assert aggregate_scan_results(scans).verdict == Verdict.FAIL


def test_aggregate_all_pass() -> None:
    scans = {
        "grype": ScanResult(
            status=ScanStatus.SUCCESS, verdict=Verdict.PASS, scanner="grype"
        ),
        "trivy": ScanResult(
            status=ScanStatus.SUCCESS, verdict=Verdict.PASS, scanner="trivy"
        ),
    }
    assert aggregate_scan_results(scans).verdict == Verdict.PASS


def test_parse_scanner_names() -> None:
    assert parse_scanner_names("grype,trivy") == ["grype", "trivy"]
    assert parse_scanner_names("trivy") == ["trivy"]
