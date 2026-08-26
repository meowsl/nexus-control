"""Сводные ``{scanner}_report.json`` в ``*-verified/``."""

from __future__ import annotations

import json
from pathlib import Path

from nexus_control.config import Settings
from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    PipelineSummary,
    ScanResult,
    ScanStatus,
    Severity,
    SeverityCounts,
    Verdict,
    VerifyResult,
    Vulnerability,
)
from nexus_control.services.verifier import Verifier


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        nexus_url="http://nexus.test",
        download_root=tmp_path / "downloads",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        log_file=tmp_path / "logs" / "test.log",
        nexus_cache_dir=tmp_path / "cache",
        overwrite_verified=True,
    )


def _scan(
    name: str,
    *,
    verdict: Verdict = Verdict.PASS,
    raw: dict | None = None,
    vulns: list[Vulnerability] | None = None,
    json_path: Path | None = None,
) -> ScanResult:
    counts = SeverityCounts()
    for vuln in vulns or []:
        counts.increment(vuln.severity)
    return ScanResult(
        status=ScanStatus.SUCCESS,
        verdict=verdict,
        scanner=name,
        scanner_version="1.0",
        vulnerabilities=list(vulns or []),
        counts=counts,
        json_report_path=json_path,
        raw=raw,
    )


def test_write_scanner_reports_aggregated(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    summary = PipelineSummary(
        repository="demo",
        scanners=["grype", "trivy"],
        scanner_versions={"grype": "0.116.0", "trivy": "0.50.0"},
        results=[
            AssetPipelineResult(
                asset_path="pkg/ok-1.0.jar",
                kind=AssetKind.FILE,
                download=DownloadResult(
                    status=DownloadStatus.SUCCESS,
                    local_path=tmp_path / "ok.jar",
                    bytes_written=10,
                ),
                scans={
                    "grype": _scan("grype", raw={"matches": []}),
                    "trivy": _scan("trivy", raw={"Results": []}),
                },
                verify=VerifyResult(copied=True, verified_path=tmp_path / "v" / "ok.jar"),
            ),
            AssetPipelineResult(
                asset_path="pkg/vuln-1.0.jar",
                kind=AssetKind.FILE,
                download=DownloadResult(
                    status=DownloadStatus.SUCCESS,
                    local_path=tmp_path / "vuln.jar",
                    bytes_written=10,
                ),
                scans={
                    "grype": _scan(
                        "grype",
                        verdict=Verdict.FAIL,
                        raw={"matches": [{"vulnerability": {"id": "CVE-1"}}]},
                        vulns=[
                            Vulnerability(
                                id="CVE-1",
                                severity=Severity.HIGH,
                                package_name="libx",
                                package_version="1.0",
                            )
                        ],
                    ),
                    "trivy": _scan(
                        "trivy",
                        verdict=Verdict.FAIL,
                        raw={"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]}]},
                    ),
                },
            ),
        ],
    )

    written = Verifier(settings).write_scanner_reports(summary)
    assert set(written) == {"grype", "trivy"}
    assert written["grype"].name == "grype_report.json"
    assert written["trivy"].name == "trivy_report.json"
    assert written["grype"].parent.name == "demo-verified"

    grype = json.loads(written["grype"].read_text(encoding="utf-8"))
    assert grype["scanner"] == "grype"
    assert grype["scanner_version"] == "0.116.0"
    assert grype["totals"] == {
        "assets": 2,
        "pass": 1,
        "fail": 1,
        "error": 0,
        "skipped": 0,
    }
    assert [a["asset_path"] for a in grype["assets"]] == [
        "pkg/ok-1.0.jar",
        "pkg/vuln-1.0.jar",
    ]
    fail = grype["assets"][1]
    assert fail["verdict"] == "FAIL"
    assert fail["vulnerability_count"] == 1
    assert fail["vulnerabilities"][0]["id"] == "CVE-1"
    assert fail["report"]["matches"][0]["vulnerability"]["id"] == "CVE-1"

    trivy = json.loads(written["trivy"].read_text(encoding="utf-8"))
    assert trivy["totals"]["fail"] == 1
    assert trivy["assets"][0]["report"] == {"Results": []}

    manifest = json.loads(
        Verifier(settings).write_manifest(summary).read_text(encoding="utf-8")
    )
    assert [a["asset_path"] for a in manifest["passed_assets"]] == ["pkg/ok-1.0.jar"]
    assert [a["asset_path"] for a in manifest["failed_assets"]] == ["pkg/vuln-1.0.jar"]


def test_write_scanner_reports_loads_raw_from_disk(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    src = reports / "grype.json"
    src.write_text('{"matches":[{"id":"from-disk"}]}', encoding="utf-8")

    summary = PipelineSummary(
        repository="demo",
        scanners=["grype"],
        results=[
            AssetPipelineResult(
                asset_path="a.jar",
                kind=AssetKind.FILE,
                download=DownloadResult(status=DownloadStatus.SUCCESS),
                scans={
                    "grype": _scan(
                        "grype",
                        verdict=Verdict.FAIL,
                        json_path=src,
                    )
                },
            )
        ],
    )
    path = Verifier(settings).write_scanner_reports(summary)["grype"]
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["assets"][0]["report"]["matches"][0]["id"] == "from-disk"
