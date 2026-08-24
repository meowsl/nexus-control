"""Tests for DefectDojo integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from nexus_control.config import Settings
from nexus_control.config_io import read_toml
from nexus_control.config_paths import resolve_config_path
from nexus_control.config_wizard import run_first_run_wizard
from nexus_control.integrations.defectdojo import (
    DefectDojoVault,
    build_generic_report,
    collect_findings,
    map_severity,
    push_pipeline_findings,
    resolve_defectdojo_settings,
    vulnerability_to_finding,
)
from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    PipelineSummary,
    ScanResult,
    ScanStatus,
    Severity,
    Verdict,
    Vulnerability,
)


@pytest.fixture
def xdg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.delenv("NEXUS_CONTROL_CONFIG", raising=False)
    monkeypatch.delenv("NEXUS_URL", raising=False)
    return xdg


def _fail_result(
    path: str,
    vulns: list[Vulnerability],
    *,
    scanner: str = "grype",
) -> AssetPipelineResult:
    return AssetPipelineResult(
        asset_path=path,
        kind=AssetKind.FILE,
        download=DownloadResult(status=DownloadStatus.SKIPPED_EXISTING),
        scans={
            scanner: ScanResult(
                status=ScanStatus.SUCCESS,
                verdict=Verdict.FAIL,
                vulnerabilities=vulns,
                scanner=scanner,
            )
        },
    )


def test_map_severity() -> None:
    assert map_severity(Severity.CRITICAL) == "Critical"
    assert map_severity(Severity.NEGLIGIBLE) == "Info"
    assert map_severity(Severity.UNKNOWN) == "Info"


def test_vulnerability_to_finding_cve() -> None:
    vuln = Vulnerability(
        id="CVE-2024-1234",
        severity=Severity.HIGH,
        package_name="lodash",
        package_version="4.17.20",
        fix_version="4.17.21",
        description="proto pollution",
    )
    finding = vulnerability_to_finding(
        vuln, repository="npm-hosted", asset_path="lodash/-/lodash-4.17.20.tgz", scanner="grype"
    )
    assert finding["title"] == "npm-hosted/lodash/-/lodash-4.17.20.tgz"
    assert finding["file_path"] == finding["title"]
    assert "Отчет сгенерирован автоматически" in finding["description"]
    assert "**npm-hosted**" in finding["description"]
    assert "CVE-2024-1234" in finding["description"]
    assert finding["severity"] == "High"
    assert finding["cve"] == "CVE-2024-1234"
    assert finding["component_name"] == "lodash"
    assert "4.17.21" in finding["description"]
    assert finding["mitigation"] == "Upgrade to 4.17.21"
    assert "fix_version" not in finding
    assert "fix_available" not in finding
    assert "npm-hosted" in finding["unique_id_from_tool"]


def test_collect_findings_only_fail() -> None:
    summary = PipelineSummary(
        repository="raw-hosted",
        results=[
            _fail_result(
                "a.jar",
                [
                    Vulnerability(
                        id="CVE-1",
                        severity=Severity.MEDIUM,
                        package_name="a",
                        package_version="1",
                    )
                ],
            ),
            AssetPipelineResult(
                asset_path="b.jar",
                kind=AssetKind.FILE,
                download=DownloadResult(status=DownloadStatus.SKIPPED_EXISTING),
                scans={
                    "grype": ScanResult(
                        status=ScanStatus.SUCCESS,
                        verdict=Verdict.PASS,
                        scanner="grype",
                    )
                },
            ),
        ],
    )
    findings = collect_findings(summary)
    assert len(findings) == 1
    assert findings[0]["vuln_id_from_tool"] == "CVE-1"
    report = build_generic_report(findings)
    assert "findings" in report
    assert len(report["findings"]) == 1


def test_vault_roundtrip(tmp_path: Path) -> None:
    vault = DefectDojoVault(tmp_path)
    vault.save(url="http://localhost:8080", api_key="secret-token")
    loaded = vault.load()
    assert loaded == ("http://localhost:8080", "secret-token")
    assert vault.vault_path.stat().st_mode & 0o777 == 0o600


def test_resolve_from_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
    DefectDojoVault(tmp_path).save(url="http://dd:8080", api_key="from-vault")
    settings = Settings(
        nexus_url="http://nexus:8081",
        nexus_cache_dir=tmp_path,
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "rp",
        verified_root=tmp_path / "vf",
        archive_root=tmp_path / "ar",
        log_file=tmp_path / "log.log",
        defectdojo_enabled=True,
        defectdojo_url="http://dd:8080",
        defectdojo_api_key="",
    )
    resolved = resolve_defectdojo_settings(settings)
    assert resolved.defectdojo_api_key == "from-vault"


def test_push_skipped_when_disabled(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://nexus:8081",
        nexus_cache_dir=tmp_path,
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "rp",
        verified_root=tmp_path / "vf",
        archive_root=tmp_path / "ar",
        log_file=tmp_path / "log.log",
        defectdojo_enabled=False,
    )
    summary = PipelineSummary(
        repository="r",
        results=[
            _fail_result(
                "x",
                [Vulnerability(id="CVE-1", severity=Severity.LOW)],
            )
        ],
    )
    result = push_pipeline_findings(settings, summary)
    assert result.skipped is True
    assert result.findings == 0


def test_push_calls_reimport(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://nexus:8081",
        nexus_cache_dir=tmp_path,
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "rp",
        verified_root=tmp_path / "vf",
        archive_root=tmp_path / "ar",
        log_file=tmp_path / "log.log",
        defectdojo_enabled=True,
        defectdojo_url="http://localhost:8080",
        defectdojo_api_key="tok",
        defectdojo_product_name="nexus-control",
    )
    summary = PipelineSummary(
        repository="maven-hosted",
        results=[
            _fail_result(
                "com/acme/lib/1.0/lib-1.0.jar",
                [
                    Vulnerability(
                        id="CVE-2020-1",
                        severity=Severity.CRITICAL,
                        package_name="lib",
                        package_version="1.0",
                    )
                ],
            )
        ],
    )
    mock_resp = {"test": 42, "engagement": 7}
    with patch(
        "nexus_control.integrations.defectdojo.DefectDojoClient.reimport_generic_findings",
        return_value=mock_resp,
    ) as mock_reimport:
        result = push_pipeline_findings(settings, summary)
    assert result.findings == 1
    assert result.test_id == 42
    assert result.engagement_id == 7
    assert result.error is None
    mock_reimport.assert_called_once()
    args, kwargs = mock_reimport.call_args
    assert kwargs["product_name"] == "nexus-control"
    assert kwargs["engagement_name"] == "maven-hosted"
    assert kwargs["close_old_findings"] is False
    assert args[0]["findings"][0]["cve"] == "CVE-2020-1"


def test_full_scan_closes_old_findings(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://nexus:8081",
        nexus_cache_dir=tmp_path,
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "rp",
        verified_root=tmp_path / "vf",
        archive_root=tmp_path / "ar",
        log_file=tmp_path / "log.log",
        defectdojo_enabled=True,
        defectdojo_url="http://localhost:8080",
        defectdojo_api_key="tok",
    )
    summary = PipelineSummary(
        repository="maven-hosted",
        scan_mode="full",
        results=[
            _fail_result(
                "com/acme/lib/1.0/lib-1.0.jar",
                [
                    Vulnerability(
                        id="CVE-2020-1",
                        severity=Severity.CRITICAL,
                        package_name="lib",
                        package_version="1.0",
                    )
                ],
            )
        ],
    )
    with patch(
        "nexus_control.integrations.defectdojo.DefectDojoClient.reimport_generic_findings",
        return_value={"test": 1, "engagement": 2},
    ) as mock_reimport:
        push_pipeline_findings(settings, summary)
    assert mock_reimport.call_args.kwargs["close_old_findings"] is True


def test_wizard_defectdojo_yes(
    xdg_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = resolve_config_path()
    cache = tmp_path / "cache"
    monkeypatch.setenv("NEXUS_CACHE_DIR", str(cache))
    answers = iter(
        [
            "ru",
            "http://nexus:8081",
            "",
            "grype",
            "y",
            "http://localhost:8080",
            "n",
            "n",  # skip webhook
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": "dd-api-token")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    run_first_run_wizard(config_path=path)
    data = read_toml(path)
    assert data["defectdojo_enabled"] is True
    assert data["defectdojo_url"] == "http://localhost:8080"
    assert data["defectdojo_verify_ssl"] is False
    assert "defectdojo_api_key" not in data
    loaded = DefectDojoVault(cache.resolve()).load()
    assert loaded is not None
    assert loaded[1] == "dd-api-token"
