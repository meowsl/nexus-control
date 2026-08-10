"""Tests for scan history store and CLI."""

from __future__ import annotations

from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

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
from nexus_control.services.scan_history import (
    list_runs,
    load_run,
    record_scan_run,
    summary_from_snapshot,
)


def _settings(tmp_path: Path, *, keep: int = 50) -> Settings:
    return Settings(
        nexus_url="http://localhost:8081",
        nexus_cache_dir=tmp_path / "cache",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        log_file=tmp_path / "logs" / "app.log",
        scan_history_keep=keep,
    )


def _summary(repo: str = "maven-hosted") -> PipelineSummary:
    result = AssetPipelineResult(
        asset_path="com/a/1.0/a.jar",
        kind=AssetKind.FILE,
        download=DownloadResult(
            status=DownloadStatus.SUCCESS,
            local_path=Path("/tmp/a.jar"),
            bytes_written=10,
        ),
        scans={
            "grype": ScanResult(
                status=ScanStatus.SUCCESS,
                verdict=Verdict.PASS,
                counts=SeverityCounts(),
                scanner="grype",
                scanner_version="0.1",
                vulnerabilities=[
                    Vulnerability(
                        id="CVE-1",
                        severity=Severity.LOW,
                        package_name="pkg",
                        package_version="1",
                    )
                ],
            )
        },
        verify=VerifyResult(
            copied=True,
            verified_path=Path("/tmp/verified/a.jar"),
        ),
    )
    return PipelineSummary(
        repository=repo,
        results=[result],
        started_at=datetime(2026, 8, 10, 10, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 8, 10, 10, 5, tzinfo=timezone.utc),
        scanners=["grype"],
        scanner_versions={"grype": "0.1"},
    )


def test_record_and_roundtrip(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    summary = _summary()
    run_id = record_scan_run(settings, summary, source="cli")
    assert run_id is not None
    loaded = load_run(settings, run_id)
    assert loaded is not None
    assert loaded.repository == "maven-hosted"
    assert loaded.total_passed == 1
    assert loaded.results[0].asset_path == "com/a/1.0/a.jar"
    assert loaded.results[0].scans["grype"].verdict == Verdict.PASS
    assert loaded.results[0].scans["grype"].vulnerabilities[0].id == "CVE-1"

    runs = list_runs(settings, repository="maven-hosted")
    assert len(runs) == 1
    assert runs[0].run_id == run_id
    assert runs[0].source == "cli"
    assert runs[0].totals.passed == 1


def test_retention_prunes_old_runs(tmp_path: Path) -> None:
    settings = _settings(tmp_path, keep=2)
    ids = []
    for i in range(3):
        s = _summary(repo=f"repo-{i}")
        rid = record_scan_run(settings, s, source="tui")
        assert rid
        ids.append(rid)
    runs = list_runs(settings)
    assert len(runs) == 2
    assert {r.run_id for r in runs} == set(ids[1:])
    assert load_run(settings, ids[0]) is None
    assert load_run(settings, ids[2]) is not None


def test_checkpoint_only_run_is_recorded(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    empty = PipelineSummary(
        repository="test-pypi",
        scanners=["grype", "trivy"],
        scanner_versions={"grype": "1", "trivy": "2"},
        finished_at=datetime.now(timezone.utc),
    )
    run_id = record_scan_run(
        settings,
        empty,
        source="cli",
        checkpoint_skipped=8,
    )
    assert run_id is not None
    runs = list_runs(settings, repository="test-pypi")
    assert len(runs) == 1
    assert runs[0].totals.checkpoint_skipped == 8
    assert runs[0].totals.passed == 0
    assert runs[0].totals.total == 8
    loaded = load_run(settings, run_id)
    assert loaded is not None
    assert loaded.results == []


def test_keep_zero_disables_history(tmp_path: Path) -> None:
    settings = _settings(tmp_path, keep=0)
    assert record_scan_run(settings, _summary(), source="cli") is None
    assert list_runs(settings) == []


def test_record_io_error_does_not_raise(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with patch(
        "nexus_control.services.scan_history.write_json",
        side_effect=OSError("disk full"),
    ):
        assert record_scan_run(settings, _summary(), source="cli") is None


def test_summary_from_snapshot_dict() -> None:
    summary = _summary()
    from nexus_control.services.scan_history import (
        _asset_to_dict,
        _meta_from_summary,
        _meta_to_dict,
    )

    meta = _meta_from_summary(
        summary,
        run_id="x",
        source="scheduler",
        rule_id="nightly",
        path_prefix=None,
        workers=2,
    )
    data = {
        "meta": _meta_to_dict(meta),
        "scanner_versions": summary.scanner_versions,
        "assets": [_asset_to_dict(r) for r in summary.results],
    }
    restored = summary_from_snapshot(data)
    assert restored.repository == summary.repository
    assert restored.total_copied == 1


def test_format_history_when() -> None:
    from datetime import datetime, timezone

    from nexus_control.services.scan_history import format_history_when

    assert format_history_when(None, None) == "-"
    assert format_history_when("not-a-date") == "-"
    utc = datetime(2026, 8, 10, 7, 31, tzinfo=timezone.utc)
    expected = utc.astimezone().strftime("%d.%m.%Y %H:%M")
    assert format_history_when("2026-08-10T07:31:00+00:00") == expected
    # Prefer finished_at over started_at.
    finished = datetime(2026, 8, 10, 10, 0, tzinfo=timezone.utc)
    assert (
        format_history_when(
            "2026-08-10T10:00:00+00:00",
            "2026-08-10T09:00:00+00:00",
        )
        == finished.astimezone().strftime("%d.%m.%Y %H:%M")
    )


def test_cli_history_list_and_show(tmp_path: Path, monkeypatch) -> None:
    from nexus_control.cli.cmd_history import run_history

    settings = _settings(tmp_path)
    run_id = record_scan_run(settings, _summary(), source="cli")
    assert run_id

    monkeypatch.setattr(
        "nexus_control.cli.cmd_history.load_cli_settings",
        lambda allow_prompt=False: settings,
    )

    code = run_history(
        Namespace(
            history_action="list",
            run_id=None,
            repo=None,
            limit=10,
            json=True,
        )
    )
    assert code == 0

    code = run_history(
        Namespace(
            history_action="show",
            run_id=run_id,
            repo=None,
            limit=10,
            json=True,
        )
    )
    assert code == 0

    code = run_history(
        Namespace(
            history_action="show",
            run_id="missing",
            repo=None,
            limit=10,
            json=False,
        )
    )
    assert code == 1


def test_parser_history_flags() -> None:
    from nexus_control.cli.__main__ import build_parser

    parser = build_parser()
    args = parser.parse_args(["history", "--repo", "r", "--limit", "5", "--json"])
    assert args._handler == "history"
    assert args.history_action == "list"
    assert args.repo == "r"
    show = parser.parse_args(["history", "show", "run123"])
    assert show.history_action == "show"
    assert show.run_id == "run123"
