"""Tests for download-aware CLI limit and PASS scan checkpoints."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from nexus_control.cli.assets import select_assets_for_cli
from nexus_control.config import Settings
from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    NexusAsset,
    PipelineSummary,
    ScanResult,
    ScanStatus,
    Verdict,
    VerifyResult,
)
from nexus_control.services.downloader import Downloader
from nexus_control.services.scan_checkpoint import (
    checkpoint_is_valid,
    write_pass_checkpoint,
)
from nexus_control.services.verified_uploader import collect_upload_items
from nexus_control.utils.safe_path import asset_download_path, asset_verified_path


def _asset(path: str, content: bytes) -> NexusAsset:
    return NexusAsset(
        id=path,
        path=path,
        download_url=f"http://nexus/repository/repo/{path}",
        repository="repo",
        format="maven2",
        file_size=len(content),
        checksum={"sha1": hashlib.sha1(content).hexdigest()},
        last_modified="2026-08-07T08:00:00Z",
    )


def _create_local(
    settings: Settings,
    downloader: Downloader,
    asset: NexusAsset,
    content: bytes,
) -> Path:
    path = asset_download_path(settings.download_root, asset.repository, asset.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    downloader._write_metadata(
        path,
        repository=asset.repository,
        asset_path=asset.path,
        download_url=asset.download_url,
        size=len(content),
        checksum=asset.checksum,
        source="nexus-rest",
        extra={"last_modified": asset.last_modified},
    )
    return path


def test_limit_counts_only_missing_or_changed_assets(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "downloads",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        assets_cache_ttl=0,
    )
    client = MagicMock()
    downloader = Downloader(settings, client)
    unchanged = _asset("pkg/unchanged.jar", b"unchanged")
    old_changed = _asset("pkg/changed.jar", b"old")
    changed = _asset("pkg/changed.jar", b"new")
    missing = _asset("pkg/missing.jar", b"missing")
    _create_local(settings, downloader, unchanged, b"unchanged")
    _create_local(settings, downloader, old_changed, b"old")
    client.iter_asset_pages.return_value = iter(
        [[unchanged, changed, missing]]
    )

    selected, total, stats = select_assets_for_cli(
        client,
        settings,
        "repo",
        limit=1,
        refresh=True,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
    )

    assert total == 2
    assert [asset.path for asset in selected] == [
        "pkg/unchanged.jar",
        "pkg/changed.jar",
    ]
    assert stats.scan_only == 1
    assert stats.download_needed == 1


def test_valid_pass_checkpoint_skips_unchanged_asset(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "downloads",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        assets_cache_ttl=0,
        scan_checkpoint_ttl=3600,
    )
    client = MagicMock()
    downloader = Downloader(settings, client)
    asset = _asset("pkg/passed.jar", b"passed")
    local = _create_local(settings, downloader, asset, b"passed")
    verified = asset_verified_path(
        settings.verified_root,
        asset.repository,
        asset.path,
    )
    verified.parent.mkdir(parents=True, exist_ok=True)
    verified.write_bytes(b"passed")
    result = AssetPipelineResult(
        asset_path=asset.path,
        kind=AssetKind.FILE,
        download=DownloadResult(
            status=DownloadStatus.SKIPPED_EXISTING,
            local_path=local,
            bytes_written=local.stat().st_size,
        ),
        scans={
            "grype": ScanResult(
                status=ScanStatus.SUCCESS,
                verdict=Verdict.PASS,
                scanner="grype",
                scanner_version="test",
            )
        },
        verify=VerifyResult(
            skipped_existing=True,
            verified_path=verified,
        ),
    )
    write_pass_checkpoint(
        settings=settings,
        asset=asset,
        result=result,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
    )
    assert checkpoint_is_valid(
        settings=settings,
        asset=asset,
        local_path=local,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
    )

    client.iter_asset_pages.return_value = iter([[asset]])
    selected, total, stats = select_assets_for_cli(
        client,
        settings,
        "repo",
        limit=1,
        refresh=True,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
    )
    assert total == 1
    assert selected == []
    assert stats.checkpoint_skipped == 1
    reused = stats.checkpoint_pass_results()
    assert len(reused) == 1
    assert reused[0].asset_path == asset.path
    assert reused[0].verdict == Verdict.PASS
    assert reused[0].verify.verified_path == verified


def test_incremental_reuses_pass_after_ttl(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "downloads",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        assets_cache_ttl=0,
        scan_checkpoint_ttl=60,
    )
    client = MagicMock()
    downloader = Downloader(settings, client)
    asset = _asset("pkg/passed.jar", b"passed")
    local = _create_local(settings, downloader, asset, b"passed")
    verified = asset_verified_path(
        settings.verified_root,
        asset.repository,
        asset.path,
    )
    verified.parent.mkdir(parents=True, exist_ok=True)
    verified.write_bytes(b"passed")
    result = AssetPipelineResult(
        asset_path=asset.path,
        kind=AssetKind.FILE,
        download=DownloadResult(
            status=DownloadStatus.SKIPPED_EXISTING,
            local_path=local,
            bytes_written=local.stat().st_size,
        ),
        scans={
            "grype": ScanResult(
                status=ScanStatus.SUCCESS,
                verdict=Verdict.PASS,
                scanner="grype",
                scanner_version="test",
            )
        },
        verify=VerifyResult(
            skipped_existing=True,
            verified_path=verified,
        ),
    )
    write_pass_checkpoint(
        settings=settings,
        asset=asset,
        result=result,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
    )
    ck_path = local.parent / f"{local.name}.scan-checkpoint.json"
    raw = json.loads(ck_path.read_text(encoding="utf-8"))
    raw["scanned_at"] = (
        datetime.now(timezone.utc) - timedelta(days=2)
    ).isoformat()
    ck_path.write_text(json.dumps(raw), encoding="utf-8")

    assert not checkpoint_is_valid(
        settings=settings,
        asset=asset,
        local_path=local,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
    )
    assert checkpoint_is_valid(
        settings=settings,
        asset=asset,
        local_path=local,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
        ignore_ttl=True,
    )

    client.iter_asset_pages.return_value = iter([[asset]])
    selected, _, stats = select_assets_for_cli(
        client,
        settings,
        "repo",
        refresh=True,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
        ignore_checkpoint_ttl=True,
    )
    assert selected == []
    assert stats.checkpoint_skipped == 1

    client.iter_asset_pages.return_value = iter([[asset]])
    selected_full, _, stats_full = select_assets_for_cli(
        client,
        settings,
        "repo",
        refresh=True,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
        use_checkpoints=False,
        ignore_checkpoint_ttl=True,
    )
    assert [a.path for a in selected_full] == [asset.path]
    assert stats_full.checkpoint_skipped == 0


def test_checkpoint_pass_is_upload_candidate(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "downloads",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        assets_cache_ttl=0,
        scan_checkpoint_ttl=3600,
    )
    client = MagicMock()
    downloader = Downloader(settings, client)
    asset = _asset("pkg/passed.jar", b"passed")
    local = _create_local(settings, downloader, asset, b"passed")
    verified = asset_verified_path(
        settings.verified_root,
        asset.repository,
        asset.path,
    )
    verified.parent.mkdir(parents=True, exist_ok=True)
    verified.write_bytes(b"passed")
    result = AssetPipelineResult(
        asset_path=asset.path,
        kind=AssetKind.FILE,
        download=DownloadResult(
            status=DownloadStatus.SKIPPED_EXISTING,
            local_path=local,
            bytes_written=local.stat().st_size,
        ),
        scans={
            "grype": ScanResult(
                status=ScanStatus.SUCCESS,
                verdict=Verdict.PASS,
                scanner="grype",
                scanner_version="test",
            )
        },
        verify=VerifyResult(
            skipped_existing=True,
            verified_path=verified,
        ),
    )
    write_pass_checkpoint(
        settings=settings,
        asset=asset,
        result=result,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
    )
    client.iter_asset_pages.return_value = iter([[asset]])
    _, _, stats = select_assets_for_cli(
        client,
        settings,
        "repo",
        refresh=True,
        scanners=["grype"],
        scanner_versions={"grype": "test"},
        ignore_checkpoint_ttl=True,
    )
    summary = PipelineSummary(repository="repo", scanners=["grype"])
    summary.results.extend(stats.checkpoint_pass_results())
    items = collect_upload_items(summary)
    assert items == [(asset.path, verified)]
