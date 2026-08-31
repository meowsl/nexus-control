"""Tests for parallel pipeline workers."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

from nexus_control.config import Settings
from nexus_control.models import (
    DownloadResult,
    DownloadStatus,
    NexusAsset,
    ScanResult,
    ScanStatus,
    Verdict,
    VerifyResult,
)
from nexus_control.services.pipeline import PipelineService


def _asset(path: str) -> NexusAsset:
    return NexusAsset(
        id=path,
        path=path,
        download_url=f"http://example/{path}",
        repository="repo",
    )


def test_pipeline_parallel_downloads_overlap(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        scanners="grype",
        pipeline_workers=4,
    )
    client = MagicMock()
    pipeline = PipelineService(settings, client)

    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_download(asset: NexusAsset) -> DownloadResult:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        path = tmp_path / "dl" / asset.path.replace("/", "_")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
        with lock:
            active -= 1
        return DownloadResult(
            status=DownloadStatus.SUCCESS,
            local_path=path,
            bytes_written=1,
        )

    def fake_scan(**kwargs: object) -> ScanResult:
        return ScanResult(
            status=ScanStatus.SUCCESS,
            verdict=Verdict.PASS,
            scanner="grype",
        )

    pipeline.downloader.download_asset = fake_download  # type: ignore[method-assign]
    pipeline.grype.scan_path = fake_scan  # type: ignore[method-assign]
    pipeline.grype.get_version = lambda: "test"  # type: ignore[method-assign]
    pipeline.verifier.copy_if_pass = lambda **kwargs: VerifyResult(  # type: ignore[method-assign]
        copied=True,
        verified_path=tmp_path / "v",
    )
    pipeline.verifier.write_scanner_reports = lambda summary: None  # type: ignore[method-assign]
    pipeline.verifier.write_manifest = lambda summary: None  # type: ignore[method-assign]
    pipeline.verifier.write_unverified_list = lambda summary, **kwargs: None  # type: ignore[method-assign]

    items = [_asset(f"pkg/{i}/a.jar") for i in range(6)]
    summary = pipeline.run(
        repository="repo",
        items=items,
        download=True,
        scan=True,
        verify=True,
        workers=4,
    )
    assert summary.total_scanned == 6
    assert summary.total_passed == 6
    assert peak >= 2  # параллельность реально случилась


def test_pipeline_workers_one_is_sequential(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        scanners="grype",
        pipeline_workers=1,
    )
    client = MagicMock()
    pipeline = PipelineService(settings, client)

    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_download(asset: NexusAsset) -> DownloadResult:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        path = tmp_path / "dl" / asset.path.replace("/", "_")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
        with lock:
            active -= 1
        return DownloadResult(
            status=DownloadStatus.SUCCESS,
            local_path=path,
            bytes_written=1,
        )

    pipeline.downloader.download_asset = fake_download  # type: ignore[method-assign]
    pipeline.grype.scan_path = lambda **kwargs: ScanResult(  # type: ignore[method-assign]
        status=ScanStatus.SUCCESS,
        verdict=Verdict.PASS,
        scanner="grype",
    )
    pipeline.grype.get_version = lambda: "test"  # type: ignore[method-assign]
    pipeline.verifier.copy_if_pass = lambda **kwargs: VerifyResult(
        copied=True
    )  # type: ignore[method-assign]
    pipeline.verifier.write_scanner_reports = lambda summary: None  # type: ignore[method-assign]
    pipeline.verifier.write_manifest = lambda summary: None  # type: ignore[method-assign]
    pipeline.verifier.write_unverified_list = lambda summary, **kwargs: None  # type: ignore[method-assign]

    items = [_asset(f"pkg/{i}/a.jar") for i in range(3)]
    pipeline.run(repository="repo", items=items, workers=1)
    assert peak == 1


def test_verify_downloads_sidecars_only_for_passed_main(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        scanners="grype",
        pipeline_workers=2,
    )
    pipeline = PipelineService(settings, MagicMock())
    downloaded: list[str] = []

    def fake_download(
        asset: NexusAsset,
        *,
        optional: bool = False,
    ) -> DownloadResult:
        downloaded.append(asset.path)
        if optional:
            return DownloadResult(status=DownloadStatus.NOT_FOUND)
        path = tmp_path / "dl" / asset.path.replace("/", "_")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
        return DownloadResult(
            status=DownloadStatus.SUCCESS,
            local_path=path,
            bytes_written=1,
        )

    def fake_scan(**kwargs: object) -> ScanResult:
        path = str(kwargs["asset_path"])
        verdict = Verdict.FAIL if "bad.jar" in path else Verdict.PASS
        return ScanResult(
            status=ScanStatus.SUCCESS,
            verdict=verdict,
            scanner="grype",
        )

    pipeline.downloader.download_asset = fake_download  # type: ignore[method-assign]
    pipeline.grype.scan_path = fake_scan  # type: ignore[method-assign]
    pipeline.grype.get_version = lambda: "test"  # type: ignore[method-assign]
    pipeline.verifier.copy_if_pass = (  # type: ignore[method-assign]
        lambda **kwargs: VerifyResult(copied=True)
    )
    pipeline.verifier.write_scanner_reports = lambda summary: None  # type: ignore[method-assign]
    pipeline.verifier.write_manifest = lambda summary: None  # type: ignore[method-assign]
    pipeline.verifier.write_unverified_list = lambda summary, **kwargs: None  # type: ignore[method-assign]

    items = [
        _asset("pkg/good.jar"),
        _asset("pkg/good.jar.sha1"),
        _asset("pkg/bad.jar"),
        _asset("pkg/bad.jar.sha1"),
    ]
    summary = pipeline.run(
        repository="repo",
        items=items,
        workers=2,
        discover_sidecars=True,
    )

    assert "pkg/good.jar.sha1" in downloaded
    assert "pkg/bad.jar.sha1" not in downloaded
    assert "pkg/good.jar.md5" in downloaded
    assert summary.total_errors == 0
    assert summary.total_scanned == 2
