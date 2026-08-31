"""Tests for resource governor limits and scanner semaphore."""

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
from nexus_control.services.downloader import DownloadInspection
from nexus_control.services.pipeline import PipelineService
from nexus_control.services.resource_governor import (
    HostResources,
    ResourceGovernor,
    compute_auto_concurrency,
    resolve_limits,
)


def _settings(tmp_path: Path, **kwargs: object) -> Settings:
    base: dict[str, object] = dict(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        scanners="grype",
        pipeline_workers=0,
        max_scanner_procs=0,
    )
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def test_compute_auto_concurrency_formula() -> None:
    host = HostResources(
        cpu_count=8,
        mem_available_gb=16.0,
        mem_total_gb=32.0,
        disk_total_bytes=100,
        disk_used_bytes=50,
        disk_free_bytes=50,
        disk_used_ratio=0.5,
        disk_path=Path("/"),
    )
    workers, scanners = compute_auto_concurrency(host, scanner_count=3)
    assert scanners == 8
    assert workers == 2  # min(4, 8//3)

    host_small = HostResources(
        cpu_count=4,
        mem_available_gb=4.0,
        mem_total_gb=8.0,
        disk_total_bytes=100,
        disk_used_bytes=50,
        disk_free_bytes=50,
        disk_used_ratio=0.5,
        disk_path=Path("/"),
    )
    workers2, scanners2 = compute_auto_concurrency(host_small, scanner_count=3)
    assert scanners2 == 2  # min(2 by ram, 4 cpu, 8)
    assert workers2 == 1


def test_resolve_limits_respects_explicit_overrides(tmp_path: Path) -> None:
    settings = _settings(tmp_path, pipeline_workers=3, max_scanner_procs=5)
    limits = resolve_limits(settings, scanner_count=2)
    assert limits.pipeline_workers == 3
    assert limits.max_scanner_procs == 5
    assert limits.workers_from_auto is False
    assert limits.scanner_procs_from_auto is False

    limits2 = resolve_limits(
        _settings(tmp_path),
        scanner_count=1,
        workers_override=2,
        max_scanner_procs_override=1,
    )
    assert limits2.pipeline_workers == 2
    assert limits2.max_scanner_procs == 1


def test_scanner_semaphore_caps_concurrency(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        scanners="grype,trivy",
        pipeline_workers=4,
        max_scanner_procs=2,
    )
    client = MagicMock()
    pipeline = PipelineService(settings, client)

    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_download(asset: NexusAsset) -> DownloadResult:
        path = tmp_path / "dl" / asset.path.replace("/", "_")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
        return DownloadResult(
            status=DownloadStatus.SUCCESS,
            local_path=path,
            bytes_written=1,
        )

    def fake_scan(**_kwargs: object) -> ScanResult:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.08)
        with lock:
            active -= 1
        return ScanResult(
            status=ScanStatus.SUCCESS,
            verdict=Verdict.PASS,
            scanner="grype",
        )

    pipeline.downloader.download_asset = fake_download  # type: ignore[method-assign]
    pipeline.grype.scan_path = fake_scan  # type: ignore[method-assign]
    pipeline.trivy.scan_path = fake_scan  # type: ignore[method-assign]
    pipeline.grype.get_version = lambda: "t"  # type: ignore[method-assign]
    pipeline.trivy.get_version = lambda: "t"  # type: ignore[method-assign]
    pipeline.verifier.copy_if_pass = lambda **kwargs: VerifyResult(  # type: ignore[method-assign]
        copied=True,
        verified_path=tmp_path / "v",
    )
    pipeline.verifier.write_scanner_reports = lambda summary: None  # type: ignore[method-assign]
    pipeline.verifier.write_manifest = lambda summary: None  # type: ignore[method-assign]
    pipeline.verifier.write_unverified_list = lambda summary, **kwargs: None  # type: ignore[method-assign]

    items = [
        NexusAsset(
            id=f"p{i}",
            path=f"pkg/{i}/a.jar",
            download_url=f"http://x/{i}",
            repository="repo",
        )
        for i in range(4)
    ]
    summary = pipeline.run(
        repository="repo",
        items=items,
        download=True,
        scan=True,
        verify=True,
        scanners=["grype", "trivy"],
        workers=4,
        max_scanner_procs=2,
    )
    assert summary.total_passed == 4
    assert peak <= 2


def test_deferred_download_when_gate_closed(tmp_path: Path) -> None:
    settings = _settings(tmp_path, pipeline_workers=1, max_scanner_procs=1)
    pipeline = PipelineService(settings, MagicMock())

    def needs_download(asset: NexusAsset) -> DownloadInspection:
        return DownloadInspection(
            needs_download=True, local_path=tmp_path / "missing"
        )

    pipeline.downloader.inspect_asset = needs_download  # type: ignore[method-assign]
    pipeline.grype.get_version = lambda: "t"  # type: ignore[method-assign]
    pipeline.verifier.write_scanner_reports = lambda s: None  # type: ignore[method-assign]
    pipeline.verifier.write_manifest = lambda s: None  # type: ignore[method-assign]
    pipeline.verifier.write_unverified_list = lambda s, **kwargs: None  # type: ignore[method-assign]

    asset = NexusAsset(
        id="a",
        path="pkg/a.jar",
        download_url="http://x/a",
        repository="repo",
    )
    summary = pipeline.run(
        repository="repo",
        items=[asset],
        allow_new_download=lambda: False,
        workers=1,
        max_scanner_procs=1,
    )
    assert len(summary.results) == 1
    assert summary.results[0].download.status == DownloadStatus.DEFERRED


def test_resourced_pipeline_runs_without_archive(tmp_path: Path) -> None:
    from nexus_control.services.resource_pipeline import run_resourced_pipeline

    settings = _settings(tmp_path, pipeline_workers=1, max_scanner_procs=1)
    local = settings.download_root / "repo" / "pkg" / "a.jar"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(b"seed")

    pipeline = PipelineService(settings, MagicMock())

    def inspect(asset: NexusAsset) -> DownloadInspection:
        path = settings.download_root / "repo" / Path(asset.path)
        return DownloadInspection(needs_download=False, local_path=path)

    pipeline.downloader.inspect_asset = inspect  # type: ignore[method-assign]

    def download_asset(_asset: NexusAsset) -> DownloadResult:
        return DownloadResult(
            status=DownloadStatus.SKIPPED_EXISTING,
            local_path=local,
        )

    pipeline.downloader.download_asset = download_asset  # type: ignore[method-assign]
    pipeline.grype.scan_path = lambda **k: ScanResult(  # type: ignore[method-assign]
        status=ScanStatus.SUCCESS, verdict=Verdict.PASS, scanner="grype"
    )
    pipeline.grype.get_version = lambda: "t"  # type: ignore[method-assign]
    pipeline.verifier.copy_if_pass = lambda **k: VerifyResult(  # type: ignore[method-assign]
        copied=True, verified_path=tmp_path / "v" / "a.jar"
    )
    pipeline.verifier.write_scanner_reports = lambda s: None  # type: ignore[method-assign]
    pipeline.verifier.write_manifest = lambda s: None  # type: ignore[method-assign]
    pipeline.verifier.write_unverified_list = lambda s, **kwargs: None  # type: ignore[method-assign]

    asset = NexusAsset(
        id="a",
        path="pkg/a.jar",
        download_url="http://x/a",
        repository="repo",
    )
    summary, uploads = run_resourced_pipeline(
        pipeline,
        repository="repo",
        items=[asset],
        workers=1,
        max_scanner_procs=1,
        history_source=None,
    )
    assert summary.total_passed == 1
    assert uploads == []
    assert local.exists()


def test_allow_new_download_false_when_critical(tmp_path: Path) -> None:
    settings = _settings(tmp_path, disk_critical_watermark=0.50)
    limits = resolve_limits(settings, scanner_count=1, workers_override=1)
    gov = ResourceGovernor(settings, limits)
    gov.disk_used_ratio = lambda: 0.99  # type: ignore[method-assign]
    assert gov.is_critical() is True
    assert gov.allow_new_download() is False
