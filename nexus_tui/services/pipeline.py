"""Оркестрация загрузки → сканирования Grype → verified copy для выбранных артефактов."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from nexus_tui.config import Settings
from nexus_tui.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    DockerTag,
    NexusAsset,
    PipelineSummary,
    ScanResult,
    ScanStatus,
    Verdict,
)
from nexus_tui.nexus.client import NexusClient
from nexus_tui.services.downloader import Downloader
from nexus_tui.services.grype_scanner import GrypeScanner
from nexus_tui.services.verifier import Verifier, apply_verify_for_result

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, float, str], None]
# (asset_path, progress 0..1, сообщение этапа)


class PipelineService:
    def __init__(self, settings: Settings, client: NexusClient) -> None:
        self.settings = settings
        self.client = client
        self.downloader = Downloader(settings, client)
        self.scanner = GrypeScanner(settings)
        self.verifier = Verifier(settings)

    def run(
        self,
        *,
        repository: str,
        items: list[NexusAsset | DockerTag],
        download: bool = True,
        scan: bool = True,
        verify: bool = True,
        on_progress: ProgressCallback | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> PipelineSummary:
        summary = PipelineSummary(repository=repository)
        total = max(len(items), 1)

        try:
            summary.grype_version = self.scanner.get_version() if scan else None
        except Exception:  # noqa: BLE001
            summary.grype_version = None

        for index, item in enumerate(items):
            if should_cancel and should_cancel():
                summary.cancelled = True
                logger.warning("Pipeline cancelled by user")
                break

            asset_path = item.path if isinstance(item, NexusAsset) else item.path
            kind = AssetKind.FILE if isinstance(item, NexusAsset) else AssetKind.IMAGE
            base = index / total

            def report(stage: str, frac: float) -> None:
                if on_progress:
                    on_progress(asset_path, min(base + frac / total, 1.0), stage)

            report("starting", 0.0)
            dl = DownloadResult(status=DownloadStatus.PENDING)
            sc = ScanResult(status=ScanStatus.PENDING, verdict=Verdict.PENDING)

            if download:
                report("download", 0.1)
                if isinstance(item, DockerTag):
                    dl = self.downloader.download_docker_tag(item)
                else:
                    dl = self.downloader.download_asset(item)
            else:
                dl = DownloadResult(
                    status=DownloadStatus.SKIPPED_EXISTING,
                    error="download skipped",
                )

            if dl.status == DownloadStatus.ERROR:
                sc = ScanResult(
                    status=ScanStatus.ERROR,
                    verdict=Verdict.ERROR,
                    error=f"Download failed: {dl.error}",
                )
                result = AssetPipelineResult(
                    asset_path=asset_path,
                    kind=kind,
                    download=dl,
                    scan=sc,
                )
                summary.results.append(result)
                report("error", 1.0)
                continue

            if scan:
                report("scan", 0.5)
                if not dl.local_path:
                    sc = ScanResult(
                        status=ScanStatus.ERROR,
                        verdict=Verdict.ERROR,
                        error="No local path after download",
                    )
                else:
                    scheme = "docker-archive" if isinstance(item, DockerTag) else None
                    sc = self.scanner.scan_path(
                        repository=repository,
                        asset_path=asset_path,
                        local_path=dl.local_path,
                        target_scheme=scheme,
                    )
            else:
                sc = ScanResult(
                    status=ScanStatus.SKIPPED,
                    verdict=Verdict.SKIPPED,
                )

            result = AssetPipelineResult(
                asset_path=asset_path,
                kind=kind,
                download=dl,
                scan=sc,
            )

            if verify and sc.verdict == Verdict.PASS:
                report("verify", 0.85)
                apply_verify_for_result(
                    self.verifier,
                    repository,
                    result,
                    is_docker=isinstance(item, DockerTag),
                    tag=item.tag if isinstance(item, DockerTag) else None,
                )
            elif verify and sc.verdict != Verdict.PASS:
                logger.info(
                    "Not copying %s to verified (verdict=%s)",
                    asset_path,
                    sc.verdict.value,
                )

            summary.results.append(result)
            report("done", 1.0)

        summary.finished_at = datetime.now(timezone.utc)
        if verify and any(r.verdict == Verdict.PASS for r in summary.results):
            try:
                self.verifier.write_manifest(summary)
            except OSError as exc:
                logger.error("Failed to write verified manifest: %s", exc)
        return summary
