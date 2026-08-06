"""Оркестрация загрузки → сканирования → verified copy для выбранных артефактов."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from nexus_control.config import Settings
from nexus_control.models import (
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
from nexus_control.nexus.client import NexusClient
from nexus_control.services.downloader import Downloader
from nexus_control.services.grype_scanner import GrypeScanner
from nexus_control.services.scan_common import KNOWN_SCANNERS, parse_scanner_names
from nexus_control.services.trivy_scanner import TrivyScanner
from nexus_control.services.verifier import Verifier, apply_verify_for_result

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, float, str], None]
# (asset_path, progress 0..1, сообщение этапа)


class PipelineService:
    def __init__(self, settings: Settings, client: NexusClient) -> None:
        self.settings = settings
        self.client = client
        self.downloader = Downloader(settings, client)
        self.grype = GrypeScanner(settings)
        self.trivy = TrivyScanner(settings)
        self.verifier = Verifier(settings)
        # Совместимость со старым кодом / тестами
        self.scanner = self.grype

    def _scanner_for(self, name: str) -> GrypeScanner | TrivyScanner:
        if name == "grype":
            return self.grype
        if name == "trivy":
            return self.trivy
        raise ValueError(f"Unknown scanner: {name}")

    def run(
        self,
        *,
        repository: str,
        items: list[NexusAsset | DockerTag],
        download: bool = True,
        scan: bool = True,
        verify: bool = True,
        scanners: Sequence[str] | None = None,
        on_progress: ProgressCallback | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> PipelineSummary:
        enabled = (
            parse_scanner_names(",".join(scanners))
            if scanners is not None
            else list(self.settings.scanners_list)
        )
        summary = PipelineSummary(repository=repository, scanners=list(enabled))
        total = max(len(items), 1)

        if scan:
            for name in enabled:
                try:
                    summary.scanner_versions[name] = self._scanner_for(name).get_version()
                except Exception:  # noqa: BLE001
                    summary.scanner_versions[name] = None

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
            scans: dict[str, ScanResult] = {}

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
                if scan:
                    for name in enabled:
                        scans[name] = ScanResult(
                            status=ScanStatus.ERROR,
                            verdict=Verdict.ERROR,
                            scanner=name,
                            error=f"Download failed: {dl.error}",
                        )
                result = AssetPipelineResult(
                    asset_path=asset_path,
                    kind=kind,
                    download=dl,
                    scans=scans,
                )
                summary.results.append(result)
                report("error", 1.0)
                continue

            if scan:
                report(f"scan:{'+'.join(enabled)}", 0.5)
                if not dl.local_path:
                    for name in enabled:
                        scans[name] = ScanResult(
                            status=ScanStatus.ERROR,
                            verdict=Verdict.ERROR,
                            scanner=name,
                            error="No local path after download",
                        )
                else:
                    scheme = "docker-archive" if isinstance(item, DockerTag) else None
                    scans = self._run_scanners(
                        enabled,
                        repository=repository,
                        asset_path=asset_path,
                        local_path=dl.local_path,
                        target_scheme=scheme,
                    )
            else:
                for name in enabled:
                    scans[name] = ScanResult(
                        status=ScanStatus.SKIPPED,
                        verdict=Verdict.SKIPPED,
                        scanner=name,
                    )

            result = AssetPipelineResult(
                asset_path=asset_path,
                kind=kind,
                download=dl,
                scans=scans,
            )

            if verify and result.verdict == Verdict.PASS:
                report("verify", 0.85)
                apply_verify_for_result(
                    self.verifier,
                    repository,
                    result,
                    is_docker=isinstance(item, DockerTag),
                    tag=item.tag if isinstance(item, DockerTag) else None,
                )
            elif verify and result.verdict != Verdict.PASS:
                logger.info(
                    "Not copying %s to verified (verdict=%s)",
                    asset_path,
                    result.verdict.value,
                )

            summary.results.append(result)
            report("done", 1.0)

        summary.finished_at = datetime.now(timezone.utc)
        if verify:
            try:
                self.verifier.write_scanner_reports(summary)
            except OSError as exc:
                logger.error("Failed to write scanner reports into verified: %s", exc)
            if any(r.verdict == Verdict.PASS for r in summary.results):
                try:
                    self.verifier.write_manifest(summary)
                except OSError as exc:
                    logger.error("Failed to write verified manifest: %s", exc)
            try:
                self.verifier.write_unverified_list(summary)
            except OSError as exc:
                logger.error("Failed to write unverified assets list: %s", exc)
        return summary

    def _run_scanners(
        self,
        enabled: Sequence[str],
        *,
        repository: str,
        asset_path: str,
        local_path: Path,
        target_scheme: str | None,
    ) -> dict[str, ScanResult]:
        """Запустить включённые сканеры параллельно."""
        if len(enabled) == 1:
            name = enabled[0]
            return {
                name: self._scanner_for(name).scan_path(
                    repository=repository,
                    asset_path=asset_path,
                    local_path=local_path,
                    target_scheme=target_scheme,
                )
            }

        results: dict[str, ScanResult] = {}
        with ThreadPoolExecutor(max_workers=len(enabled)) as pool:
            futures = {
                pool.submit(
                    self._scanner_for(name).scan_path,
                    repository=repository,
                    asset_path=asset_path,
                    local_path=local_path,
                    target_scheme=target_scheme,
                ): name
                for name in enabled
                if name in KNOWN_SCANNERS
            }
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    results[name] = fut.result()
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Scanner %s crashed", name)
                    results[name] = ScanResult(
                        status=ScanStatus.ERROR,
                        verdict=Verdict.ERROR,
                        scanner=name,
                        error=str(exc),
                    )
        # Стабильный порядок ключей как в enabled
        return {name: results[name] for name in enabled if name in results}
