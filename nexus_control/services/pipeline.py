"""Оркестрация загрузки → сканирования → verified copy для выбранных артефактов."""

from __future__ import annotations

import logging
import threading
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
from nexus_control.services.scan_checkpoint import write_pass_checkpoint
from nexus_control.services.scan_common import (
    KNOWN_SCANNERS,
    is_scan_ignored_path,
    main_asset_path_for_sidecar,
    parse_scanner_names,
)
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

    def scanner_versions(
        self,
        scanners: Sequence[str],
    ) -> dict[str, str | None]:
        versions: dict[str, str | None] = {}
        for name in scanners:
            try:
                versions[name] = self._scanner_for(name).get_version()
            except Exception:  # noqa: BLE001
                versions[name] = None
        return versions

    def run(
        self,
        *,
        repository: str,
        items: list[NexusAsset | DockerTag],
        download: bool = True,
        scan: bool = True,
        verify: bool = True,
        scanners: Sequence[str] | None = None,
        workers: int | None = None,
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
        worker_count = max(
            1,
            int(workers if workers is not None else self.settings.pipeline_workers)
        )

        if scan:
            summary.scanner_versions = self.scanner_versions(enabled)

        # Сначала основные артефакты (параллельно), потом sidecar'ы
        # (им нужен PASS main в summary.results).
        mains: list[tuple[int, NexusAsset | DockerTag]] = []
        sidecars: list[tuple[int, NexusAsset | DockerTag]] = []
        for index, item in enumerate(items):
            path = item.path if isinstance(item, NexusAsset) else item.path
            if isinstance(item, NexusAsset) and is_scan_ignored_path(path):
                sidecars.append((index, item))
            else:
                mains.append((index, item))

        results_lock = threading.Lock()
        progress_lock = threading.Lock()
        done_count = 0
        cancel_flag = threading.Event()

        def report_item(asset_path: str, stage: str) -> None:
            if on_progress is None:
                return
            with progress_lock:
                # progress ≈ completed / total (грубо, но стабильно при параллелизме)
                frac = done_count / total
                on_progress(asset_path, min(frac, 0.99), stage)

        def mark_done(asset_path: str) -> None:
            nonlocal done_count
            with progress_lock:
                done_count += 1
                if on_progress is not None:
                    on_progress(asset_path, min(done_count / total, 1.0), "done")

        def process_one(index: int, item: NexusAsset | DockerTag) -> AssetPipelineResult | None:
            if cancel_flag.is_set() or (should_cancel and should_cancel()):
                cancel_flag.set()
                return None
            result = self._process_item(
                repository=repository,
                item=item,
                download=download,
                scan=scan,
                verify=verify,
                enabled=enabled,
                scanner_versions=summary.scanner_versions,
                summary_results=summary.results,
                results_lock=results_lock,
                report=report_item,
            )
            mark_done(result.asset_path)
            return result

        def run_batch(batch: list[tuple[int, NexusAsset | DockerTag]]) -> None:
            if not batch:
                return
            if worker_count == 1 or len(batch) == 1:
                for index, item in batch:
                    if cancel_flag.is_set():
                        break
                    result = process_one(index, item)
                    if result is None:
                        summary.cancelled = True
                        break
                    with results_lock:
                        summary.results.append(result)
                return

            logger.info(
                "Pipeline parallel workers=%d items=%d (batch)",
                worker_count,
                len(batch),
            )
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                futures = {
                    pool.submit(process_one, index, item): (index, item)
                    for index, item in batch
                }
                # Сохраняем относительный порядок по исходному index
                completed: dict[int, AssetPipelineResult] = {}
                for fut in as_completed(futures):
                    index, _item = futures[fut]
                    try:
                        result = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        logger.exception("Pipeline worker crashed for index=%s", index)
                        item = _item
                        path = item.path if isinstance(item, NexusAsset) else item.path
                        result = AssetPipelineResult(
                            asset_path=path,
                            kind=(
                                AssetKind.FILE
                                if isinstance(item, NexusAsset)
                                else AssetKind.IMAGE
                            ),
                            download=DownloadResult(
                                status=DownloadStatus.ERROR,
                                error=str(exc),
                            ),
                            scans={
                                name: ScanResult(
                                    status=ScanStatus.ERROR,
                                    verdict=Verdict.ERROR,
                                    scanner=name,
                                    error=str(exc),
                                )
                                for name in enabled
                            },
                        )
                        mark_done(path)
                    if result is None:
                        summary.cancelled = True
                        cancel_flag.set()
                        continue
                    completed[index] = result
                for index, _item in batch:
                    if index in completed:
                        with results_lock:
                            summary.results.append(completed[index])

        run_batch(mains)
        if not summary.cancelled:
            if verify:
                # Sidecar имеет смысл загружать только после успешного main.
                # Это не меняет содержимое verified: sidecar для FAIL/ERROR
                # артефакта туда всё равно никогда не копировался.
                eligible_sidecars: list[tuple[int, NexusAsset | DockerTag]] = []
                for entry in sidecars:
                    _index, item = entry
                    main_path = main_asset_path_for_sidecar(item.path)
                    if main_path and _main_artifact_verified(
                        summary.results,
                        main_path,
                    ):
                        eligible_sidecars.append(entry)
                    else:
                        mark_done(item.path)
                run_batch(eligible_sidecars)
            else:
                run_batch(sidecars)

        if cancel_flag.is_set() and should_cancel and should_cancel():
            summary.cancelled = True
            logger.warning("Pipeline cancelled by user")

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

    def _process_item(
        self,
        *,
        repository: str,
        item: NexusAsset | DockerTag,
        download: bool,
        scan: bool,
        verify: bool,
        enabled: Sequence[str],
        scanner_versions: dict[str, str | None],
        summary_results: list[AssetPipelineResult],
        results_lock: threading.Lock,
        report: Callable[[str, str], None],
    ) -> AssetPipelineResult:
        asset_path = item.path if isinstance(item, NexusAsset) else item.path
        kind = AssetKind.FILE if isinstance(item, NexusAsset) else AssetKind.IMAGE
        report(asset_path, "starting")
        scans: dict[str, ScanResult] = {}

        if download:
            report(asset_path, "download")
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
            return AssetPipelineResult(
                asset_path=asset_path,
                kind=kind,
                download=dl,
                scans=scans,
            )

        if scan:
            report(asset_path, f"scan:{'+'.join(enabled)}")
            if is_scan_ignored_path(asset_path):
                logger.debug("Skipping vulnerability scan for sidecar: %s", asset_path)
                for name in enabled:
                    scans[name] = ScanResult(
                        status=ScanStatus.SKIPPED,
                        verdict=Verdict.SKIPPED,
                        scanner=name,
                    )
            elif not dl.local_path:
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
            report(asset_path, "verify")
            apply_verify_for_result(
                self.verifier,
                repository,
                result,
                is_docker=isinstance(item, DockerTag),
                tag=item.tag if isinstance(item, DockerTag) else None,
            )
        elif (
            verify
            and is_scan_ignored_path(asset_path)
            and result.verdict == Verdict.SKIPPED
            and dl.local_path is not None
            and dl.status != DownloadStatus.ERROR
        ):
            main_path = main_asset_path_for_sidecar(asset_path)
            with results_lock:
                mains_snapshot = list(summary_results)
            if main_path and _main_artifact_verified(mains_snapshot, main_path):
                report(asset_path, "verify")
                result.verify = self.verifier.copy_if_pass(
                    repository=repository,
                    asset_path=asset_path,
                    local_path=dl.local_path,
                    is_docker=False,
                )
            else:
                logger.debug(
                    "Sidecar %s not copied yet (main artifact not PASS/verified)",
                    asset_path,
                )
        elif verify and result.verdict != Verdict.PASS:
            logger.info(
                "Not copying %s to verified (verdict=%s)",
                asset_path,
                result.verdict.value,
            )

        if verify and isinstance(item, NexusAsset):
            write_pass_checkpoint(
                settings=self.settings,
                asset=item,
                result=result,
                scanners=enabled,
                scanner_versions=scanner_versions,
            )

        return result

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


def _main_artifact_verified(
    results: Sequence[AssetPipelineResult],
    main_asset_path: str,
) -> bool:
    """True, если основной артефакт уже PASS и скопирован (или уже был) в verified."""
    for result in results:
        if result.asset_path != main_asset_path:
            continue
        if result.verdict != Verdict.PASS:
            return False
        return bool(result.verify.copied or result.verify.skipped_existing)
    return False
