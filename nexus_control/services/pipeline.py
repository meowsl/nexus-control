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
from nexus_control.services.osv_scanner import OsvScanner
from nexus_control.services.resource_governor import ResourceGovernor, resolve_limits
from nexus_control.services.scan_checkpoint import write_pass_checkpoint
from nexus_control.services.scan_common import (
    KNOWN_SCANNERS,
    SCAN_IGNORE_SUFFIXES,
    is_scan_ignored_path,
    main_asset_path_for_sidecar,
    parse_scanner_names,
)
from nexus_control.services.trivy_scanner import TrivyScanner
from nexus_control.services.verifier import Verifier, apply_verify_for_result
from nexus_control.nexus.uploads import is_nuget_package_path, is_scan_package_asset
from nexus_control.services.nuget_osv import is_nupkg_local_path

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, float, str], None]
# (asset_path, progress 0..1, сообщение этапа)
DownloadGate = Callable[[], bool]


class PipelineService:
    def __init__(self, settings: Settings, client: NexusClient) -> None:
        self.settings = settings
        self.client = client
        self.downloader = Downloader(settings, client)
        self.grype = GrypeScanner(settings)
        self.trivy = TrivyScanner(settings)
        self.osv = OsvScanner(settings)
        self.verifier = Verifier(settings)
        # Совместимость со старым кодом / тестами
        self.scanner = self.grype
        self._governor: ResourceGovernor | None = None

    def _scanner_for(self, name: str) -> GrypeScanner | TrivyScanner | OsvScanner:
        if name == "grype":
            return self.grype
        if name == "trivy":
            return self.trivy
        if name == "osv":
            return self.osv
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
        max_scanner_procs: int | None = None,
        governor: ResourceGovernor | None = None,
        allow_new_download: DownloadGate | None = None,
        discover_sidecars: bool = False,
        finalize: bool = True,
        on_progress: ProgressCallback | None = None,
        should_cancel: Callable[[], bool] | None = None,
        history_source: str | None = None,
        history_rule_id: str | None = None,
        history_path_prefix: str | None = None,
        history_checkpoint_skipped: int = 0,
    ) -> PipelineSummary:
        enabled = (
            parse_scanner_names(",".join(scanners))
            if scanners is not None
            else list(self.settings.scanners_list)
        )
        summary = PipelineSummary(repository=repository, scanners=list(enabled))
        total = max(len(items), 1)
        limits = resolve_limits(
            self.settings,
            scanner_count=len(enabled),
            workers_override=workers,
            max_scanner_procs_override=max_scanner_procs,
        )
        worker_count = limits.pipeline_workers
        self._governor = governor or ResourceGovernor(self.settings, limits)
        if governor is None:
            logger.info("Resource limits: %s", limits.describe())

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
            elif isinstance(item, NexusAsset) and not is_scan_package_asset(
                item.format, path
            ):
                # nuget registration/index и пр. — не пакеты: не сканируем и
                # не копируем в verified (обработаем в конце как skip-only).
                sidecars.append((index, item))
            else:
                mains.append((index, item))

        results_lock = threading.Lock()
        progress_lock = threading.Lock()
        done_count = 0
        cancel_flag = threading.Event()
        optional_sidecar_paths: set[str] = set()

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
                optional_download=(
                    isinstance(item, NexusAsset)
                    and item.path in optional_sidecar_paths
                ),
                allow_new_download=allow_new_download,
                summary_results=summary.results,
                results_lock=results_lock,
                report=report_item,
            )
            if result.download.status != DownloadStatus.DEFERRED:
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
                # При ограниченном листинге sidecar может находиться на ещё не
                # прочитанной странице. Для PASS main пробуем стандартные
                # companion-paths напрямую; 404 для них является нормой.
                if discover_sidecars:
                    known_sidecars = {
                        item.path
                        for _index, item in sidecars
                        if isinstance(item, NexusAsset)
                    }
                    next_index = len(items)
                    generated = 0
                    for _index, item in mains:
                        if not isinstance(item, NexusAsset):
                            continue
                        if not _main_artifact_verified(summary.results, item.path):
                            continue
                        for suffix in SCAN_IGNORE_SUFFIXES:
                            sidecar_path = item.path + suffix
                            if sidecar_path in known_sidecars:
                                continue
                            sidecars.append(
                                (
                                    next_index,
                                    NexusAsset(
                                        id=f"{item.id}:{suffix}",
                                        path=sidecar_path,
                                        download_url=(
                                            f"{item.download_url}{suffix}"
                                            if item.download_url
                                            else None
                                        ),
                                        repository=item.repository,
                                        format=item.format,
                                    ),
                                )
                            )
                            optional_sidecar_paths.add(sidecar_path)
                            known_sidecars.add(sidecar_path)
                            next_index += 1
                            generated += 1
                    total += generated

                # Sidecar имеет смысл загружать только после успешного main.
                # Это не меняет содержимое verified: sidecar для FAIL/ERROR
                # артефакта туда всё равно никогда не копировался.
                eligible_sidecars: list[tuple[int, NexusAsset | DockerTag]] = []
                for entry in sidecars:
                    _index, item = entry
                    if isinstance(item, NexusAsset) and not is_scan_package_asset(
                        item.format, item.path
                    ):
                        # Non-package metadata: always process (early skip, no download).
                        eligible_sidecars.append(entry)
                        continue
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

        if finalize:
            self.finalize_summary(
                summary,
                verify=verify,
                history_source=history_source,
                history_rule_id=history_rule_id,
                history_path_prefix=history_path_prefix,
                history_workers=(
                    worker_count if download or scan or verify else None
                ),
                history_checkpoint_skipped=history_checkpoint_skipped,
            )
        return summary

    def finalize_summary(
        self,
        summary: PipelineSummary,
        *,
        verify: bool = True,
        history_source: str | None = None,
        history_rule_id: str | None = None,
        history_path_prefix: str | None = None,
        history_workers: int | None = None,
        history_checkpoint_skipped: int = 0,
    ) -> None:
        """Записать reports/manifest/history в конце (в т.ч. после batch-оркестрации)."""
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

        if history_source in {"tui", "cli", "scheduler"}:
            try:
                from nexus_control.services.scan_history import record_scan_run

                record_scan_run(
                    self.settings,
                    summary,
                    source=history_source,  # type: ignore[arg-type]
                    rule_id=history_rule_id,
                    path_prefix=history_path_prefix,
                    workers=history_workers,
                    checkpoint_skipped=history_checkpoint_skipped,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Scan history recording failed: %s", exc)

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
        optional_download: bool,
        allow_new_download: DownloadGate | None,
        summary_results: list[AssetPipelineResult],
        results_lock: threading.Lock,
        report: Callable[[str, str], None],
    ) -> AssetPipelineResult:
        asset_path = item.path if isinstance(item, NexusAsset) else item.path
        kind = AssetKind.FILE if isinstance(item, NexusAsset) else AssetKind.IMAGE
        report(asset_path, "starting")
        scans: dict[str, ScanResult] = {}
        asset_fmt = item.format if isinstance(item, NexusAsset) else None
        checkpoint_scanners: list[str] = list(enabled)

        # NuGet V3 registration/index и аналогичная metadata — не качаем и не сканим.
        if isinstance(item, NexusAsset) and not is_scan_package_asset(
            asset_fmt, asset_path
        ):
            logger.info(
                "Skipping non-package asset (%s): %s",
                asset_fmt or "unknown-format",
                asset_path,
            )
            for name in enabled:
                scans[name] = ScanResult(
                    status=ScanStatus.SKIPPED,
                    verdict=Verdict.SKIPPED,
                    scanner=name,
                )
            return AssetPipelineResult(
                asset_path=asset_path,
                kind=kind,
                download=DownloadResult(
                    status=DownloadStatus.SKIPPED_EXISTING,
                    error="non-package asset",
                ),
                scans=scans,
            )

        if download:
            report(asset_path, "download")
            deferred = self._maybe_defer_download(
                item,
                optional_download=optional_download,
                allow_new_download=allow_new_download,
            )
            if deferred is not None:
                for name in enabled:
                    scans[name] = ScanResult(
                        status=ScanStatus.SKIPPED,
                        verdict=Verdict.SKIPPED,
                        scanner=name,
                    )
                return AssetPipelineResult(
                    asset_path=asset_path,
                    kind=kind,
                    download=deferred,
                    scans=scans,
                )
            if isinstance(item, DockerTag):
                dl = self.downloader.download_docker_tag(item)
            elif optional_download:
                dl = self.downloader.download_asset(item, optional=True)
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
                scan_names = _effective_scanners_for_asset(
                    enabled,
                    asset_fmt=asset_fmt,
                    asset_path=asset_path,
                    local_path=dl.local_path,
                )
                scans = self._run_scanners(
                    scan_names,
                    repository=repository,
                    asset_path=asset_path,
                    local_path=dl.local_path,
                    target_scheme=scheme,
                    asset_fmt=asset_fmt,
                )
                checkpoint_scanners = checkpoint_scanners_for_asset(
                    enabled,
                    asset_fmt=asset_fmt,
                    asset_path=asset_path,
                    local_path=dl.local_path,
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
            # Для NuGet checkpoint должен отражать osv (identity), не grype/trivy.
            ck_scanners = checkpoint_scanners
            ck_versions = {
                name: scanner_versions.get(name)
                for name in ck_scanners
            }
            if "osv" in ck_scanners and ck_versions.get("osv") is None:
                try:
                    ck_versions["osv"] = self.osv.get_version()
                except Exception:  # noqa: BLE001
                    ck_versions["osv"] = None
            write_pass_checkpoint(
                settings=self.settings,
                asset=item,
                result=result,
                scanners=ck_scanners,
                scanner_versions=ck_versions,
            )

        return result

    def _maybe_defer_download(
        self,
        item: NexusAsset | DockerTag,
        *,
        optional_download: bool,
        allow_new_download: DownloadGate | None,
    ) -> DownloadResult | None:
        """Если disk-pressure запрещает новые downloads и файл не локальный — DEFERRED."""
        if allow_new_download is None or allow_new_download():
            return None
        if isinstance(item, DockerTag):
            # Docker archives: без inspect считаем, что нужен download.
            return DownloadResult(
                status=DownloadStatus.DEFERRED,
                error="disk pressure: download paused",
            )
        inspection = self.downloader.inspect_asset(item)
        if not inspection.needs_download:
            return None
        if optional_download:
            # Optional sidecar: отсутствие файла — норма; не откладываем весь batch.
            return None
        return DownloadResult(
            status=DownloadStatus.DEFERRED,
            error="disk pressure: download paused",
            local_path=inspection.local_path,
        )

    def _run_scanners(
        self,
        enabled: Sequence[str],
        *,
        repository: str,
        asset_path: str,
        local_path: Path,
        target_scheme: str | None,
        asset_fmt: str | None = None,
    ) -> dict[str, ScanResult]:
        """Запустить включённые сканеры параллельно под глобальным semaphore."""
        nuget = _is_nuget_scan_target(
            asset_fmt=asset_fmt,
            asset_path=asset_path,
            local_path=local_path,
        )
        # NuGet: Grype/Trivy дают ложный empty PASS — пропускаем, гоняем только OSV API.
        run_names = list(enabled)
        skipped: dict[str, ScanResult] = {}
        if nuget:
            run_names = []
            for name in enabled:
                if name == "osv":
                    run_names.append(name)
                elif name in {"grype", "trivy"}:
                    skipped[name] = ScanResult(
                        status=ScanStatus.SKIPPED,
                        verdict=Verdict.SKIPPED,
                        scanner=name,
                        error="NuGet packages use osv-scanner identity scan (nuspec → lockfile)",
                    )
            if "osv" not in run_names:
                run_names.append("osv")
            logger.info(
                "NuGet package %s: osv-scanner identity scan (skipping %s)",
                asset_path,
                ", ".join(sorted(skipped)) or "none",
            )

        def scan_one(name: str) -> ScanResult:
            gov = self._governor
            if gov is not None:
                gov.acquire_scanner()
            try:
                return self._scanner_for(name).scan_path(
                    repository=repository,
                    asset_path=asset_path,
                    local_path=local_path,
                    target_scheme=target_scheme,
                )
            finally:
                if gov is not None:
                    gov.release_scanner()

        results: dict[str, ScanResult] = dict(skipped)
        if not run_names:
            return results

        if len(run_names) == 1:
            name = run_names[0]
            results[name] = scan_one(name)
        else:
            with ThreadPoolExecutor(max_workers=len(run_names)) as pool:
                futures = {
                    pool.submit(scan_one, name): name
                    for name in run_names
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
        # Стабильный порядок: сначала enabled, затем автодобавленный osv.
        ordered: dict[str, ScanResult] = {}
        for name in enabled:
            if name in results:
                ordered[name] = results[name]
        for name, sc in results.items():
            if name not in ordered:
                ordered[name] = sc
        return ordered


def _is_nuget_scan_target(
    *,
    asset_fmt: str | None,
    asset_path: str,
    local_path: Path | None,
) -> bool:
    """NuGet package asset / локальный ``.nupkg`` — нужен identity-скан."""
    if local_path is not None and is_nupkg_local_path(local_path):
        return True
    if is_nuget_package_path(asset_path):
        return True
    fmt = (asset_fmt or "").lower().strip()
    if fmt == "nuget" and is_scan_package_asset(fmt, asset_path):
        return True
    return False


def _effective_scanners_for_asset(
    enabled: Sequence[str],
    *,
    asset_fmt: str | None,
    asset_path: str,
    local_path: Path | None,
) -> list[str]:
    """Для NuGet гарантировать osv в списке (остальное решит ``_run_scanners``)."""
    names = list(enabled)
    if not _is_nuget_scan_target(
        asset_fmt=asset_fmt,
        asset_path=asset_path,
        local_path=local_path,
    ):
        return names
    if "osv" not in names:
        names.append("osv")
    return names


def checkpoint_scanners_for_asset(
    enabled: Sequence[str],
    *,
    asset_fmt: str | None,
    asset_path: str,
    local_path: Path | None,
) -> list[str]:
    """Сканеры, которые реально участвуют в вердикте (для PASS-checkpoint).

    NuGet → только ``osv`` (Grype/Trivy SKIPPED).
    """
    if _is_nuget_scan_target(
        asset_fmt=asset_fmt,
        asset_path=asset_path,
        local_path=local_path,
    ):
        return ["osv"]
    return list(enabled)


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
