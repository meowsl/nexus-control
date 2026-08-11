"""Оркестрация verify с resource governor и disk-pressure batches."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from nexus_control.models import (
    DockerTag,
    DownloadStatus,
    NexusAsset,
    PipelineSummary,
    Verdict,
)
from nexus_control.services.pipeline import PipelineService, ProgressCallback
from nexus_control.services.resource_governor import (
    DiskPressureError,
    ResourceGovernor,
    format_reclaim_notice,
    resolve_limits,
)
from nexus_control.services.scan_common import parse_scanner_names
from nexus_control.services.verified_uploader import UploadSummary

logger = logging.getLogger(__name__)

StatusCallback = Callable[[str], None]
UploadCallback = Callable[[PipelineSummary], UploadSummary | None]


def _item_path(item: NexusAsset | DockerTag) -> str:
    return item.path


def _partition_local(
    pipeline: PipelineService,
    items: list[NexusAsset | DockerTag],
) -> tuple[list[NexusAsset | DockerTag], list[NexusAsset | DockerTag]]:
    """Разделить на уже локальные (без re-download) и требующие сети."""
    local: list[NexusAsset | DockerTag] = []
    remote: list[NexusAsset | DockerTag] = []
    for item in items:
        if isinstance(item, DockerTag):
            remote.append(item)
            continue
        inspection = pipeline.downloader.inspect_asset(item)
        if inspection.needs_download:
            remote.append(item)
        else:
            local.append(item)
    return local, remote


def run_resourced_pipeline(
    pipeline: PipelineService,
    *,
    repository: str,
    items: list[NexusAsset | DockerTag],
    download: bool = True,
    scan: bool = True,
    verify: bool = True,
    scanners: Sequence[str] | None = None,
    workers: int | None = None,
    max_scanner_procs: int | None = None,
    discover_sidecars: bool = False,
    on_progress: ProgressCallback | None = None,
    on_status: StatusCallback | None = None,
    should_cancel: Callable[[], bool] | None = None,
    do_upload: UploadCallback | None = None,
    history_source: str | None = None,
    history_rule_id: str | None = None,
    history_path_prefix: str | None = None,
    history_checkpoint_skipped: int = 0,
) -> tuple[PipelineSummary, list[UploadSummary]]:
    """Verify с auto-limits, scanner semaphore и disk-pressure loop.

    Returns ``(summary, upload_summaries)``.
    """
    enabled = (
        parse_scanner_names(",".join(scanners))
        if scanners is not None
        else list(pipeline.settings.scanners_list)
    )
    limits = resolve_limits(
        pipeline.settings,
        scanner_count=len(enabled),
        workers_override=workers,
        max_scanner_procs_override=max_scanner_procs,
    )
    governor = ResourceGovernor(pipeline.settings, limits)
    if on_status is not None:
        on_status(f"Resource limits: {limits.describe()}")
    logger.info("Resource limits: %s", limits.describe())

    combined = PipelineSummary(repository=repository, scanners=list(enabled))
    if scan:
        combined.scanner_versions = pipeline.scanner_versions(enabled)

    upload_summaries: list[UploadSummary] = []
    pending = list(items)
    by_path = {_item_path(i): i for i in items}
    unreclaimed: list[str] = []
    paused_for_disk = limits.disk_reclaim_enabled and governor.is_high()
    stall_guard = 0
    max_stalls = max(8, len(items) + 2)

    def status(msg: str) -> None:
        logger.info("%s", msg)
        if on_status is not None:
            on_status(msg)

    def merge_done(part: PipelineSummary) -> list[str]:
        """Добавить non-deferred results; вернуть пути completed в этом куске."""
        done_paths: list[str] = []
        for result in part.results:
            if result.download.status == DownloadStatus.DEFERRED:
                continue
            combined.results.append(result)
            done_paths.append(result.asset_path)
            unreclaimed.append(result.asset_path)
        if part.cancelled:
            combined.cancelled = True
        return done_paths

    def pending_from_deferred(part: PipelineSummary) -> list[NexusAsset | DockerTag]:
        deferred_paths = {
            r.asset_path
            for r in part.results
            if r.download.status == DownloadStatus.DEFERRED
        }
        # Также всё, что не попало в results (не должно случаться)
        seen = {r.asset_path for r in part.results}
        out: list[NexusAsset | DockerTag] = []
        for path in deferred_paths:
            item = by_path.get(path)
            if item is not None:
                out.append(item)
        for item in pending:
            path = _item_path(item)
            if path not in seen and path not in deferred_paths:
                out.append(item)
        return out

    def reclaim_if_needed(*, force: bool = False) -> bool:
        nonlocal unreclaimed
        if not limits.disk_reclaim_enabled:
            return False
        if not unreclaimed:
            return False
        if not force and not governor.is_high():
            return False
        paths = list(dict.fromkeys(unreclaimed))
        result = governor.archive_and_purge(repository, paths)
        unreclaimed = []
        status(format_reclaim_notice(result))
        return result.asset_count > 0 or result.bytes_freed > 0

    def upload_slice(done_paths: list[str]) -> None:
        if do_upload is None or not done_paths:
            return
        path_set = set(done_paths)
        slice_summary = PipelineSummary(
            repository=repository,
            scanners=list(enabled),
            scanner_versions=dict(combined.scanner_versions),
            results=[r for r in combined.results if r.asset_path in path_set],
        )
        # Только PASS с verified path имеют смысл для upload
        if not any(r.verdict == Verdict.PASS for r in slice_summary.results):
            return
        status(f"disk pressure: uploading {len(slice_summary.results)} finished assets…")
        up = do_upload(slice_summary)
        if up is not None:
            upload_summaries.append(up)

    while pending:
        if should_cancel and should_cancel():
            combined.cancelled = True
            break
        stall_guard += 1
        if stall_guard > max_stalls:
            raise DiskPressureError(
                "disk-pressure loop stalled: too many iterations without progress"
            )

        if governor.is_critical():
            raise DiskPressureError(
                f"disk critically full "
                f"({governor.host.disk_used_ratio:.0%} >= "
                f"{limits.disk_critical_watermark:.0%}) on {governor.host.disk_path}"
            )

        if limits.disk_reclaim_enabled and (
            paused_for_disk or governor.is_high()
        ):
            paused_for_disk = True
            status(
                f"disk pressure: pause downloads "
                f"(usage {governor.host.disk_used_ratio:.0%} "
                f">= high {limits.disk_high_watermark:.0%})"
            )
            local_items, _remote = _partition_local(pipeline, pending)
            progress_made = False

            if local_items:
                status(
                    f"disk pressure: scanning {len(local_items)} local assets…"
                )
                part = pipeline.run(
                    repository=repository,
                    items=local_items,
                    download=download,
                    scan=scan,
                    verify=verify,
                    scanners=enabled,
                    workers=limits.pipeline_workers,
                    max_scanner_procs=limits.max_scanner_procs,
                    governor=governor,
                    allow_new_download=lambda: False,
                    discover_sidecars=discover_sidecars,
                    finalize=False,
                    on_progress=on_progress,
                    should_cancel=should_cancel,
                    history_source=None,
                )
                done_paths = merge_done(part)
                deferred = pending_from_deferred(part)
                done_set = set(done_paths)
                pending = [
                    i
                    for i in pending
                    if _item_path(i) not in done_set
                ]
                # deferred locals should be rare; keep them
                for item in deferred:
                    if item not in pending:
                        pending.append(item)
                if done_paths:
                    progress_made = True
                    upload_slice(done_paths)
                    reclaim_if_needed(force=True)
            else:
                # Нечего сканировать локально — пробуем освободить место.
                if reclaim_if_needed(force=True):
                    progress_made = True
                elif unreclaimed:
                    # unreclaimed cleared inside reclaim; nothing else
                    pass
                else:
                    raise DiskPressureError(
                        f"disk usage {governor.host.disk_used_ratio:.0%} above "
                        f"high watermark {limits.disk_high_watermark:.0%} and "
                        "no local assets to scan or reclaim"
                    )

            if governor.is_low_or_below():
                status(
                    f"disk pressure: resume downloads "
                    f"(usage {governor.host.disk_used_ratio:.0%} "
                    f"<= low {limits.disk_low_watermark:.0%})"
                )
                paused_for_disk = False
            elif not progress_made and not governor.is_low_or_below():
                # После reclaim всё ещё high и нет прогресса
                if not pending:
                    break
                if not _partition_local(pipeline, pending)[0]:
                    raise DiskPressureError(
                        f"disk still above low watermark "
                        f"({governor.host.disk_used_ratio:.0%} > "
                        f"{limits.disk_low_watermark:.0%}) after reclaim; "
                        "free space manually or lower watermarks"
                    )
            if progress_made:
                stall_guard = 0
            continue

        # Нормальный проход: downloads разрешены, gate следит за high mid-batch.
        part = pipeline.run(
            repository=repository,
            items=pending,
            download=download,
            scan=scan,
            verify=verify,
            scanners=enabled,
            workers=limits.pipeline_workers,
            max_scanner_procs=limits.max_scanner_procs,
            governor=governor,
            allow_new_download=governor.allow_new_download,
            discover_sidecars=discover_sidecars,
            finalize=False,
            on_progress=on_progress,
            should_cancel=should_cancel,
            history_source=None,
        )
        done_paths = merge_done(part)
        pending = pending_from_deferred(part)
        if done_paths:
            stall_guard = 0
            # Upload+reclaim when we hit pressure or finished everything
            if not pending or governor.is_high():
                upload_slice(done_paths)
                if limits.disk_reclaim_enabled and (
                    governor.is_high() or not pending
                ):
                    reclaim_if_needed(force=governor.is_high() or not pending)
            if governor.is_high():
                paused_for_disk = True
        elif not pending:
            break
        else:
            # Everything deferred without progress
            paused_for_disk = True

        if combined.cancelled:
            break

    # Финальный upload для всего, что ещё не выгружали по слайсам:
    # если do_upload вызывался по слайсам — повторный upload безопасен (skip unchanged).
    if do_upload is not None and combined.results:
        # Если были промежуточные upload — всё равно можно финализировать skipped.
        if not upload_summaries:
            status("Uploading verified assets…")
            up = do_upload(combined)
            if up is not None:
                upload_summaries.append(up)

    # Финальный reclaim только если диск всё ещё выше low (не чистим кэш «на всякий»).
    if unreclaimed and limits.disk_reclaim_enabled and not governor.is_low_or_below():
        reclaim_if_needed(force=True)

    pipeline.finalize_summary(
        combined,
        verify=verify,
        history_source=history_source,
        history_rule_id=history_rule_id,
        history_path_prefix=history_path_prefix,
        history_workers=limits.pipeline_workers if (download or scan or verify) else None,
        history_checkpoint_skipped=history_checkpoint_skipped,
    )
    if combined.finished_at is None:
        combined.finished_at = datetime.now(timezone.utc)
    return combined, upload_summaries
