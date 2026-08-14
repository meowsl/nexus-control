"""Оркестрация verify с resource governor (лимиты CPU/RAM, без archive)."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from nexus_control.models import (
    DockerTag,
    NexusAsset,
    PipelineSummary,
)
from nexus_control.services.pipeline import PipelineService, ProgressCallback
from nexus_control.services.resource_governor import ResourceGovernor, resolve_limits
from nexus_control.services.scan_common import parse_scanner_names
from nexus_control.services.verified_uploader import UploadSummary

logger = logging.getLogger(__name__)

StatusCallback = Callable[[str], None]
UploadCallback = Callable[[PipelineSummary], UploadSummary | None]


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
    """Verify с auto-limits и scanner semaphore. Без archive/purge downloads.

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

    if governor.is_critical():
        msg = (
            f"disk critically full ({governor.host.disk_used_ratio:.0%} >= "
            f"{limits.disk_critical_watermark:.0%}) on {governor.host.disk_path}; "
            "new downloads disabled, scanning local assets only"
        )
        logger.warning("%s", msg)
        if on_status is not None:
            on_status(msg)

    summary = pipeline.run(
        repository=repository,
        items=items,
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

    upload_summaries: list[UploadSummary] = []
    if do_upload is not None and summary.results:
        if on_status is not None:
            on_status("Uploading verified assets…")
        logger.info("Uploading verified assets…")
        up = do_upload(summary)
        if up is not None:
            upload_summaries.append(up)

    pipeline.finalize_summary(
        summary,
        verify=verify,
        history_source=history_source,
        history_rule_id=history_rule_id,
        history_path_prefix=history_path_prefix,
        history_workers=limits.pipeline_workers if (download or scan or verify) else None,
        history_checkpoint_skipped=history_checkpoint_skipped,
    )
    if summary.finished_at is None:
        summary.finished_at = datetime.now(timezone.utc)
    return summary, upload_summaries
