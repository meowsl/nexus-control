"""Авто-лимиты CPU/RAM и disk-pressure (watermarks, archive/purge)."""

from __future__ import annotations

import logging
import os
import shutil
import tarfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from nexus_control.config import Settings
from nexus_control.utils.fs import ensure_dir
from nexus_control.nexus.uploads import normalize_storage_asset_path
from nexus_control.utils.safe_path import (
    UnsafePathError,
    asset_download_path,
    resolve_storage_path,
    sanitize_repo_name,
)

logger = logging.getLogger(__name__)

# ~2 GiB пик на один concurrent scanner (Grype/Trivy/OSV + DB).
_GB_PER_SCANNER = 2.0
_SCANNER_HARD_CAP = 8
_DISK_CRITICAL_DEFAULT = 0.95


class DiskPressureError(RuntimeError):
    """Диск заполнен, а reclaim/scan-local не освобождает место."""


@dataclass(frozen=True, slots=True)
class HostResources:
    cpu_count: int
    mem_available_gb: float
    mem_total_gb: float
    disk_total_bytes: int
    disk_used_bytes: int
    disk_free_bytes: int
    disk_used_ratio: float
    disk_path: Path


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    pipeline_workers: int
    max_scanner_procs: int
    disk_high_watermark: float
    disk_low_watermark: float
    disk_critical_watermark: float
    disk_reclaim_enabled: bool
    host: HostResources
    workers_from_auto: bool
    scanner_procs_from_auto: bool

    def describe(self) -> str:
        auto_w = "auto" if self.workers_from_auto else "cfg"
        auto_s = "auto" if self.scanner_procs_from_auto else "cfg"
        return (
            f"cpus={self.host.cpu_count} mem_avail={self.host.mem_available_gb:.1f}GiB "
            f"→ workers={self.pipeline_workers}({auto_w}) "
            f"max_scanner_procs={self.max_scanner_procs}({auto_s}) "
            f"disk={self.host.disk_used_ratio:.0%} "
            f"(high={self.disk_high_watermark:.0%} "
            f"low={self.disk_low_watermark:.0%})"
        )


@dataclass(frozen=True, slots=True)
class ArchiveResult:
    archive_path: Path | None
    asset_count: int
    bytes_before: int
    bytes_freed: int
    disk_ratio_before: float
    disk_ratio_after: float


def read_mem_gb() -> tuple[float, float]:
    """Вернуть ``(available_gb, total_gb)`` из ``/proc/meminfo`` или fallback."""
    total_kb: int | None = None
    avail_kb: int | None = None
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
    except OSError:
        text = ""
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            total_kb = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            avail_kb = int(line.split()[1])
    if total_kb and total_kb > 0:
        total_gb = total_kb / (1024 * 1024)
        if avail_kb is not None and avail_kb >= 0:
            return avail_kb / (1024 * 1024), total_gb
        return total_gb * 0.5, total_gb
    # Не Linux / нет meminfo
    return 4.0, 8.0


def disk_usage_for_paths(paths: list[Path]) -> tuple[Path, int, int, int]:
    """Выбрать volume с наибольшим used ratio.

    Returns ``(path, total, used, free)``.
    """
    best_path = paths[0] if paths else Path(".")
    try:
        ensure_dir(best_path)
    except OSError:
        pass
    best = shutil.disk_usage(str(best_path))
    best_ratio = (best.used / best.total) if best.total else 0.0
    for path in paths:
        try:
            ensure_dir(path)
            usage = shutil.disk_usage(str(path))
        except OSError:
            continue
        ratio = (usage.used / usage.total) if usage.total else 0.0
        if ratio >= best_ratio:
            best_ratio = ratio
            best = usage
            best_path = path
    return best_path, best.total, best.used, best.free


def detect_host_resources(settings: Settings) -> HostResources:
    cpus = os.cpu_count() or 2
    avail_gb, total_gb = read_mem_gb()
    paths = [
        settings.download_root,
        settings.reports_root,
        settings.verified_root,
    ]
    if settings.disk_reclaim_enabled:
        paths.append(settings.archive_root)
    disk_path, total_b, used_b, free_b = disk_usage_for_paths(paths)
    ratio = (used_b / total_b) if total_b else 0.0
    return HostResources(
        cpu_count=max(1, cpus),
        mem_available_gb=max(0.0, avail_gb),
        mem_total_gb=max(0.0, total_gb),
        disk_total_bytes=total_b,
        disk_used_bytes=used_b,
        disk_free_bytes=free_b,
        disk_used_ratio=ratio,
        disk_path=disk_path,
    )


def compute_auto_concurrency(
    host: HostResources,
    *,
    scanner_count: int,
) -> tuple[int, int]:
    """``(pipeline_workers, max_scanner_procs)`` по формуле из плана."""
    by_ram = max(1, int(host.mem_available_gb // _GB_PER_SCANNER))
    by_cpu = max(1, host.cpu_count)
    max_scanner_procs = min(by_ram, by_cpu, _SCANNER_HARD_CAP)
    n_scanners = max(1, scanner_count)
    pipeline_workers = max(1, min(4, max_scanner_procs // n_scanners))
    return pipeline_workers, max_scanner_procs


def resolve_limits(
    settings: Settings,
    *,
    scanner_count: int,
    workers_override: int | None = None,
    max_scanner_procs_override: int | None = None,
) -> ResourceLimits:
    host = detect_host_resources(settings)
    auto_workers, auto_scanners = compute_auto_concurrency(
        host, scanner_count=scanner_count
    )

    if workers_override is not None:
        workers = max(1, int(workers_override))
        workers_auto = False
    elif settings.pipeline_workers and settings.pipeline_workers > 0:
        workers = int(settings.pipeline_workers)
        workers_auto = False
    else:
        workers = auto_workers
        workers_auto = True

    if max_scanner_procs_override is not None:
        max_scanner = max(1, int(max_scanner_procs_override))
        scanners_auto = False
    elif settings.max_scanner_procs and settings.max_scanner_procs > 0:
        max_scanner = int(settings.max_scanner_procs)
        scanners_auto = False
    else:
        max_scanner = auto_scanners
        scanners_auto = True

    high = float(settings.disk_high_watermark)
    low = float(settings.disk_low_watermark)
    critical = float(settings.disk_critical_watermark)
    return ResourceLimits(
        pipeline_workers=workers,
        max_scanner_procs=max_scanner,
        disk_high_watermark=high,
        disk_low_watermark=low,
        disk_critical_watermark=critical,
        disk_reclaim_enabled=bool(settings.disk_reclaim_enabled),
        host=host,
        workers_from_auto=workers_auto,
        scanner_procs_from_auto=scanners_auto,
    )


class ResourceGovernor:
    """Проверки диска + семафор сканеров + archive/purge downloads."""

    def __init__(self, settings: Settings, limits: ResourceLimits) -> None:
        self.settings = settings
        self.limits = limits
        self._scanner_sem = threading.Semaphore(limits.max_scanner_procs)
        self._host = limits.host

    @property
    def host(self) -> HostResources:
        return self._host

    def refresh_disk(self) -> HostResources:
        self._host = detect_host_resources(self.settings)
        return self._host

    def disk_used_ratio(self) -> float:
        return self.refresh_disk().disk_used_ratio

    def is_high(self) -> bool:
        return self.disk_used_ratio() >= self.limits.disk_high_watermark

    def is_low_or_below(self) -> bool:
        return self.disk_used_ratio() <= self.limits.disk_low_watermark

    def is_critical(self) -> bool:
        return self.disk_used_ratio() >= self.limits.disk_critical_watermark

    def allow_new_download(self) -> bool:
        if self.is_critical():
            return False
        return not self.is_high()

    def acquire_scanner(self) -> None:
        self._scanner_sem.acquire()

    def release_scanner(self) -> None:
        self._scanner_sem.release()

    def archive_and_purge(
        self,
        repository: str,
        asset_paths: list[str],
        *,
        batch_id: str | None = None,
    ) -> ArchiveResult:
        """Упаковать локальные downloads в tar.gz и удалить оригиналы."""
        ratio_before = self.disk_used_ratio()
        unique_paths = sorted({p.replace("\\", "/").lstrip("/") for p in asset_paths if p})
        files: list[tuple[str, Path]] = []
        bytes_before = 0
        for asset_path in unique_paths:
            try:
                dest = asset_download_path(
                    self.settings.download_root,
                    repository,
                    normalize_storage_asset_path(asset_path),
                )
            except UnsafePathError:
                continue
            local = resolve_storage_path(dest)
            if not local.is_file():
                # Legacy path without .nupkg suffix (pre-normalize storage).
                try:
                    legacy = asset_download_path(
                        self.settings.download_root, repository, asset_path
                    )
                except UnsafePathError:
                    continue
                local = resolve_storage_path(legacy)
                if not local.is_file():
                    continue
            try:
                size = local.stat().st_size
            except OSError:
                size = 0
            bytes_before += size
            files.append((asset_path, local))
            # Checkpoint рядом с файлом
            checkpoint = local.parent / f"{local.name}.scan-checkpoint.json"
            if checkpoint.is_file():
                files.append((f"{asset_path}.scan-checkpoint.json", checkpoint))

        if not files:
            return ArchiveResult(
                archive_path=None,
                asset_count=0,
                bytes_before=0,
                bytes_freed=0,
                disk_ratio_before=ratio_before,
                disk_ratio_after=ratio_before,
            )

        stamp = batch_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        repo_safe = sanitize_repo_name(repository)
        archive_dir = ensure_dir(self.settings.archive_root / repo_safe)
        archive_path = archive_dir / f"{stamp}.tar.gz"

        # Дедуп путей на диске (main + checkpoint)
        seen: set[Path] = set()
        unique_files: list[tuple[str, Path]] = []
        for name, path in files:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            unique_files.append((name, path))

        with tarfile.open(archive_path, "w:gz") as tar:
            for arcname, path in unique_files:
                try:
                    tar.add(path, arcname=arcname, recursive=False)
                except OSError as exc:
                    logger.warning("Archive skip %s: %s", path, exc)

        freed = 0
        for _name, path in unique_files:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            try:
                path.unlink(missing_ok=True)
                freed += size
            except OSError as exc:
                logger.warning("Purge failed for %s: %s", path, exc)

        ratio_after = self.disk_used_ratio()
        logger.info(
            "disk reclaim: archived %d files (%d assets) → %s, "
            "freed≈%.2f GiB, usage %.0f%%→%.0f%%",
            len(unique_files),
            len(unique_paths),
            archive_path,
            freed / (1024**3),
            ratio_before * 100,
            ratio_after * 100,
        )
        return ArchiveResult(
            archive_path=archive_path,
            asset_count=len(unique_paths),
            bytes_before=bytes_before,
            bytes_freed=freed,
            disk_ratio_before=ratio_before,
            disk_ratio_after=ratio_after,
        )


def format_reclaim_notice(result: ArchiveResult) -> str:
    if result.asset_count == 0:
        return "disk reclaim: nothing to archive"
    where = str(result.archive_path) if result.archive_path else "?"
    return (
        f"disk reclaim: archived {result.asset_count} assets → {where}, "
        f"freed≈{result.bytes_freed / (1024**3):.2f} GiB, "
        f"usage {result.disk_ratio_before:.0%}→{result.disk_ratio_after:.0%}"
    )


# Re-export for tests / callers that want the constant.
DISK_CRITICAL_DEFAULT = _DISK_CRITICAL_DEFAULT
