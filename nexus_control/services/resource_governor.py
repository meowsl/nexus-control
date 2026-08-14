"""Авто-лимиты CPU/RAM и проверка заполнения диска (без archive/purge)."""

from __future__ import annotations

import logging
import os
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path

from nexus_control.config import Settings
from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

# ~2 GiB пик на один concurrent scanner (Grype/Trivy/OSV + DB).
_GB_PER_SCANNER = 2.0
_SCANNER_HARD_CAP = 8
_DISK_CRITICAL_DEFAULT = 0.95


class DiskPressureError(RuntimeError):
    """Диск заполнен критически, новые downloads невозможны."""


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
    disk_critical_watermark: float
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
            f"(critical={self.disk_critical_watermark:.0%})"
        )


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

    critical = float(settings.disk_critical_watermark)
    return ResourceLimits(
        pipeline_workers=workers,
        max_scanner_procs=max_scanner,
        disk_critical_watermark=critical,
        host=host,
        workers_from_auto=workers_auto,
        scanner_procs_from_auto=scanners_auto,
    )


class ResourceGovernor:
    """Семафор сканеров + проверка critical disk (без archive)."""

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

    def is_critical(self) -> bool:
        return self.disk_used_ratio() >= self.limits.disk_critical_watermark

    def allow_new_download(self) -> bool:
        return not self.is_critical()

    def acquire_scanner(self) -> None:
        self._scanner_sem.acquire()

    def release_scanner(self) -> None:
        self._scanner_sem.release()


DISK_CRITICAL_DEFAULT = _DISK_CRITICAL_DEFAULT
