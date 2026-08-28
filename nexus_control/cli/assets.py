"""Helpers: list/filter assets for CLI verify."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from nexus_control.config import Settings
from nexus_control.models import AssetPipelineResult, NexusAsset, Repository
from nexus_control.nexus.asset_cache import (
    iter_cached_assets,
    load_cached_assets,
    save_cached_assets,
)
from nexus_control.nexus.client import NexusClient
from nexus_control.services.downloader import Downloader
from nexus_control.services.scan_checkpoint import (
    checkpoint_is_valid,
    load_pass_checkpoint,
    result_from_pass_checkpoint,
)
from nexus_control.nexus.uploads import (
    is_maven_repo_root_path,
    is_scan_package_asset,
    looks_like_nuget_metadata_path,
)
from nexus_control.services.pipeline import checkpoint_scanners_for_asset
from nexus_control.services.scan_common import main_asset_path_for_sidecar
from nexus_control.utils.path_prefixes import (
    normalize_path_prefixes,
    path_allowed_by_filters,
    path_is_excluded,
)
logger = logging.getLogger(__name__)

# (inspected_count, stats, source_label) — source: "nexus" | "cache"
SelectionProgressCallback = Callable[[int, "AssetSelectionStats", str], None]


@dataclass(slots=True)
class CheckpointSkip:
    """PASS-ассет, пропущенный по checkpoint (для upload/manifest)."""

    asset: NexusAsset
    local_path: Path
    raw: dict


@dataclass(slots=True)
class AssetSelectionStats:
    download_needed: int = 0
    scan_only: int = 0
    checkpoint_skipped: int = 0
    skipped_passes: list[CheckpointSkip] = field(default_factory=list)

    def checkpoint_pass_results(self) -> list[AssetPipelineResult]:
        """Синтетические PASS-results для upload/manifest."""
        out: list[AssetPipelineResult] = []
        for skip in self.skipped_passes:
            result = result_from_pass_checkpoint(skip.asset, skip.local_path, skip.raw)
            if result is not None:
                out.append(result)
        return out


def require_non_docker_repo(repo: Repository) -> None:
    if repo.is_docker:
        raise SystemExit(
            f"Repository {repo.name!r} is docker format. "
            "CLI v1 does not support docker adapters; use the TUI (nexus-control)."
        )


def list_assets_for_cli(
    client: NexusClient,
    settings: Settings,
    repository: str,
    *,
    refresh: bool = False,
) -> list[NexusAsset]:
    """Список ассетов: кэш (если есть) или Nexus; ``refresh`` — всегда с сервера."""
    ttl = settings.assets_cache_ttl
    if not refresh and ttl > 0:
        cached = load_cached_assets(
            settings.nexus_cache_dir,
            settings.nexus_url,
            repository,
            ttl_seconds=ttl,
            allow_stale=True,
        )
        if cached is not None:
            assets, age = cached
            logger.info(
                "Using asset list cache for %s (%d assets, age=%ds)",
                repository,
                len(assets),
                int(age),
            )
            return assets

    logger.info("Listing assets from Nexus for %s…", repository)

    def on_page(page: int, total: int) -> None:
        if page == 1 or page % 10 == 0:
            logger.info("Listed %d assets (page %d)…", total, page)

    assets = client.list_assets(repository, on_page=on_page)
    if ttl > 0:
        save_cached_assets(
            settings.nexus_cache_dir,
            settings.nexus_url,
            repository,
            assets,
        )
    return assets


def filter_assets_for_pipeline(
    assets: list[NexusAsset],
    *,
    path_prefix: str | Sequence[str] | None = None,
    exclude_prefix: str | Sequence[str] | None = None,
    limit: int | None = None,
    scan_limit: int | None = None,
) -> list[NexusAsset]:
    """Отфильтровать ассеты для pipeline.

    Sidecar'ы (``.md5``/…) **оставляем** в списке — pipeline сам skip'ает scan
    и копирует их вместе с PASS. ``limit`` / ``scan_limit`` считают только
    non-sidecar.
    """
    selected, _total, _stats = _select_assets(
        assets,
        path_prefix=path_prefix,
        exclude_prefix=exclude_prefix,
        limit=limit,
        scan_limit=scan_limit,
    )
    return selected


def select_assets_for_cli(
    client: NexusClient,
    settings: Settings,
    repository: str,
    *,
    path_prefix: str | Sequence[str] | None = None,
    exclude_prefix: str | Sequence[str] | None = None,
    limit: int | None = None,
    scan_limit: int | None = None,
    refresh: bool = False,
    scanners: Sequence[str] | None = None,
    scanner_versions: Mapping[str, str | None] | None = None,
    use_checkpoints: bool = True,
    ignore_checkpoint_ttl: bool = False,
    on_progress: SelectionProgressCallback | None = None,
) -> tuple[list[NexusAsset], int, AssetSelectionStats]:
    """Потоково выбрать pipeline-items и вернуть ``(items, total_listed)``.

    При чтении Nexus и дискового кэша полный список не материализуется. Sidecar
    сохраняются только для выбранных main-артефактов, поэтому качество verify
    не меняется.

    ``limit`` — max ассетов, которым нужен download/re-download.
    ``scan_limit`` — max main-ассетов, попадающих в pipeline (download+scan-only);
    удобно для дебага на большой выборке.
    """
    ttl = settings.assets_cache_ttl
    if not refresh and ttl > 0:
        cached = iter_cached_assets(
            settings.nexus_cache_dir,
            settings.nexus_url,
            repository,
            ttl_seconds=ttl,
            allow_stale=False,
        )
        if cached is not None:
            stream, age = cached
            logger.info(
                "Using streaming asset cache for %s (age=%ds); "
                "inspecting local downloads/checkpoints…",
                repository,
                int(age),
            )
            selected, total, stats = _select_assets(
                stream,
                path_prefix=path_prefix,
                exclude_prefix=exclude_prefix,
                limit=limit,
                scan_limit=scan_limit,
                settings=settings,
                client=client,
                scanners=scanners,
                scanner_versions=scanner_versions,
                use_checkpoints=use_checkpoints,
                ignore_checkpoint_ttl=ignore_checkpoint_ttl,
                on_progress=on_progress,
                progress_source="cache",
            )
            logger.info(
                "Finished asset cache for %s (%d assets inspected)",
                repository,
                total,
            )
            return selected, total, stats

    logger.info("Streaming assets from Nexus for %s…", repository)
    selector = _AssetSelector(
        path_prefix=path_prefix,
        exclude_prefix=exclude_prefix,
        limit=limit,
        scan_limit=scan_limit,
        settings=settings,
        client=client,
        scanners=scanners,
        scanner_versions=scanner_versions,
        use_checkpoints=use_checkpoints,
        ignore_checkpoint_ttl=ignore_checkpoint_ttl,
        on_progress=on_progress,
        progress_source="nexus",
    )

    if limit is not None or scan_limit is not None:
        for page_number, page in enumerate(
            client.iter_asset_pages(repository),
            start=1,
        ):
            for asset in page:
                selector.add(asset)
                if selector.limit_reached:
                    break
            if page_number == 1 or page_number % 10 == 0:
                logger.info(
                    "Listed %d assets (page %d)…",
                    selector.total,
                    page_number,
                )
            selector.emit_progress(force=True)
            if selector.limit_reached:
                logger.info(
                    "Stopped Nexus listing after limit/scan_limit "
                    "(download_limit=%s scan_limit=%s, inspected=%d, "
                    "selected_mains=%d)",
                    limit,
                    scan_limit,
                    selector.total,
                    len(selector._mains),
                )
                break
        # Частичный результат нельзя сохранять как полный asset-list cache.
        return selector.finish(), selector.total, selector.stats

    def tracked_assets() -> Iterable[NexusAsset]:
        total = 0
        for page_number, page in enumerate(
            client.iter_asset_pages(repository),
            start=1,
        ):
            for asset in page:
                total += 1
                selector.add(asset)
                yield asset
            if page_number == 1 or page_number % 10 == 0:
                logger.info("Listed %d assets (page %d)…", total, page_number)
            selector.emit_progress(force=True)

    stream = iter(tracked_assets())
    if ttl > 0:
        save_cached_assets(
            settings.nexus_cache_dir,
            settings.nexus_url,
            repository,
            stream,
        )
    # Если запись кэша оборвалась из-за I/O ошибки, дочитать Nexus всё равно надо.
    for _asset in stream:
        pass
    return selector.finish(), selector.total, selector.stats


def _select_assets(
    assets: Iterable[NexusAsset],
    *,
    path_prefix: str | Sequence[str] | None,
    exclude_prefix: str | Sequence[str] | None = None,
    limit: int | None,
    scan_limit: int | None = None,
    settings: Settings | None = None,
    client: NexusClient | None = None,
    scanners: Sequence[str] | None = None,
    scanner_versions: Mapping[str, str | None] | None = None,
    use_checkpoints: bool = True,
    ignore_checkpoint_ttl: bool = False,
    on_progress: SelectionProgressCallback | None = None,
    progress_source: str = "nexus",
) -> tuple[list[NexusAsset], int, AssetSelectionStats]:
    selector = _AssetSelector(
        path_prefix=path_prefix,
        exclude_prefix=exclude_prefix,
        limit=limit,
        scan_limit=scan_limit,
        settings=settings,
        client=client,
        scanners=scanners,
        scanner_versions=scanner_versions,
        use_checkpoints=use_checkpoints,
        ignore_checkpoint_ttl=ignore_checkpoint_ttl,
        on_progress=on_progress,
        progress_source=progress_source,
    )
    for asset in assets:
        selector.add(asset)
        if selector.limit_reached:
            break
    return selector.finish(), selector.total, selector.stats


class _AssetSelector:
    def __init__(
        self,
        *,
        path_prefix: str | Sequence[str] | None,
        exclude_prefix: str | Sequence[str] | None = None,
        limit: int | None,
        scan_limit: int | None = None,
        settings: Settings | None = None,
        client: NexusClient | None = None,
        scanners: Sequence[str] | None = None,
        scanner_versions: Mapping[str, str | None] | None = None,
        use_checkpoints: bool = True,
        ignore_checkpoint_ttl: bool = False,
        on_progress: SelectionProgressCallback | None = None,
        progress_source: str = "nexus",
        progress_every: int = 50,
    ) -> None:
        self.prefixes = normalize_path_prefixes(path_prefix)
        self.excluded_prefixes = normalize_path_prefixes(exclude_prefix)
        self.limit = limit
        self.scan_limit = scan_limit
        self.total = 0
        self.stats = AssetSelectionStats()
        self._mains: list[NexusAsset] = []
        self._main_paths: set[str] = set()
        self._sidecars: dict[str, list[NexusAsset]] = {}
        self._settings = settings
        self._downloader = (
            Downloader(settings, client)
            if settings is not None and client is not None
            else None
        )
        self._scanners = list(scanners or ())
        self._scanner_versions = dict(scanner_versions or {})
        self._use_checkpoints = use_checkpoints
        self._ignore_checkpoint_ttl = ignore_checkpoint_ttl
        self._on_progress = on_progress
        self._progress_source = progress_source
        self._progress_every = max(1, progress_every)

    @property
    def limit_reached(self) -> bool:
        if self.limit is not None and self.stats.download_needed >= self.limit:
            return True
        if self.scan_limit is not None and len(self._mains) >= self.scan_limit:
            return True
        return False

    def emit_progress(self, *, force: bool = False) -> None:
        if self._on_progress is None:
            return
        if not force and self.total % self._progress_every != 0:
            return
        self._on_progress(self.total, self.stats, self._progress_source)

    def add(self, asset: NexusAsset) -> None:
        self.total += 1
        path = asset.path.replace("\\", "/").lstrip("/")
        if is_maven_repo_root_path(path):
            allowed = not path_is_excluded(path, self.excluded_prefixes)
        else:
            allowed = path_allowed_by_filters(
                path,
                prefixes=self.prefixes,
                excluded_prefixes=self.excluded_prefixes,
            )
        if not allowed:
            self.emit_progress()
            return
        main_path = main_asset_path_for_sidecar(path)
        if main_path is not None:
            self._sidecars.setdefault(main_path, []).append(asset)
            self.emit_progress()
            return
        # NuGet V3 registration/index и т.п. — не пакеты, в verify не берём.
        if looks_like_nuget_metadata_path(path) or not is_scan_package_asset(
            asset.format, path
        ):
            self.emit_progress()
            return
        if self.scan_limit is not None and len(self._mains) >= self.scan_limit:
            self.emit_progress()
            return
        if self._downloader is not None and self._settings is not None:
            inspection = self._downloader.inspect_asset(asset)
            if inspection.needs_download:
                if (
                    self.limit is not None
                    and self.stats.download_needed >= self.limit
                ):
                    self.emit_progress()
                    return
                self.stats.download_needed += 1
            elif self._use_checkpoints and inspection.local_path is not None:
                ck_scanners = checkpoint_scanners_for_asset(
                    self._scanners,
                    asset_fmt=asset.format,
                    asset_path=path,
                    local_path=inspection.local_path,
                )
                if checkpoint_is_valid(
                    settings=self._settings,
                    asset=asset,
                    local_path=inspection.local_path,
                    scanners=ck_scanners,
                    scanner_versions=self._scanner_versions,
                    ignore_ttl=self._ignore_checkpoint_ttl,
                ):
                    raw = load_pass_checkpoint(inspection.local_path)
                    if raw is not None:
                        self.stats.skipped_passes.append(
                            CheckpointSkip(
                                asset=asset,
                                local_path=inspection.local_path,
                                raw=raw,
                            )
                        )
                    self.stats.checkpoint_skipped += 1
                    self.emit_progress()
                    return
                self.stats.scan_only += 1
            else:
                self.stats.scan_only += 1
        elif self.limit is not None and len(self._mains) >= self.limit:
            # Без downloader ``limit`` трактуем как max mains (legacy).
            self.emit_progress()
            return
        self._mains.append(asset)
        self._main_paths.add(path)
        self.emit_progress()

    def finish(self) -> list[NexusAsset]:
        self.emit_progress(force=True)
        selected = list(self._mains)
        for main_path in self._main_paths:
            selected.extend(self._sidecars.get(main_path, ()))
        return selected
