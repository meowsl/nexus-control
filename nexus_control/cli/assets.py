"""Helpers: list/filter assets for CLI verify."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from nexus_control.config import Settings
from nexus_control.models import NexusAsset, Repository
from nexus_control.nexus.asset_cache import (
    iter_cached_assets,
    load_cached_assets,
    save_cached_assets,
)
from nexus_control.nexus.client import NexusClient
from nexus_control.services.scan_common import main_asset_path_for_sidecar

logger = logging.getLogger(__name__)


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
    path_prefix: str | None = None,
    limit: int | None = None,
) -> list[NexusAsset]:
    """Отфильтровать ассеты для pipeline.

    Sidecar'ы (``.md5``/…) **оставляем** в списке — pipeline сам skip'ает scan
    и копирует их вместе с PASS. ``limit`` считает только non-sidecar.
    """
    selected, _total = _select_assets(
        assets,
        path_prefix=path_prefix,
        limit=limit,
    )
    return selected


def select_assets_for_cli(
    client: NexusClient,
    settings: Settings,
    repository: str,
    *,
    path_prefix: str | None = None,
    limit: int | None = None,
    refresh: bool = False,
) -> tuple[list[NexusAsset], int]:
    """Потоково выбрать pipeline-items и вернуть ``(items, total_listed)``.

    При чтении Nexus и дискового кэша полный список не материализуется. Sidecar
    сохраняются только для выбранных main-артефактов, поэтому качество verify
    не меняется.
    """
    ttl = settings.assets_cache_ttl
    if not refresh and ttl > 0:
        cached = iter_cached_assets(
            settings.nexus_cache_dir,
            settings.nexus_url,
            repository,
            ttl_seconds=ttl,
            allow_stale=True,
        )
        if cached is not None:
            stream, age = cached
            selected, total = _select_assets(
                stream,
                path_prefix=path_prefix,
                limit=limit,
            )
            logger.info(
                "Using streaming asset cache for %s (%d assets, age=%ds)",
                repository,
                total,
                int(age),
            )
            return selected, total

    logger.info("Streaming assets from Nexus for %s…", repository)
    selector = _AssetSelector(path_prefix=path_prefix, limit=limit)

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
    return selector.finish(), selector.total


def _select_assets(
    assets: Iterable[NexusAsset],
    *,
    path_prefix: str | None,
    limit: int | None,
) -> tuple[list[NexusAsset], int]:
    selector = _AssetSelector(path_prefix=path_prefix, limit=limit)
    for asset in assets:
        selector.add(asset)
    return selector.finish(), selector.total


class _AssetSelector:
    def __init__(self, *, path_prefix: str | None, limit: int | None) -> None:
        self.prefix = (path_prefix or "").strip().lstrip("/")
        self.limit = limit
        self.total = 0
        self._mains: list[NexusAsset] = []
        self._main_paths: set[str] = set()
        self._sidecars: dict[str, list[NexusAsset]] = {}

    def add(self, asset: NexusAsset) -> None:
        self.total += 1
        path = asset.path.replace("\\", "/").lstrip("/")
        if self.prefix and not path.startswith(self.prefix):
            return
        main_path = main_asset_path_for_sidecar(path)
        if main_path is not None:
            self._sidecars.setdefault(main_path, []).append(asset)
            return
        if self.limit is not None and len(self._mains) >= self.limit:
            return
        self._mains.append(asset)
        self._main_paths.add(path)

    def finish(self) -> list[NexusAsset]:
        selected = list(self._mains)
        for main_path in self._main_paths:
            selected.extend(self._sidecars.get(main_path, ()))
        return selected
