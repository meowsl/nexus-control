"""Дисковый кэш списков артефактов Nexus (ускорение повторного открытия)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from nexus_control.models import NexusAsset
from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

_CACHE_VERSION = 1
_SAFE_REPO = re.compile(r"[^\w.\-]+", re.UNICODE)


def asset_list_cache_path(cache_dir: Path, nexus_url: str, repository: str) -> Path:
    """Путь файла кэша для пары (nexus_url, repository)."""
    digest = hashlib.sha256(f"{nexus_url.strip()}\n{repository}".encode()).hexdigest()[:16]
    safe = _SAFE_REPO.sub("_", repository).strip("._")[:64] or "repo"
    return cache_dir / "asset-lists" / f"{safe}-{digest}.json"


def asset_to_cache_dict(asset: NexusAsset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "path": asset.path,
        "downloadUrl": asset.download_url,
        "repository": asset.repository,
        "format": asset.format,
        "contentType": asset.content_type,
        "lastModified": asset.last_modified,
        "fileSize": asset.file_size,
        "checksum": dict(asset.checksum),
        "uploader": asset.uploader,
        "blobCreated": asset.blob_created,
    }


def asset_from_cache_dict(data: dict[str, Any]) -> NexusAsset | None:
    """Восстановить артефакт из кэша (тот же shape, что у API)."""
    from nexus_control.nexus.assets import parse_asset

    return parse_asset(data)


def load_cached_assets(
    cache_dir: Path,
    nexus_url: str,
    repository: str,
    *,
    ttl_seconds: int,
) -> tuple[list[NexusAsset], float] | None:
    """Загрузить кэш, если он свежий.

    Возвращает ``(assets, age_seconds)`` или ``None``.
    ``ttl_seconds <= 0`` — кэш отключён.
    """
    if ttl_seconds <= 0:
        return None
    path = asset_list_cache_path(cache_dir, nexus_url, repository)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Asset list cache unreadable (%s): %s", path, exc)
        return None
    if not isinstance(raw, dict) or raw.get("version") != _CACHE_VERSION:
        return None
    if str(raw.get("nexus_url") or "") != nexus_url.strip():
        return None
    if str(raw.get("repository") or "") != repository:
        return None
    try:
        fetched_at = float(raw.get("fetched_at") or 0)
    except (TypeError, ValueError):
        return None
    age = time.time() - fetched_at
    if age < 0 or age > ttl_seconds:
        return None
    items = raw.get("assets")
    if not isinstance(items, list):
        return None
    assets: list[NexusAsset] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        asset = asset_from_cache_dict(item)
        if asset is not None:
            assets.append(asset)
    return assets, age


def save_cached_assets(
    cache_dir: Path,
    nexus_url: str,
    repository: str,
    assets: list[NexusAsset],
) -> Path | None:
    """Сохранить список артефактов на диск. При ошибке — ``None``."""
    path = asset_list_cache_path(cache_dir, nexus_url, repository)
    try:
        ensure_dir(path.parent, mode=0o700)
        payload = {
            "version": _CACHE_VERSION,
            "nexus_url": nexus_url.strip(),
            "repository": repository,
            "fetched_at": time.time(),
            "assets": [asset_to_cache_dict(a) for a in assets],
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
        )
        tmp.replace(path)
        return path
    except OSError as exc:
        logger.warning("Failed to write asset list cache (%s): %s", path, exc)
        return None
