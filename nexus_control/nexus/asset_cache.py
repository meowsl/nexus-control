"""Дисковый кэш списков артефактов Nexus (ускорение повторного открытия)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from nexus_control.models import NexusAsset
from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

_CACHE_VERSION = 1
_SAFE_REPO = re.compile(r"[^\w.\-]+", re.UNICODE)
_ASSETS_MARKER = '"assets":['
_ASSETS_PATTERN = re.compile(r'"assets"\s*:\s*\[')


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
    allow_stale: bool = False,
) -> tuple[list[NexusAsset], float] | None:
    """Загрузить кэш списка ассетов.

    Возвращает ``(assets, age_seconds)`` или ``None``.

    ``ttl_seconds <= 0`` — кэш выключен.
    ``allow_stale=False`` — только если возраст ≤ ``ttl_seconds``.
    ``allow_stale=True`` — любой возраст (для мгновенного открытия + фон-обновление).
    """
    if ttl_seconds <= 0:
        return None
    cached = iter_cached_assets(
        cache_dir,
        nexus_url,
        repository,
        ttl_seconds=ttl_seconds,
        allow_stale=allow_stale,
    )
    if cached is None:
        return None
    items, age = cached
    return list(items), age


def iter_cached_assets(
    cache_dir: Path,
    nexus_url: str,
    repository: str,
    *,
    ttl_seconds: int,
    allow_stale: bool = False,
) -> tuple[Iterator[NexusAsset], float] | None:
    """Потоково читать ассеты из JSON-кэша, не загружая весь массив в RAM."""
    if ttl_seconds <= 0:
        return None
    path = asset_list_cache_path(cache_dir, nexus_url, repository)
    header = _read_cache_header(path)
    if header is None or header.get("version") != _CACHE_VERSION:
        return None
    if str(header.get("nexus_url") or "") != nexus_url.strip():
        return None
    if str(header.get("repository") or "") != repository:
        return None
    try:
        fetched_at = float(header.get("fetched_at") or 0)
    except (TypeError, ValueError):
        return None
    age = time.time() - fetched_at
    if age < 0 or (not allow_stale and age > ttl_seconds):
        return None
    return _iter_cache_file_assets(path), age


def save_cached_assets(
    cache_dir: Path,
    nexus_url: str,
    repository: str,
    assets: Iterable[NexusAsset],
) -> Path | None:
    """Сохранить список артефактов на диск. При ошибке — ``None``."""
    path = asset_list_cache_path(cache_dir, nexus_url, repository)
    try:
        ensure_dir(path.parent, mode=0o700)
        header = {
            "version": _CACHE_VERSION,
            "nexus_url": nexus_url.strip(),
            "repository": repository,
            "fetched_at": time.time(),
        }
        tmp = path.with_suffix(".tmp")
        encoded_header = json.dumps(
            header,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write(encoded_header[:-1])
            fh.write(f",{_ASSETS_MARKER}")
            first = True
            for asset in assets:
                if not first:
                    fh.write(",")
                json.dump(
                    asset_to_cache_dict(asset),
                    fh,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                first = False
            fh.write("]}")
        tmp.replace(path)
        return path
    except OSError as exc:
        logger.warning("Failed to write asset list cache (%s): %s", path, exc)
        return None


def _read_cache_header(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            prefix = ""
            match = None
            while match is None:
                chunk = fh.read(4096)
                if not chunk:
                    return None
                prefix += chunk
                match = _ASSETS_PATTERN.search(prefix)
                if len(prefix) > 1024 * 1024:
                    return None
        before = prefix[: match.start()]
        header = json.loads(before + '"assets":[]}')
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        logger.warning("Asset list cache unreadable (%s): %s", path, exc)
        return None
    return header if isinstance(header, dict) else None


def _iter_cache_file_assets(path: Path) -> Iterator[NexusAsset]:
    decoder = json.JSONDecoder()
    try:
        with path.open("r", encoding="utf-8") as fh:
            buffer = ""
            match = None
            while match is None:
                chunk = fh.read(64 * 1024)
                if not chunk:
                    return
                buffer += chunk
                match = _ASSETS_PATTERN.search(buffer)
            assets_start = match.end()
            buffer = buffer[assets_start:]

            while True:
                buffer = buffer.lstrip(" \t\r\n,")
                if buffer.startswith("]"):
                    return
                try:
                    item, end = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    chunk = fh.read(64 * 1024)
                    if not chunk:
                        logger.warning("Asset list cache truncated: %s", path)
                        return
                    buffer += chunk
                    continue
                buffer = buffer[end:]
                if isinstance(item, dict):
                    asset = asset_from_cache_dict(item)
                    if asset is not None:
                        yield asset
    except (OSError, UnicodeError) as exc:
        logger.warning("Asset list cache unreadable (%s): %s", path, exc)
