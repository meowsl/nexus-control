"""Разбор списка артефактов и вспомогательные функции пагинации."""

from __future__ import annotations

from typing import Any

from nexus_tui.models import NexusAsset


def parse_asset(item: dict[str, Any]) -> NexusAsset | None:
    """Разобрать один объект артефакта из API assets Nexus."""
    path = str(item.get("path") or "").strip()
    repository = str(item.get("repository") or "").strip()
    asset_id = str(item.get("id") or path)
    if not path or not repository:
        return None

    checksum_raw = item.get("checksum") or {}
    checksum: dict[str, str] = {}
    if isinstance(checksum_raw, dict):
        checksum = {str(k): str(v) for k, v in checksum_raw.items() if v is not None}

    file_size = item.get("fileSize")
    if file_size is not None:
        try:
            file_size = int(file_size)
        except (TypeError, ValueError):
            file_size = None

    return NexusAsset(
        id=asset_id,
        path=path.lstrip("/") if path.startswith("/") else path,
        download_url=item.get("downloadUrl"),
        repository=repository,
        format=item.get("format"),
        content_type=item.get("contentType"),
        last_modified=item.get("lastModified"),
        file_size=file_size,
        checksum=checksum,
        uploader=item.get("uploader"),
        blob_created=item.get("blobCreated"),
    )


def parse_assets_page(data: Any) -> tuple[list[NexusAsset], str | None]:
    """Разобрать одну страницу ``GET /assets``.

    Возвращает ``(assets, continuation_token)``. Token равен ``None``, когда данные закончились.
    """
    if data is None:
        return [], None
    if not isinstance(data, dict):
        # Некоторые прокси могут вернуть голый список.
        if isinstance(data, list):
            assets = [a for a in (parse_asset(i) for i in data if isinstance(i, dict)) if a]
            return assets, None
        raise ValueError("Unexpected assets response shape")

    items = data.get("items") or []
    assets: list[NexusAsset] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        asset = parse_asset(item)
        if asset is not None:
            assets.append(asset)

    token = data.get("continuationToken")
    if token is None or token == "":
        return assets, None
    return assets, str(token)
