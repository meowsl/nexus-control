"""Tests for paginated asset listing progress callback."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from nexus_control.models import NexusAsset
from nexus_control.nexus.client import NexusClient


def _page(items: list[dict[str, Any]], token: str | None = None) -> dict[str, Any]:
    return {"items": items, "continuationToken": token}


def _item(path: str) -> dict[str, Any]:
    return {
        "id": path,
        "path": path,
        "repository": "raw",
        "downloadUrl": f"http://n/repository/raw/{path}",
    }


def test_list_assets_calls_on_page() -> None:
    client = NexusClient.__new__(NexusClient)
    pages = [
        _page([_item("a"), _item("b")], "t1"),
        _page([_item("c")], None),
    ]
    client._request_json = MagicMock(side_effect=pages)  # type: ignore[method-assign]

    seen: list[tuple[int, int]] = []

    def on_page(page: int, total: int) -> None:
        seen.append((page, total))

    assets = NexusClient.list_assets(client, "raw", on_page=on_page)
    assert [a.path for a in assets] == ["a", "b", "c"]
    assert seen == [(1, 2), (2, 3)]
    assert all(isinstance(a, NexusAsset) for a in assets)
