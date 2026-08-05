"""Вспомогательные функции разбора списка репозиториев."""

from __future__ import annotations

from typing import Any

from nexus_control.models import Repository


def parse_repositories(data: Any) -> list[Repository]:
    """Разобрать JSON Nexus ``GET /repositories`` в доменные модели."""
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array from /repositories")
    repos: list[Repository] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        repos.append(
            Repository(
                name=name,
                format=str(item.get("format") or "unknown"),
                type=str(item.get("type") or "unknown"),
                url=item.get("url"),
                attributes=dict(item.get("attributes") or {}),
            )
        )
    return repos
