"""Небольшие текстовые вспомогательные функции для UI и отчётов."""

from __future__ import annotations

from typing import Any


def human_size(num_bytes: int | None) -> str:
    """Форматировать размер в байтах для отображения."""
    if num_bytes is None:
        return "-"
    if num_bytes < 0:
        return "?"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def truncate(text: str, max_len: int = 80) -> str:
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def format_attrs(attrs: dict[str, Any] | None, limit: int = 3) -> str:
    if not attrs:
        return ""
    items = list(attrs.items())[:limit]
    return ", ".join(f"{k}={v}" for k, v in items)
