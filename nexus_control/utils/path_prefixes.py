"""Normalize asset path prefixes for verify / schedule filters."""

from __future__ import annotations

from collections.abc import Sequence


def normalize_path_prefixes(value: str | Sequence[str] | None) -> list[str]:
    """Strip, drop leading ``/``, dedupe (order preserved).

    Accepts a single string, a sequence of strings, or ``None``.
    """
    if value is None:
        return []
    if isinstance(value, str):
        items: list[str] = [value]
    else:
        items = [str(item) for item in value]

    out: list[str] = []
    seen: set[str] = set()
    for raw in items:
        prefix = raw.strip().lstrip("/")
        if not prefix or prefix in seen:
            continue
        seen.add(prefix)
        out.append(prefix)
    return out


def path_matches_prefixes(path: str, prefixes: Sequence[str]) -> bool:
    """True if ``path`` matches any prefix, or if ``prefixes`` is empty (no filter)."""
    if not prefixes:
        return True
    normalized = path.replace("\\", "/").lstrip("/")
    return any(normalized.startswith(prefix) for prefix in prefixes)


def format_path_prefixes(value: str | Sequence[str] | None) -> str | None:
    """Compact string for history / display (comma-joined), or None."""
    prefixes = normalize_path_prefixes(value)
    if not prefixes:
        return None
    return ",".join(prefixes)
