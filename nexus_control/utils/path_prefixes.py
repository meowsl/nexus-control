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


def path_is_excluded(path: str, excluded_prefixes: Sequence[str]) -> bool:
    """True if ``path`` starts with any exclude prefix. Empty list → nothing excluded."""
    if not excluded_prefixes:
        return False
    return path_matches_prefixes(path, excluded_prefixes)


def path_allowed_by_filters(
    path: str,
    *,
    prefixes: Sequence[str] | None = None,
    excluded_prefixes: Sequence[str] | None = None,
) -> bool:
    """Include prefixes (OR, empty=all) then exclude prefixes (OR, empty=none)."""
    if prefixes and not path_matches_prefixes(path, prefixes):
        return False
    if path_is_excluded(path, excluded_prefixes or ()):
        return False
    return True


def format_path_prefixes(value: str | Sequence[str] | None) -> str | None:
    """Compact string for history / display (comma-joined), or None."""
    prefixes = normalize_path_prefixes(value)
    if not prefixes:
        return None
    return ",".join(prefixes)


def format_path_filters(
    prefixes: str | Sequence[str] | None,
    excluded_prefixes: str | Sequence[str] | None = None,
) -> str | None:
    """History/display string for include + exclude filters."""
    inc = format_path_prefixes(prefixes)
    exc = format_path_prefixes(excluded_prefixes)
    if not inc and not exc:
        return None
    if not exc:
        return inc
    if not inc:
        return f"exclude:{exc}"
    return f"{inc} exclude:{exc}"
