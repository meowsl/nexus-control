"""Безопасное построение путей: предотвращение path traversal и выхода за абсолютный корень."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath


class UnsafePathError(ValueError):
    """Выбрасывается, когда путь отклонён по соображениям безопасности."""


# Имя листа для npm-метаданных, когда путь одновременно файл и префикс каталога
# (например ``lodash`` + ``lodash/-/lodash-4.17.15.tgz``).
ASSET_META_LEAF = "(metadata)"

# Символы, небезопасные или неудобные на распространённых ФС.
_UNSAFE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
_REPO_SAFE = re.compile(r"[^A-Za-z0-9._+-]+")


def resolve_storage_path(path: Path) -> Path:
    """Если ``path`` уже каталог — писать файл как ``path/(metadata)``.

    Нужно для npm/hosted, где metadata лежит на том же path, что и префикс tarball.
    """
    try:
        if path.exists() and path.is_dir():
            return path / ASSET_META_LEAF
    except OSError:
        pass
    return path


def sanitize_repo_name(name: str) -> str:
    """Сделать имя репозитория безопасным для использования как компонента каталога."""
    cleaned = _REPO_SAFE.sub("_", name.strip())
    cleaned = cleaned.strip("._")
    if not cleaned or cleaned in {".", ".."}:
        raise UnsafePathError(f"Invalid repository name: {name!r}")
    return cleaned[:200]


def sanitize_filename(name: str) -> str:
    """Санитизировать один компонент имени файла / тега для локальной ФС."""
    cleaned = _UNSAFE_CHARS.sub("_", name)
    cleaned = cleaned.replace("/", "_").replace("\\", "_").replace(" ", "_")
    cleaned = cleaned.strip(" .")
    if not cleaned or cleaned in {".", ".."}:
        raise UnsafePathError(f"Invalid filename: {name!r}")
    return cleaned[:200]


def normalize_asset_path(asset_path: str) -> PurePosixPath:
    """Нормализовать путь артефакта Nexus в относительный POSIX-путь.

    Отклоняет абсолютные пути, компоненты ``..`` и пустые пути.
    """
    if asset_path is None:
        raise UnsafePathError("Asset path is empty")

    raw = str(asset_path).strip().replace("\\", "/")
    if not raw:
        raise UnsafePathError("Asset path is empty")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise UnsafePathError(f"Absolute asset paths are not allowed: {asset_path!r}")
    if "\x00" in raw:
        raise UnsafePathError("Null byte in asset path")

    posix = PurePosixPath(raw)
    parts: list[str] = []
    for part in posix.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            raise UnsafePathError(f"Path traversal detected: {asset_path!r}")
        if _UNSAFE_CHARS.search(part):
            raise UnsafePathError(f"Unsafe characters in path component: {part!r}")
        parts.append(part)

    if not parts:
        raise UnsafePathError(f"Asset path resolved empty: {asset_path!r}")

    return PurePosixPath(*parts)


def safe_join(root: Path, *relative_parts: str) -> Path:
    """Объединить ``relative_parts`` под ``root`` и убедиться, что результат остаётся внутри root."""
    root_resolved = root.expanduser().resolve()
    candidate = root_resolved
    for part in relative_parts:
        # Разрешить вложенные относительные сегменты через normalize
        norm = normalize_asset_path(part) if ("/" in part or "\\" in part) else None
        if norm is not None:
            candidate = candidate.joinpath(*norm.parts)
        else:
            if part in {"", ".", ".."} or _UNSAFE_CHARS.search(part) or "/" in part or "\\" in part:
                # Проверка одного компонента
                if part in {"", ".", ".."}:
                    raise UnsafePathError(f"Invalid path component: {part!r}")
                if "/" in part or "\\" in part:
                    raise UnsafePathError(f"Unexpected separators in component: {part!r}")
                if _UNSAFE_CHARS.search(part):
                    raise UnsafePathError(f"Unsafe characters in component: {part!r}")
            candidate = candidate / part

    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise UnsafePathError(
            f"Resolved path escapes root: {resolved} not under {root_resolved}"
        ) from exc
    return resolved


def asset_download_path(download_root: Path, repository: str, asset_path: str) -> Path:
    """Безопасно построить ``DOWNLOAD_ROOT/<repo>/<asset_path>``."""
    repo = sanitize_repo_name(repository)
    norm = normalize_asset_path(asset_path)
    return safe_join(download_root, repo, *norm.parts)


def asset_verified_path(verified_root: Path, repository: str, asset_path: str) -> Path:
    """Безопасно построить ``VERIFIED_ROOT/<repo>-verified/<asset_path>``."""
    repo_dir = f"{sanitize_repo_name(repository)}-verified"
    norm = normalize_asset_path(asset_path)
    return safe_join(verified_root, repo_dir, *norm.parts)


def report_paths(reports_root: Path, repository: str, asset_path: str) -> tuple[Path, Path]:
    """Вернуть пути ``(json_report, text_report)`` для артефакта."""
    repo = sanitize_repo_name(repository)
    norm = normalize_asset_path(asset_path)
    # Свести путь с __, чтобы избежать глубоких деревьев отчётов, сохраняя уникальность.
    flat = "__".join(norm.parts)
    flat = sanitize_filename(flat)
    base = safe_join(reports_root, repo, flat)
    return Path(str(base) + ".grype.json"), Path(str(base) + ".grype.txt")


def docker_archive_path(download_root: Path, repository: str, tag: str) -> Path:
    """Построить ``DOWNLOAD_ROOT/<repo>/images/<tag-safe>.tar``."""
    safe_tag = sanitize_filename(tag.replace(":", "_").replace("/", "_"))
    return asset_download_path(download_root, repository, f"images/{safe_tag}.tar")
