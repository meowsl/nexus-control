"""Модульные тесты вспомогательных функций безопасных путей."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_tui.utils.safe_path import (
    UnsafePathError,
    asset_download_path,
    normalize_asset_path,
    safe_join,
    sanitize_filename,
    sanitize_repo_name,
)


def test_normal_paths_allowed(tmp_path: Path) -> None:
    p = normalize_asset_path("com/example/app-1.0.jar")
    assert p.parts == ("com", "example", "app-1.0.jar")
    dest = asset_download_path(tmp_path, "my-repo", "com/example/app-1.0.jar")
    assert dest.is_relative_to(tmp_path.resolve())
    assert dest.name == "app-1.0.jar"


def test_path_traversal_blocked() -> None:
    with pytest.raises(UnsafePathError):
        normalize_asset_path("../etc/passwd")
    with pytest.raises(UnsafePathError):
        normalize_asset_path("foo/../../etc/passwd")


def test_absolute_paths_blocked() -> None:
    with pytest.raises(UnsafePathError):
        normalize_asset_path("/etc/passwd")
    with pytest.raises(UnsafePathError):
        normalize_asset_path("C:/Windows/system32")


def test_safe_join_escape_blocked(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, "..", "outside.txt")


def test_sanitize_repo_and_filename() -> None:
    assert sanitize_repo_name("my/repo:name") == "my_repo_name"
    assert sanitize_filename("1.2.3:latest") == "1.2.3_latest"
    with pytest.raises(UnsafePathError):
        sanitize_repo_name("..")
    with pytest.raises(UnsafePathError):
        sanitize_filename("")
