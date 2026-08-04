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


def test_resolve_storage_path_when_dir(tmp_path: Path) -> None:
    from nexus_tui.utils.safe_path import ASSET_META_LEAF, resolve_storage_path

    pkg = tmp_path / "lodash"
    pkg.mkdir()
    assert resolve_storage_path(pkg) == pkg / ASSET_META_LEAF
    assert resolve_storage_path(tmp_path / "missing") == tmp_path / "missing"


def test_prepare_asset_destination_promotes_file(tmp_path: Path) -> None:
    from nexus_tui.utils.fs import prepare_asset_destination
    from nexus_tui.utils.safe_path import ASSET_META_LEAF

    # Сначала скачан npm metadata как файл `lodash`
    meta_file = tmp_path / "lodash"
    meta_file.write_text('{"name":"lodash"}', encoding="utf-8")
    sidecar = tmp_path / "lodash.metadata.json"
    sidecar.write_text("{}", encoding="utf-8")

    # Затем tarball требует каталог lodash/-/
    tarball = tmp_path / "lodash" / "-" / "lodash-4.17.15.tgz"
    dest = prepare_asset_destination(tarball)

    assert dest == tarball
    assert (tmp_path / "lodash").is_dir()
    assert (tmp_path / "lodash" / ASSET_META_LEAF).is_file()
    assert (tmp_path / "lodash" / ASSET_META_LEAF).read_text(encoding="utf-8") == (
        '{"name":"lodash"}'
    )
    assert (tmp_path / "lodash" / f"{ASSET_META_LEAF}.metadata.json").is_file()
    assert dest.parent.is_dir()
