"""Tests for scan ignore rules (checksum / signature sidecars)."""

from __future__ import annotations

from pathlib import Path

from nexus_control.services.scan_common import (
    is_scan_ignored_path,
    iter_local_companion_sidecars,
    main_asset_path_for_sidecar,
)


def test_scan_ignored_checksum_and_signature_suffixes() -> None:
    assert is_scan_ignored_path("org/foo/bar/1.0/bar-1.0.jar.md5")
    assert is_scan_ignored_path("org/foo/bar/1.0/bar-1.0.jar.sha1")
    assert is_scan_ignored_path("a/b/c.sha256")
    assert is_scan_ignored_path("a/b/c.SHA512")
    assert is_scan_ignored_path("pkg-1.0.jar.asc")


def test_scan_not_ignored_real_artifacts() -> None:
    assert not is_scan_ignored_path("org/foo/bar/1.0/bar-1.0.jar")
    assert not is_scan_ignored_path("org/foo/bar/1.0/bar-1.0.pom")
    assert not is_scan_ignored_path("org/foo/bar/1.0/bar-1.0.zip")
    assert not is_scan_ignored_path("axios/-/axios-1.0.0.tgz")
    assert not is_scan_ignored_path("images/latest")


def test_main_asset_path_for_sidecar() -> None:
    assert (
        main_asset_path_for_sidecar("org/foo/bar/1.0/bar-1.0.jar.md5")
        == "org/foo/bar/1.0/bar-1.0.jar"
    )
    assert main_asset_path_for_sidecar("org/foo/bar/1.0/bar-1.0.jar") is None


def test_iter_local_companion_sidecars(tmp_path: Path) -> None:
    jar = tmp_path / "lib.jar"
    jar.write_bytes(b"jar")
    md5 = tmp_path / "lib.jar.md5"
    md5.write_text("abc", encoding="utf-8")
    (tmp_path / "lib.jar.sha1").write_text("def", encoding="utf-8")
    (tmp_path / "other.jar.md5").write_text("x", encoding="utf-8")

    found = {p.name for p in iter_local_companion_sidecars(jar)}
    assert found == {"lib.jar.md5", "lib.jar.sha1"}
