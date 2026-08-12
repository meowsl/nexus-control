"""verified PASS placement: hardlink (auto) vs full copy."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from nexus_control.config import Settings
from nexus_control.services.verifier import Verifier
from nexus_control.utils.fs import link_or_copy_file


def test_link_or_copy_auto_hardlinks_same_fs(tmp_path: Path) -> None:
    src = tmp_path / "dl" / "a.jar"
    dst = tmp_path / "vf" / "a.jar"
    src.parent.mkdir()
    src.write_bytes(b"payload-bytes")
    placed, skipped = link_or_copy_file(src, dst, mode="auto")
    assert placed and not skipped
    assert dst.read_bytes() == b"payload-bytes"
    assert os.path.samefile(src, dst)
    assert src.stat().st_nlink >= 2


def test_link_or_copy_mode_copy_duplicates(tmp_path: Path) -> None:
    src = tmp_path / "dl" / "a.jar"
    dst = tmp_path / "vf" / "a.jar"
    src.parent.mkdir()
    src.write_bytes(b"x")
    placed, skipped = link_or_copy_file(src, dst, mode="copy")
    assert placed and not skipped
    assert dst.read_bytes() == b"x"
    assert not os.path.samefile(src, dst)


def test_link_or_copy_auto_falls_back_on_exdev(tmp_path: Path) -> None:
    src = tmp_path / "dl" / "a.jar"
    dst = tmp_path / "vf" / "a.jar"
    src.parent.mkdir()
    src.write_bytes(b"fallback")

    def _boom(source: str, link: str) -> None:
        raise OSError(18, "Invalid cross-device link")  # EXDEV

    with patch("os.link", side_effect=_boom):
        placed, skipped = link_or_copy_file(src, dst, mode="auto")
    assert placed and not skipped
    assert dst.read_bytes() == b"fallback"
    assert not os.path.samefile(src, dst)


def test_link_or_copy_skip_existing(tmp_path: Path) -> None:
    src = tmp_path / "a.jar"
    dst = tmp_path / "b.jar"
    src.write_bytes(b"one")
    dst.write_bytes(b"other")
    placed, skipped = link_or_copy_file(src, dst, overwrite=False, mode="auto")
    assert not placed and skipped
    assert dst.read_bytes() == b"other"


def test_link_or_copy_overwrite_replaces_with_hardlink(tmp_path: Path) -> None:
    src = tmp_path / "a.jar"
    dst = tmp_path / "b.jar"
    src.write_bytes(b"new")
    dst.write_bytes(b"old")
    placed, skipped = link_or_copy_file(src, dst, overwrite=True, mode="auto")
    assert placed and not skipped
    assert os.path.samefile(src, dst)
    assert dst.read_bytes() == b"new"


def test_replace_download_keeps_verified_hardlink_content(tmp_path: Path) -> None:
    """Downloader .partial+replace must not mutate already-linked verified."""
    src = tmp_path / "dl" / "a.jar"
    dst = tmp_path / "vf" / "a.jar"
    src.parent.mkdir()
    src.write_bytes(b"v1")
    link_or_copy_file(src, dst, mode="auto")
    assert os.path.samefile(src, dst)

    partial = src.with_suffix(src.suffix + ".partial")
    partial.write_bytes(b"v2-new-download")
    partial.replace(src)

    assert dst.read_bytes() == b"v1"
    assert src.read_bytes() == b"v2-new-download"
    assert not os.path.samefile(src, dst)


def test_verifier_copy_if_pass_uses_hardlink(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://nexus.test",
        download_root=tmp_path / "downloads",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        log_file=tmp_path / "logs" / "test.log",
        nexus_cache_dir=tmp_path / "cache",
        verified_link_mode="auto",
    )
    local = settings.download_root / "repo" / "com" / "acme" / "1.0" / "a.jar"
    local.parent.mkdir(parents=True)
    local.write_bytes(b"jar-bytes")
    result = Verifier(settings).copy_if_pass(
        repository="repo",
        asset_path="com/acme/1.0/a.jar",
        local_path=local,
    )
    assert result.error is None
    assert result.copied
    assert result.verified_path is not None
    assert os.path.samefile(local, result.verified_path)


def test_verifier_link_mode_copy(tmp_path: Path) -> None:
    settings = Settings(
        nexus_url="http://nexus.test",
        download_root=tmp_path / "downloads",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        log_file=tmp_path / "logs" / "test.log",
        nexus_cache_dir=tmp_path / "cache",
        verified_link_mode="copy",
    )
    local = settings.download_root / "repo" / "pkg.jar"
    local.parent.mkdir(parents=True)
    local.write_bytes(b"x")
    result = Verifier(settings).copy_if_pass(
        repository="repo",
        asset_path="pkg.jar",
        local_path=local,
    )
    assert result.copied and result.verified_path is not None
    assert not os.path.samefile(local, result.verified_path)


def test_settings_rejects_bad_link_mode(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="verified_link_mode"):
        Settings(
            nexus_url="http://nexus.test",
            download_root=tmp_path / "downloads",
            reports_root=tmp_path / "reports",
            verified_root=tmp_path / "verified",
            log_file=tmp_path / "logs" / "test.log",
            nexus_cache_dir=tmp_path / "cache",
            verified_link_mode="symlink",  # type: ignore[arg-type]
        )
