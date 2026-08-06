"""Tests for metadata-based fast skip of unchanged downloads."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from nexus_control.config import Settings
from nexus_control.models import DownloadStatus, NexusAsset
from nexus_control.services.downloader import Downloader
from nexus_control.utils.safe_path import asset_download_path


def test_unchanged_metadata_skips_without_rehash_or_rewrite(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "downloads",
    )
    asset = NexusAsset(
        id="a",
        path="pkg/a.jar",
        download_url="http://nexus/repository/repo/pkg/a.jar",
        repository="repo",
        format="maven2",
        last_modified="2026-08-06T12:00:00Z",
        file_size=7,
        checksum={"sha1": "1" * 40},
    )
    dest = asset_download_path(settings.download_root, "repo", asset.path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"content")

    downloader = Downloader(settings, MagicMock())
    meta = downloader._write_metadata(
        dest,
        repository="repo",
        asset_path=asset.path,
        download_url=asset.download_url,
        size=dest.stat().st_size,
        checksum=asset.checksum,
        source="nexus-rest",
        extra={"last_modified": asset.last_modified},
    )
    original_metadata = meta.read_text(encoding="utf-8")

    def unexpected_hash(*args, **kwargs):
        raise AssertionError("unchanged file must not be re-hashed")

    monkeypatch.setattr("nexus_control.utils.hashing.hash_file", unexpected_hash)
    result = downloader.download_asset(asset)

    assert result.status == DownloadStatus.SKIPPED_EXISTING
    assert meta.read_text(encoding="utf-8") == original_metadata


def test_legacy_metadata_is_upgraded_after_one_hash(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "downloads",
    )
    checksum = "1" * 40
    asset = NexusAsset(
        id="a",
        path="pkg/a.jar",
        download_url="http://nexus/repository/repo/pkg/a.jar",
        repository="repo",
        format="maven2",
        last_modified="2026-08-06T12:00:00Z",
        file_size=7,
        checksum={"sha1": checksum},
    )
    dest = asset_download_path(settings.download_root, "repo", asset.path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"content")
    meta = dest.parent / f"{dest.name}.metadata.json"
    meta.write_text(
        json.dumps(
            {
                "repository": "repo",
                "asset_path": asset.path,
                "size": 7,
                "checksum": asset.checksum,
                "last_modified": asset.last_modified,
            }
        ),
        encoding="utf-8",
    )
    hash_calls = 0

    def matching_hash(*args, **kwargs):
        nonlocal hash_calls
        hash_calls += 1
        return checksum

    monkeypatch.setattr("nexus_control.utils.hashing.hash_file", matching_hash)
    downloader = Downloader(settings, MagicMock())

    assert downloader.download_asset(asset).status == DownloadStatus.SKIPPED_EXISTING
    assert hash_calls == 1
    assert "local_mtime_ns" in json.loads(meta.read_text(encoding="utf-8"))

    assert downloader.download_asset(asset).status == DownloadStatus.SKIPPED_EXISTING
    assert hash_calls == 1
