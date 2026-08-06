"""Tests for on-disk Nexus asset list cache."""

from __future__ import annotations

import time
from pathlib import Path

from nexus_control.models import NexusAsset
from nexus_control.nexus.asset_cache import (
    asset_list_cache_path,
    load_cached_assets,
    save_cached_assets,
)


def _asset(path: str = "a/b.jar") -> NexusAsset:
    return NexusAsset(
        id=f"id-{path}",
        path=path,
        download_url=f"http://nexus/repository/raw/{path}",
        repository="raw",
        format="raw",
        content_type="application/java-archive",
        last_modified="2024-01-01T00:00:00.000+00:00",
        file_size=12,
        checksum={"sha1": "abc"},
    )


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    assets = [_asset("one.jar"), _asset("two/three.jar")]
    path = save_cached_assets(tmp_path, "http://nexus:8081", "raw", assets)
    assert path is not None
    assert path.is_file()

    loaded = load_cached_assets(
        tmp_path, "http://nexus:8081", "raw", ttl_seconds=300
    )
    assert loaded is not None
    got, age = loaded
    assert age < 5
    assert len(got) == 2
    assert got[0].path == "one.jar"
    assert got[0].checksum == {"sha1": "abc"}
    assert got[1].path == "two/three.jar"


def test_ttl_expired(tmp_path: Path) -> None:
    save_cached_assets(tmp_path, "http://nexus", "r", [_asset()])
    path = asset_list_cache_path(tmp_path, "http://nexus", "r")
    # Backdate fetched_at via rewriting JSON would be heavy; use ttl=0 disable instead
    assert load_cached_assets(tmp_path, "http://nexus", "r", ttl_seconds=0) is None

    # Force stale by rewriting fetched_at
    text = path.read_text(encoding="utf-8")
    import json

    data = json.loads(text)
    data["fetched_at"] = time.time() - 10_000
    path.write_text(json.dumps(data), encoding="utf-8")
    assert load_cached_assets(tmp_path, "http://nexus", "r", ttl_seconds=60) is None
    stale = load_cached_assets(
        tmp_path, "http://nexus", "r", ttl_seconds=60, allow_stale=True
    )
    assert stale is not None
    got, age = stale
    assert len(got) == 1
    assert age > 60


def test_wrong_url_or_repo_misses(tmp_path: Path) -> None:
    save_cached_assets(tmp_path, "http://a", "repo", [_asset()])
    assert load_cached_assets(tmp_path, "http://b", "repo", ttl_seconds=300) is None
    assert load_cached_assets(tmp_path, "http://a", "other", ttl_seconds=300) is None


def test_cache_paths_differ_by_url(tmp_path: Path) -> None:
    p1 = asset_list_cache_path(tmp_path, "http://a", "same")
    p2 = asset_list_cache_path(tmp_path, "http://b", "same")
    assert p1 != p2
