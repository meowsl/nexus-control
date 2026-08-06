"""Имена целевых репозиториев и skip неизменённых remote-ассетов."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_control.models import NexusAsset
from nexus_control.services.verified_uploader import (
    index_remote_assets,
    normalize_upload_repo_name,
    should_skip_unchanged_upload,
    verified_repo_name,
)
from nexus_control.utils.hashing import hash_file
from nexus_control.utils.safe_path import UnsafePathError


def test_verified_repo_name_default() -> None:
    assert verified_repo_name("test-maven") == "test-maven-verified"
    assert verified_repo_name("my/repo") == "my_repo-verified"


def test_normalize_upload_repo_name_custom() -> None:
    assert normalize_upload_repo_name("  my-custom-verified  ") == "my-custom-verified"
    assert normalize_upload_repo_name("acme/prod verified!") == "acme_prod_verified"


def test_normalize_upload_repo_name_rejects_empty() -> None:
    with pytest.raises(UnsafePathError):
        normalize_upload_repo_name("...")


def test_index_remote_assets_normalizes_path() -> None:
    assets = [
        NexusAsset(
            id="1",
            path="/pkg/a.jar",
            download_url=None,
            repository="r",
            checksum={"sha256": "abc"},
            file_size=10,
        ),
        NexusAsset(
            id="2",
            path="pkg/b.jar",
            download_url=None,
            repository="r",
        ),
    ]
    indexed = index_remote_assets(assets)
    assert set(indexed) == {"pkg/a.jar", "pkg/b.jar"}
    assert indexed["pkg/a.jar"].checksum["sha256"] == "abc"


def test_should_skip_unchanged_upload(tmp_path: Path) -> None:
    local = tmp_path / "a.jar"
    local.write_bytes(b"hello")
    digest = hash_file(local, "sha256")

    assert should_skip_unchanged_upload(local, None) is False

    same = NexusAsset(
        id="1",
        path="a.jar",
        download_url=None,
        repository="r",
        checksum={"sha256": digest},
        file_size=5,
    )
    assert should_skip_unchanged_upload(local, same) is True

    different = NexusAsset(
        id="2",
        path="a.jar",
        download_url=None,
        repository="r",
        checksum={"sha256": "0" * 64},
    )
    assert should_skip_unchanged_upload(local, different) is False

    no_data = NexusAsset(
        id="3",
        path="a.jar",
        download_url=None,
        repository="r",
    )
    # Недостаточно данных → не skip (безопаснее перезалить).
    assert should_skip_unchanged_upload(local, no_data) is False
