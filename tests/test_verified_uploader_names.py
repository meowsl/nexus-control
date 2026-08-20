"""Имена целевых репозиториев и skip неизменённых remote-ассетов."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    NexusAsset,
    PipelineSummary,
    ScanResult,
    ScanStatus,
    Verdict,
    VerifyResult,
)
from nexus_control.services.verified_uploader import (
    collect_upload_items,
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


def _result(
    path: str,
    local: Path,
    *,
    verdict: Verdict,
    copied: bool = True,
) -> AssetPipelineResult:
    status = ScanStatus.SUCCESS if verdict == Verdict.PASS else ScanStatus.SKIPPED
    return AssetPipelineResult(
        asset_path=path,
        kind=AssetKind.FILE,
        download=DownloadResult(status=DownloadStatus.SUCCESS, local_path=local),
        scans={
            "grype": ScanResult(status=status, verdict=verdict, scanner="grype"),
        },
        verify=VerifyResult(copied=copied, verified_path=local),
    )


def test_collect_upload_items_includes_skipped_sidecars(tmp_path: Path) -> None:
    jar = tmp_path / "jdbc-2.0.1.jar"
    sha1 = tmp_path / "jdbc-2.0.1.jar.sha1"
    md5 = tmp_path / "jdbc-2.0.1.jar.md5"
    jar.write_bytes(b"jar")
    sha1.write_text("deadbeef", encoding="utf-8")
    md5.write_text("cafebabe", encoding="utf-8")
    fail_jar = tmp_path / "bad.jar"
    fail_sha1 = tmp_path / "bad.jar.sha1"
    fail_jar.write_bytes(b"bad")
    fail_sha1.write_text("ffff", encoding="utf-8")

    summary = PipelineSummary(
        repository="maven-hosted",
        results=[
            _result("cib/jdbc/2.0.1/jdbc-2.0.1.jar", jar, verdict=Verdict.PASS),
            _result(
                "cib/jdbc/2.0.1/jdbc-2.0.1.jar.sha1",
                sha1,
                verdict=Verdict.SKIPPED,
            ),
            _result("cib/jdbc/2.0.1/bad.jar", fail_jar, verdict=Verdict.FAIL),
            _result(
                "cib/jdbc/2.0.1/bad.jar.sha1",
                fail_sha1,
                verdict=Verdict.SKIPPED,
            ),
        ],
    )
    # FAIL sidecar даже с локальной копией не заливаем: main не PASS.
    summary.results[2].verify = VerifyResult(copied=False, verified_path=fail_jar)
    summary.results[3].verify = VerifyResult(copied=True, verified_path=fail_sha1)

    paths = [p for p, _local in collect_upload_items(summary)]
    assert "cib/jdbc/2.0.1/jdbc-2.0.1.jar" in paths
    assert "cib/jdbc/2.0.1/jdbc-2.0.1.jar.sha1" in paths
    assert "cib/jdbc/2.0.1/jdbc-2.0.1.jar.md5" in paths
    assert "cib/jdbc/2.0.1/bad.jar" not in paths
    assert "cib/jdbc/2.0.1/bad.jar.sha1" not in paths
    assert len(paths) == len(set(paths))
