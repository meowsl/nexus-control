"""Имена целевых репозиториев и skip неизменённых remote-ассетов."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_control.config import Settings
from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    NexusAsset,
    PipelineSummary,
    Repository,
    ScanResult,
    ScanStatus,
    Verdict,
    VerifyResult,
)
from nexus_control.services.verified_uploader import (
    VerifiedUploader,
    collect_revoke_mains,
    collect_upload_items,
    expand_revoke_keys,
    index_remote_assets,
    is_shared_metadata_path,
    normalize_upload_repo_name,
    remote_assets_to_revoke,
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


def test_collect_revoke_mains_only_fail() -> None:
    jar = Path("/tmp/x.jar")
    summary = PipelineSummary(
        repository="maven-hosted",
        results=[
            _result("cib/jdbc/2.0.1/jdbc-2.0.1.jar", jar, verdict=Verdict.PASS),
            _result("cib/jdbc/2.0.1/bad.jar", jar, verdict=Verdict.FAIL),
            _result("cib/jdbc/2.0.1/oops.jar", jar, verdict=Verdict.ERROR),
            _result("cib/jdbc/2.0.1/bad.jar.sha1", jar, verdict=Verdict.FAIL),
            _result(
                "org/foo/maven-metadata.xml",
                jar,
                verdict=Verdict.FAIL,
            ),
        ],
    )
    mains = collect_revoke_mains(summary)
    assert mains == ["cib/jdbc/2.0.1/bad.jar"]
    extra = collect_revoke_mains(summary, extra_paths=["other/lib-1.0.jar"])
    assert extra == ["cib/jdbc/2.0.1/bad.jar", "other/lib-1.0.jar"]


def test_is_shared_metadata_path() -> None:
    assert is_shared_metadata_path("org/foo/maven-metadata.xml")
    assert is_shared_metadata_path("org/foo/maven-metadata.xml.sha1")
    assert is_shared_metadata_path("archetype-catalog.xml.md5")
    assert not is_shared_metadata_path("org/foo/1.0/foo-1.0.jar")


def test_expand_revoke_keys_includes_sidecars_and_nuget_variants() -> None:
    maven = expand_revoke_keys(
        ["cib/jdbc/2.0.1/jdbc-2.0.1.jar"],
        fmt="maven2",
    )
    assert "cib/jdbc/2.0.1/jdbc-2.0.1.jar" in maven
    assert "cib/jdbc/2.0.1/jdbc-2.0.1.jar.sha1" in maven
    assert "cib/jdbc/2.0.1/jdbc-2.0.1.jar.md5" in maven
    assert "org/foo/maven-metadata.xml" not in maven

    nuget = expand_revoke_keys(["NexusControl.Seed.Pkg003/1.0.3"], fmt="nuget")
    assert "NexusControl.Seed.Pkg003/1.0.3" in nuget
    assert (
        "NexusControl.Seed.Pkg003/1.0.3/"
        "NexusControl.Seed.Pkg003-1.0.3.nupkg"
    ) in nuget


def test_remote_assets_to_revoke_matches_sidecars() -> None:
    remote = index_remote_assets(
        [
            NexusAsset(
                id="jar",
                path="cib/jdbc/2.0.1/bad.jar",
                download_url=None,
                repository="v",
            ),
            NexusAsset(
                id="sha1",
                path="cib/jdbc/2.0.1/bad.jar.sha1",
                download_url=None,
                repository="v",
            ),
            NexusAsset(
                id="keep",
                path="cib/jdbc/2.0.1/good.jar",
                download_url=None,
                repository="v",
            ),
            NexusAsset(
                id="meta",
                path="cib/jdbc/maven-metadata.xml",
                download_url=None,
                repository="v",
            ),
        ]
    )
    keys = expand_revoke_keys(["cib/jdbc/2.0.1/bad.jar"], fmt="maven2")
    revoked = remote_assets_to_revoke(remote, keys)
    ids = {a.id for a in revoked}
    assert ids == {"jar", "sha1"}


class _FakeNexus:
    def __init__(self, tmp_path: Path, remote: list[NexusAsset]) -> None:
        self.settings = Settings(
            nexus_url="http://nexus.test",
            download_root=tmp_path / "dl",
            reports_root=tmp_path / "rp",
            verified_root=tmp_path / "verified",
            archive_root=tmp_path / "ar",
            log_file=tmp_path / "log.log",
            nexus_cache_dir=tmp_path / "cache",
        )
        self.remote = list(remote)
        self.deleted_ids: list[str] = []
        self.uploaded_paths: list[str] = []
        self.ensure_called = False
        self._source = Repository(
            name="maven-hosted", format="maven2", type="hosted", url=None
        )
        self._target = Repository(
            name="maven-hosted-verified", format="maven2", type="hosted", url=None
        )

    def get_repository(self, name: str) -> Repository | None:
        if name == "maven-hosted":
            return self._source
        if name == "maven-hosted-verified":
            return self._target
        return None

    def ensure_hosted(self, name: str, fmt: str) -> Repository:
        self.ensure_called = True
        return self._target

    def list_assets(self, repository: str) -> list[NexusAsset]:
        return list(self.remote)

    def delete_asset(self, asset_id: str) -> bool:
        self.deleted_ids.append(asset_id)
        self.remote = [a for a in self.remote if a.id != asset_id]
        return True

    def upload_asset(self, repository: str, fmt: str, path: str, local: Path) -> None:
        self.uploaded_paths.append(path)


def test_upload_revokes_fail_and_sidecars_even_without_pass(tmp_path: Path) -> None:
    verified = tmp_path / "verified" / "maven-hosted-verified" / "cib" / "jdbc" / "2.0.1"
    verified.mkdir(parents=True)
    bad = verified / "bad.jar"
    sha1 = verified / "bad.jar.sha1"
    keep = verified / "good.jar"
    bad.write_bytes(b"bad")
    sha1.write_text("ffff", encoding="utf-8")
    keep.write_bytes(b"good")

    remote = [
        NexusAsset(
            id="bad-id",
            path="cib/jdbc/2.0.1/bad.jar",
            download_url=None,
            repository="maven-hosted-verified",
        ),
        NexusAsset(
            id="sha-id",
            path="cib/jdbc/2.0.1/bad.jar.sha1",
            download_url=None,
            repository="maven-hosted-verified",
        ),
        NexusAsset(
            id="good-id",
            path="cib/jdbc/2.0.1/good.jar",
            download_url=None,
            repository="maven-hosted-verified",
        ),
        NexusAsset(
            id="meta-id",
            path="cib/jdbc/maven-metadata.xml",
            download_url=None,
            repository="maven-hosted-verified",
        ),
    ]
    client = _FakeNexus(tmp_path, remote)
    summary = PipelineSummary(
        repository="maven-hosted",
        results=[
            _result(
                "cib/jdbc/2.0.1/bad.jar",
                bad,
                verdict=Verdict.FAIL,
                copied=False,
            ),
        ],
    )
    summary.results[0].verify = VerifyResult(copied=False)

    up = VerifiedUploader(client).upload(summary)  # type: ignore[arg-type]
    assert sorted(client.deleted_ids) == ["bad-id", "sha-id"]
    assert client.uploaded_paths == []
    assert not client.ensure_called
    assert up.deleted == 2
    assert up.uploaded == 0
    assert up.failed == 0
    assert not bad.exists()
    assert not sha1.exists()
    assert keep.exists()


def test_upload_revoke_skips_missing_remote_repo(tmp_path: Path) -> None:
    verified = tmp_path / "verified" / "maven-hosted-verified" / "bad.jar"
    verified.parent.mkdir(parents=True)
    verified.write_bytes(b"bad")
    client = _FakeNexus(tmp_path, [])
    client._target = None  # type: ignore[assignment]
    summary = PipelineSummary(
        repository="maven-hosted",
        results=[_result("bad.jar", verified, verdict=Verdict.FAIL, copied=False)],
    )
    summary.results[0].verify = VerifyResult(copied=False)
    up = VerifiedUploader(client).upload(summary)  # type: ignore[arg-type]
    assert client.deleted_ids == []
    assert not client.ensure_called
    assert up.deleted == 0
    assert not verified.exists()


def test_upload_revokes_fail_then_uploads_pass(tmp_path: Path) -> None:
    root = tmp_path / "verified" / "maven-hosted-verified" / "cib" / "jdbc" / "2.0.1"
    root.mkdir(parents=True)
    good = root / "good.jar"
    bad = root / "bad.jar"
    good.write_bytes(b"good")
    bad.write_bytes(b"bad")

    client = _FakeNexus(
        tmp_path,
        [
            NexusAsset(
                id="bad-id",
                path="cib/jdbc/2.0.1/bad.jar",
                download_url=None,
                repository="maven-hosted-verified",
            )
        ],
    )
    summary = PipelineSummary(
        repository="maven-hosted",
        results=[
            _result("cib/jdbc/2.0.1/good.jar", good, verdict=Verdict.PASS),
            _result("cib/jdbc/2.0.1/bad.jar", bad, verdict=Verdict.FAIL, copied=False),
        ],
    )
    summary.results[1].verify = VerifyResult(copied=False)

    up = VerifiedUploader(client).upload(summary)  # type: ignore[arg-type]
    assert client.deleted_ids == ["bad-id"]
    assert client.uploaded_paths == ["cib/jdbc/2.0.1/good.jar"]
    assert client.ensure_called
    assert up.deleted == 1
    assert up.uploaded == 1
    assert not bad.exists()
    assert good.exists()


def test_delete_asset_404_and_encoding() -> None:
    from nexus_control.nexus.client import NexusClient
    from nexus_control.nexus.errors import NexusAPIError, NexusNotFoundError

    client = NexusClient.__new__(NexusClient)
    calls: list[tuple[str, str]] = []

    def fake_request(method: str, path: str, **kwargs: object) -> None:
        calls.append((method, path))
        raise NexusNotFoundError("gone", status_code=404)

    client._request = fake_request  # type: ignore[method-assign]
    assert client.delete_asset("abc+def") is True
    assert calls == [("DELETE", "/service/rest/v1/assets/abc%2Bdef")]

    with pytest.raises(NexusAPIError, match="empty id"):
        client.delete_asset("  ")
