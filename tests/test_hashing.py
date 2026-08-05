"""Тесты сверки локальных файлов с remote checksums."""

from __future__ import annotations

import hashlib
from pathlib import Path

from nexus_control.models import NexusAsset
from nexus_control.utils.hashing import (
    checksum_is_authoritative,
    checksums_mismatch,
    hash_file,
    hashers_for_expected,
    local_matches_remote,
    pick_remote_checksum,
    remote_identity_unchanged,
)


def test_pick_remote_checksum_prefers_sha256() -> None:
    assert pick_remote_checksum(
        {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}
    ) == ("sha256", "c" * 64)


def test_pick_remote_checksum_falls_back_to_sha1() -> None:
    assert pick_remote_checksum({"SHA1": "AbCd", "md5": "x"}) == ("sha1", "abcd")


def test_hash_file_and_match(tmp_path: Path) -> None:
    path = tmp_path / "blob.bin"
    data = b"hello-nexus"
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    assert hash_file(path, "sha256") == digest
    assert local_matches_remote(path, {"sha256": digest}) is True
    assert local_matches_remote(path, {"sha256": "0" * 64}) is False


def test_match_by_size_when_no_checksum(tmp_path: Path) -> None:
    path = tmp_path / "blob.bin"
    path.write_bytes(b"abc")
    assert local_matches_remote(path, {}, file_size=3) is True
    assert local_matches_remote(path, {}, file_size=9) is False
    assert local_matches_remote(path, {}) is None


def test_streaming_hasher_and_mismatch() -> None:
    hasher = hashers_for_expected({"sha1": "x", "sha256": "y"})
    hasher.update(b"abc")
    digests = hasher.hexdigests()
    assert "sha256" in digests and "sha1" in digests
    expected_sha256 = hashlib.sha256(b"abc").hexdigest()
    assert checksums_mismatch({"sha256": expected_sha256}, digests) is None
    assert checksums_mismatch({"sha256": "0" * 64}, digests) is not None


def test_npm_metadata_checksum_not_authoritative() -> None:
    meta = NexusAsset(
        id="1",
        path="lodash",
        download_url=None,
        repository="test-npm",
        format="npm",
        checksum={"sha1": "e" * 40},
    )
    tgz = NexusAsset(
        id="2",
        path="lodash/-/lodash-4.17.21.tgz",
        download_url=None,
        repository="test-npm",
        format="npm",
        checksum={"sha1": "a" * 40},
    )
    assert checksum_is_authoritative(meta) is False
    assert checksum_is_authoritative(tgz) is True


def test_soft_mismatch_ignores_sha1() -> None:
    actual = {"sha1": "a" * 40, "sha256": "b" * 64}
    expected = {"sha1": "c" * 40}
    assert checksums_mismatch(expected, actual, authoritative=False) is None
    assert checksums_mismatch(expected, actual, authoritative=True) is not None


def test_remote_identity_unchanged() -> None:
    remote = {"sha1": "AbCd"}
    assert (
        remote_identity_unchanged(
            remote,
            remote_last_modified="t1",
            sidecar={"checksum": {"sha1": "abcd", "md5": "1" * 32}},
        )
        is True
    )
    assert (
        remote_identity_unchanged(
            remote,
            remote_last_modified="t1",
            sidecar={"checksum": {"sha1": "ffff"}},
        )
        is False
    )
    assert (
        remote_identity_unchanged(remote, remote_last_modified="t1", sidecar=None)
        is None
    )
