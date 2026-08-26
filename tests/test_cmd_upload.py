"""Tests: upload gated by verified-manifest.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_control.cli.cmd_upload import (
    _summary_from_verified_dir,
    load_manifest_failed_paths,
    load_manifest_passed_paths,
)
from nexus_control.config import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "rp",
        verified_root=tmp_path / "verified",
        archive_root=tmp_path / "ar",
        log_file=tmp_path / "log.log",
        nexus_cache_dir=tmp_path / "cache",
    )


def test_load_manifest_passed_paths(tmp_path: Path) -> None:
    verified = tmp_path / "repo-verified"
    verified.mkdir()
    (verified / "verified-manifest.json").write_text(
        json.dumps(
            {
                "passed_assets": [
                    {"asset_path": "lodash/-/lodash-4.18.1.tgz"},
                    {"asset_path": "/ms/-/ms-2.1.3.tgz"},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert load_manifest_passed_paths(verified) == [
        "lodash/-/lodash-4.18.1.tgz",
        "ms/-/ms-2.1.3.tgz",
    ]


def test_summary_skips_stale_not_in_manifest(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = settings.verified_repo_dir("test-npm")
    good = root / "lodash" / "-" / "lodash-4.18.1.tgz"
    stale = root / "lodash" / "-" / "lodash-4.17.11.tgz"
    good.parent.mkdir(parents=True)
    good.write_bytes(b"good")
    stale.write_bytes(b"stale")
    (root / "verified-manifest.json").write_text(
        json.dumps(
            {
                "repository": "test-npm",
                "passed_assets": [{"asset_path": "lodash/-/lodash-4.18.1.tgz"}],
            }
        ),
        encoding="utf-8",
    )

    summary, skipped = _summary_from_verified_dir(
        settings, "test-npm", fmt="npm"
    )
    assert skipped == 1
    assert [r.asset_path for r in summary.results] == [
        "lodash/-/lodash-4.18.1.tgz"
    ]


def test_summary_includes_maven_sidecars_of_passed_main(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = settings.verified_repo_dir("maven-hosted")
    main = root / "cib" / "jdbc" / "2.0.1" / "jdbc-2.0.1.pom"
    sha1 = root / "cib" / "jdbc" / "2.0.1" / "jdbc-2.0.1.pom.sha1"
    stale_sha1 = root / "cib" / "jdbc" / "1.0.0" / "jdbc-1.0.0.pom.sha1"
    main.parent.mkdir(parents=True)
    stale_sha1.parent.mkdir(parents=True)
    main.write_text("<project/>", encoding="utf-8")
    sha1.write_text("abc", encoding="utf-8")
    stale_sha1.write_text("old", encoding="utf-8")
    (root / "verified-manifest.json").write_text(
        json.dumps(
            {
                "repository": "maven-hosted",
                "passed_assets": [
                    {"asset_path": "cib/jdbc/2.0.1/jdbc-2.0.1.pom"},
                ],
            }
        ),
        encoding="utf-8",
    )

    summary, skipped = _summary_from_verified_dir(
        settings, "maven-hosted", fmt="maven2"
    )
    paths = {r.asset_path for r in summary.results}
    assert "cib/jdbc/2.0.1/jdbc-2.0.1.pom" in paths
    assert "cib/jdbc/2.0.1/jdbc-2.0.1.pom.sha1" in paths
    assert "cib/jdbc/1.0.0/jdbc-1.0.0.pom.sha1" not in paths
    assert skipped == 1


def test_summary_requires_manifest(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = settings.verified_repo_dir("test-npm")
    pkg = root / "a.tgz"
    pkg.parent.mkdir(parents=True)
    pkg.write_bytes(b"x")
    with pytest.raises(SystemExit, match="verified-manifest"):
        _summary_from_verified_dir(settings, "test-npm", fmt="npm")


def test_load_manifest_failed_paths(tmp_path: Path) -> None:
    verified = tmp_path / "repo-verified"
    verified.mkdir()
    (verified / "verified-manifest.json").write_text(
        json.dumps(
            {
                "passed_assets": [{"asset_path": "ok.jar"}],
                "failed_assets": [
                    {"asset_path": "cib/jdbc/2.0.1/bad.jar"},
                    {"asset_path": "/cib/jdbc/2.0.1/bad.jar"},
                ],
            }
        ),
        encoding="utf-8",
    )
    assert load_manifest_failed_paths(verified) == ["cib/jdbc/2.0.1/bad.jar"]


def test_summary_allows_failed_only_manifest(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = settings.verified_repo_dir("maven-hosted")
    stale = root / "cib" / "jdbc" / "2.0.1" / "bad.jar"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"bad")
    (root / "verified-manifest.json").write_text(
        json.dumps(
            {
                "repository": "maven-hosted",
                "passed_assets": [],
                "failed_assets": [{"asset_path": "cib/jdbc/2.0.1/bad.jar"}],
            }
        ),
        encoding="utf-8",
    )
    summary, skipped = _summary_from_verified_dir(
        settings, "maven-hosted", fmt="maven2"
    )
    assert summary.results == []
    assert skipped == 1
    assert load_manifest_passed_paths(root) == []
    assert load_manifest_failed_paths(root) == ["cib/jdbc/2.0.1/bad.jar"]
