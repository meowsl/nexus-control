"""Tests: upload gated by verified-manifest.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_control.cli.cmd_upload import (
    _summary_from_verified_dir,
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


def test_summary_requires_manifest(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = settings.verified_repo_dir("test-npm")
    pkg = root / "a.tgz"
    pkg.parent.mkdir(parents=True)
    pkg.write_bytes(b"x")
    with pytest.raises(SystemExit, match="verified-manifest"):
        _summary_from_verified_dir(settings, "test-npm", fmt="npm")
