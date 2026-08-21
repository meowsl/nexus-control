"""Tests for nexus-control-cli helpers and argparse."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from nexus_control.cli.__main__ import build_parser
from nexus_control.cli.assets import (
    filter_assets_for_pipeline,
    select_assets_for_cli,
)
from nexus_control.config import Settings
from nexus_control.models import NexusAsset
from nexus_control.services.scan_common import is_scan_ignored_path
from nexus_control.utils.path_prefixes import path_allowed_by_filters


def _asset(path: str, fmt: str | None = None) -> NexusAsset:
    return NexusAsset(
        id=path,
        path=path,
        download_url=None,
        repository="repo",
        format=fmt,
    )


def test_path_allowed_by_filters() -> None:
    assert path_allowed_by_filters("com/a.jar") is True
    assert path_allowed_by_filters("com/a.jar", prefixes=["com/"]) is True
    assert path_allowed_by_filters("org/a.jar", prefixes=["com/"]) is False
    assert path_allowed_by_filters(
        "archetype-catalog.xml", excluded_prefixes=["com/"]
    )
    assert not path_allowed_by_filters("com/a.jar", excluded_prefixes=["com/"])
    assert not path_allowed_by_filters(
        "com/internal/a.jar",
        prefixes=["com/"],
        excluded_prefixes=["com/internal/"],
    )


def test_parser_verify_flags() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "verify",
            "--repo",
            "maven-hosted",
            "--upload",
            "--target",
            "maven-hosted-verified",
            "--path-prefix",
            "com/example",
            "--limit",
            "5",
            "--scan-limit",
            "3",
            "--workers",
            "8",
            "--refresh",
            "--json",
            "--scanners",
            "grype,trivy",
            "--severity",
            "high",
        ]
    )
    assert args._handler == "verify"
    assert args.repo == "maven-hosted"
    assert args.upload is True
    assert args.scan_mode == "incremental"
    assert args.target == "maven-hosted-verified"
    assert args.path_prefix == ["com/example"]
    multi = parser.parse_args(
        ["verify", "--repo", "r", "--path-prefix", "com/", "--path-prefix", "org/"]
    )
    assert multi.path_prefix == ["com/", "org/"]
    excluded = parser.parse_args(
        [
            "verify",
            "--repo",
            "r",
            "--exclude-prefix",
            "com/",
            "--exclude-prefix",
            "org/experimental/",
        ]
    )
    assert excluded.exclude_prefix == ["com/", "org/experimental/"]
    assert args.limit == 5
    assert args.scan_limit == 3
    assert args.workers == 8
    assert args.refresh is True
    assert args.json is True
    assert args.scanners == "grype,trivy"
    assert args.severity == "high"


def test_parser_repos_and_upload() -> None:
    parser = build_parser()
    assert parser.parse_args(["repos", "--json"])._handler == "repos"
    up = parser.parse_args(["upload", "--repo", "r", "--target", "r-v"])
    assert up._handler == "upload"
    assert up.target == "r-v"


def test_parser_schedule_flags() -> None:
    parser = build_parser()
    menu = parser.parse_args(["schedule"])
    assert menu._handler == "schedule"
    assert menu.schedule_action == "menu"
    run = parser.parse_args(["schedule", "run", "nightly-core"])
    assert run.schedule_action == "run"
    assert run.rule_id == "nightly-core"
    start = parser.parse_args(["schedule", "start", "--schedule-file", "/tmp/s.toml"])
    assert start.schedule_action == "start"
    assert start.schedule_file == "/tmp/s.toml"
    login = parser.parse_args(["schedule", "login"])
    assert login.schedule_action == "login"
    logout = parser.parse_args(["schedule", "logout"])
    assert logout.schedule_action == "logout"
    mon = parser.parse_args(["schedule", "status", "-m", "--interval", "0.5"])
    assert mon.schedule_action == "status"
    assert mon.monitor is True
    assert mon.monitor_interval == 0.5
    run_lim = parser.parse_args(
        ["schedule", "run", "nightly-core", "--scan-limit", "10"]
    )
    assert run_lim.schedule_action == "run"
    assert run_lim.scan_limit == 10
    fg = parser.parse_args(["schedule", "run", "nightly-core", "--foreground"])
    assert fg.foreground is True


def test_parser_vk_teams_flags() -> None:
    parser = build_parser()
    status = parser.parse_args(["vk-teams", "status", "--json"])
    assert status._handler == "vk_teams"
    assert status.vk_action == "status"
    assert status.json is True
    disable = parser.parse_args(["vk-teams", "disable", "--clear-vault"])
    assert disable.vk_action == "disable"
    assert disable.clear_vault is True
    configure = parser.parse_args(["vk-teams", "configure"])
    assert configure.vk_action == "configure"
    test = parser.parse_args(["vk-teams", "test"])
    assert test.vk_action == "test"


def test_filter_path_prefix_and_limit() -> None:
    assets = [
        _asset("com/a/1.0/a.jar"),
        _asset("com/a/1.0/a.jar.md5"),
        _asset("com/a/1.0/a.jar.sha1"),
        _asset("com/b/1.0/b.jar"),
        _asset("org/x/1.0/x.jar"),
    ]
    filtered = filter_assets_for_pipeline(
        assets, path_prefix="com/a", limit=None
    )
    paths = {a.path for a in filtered}
    assert paths == {
        "com/a/1.0/a.jar",
        "com/a/1.0/a.jar.md5",
        "com/a/1.0/a.jar.sha1",
    }

    multi = filter_assets_for_pipeline(
        assets, path_prefix=["com/a", "org/"], limit=None
    )
    assert {a.path for a in multi} == {
        "com/a/1.0/a.jar",
        "com/a/1.0/a.jar.md5",
        "com/a/1.0/a.jar.sha1",
        "org/x/1.0/x.jar",
    }

    limited = filter_assets_for_pipeline(assets, path_prefix="com", limit=1)
    non_side = [a for a in limited if not is_scan_ignored_path(a.path)]
    assert len(non_side) == 1
    # Sidecars for the selected main should be attached
    assert any(is_scan_ignored_path(a.path) for a in limited)

    # Sidecars before the main so they are seen before scan_limit stops the loop.
    scan_assets = [
        _asset("com/a/1.0/a.jar.md5"),
        _asset("com/a/1.0/a.jar.sha1"),
        _asset("com/a/1.0/a.jar"),
        _asset("com/b/1.0/b.jar"),
    ]
    scan_limited = filter_assets_for_pipeline(
        scan_assets, path_prefix="com", scan_limit=1
    )
    scan_mains = [a for a in scan_limited if not is_scan_ignored_path(a.path)]
    assert len(scan_mains) == 1
    assert scan_mains[0].path == "com/a/1.0/a.jar"
    assert {a.path for a in scan_limited if is_scan_ignored_path(a.path)} == {
        "com/a/1.0/a.jar.md5",
        "com/a/1.0/a.jar.sha1",
    }


def test_filter_excluded_prefixes() -> None:
    assets = [
        _asset("archetype-catalog.xml"),
        _asset("archetype-catalog.xml.sha1"),
        _asset("com/a/1.0/a.jar"),
        _asset("com/a/1.0/a.jar.md5"),
        _asset("org/x/1.0/x.jar"),
        _asset("org/x/1.0/x.jar.sha1"),
    ]
    without_com = filter_assets_for_pipeline(
        assets, exclude_prefix="com/", limit=None
    )
    assert {a.path for a in without_com} == {
        "archetype-catalog.xml",
        "archetype-catalog.xml.sha1",
        "org/x/1.0/x.jar",
        "org/x/1.0/x.jar.sha1",
    }

    include_and_exclude = filter_assets_for_pipeline(
        assets,
        path_prefix=["com/", "org/"],
        exclude_prefix="com/a/",
        limit=None,
    )
    assert {a.path for a in include_and_exclude} == {
        "org/x/1.0/x.jar",
        "org/x/1.0/x.jar.sha1",
    }


def test_limit_stops_streaming_listing_and_preserves_seen_sidecars(
    tmp_path: Path,
) -> None:
    settings = Settings(
        nexus_url="http://localhost:8081",
        nexus_cache_dir=tmp_path / "cache",
        assets_cache_ttl=300,
    )
    pages = [
        [
            _asset("com/a.jar.sha1"),
            _asset("com/a.jar"),
            _asset("com/b.jar"),
        ],
        [
            _asset("com/b.jar.sha1"),
            _asset("org/c.jar"),
        ],
    ]
    client = MagicMock()
    client.iter_asset_pages.return_value = iter(pages)

    progress_calls: list[tuple[int, str]] = []

    def on_progress(listed: int, stats, source: str) -> None:
        progress_calls.append((listed, source))

    selected, total, stats = select_assets_for_cli(
        client,
        settings,
        "repo",
        path_prefix="com",
        limit=1,
        refresh=True,
        on_progress=on_progress,
    )
    assert total == 2
    assert sorted(a.path for a in selected) == [
        "com/a.jar",
        "com/a.jar.sha1",
    ]
    assert stats.download_needed == 1
    assert progress_calls
    assert progress_calls[-1] == (2, "nexus")


def test_scan_limit_stops_streaming_even_when_download_not_needed(
    tmp_path: Path,
) -> None:
    """scan_limit caps mains; unlike --limit it still stops when downloads are not needed."""
    from unittest.mock import patch

    from nexus_control.services.downloader import DownloadInspection

    settings = Settings(
        nexus_url="http://localhost:8081",
        nexus_cache_dir=tmp_path / "cache",
        assets_cache_ttl=300,
    )
    pages = [
        [
            _asset("com/a.jar.sha1"),
            _asset("com/a.jar"),
            _asset("com/b.jar"),
            _asset("com/b.jar.sha1"),
            _asset("com/c.jar"),
        ],
    ]
    client = MagicMock()
    client.iter_asset_pages.return_value = iter(pages)

    with patch(
        "nexus_control.cli.assets.Downloader.inspect_asset",
        return_value=DownloadInspection(
            needs_download=False,
            local_path=tmp_path / "cached.jar",
        ),
    ):
        selected, total, stats = select_assets_for_cli(
            client,
            settings,
            "repo",
            path_prefix="com",
            scan_limit=1,
            refresh=True,
            use_checkpoints=False,
        )

    assert sorted(a.path for a in selected) == [
        "com/a.jar",
        "com/a.jar.sha1",
    ]
    assert total == 2
    assert stats.download_needed == 0
    assert stats.scan_only == 1
