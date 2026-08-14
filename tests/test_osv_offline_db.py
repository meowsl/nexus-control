"""Тесты preflight offline OSV DB."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_control.config import Settings
from nexus_control.services.osv_offline_db import (
    EnsureStatus,
    ecosystems_required_for_verify,
    ensure_osv_offline_db,
    missing_osv_ecosystems,
    offline_db_ready,
    osv_db_cache_root,
    preferred_ecosystem_db_path,
    with_osv_offline_flags,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        nexus_url="http://localhost:8081",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        archive_root=tmp_path / "archive",
        log_file=tmp_path / "log.txt",
        osv_local_db_cache_dir=tmp_path / "cache",
    )


def test_ecosystems_required_by_format() -> None:
    assert ecosystems_required_for_verify("nuget", ["grype"]) == ["NuGet"]
    assert ecosystems_required_for_verify("pypi", ["trivy", "grype", "osv"]) == ["PyPI"]
    assert ecosystems_required_for_verify("npm", ["osv"]) == ["npm"]
    assert ecosystems_required_for_verify("maven2", ["osv"]) == ["Maven"]
    assert ecosystems_required_for_verify("rubygems", ["osv"]) == ["RubyGems"]
    assert ecosystems_required_for_verify("go", ["osv"]) == ["Go"]
    assert ecosystems_required_for_verify("apt", ["osv"]) == ["Debian"]
    assert ecosystems_required_for_verify("yum", ["osv"]) == ["Red Hat"]
    # osv включён, но у raw нет OSV ecosystem → пустой список (не блокируем).
    assert ecosystems_required_for_verify("raw", ["osv"]) == []
    assert ecosystems_required_for_verify("maven2", ["grype"]) is None


def test_ecosystems_for_nexus_format() -> None:
    from nexus_control.services.osv_offline_db import ecosystems_for_nexus_format

    assert ecosystems_for_nexus_format("pypi") == ["PyPI"]
    assert ecosystems_for_nexus_format("docker") is None
    assert ecosystems_for_nexus_format("helm") is None


def test_offline_db_ready_empty_required(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = osv_db_cache_root(settings)
    # Пустой required: не нужна никакая DB (unmapped format).
    assert offline_db_ready(root, []) is True


def test_offline_db_ready_nuget(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = osv_db_cache_root(settings)
    assert missing_osv_ecosystems(root, ["NuGet"]) == ["NuGet"]
    assert not offline_db_ready(root, ["NuGet"])
    path = preferred_ecosystem_db_path(root, "NuGet")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"fake-zip")
    assert offline_db_ready(root, ["NuGet"])
    assert missing_osv_ecosystems(root, ["NuGet"]) == []


def test_with_osv_offline_flags_idempotent(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    updated = with_osv_offline_flags(settings)
    assert "--offline" in updated.osv_extra_args_list
    assert "--offline-vulnerabilities" in updated.osv_extra_args_list
    again = with_osv_offline_flags(updated)
    assert again.osv_extra_args_list.count("--offline") == 1


def test_ensure_skipped_when_osv_not_needed(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    result = ensure_osv_offline_db(
        settings,
        repo_format="maven2",
        enabled_scanners=["grype"],
        interactive=False,
    )
    assert result.status == EnsureStatus.SKIPPED


def test_ensure_ok_when_db_present(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = osv_db_cache_root(settings)
    path = preferred_ecosystem_db_path(root, "NuGet")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"fake")
    result = ensure_osv_offline_db(
        settings,
        repo_format="nuget",
        enabled_scanners=["grype"],
        interactive=False,
    )
    assert result.status == EnsureStatus.OK
    assert result.settings is not None
    assert "--offline" in result.settings.osv_extra_args_list


def test_ensure_cancelled_non_interactive_missing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    result = ensure_osv_offline_db(
        settings,
        repo_format="nuget",
        enabled_scanners=["osv"],
        interactive=False,
    )
    assert result.status == EnsureStatus.CANCELLED
    assert "cancelled" in result.message.lower()


def test_ensure_cancelled_when_user_declines(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    result = ensure_osv_offline_db(
        settings,
        repo_format="nuget",
        enabled_scanners=["osv"],
        interactive=True,
        ask=lambda: False,
    )
    assert result.status == EnsureStatus.CANCELLED
    assert "declined" in result.message.lower()
    assert "required" in result.message.lower() or "disabled" in result.message.lower()


def test_ensure_pypi_requires_pypi_db(tmp_path: Path) -> None:
    """Наличие NuGet DB не должно удовлетворять preflight для pypi."""
    settings = _settings(tmp_path)
    root = osv_db_cache_root(settings)
    nuget = preferred_ecosystem_db_path(root, "NuGet")
    nuget.parent.mkdir(parents=True)
    nuget.write_bytes(b"fake")
    result = ensure_osv_offline_db(
        settings,
        repo_format="pypi",
        enabled_scanners=["trivy", "grype", "osv"],
        interactive=False,
    )
    assert result.status == EnsureStatus.CANCELLED
    assert "PyPI" in result.message


def test_ensure_pypi_ok_when_pypi_present(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    root = osv_db_cache_root(settings)
    path = preferred_ecosystem_db_path(root, "PyPI")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"fake")
    result = ensure_osv_offline_db(
        settings,
        repo_format="pypi",
        enabled_scanners=["osv"],
        interactive=False,
    )
    assert result.status == EnsureStatus.OK


def test_ensure_downloads_when_accepted(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    downloaded: list[str] = []

    def fake_download() -> None:
        downloaded.append("ok")
        path = preferred_ecosystem_db_path(osv_db_cache_root(settings), "NuGet")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"zip")

    result = ensure_osv_offline_db(
        settings,
        repo_format="nuget",
        enabled_scanners=["osv"],
        interactive=True,
        ask=lambda: True,
        download=fake_download,
    )
    assert result.status == EnsureStatus.OK
    assert downloaded == ["ok"]
    assert result.settings is not None
