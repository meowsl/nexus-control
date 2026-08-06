"""Тесты XDG config.toml, precedence и first-run wizard."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_control.config import ConfigError, clear_settings_cache, load_settings
from nexus_control.config_io import read_toml, write_toml_atomic
from nexus_control.config_paths import resolve_config_path
from nexus_control.config_wizard import (
    ensure_configured,
    needs_setup,
    normalize_nexus_url,
    peek_nexus_url,
    run_first_run_wizard,
)


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    clear_settings_cache()
    yield
    clear_settings_cache()


@pytest.fixture
def xdg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.delenv("NEXUS_CONTROL_CONFIG", raising=False)
    monkeypatch.delenv("NEXUS_URL", raising=False)
    return xdg


def test_resolve_config_path_xdg(xdg_home: Path) -> None:
    path = resolve_config_path()
    assert path == (xdg_home / "nexus-control" / "config.toml").resolve()


def test_resolve_config_path_override(
    xdg_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    custom = tmp_path / "custom.toml"
    monkeypatch.setenv("NEXUS_CONTROL_CONFIG", str(custom))
    assert resolve_config_path() == custom.resolve()


def test_write_toml_permissions(xdg_home: Path) -> None:
    path = resolve_config_path()
    write_toml_atomic(path, {"nexus_url": "http://localhost:8081"})
    assert path.is_file()
    assert (path.parent.stat().st_mode & 0o777) == 0o700
    assert (path.stat().st_mode & 0o777) == 0o600
    data = read_toml(path)
    assert data["nexus_url"] == "http://localhost:8081"
    assert "nexus_password" not in data


def test_update_toml_key_preserves_other_keys(xdg_home: Path) -> None:
    from nexus_control.config_io import update_toml_key

    path = resolve_config_path()
    write_toml_atomic(
        path,
        {"nexus_url": "https://nexus.lab:8443", "nexus_verify_ssl": True},
    )
    update_toml_key(path, "nexus_verify_ssl", False)
    data = read_toml(path)
    assert data["nexus_url"] == "https://nexus.lab:8443"
    assert data["nexus_verify_ssl"] is False


def test_write_toml_strips_secrets(xdg_home: Path) -> None:
    path = resolve_config_path()
    write_toml_atomic(
        path,
        {
            "nexus_url": "http://localhost:8081",
            "nexus_username": "admin",
            "nexus_password": "secret",
        },
    )
    data = read_toml(path)
    assert "nexus_password" not in data
    assert "nexus_username" not in data


def test_peek_and_needs_setup(xdg_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert needs_setup(env_file=None) is True
    path = resolve_config_path()
    write_toml_atomic(path, {"nexus_url": "http://nexus.lab:8081"})
    assert peek_nexus_url(config_path=path, env_file=None) == "http://nexus.lab:8081"
    assert needs_setup(config_path=path, env_file=None) is False

    monkeypatch.setenv("NEXUS_URL", "http://from-env:8081/")
    assert peek_nexus_url(config_path=path, env_file=None) == "http://from-env:8081"


def test_env_overrides_toml(
    xdg_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = resolve_config_path()
    write_toml_atomic(
        path,
        {
            "nexus_url": "http://from-toml:8081",
            "scanners": "trivy",
        },
    )
    monkeypatch.setenv("NEXUS_URL", "http://from-env:8081")
    # Изолировать download dirs в tmp
    monkeypatch.setenv("DOWNLOAD_ROOT", str(tmp_path / "dl"))
    monkeypatch.setenv("REPORTS_ROOT", str(tmp_path / "rp"))
    monkeypatch.setenv("VERIFIED_ROOT", str(tmp_path / "vf"))
    monkeypatch.setenv("NEXUS_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "log.log"))

    settings = load_settings(env_file=None, config_path=path, run_wizard=False)
    assert settings.nexus_url == "http://from-env:8081"
    assert settings.scanners == "trivy"


def test_toml_loaded_when_no_env(
    xdg_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = resolve_config_path()
    write_toml_atomic(path, {"nexus_url": "http://toml-only:8081", "scanners": "grype,trivy"})
    monkeypatch.setenv("DOWNLOAD_ROOT", str(tmp_path / "dl"))
    monkeypatch.setenv("REPORTS_ROOT", str(tmp_path / "rp"))
    monkeypatch.setenv("VERIFIED_ROOT", str(tmp_path / "vf"))
    monkeypatch.setenv("NEXUS_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "log.log"))

    settings = load_settings(env_file=None, config_path=path, run_wizard=False)
    assert settings.nexus_url == "http://toml-only:8081"
    assert settings.scanners_list == ["grype", "trivy"]


def test_legacy_dotenv_without_toml(
    xdg_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("NEXUS_URL=http://dotenv:8081\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DOWNLOAD_ROOT", str(tmp_path / "dl"))
    monkeypatch.setenv("REPORTS_ROOT", str(tmp_path / "rp"))
    monkeypatch.setenv("VERIFIED_ROOT", str(tmp_path / "vf"))
    monkeypatch.setenv("NEXUS_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "log.log"))

    settings = load_settings(env_file=env_file, run_wizard=False)
    assert settings.nexus_url == "http://dotenv:8081"


def test_wizard_writes_config(
    xdg_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = resolve_config_path()
    answers = iter(
        [
            "http://wizard:8081",
            "n",
            "trivy",
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    written = run_first_run_wizard(config_path=path)
    assert written == path
    data = read_toml(path)
    assert data["nexus_url"] == "http://wizard:8081"
    assert data["nexus_verify_ssl"] is False
    assert data["scanners"] == "trivy"
    assert "nexus_password" not in data


def test_wizard_non_tty_raises(xdg_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    with pytest.raises(ConfigError, match="No configuration found"):
        ensure_configured(run_wizard=True, env_file=None)


def test_normalize_url() -> None:
    assert normalize_nexus_url(" http://x:8081/ ") == "http://x:8081"
    with pytest.raises(ConfigError):
        normalize_nexus_url("not-a-url")


def test_invalid_toml_raises(
    xdg_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = resolve_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("nexus_url = [[[broken\n", encoding="utf-8")
    monkeypatch.setenv("DOWNLOAD_ROOT", str(tmp_path / "dl"))
    monkeypatch.setenv("REPORTS_ROOT", str(tmp_path / "rp"))
    monkeypatch.setenv("VERIFIED_ROOT", str(tmp_path / "vf"))
    monkeypatch.setenv("NEXUS_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "log.log"))
    # URL отсутствует из-за битого TOML; wizard выключен → ConfigError
    with pytest.raises(ConfigError):
        load_settings(env_file=None, config_path=path, run_wizard=False)
