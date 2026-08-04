"""Тесты encrypted credential vault и resolve без TTY prompt."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nexus_control.config import ConfigError, Settings
from nexus_control.nexus.credentials import (
    CredentialVault,
    prompt_nexus_credentials,
    resolve_runtime_credentials,
)
from nexus_control.nexus.session import SessionStore


def _settings(tmp_path: Path, **kwargs: object) -> Settings:
    base = {
        "nexus_url": "http://localhost:8081",
        "nexus_username": "",
        "nexus_password": "",
        "nexus_cache_dir": tmp_path / "cache",
        "download_root": tmp_path / "dl",
        "reports_root": tmp_path / "rp",
        "verified_root": tmp_path / "vf",
        "log_file": tmp_path / "logs" / "t.log",
    }
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def test_vault_roundtrip(tmp_path: Path) -> None:
    vault = CredentialVault(tmp_path / "cache")
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    vault.save(
        nexus_url="http://localhost:8081",
        username="admin",
        password="s3cret",
        expires_at=expires,
    )
    loaded = vault.load()
    assert loaded is not None
    assert loaded.username == "admin"
    assert loaded.password == "s3cret"
    assert loaded.matches("http://localhost:8081/", "admin")
    assert (tmp_path / "cache" / "credentials.vault").stat().st_mode & 0o777 == 0o600


def test_vault_expired_clears(tmp_path: Path) -> None:
    vault = CredentialVault(tmp_path / "cache")
    expires = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    vault.save(
        nexus_url="http://localhost:8081",
        username="admin",
        password="s3cret",
        expires_at=expires,
    )
    assert vault.load() is None
    assert not vault.vault_path.exists()


def test_resolve_from_env(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        nexus_username="ci-user",
        nexus_password="ci-pass",
    )
    resolved = resolve_runtime_credentials(settings)
    assert resolved.nexus_username == "ci-user"
    assert resolved.nexus_password == "ci-pass"


def test_resolve_from_vault_with_active_session(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = SessionStore(settings.nexus_cache_dir)
    session = store.create(
        nexus_url=settings.nexus_url,
        username="vault-user",
        ttl_seconds=3600,
    )
    vault = CredentialVault(settings.nexus_cache_dir)
    vault.save(
        nexus_url=settings.nexus_url,
        username="vault-user",
        password="vault-pass",
        expires_at=session.expires_at,
    )
    resolved = resolve_runtime_credentials(settings)
    assert resolved.nexus_username == "vault-user"
    assert resolved.nexus_password == "vault-pass"


def test_prompt_requires_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    with pytest.raises(ConfigError, match="non-interactive"):
        prompt_nexus_credentials()
