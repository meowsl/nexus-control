"""Тесты encrypted credential vault и resolve без TTY prompt."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nexus_control.config import ConfigError, Settings
from nexus_control.nexus.credentials import (
    NON_INTERACTIVE_CREDS_HINT,
    SCHEDULER_VAULT_FILENAME,
    CredentialVault,
    clear_scheduler_credentials,
    prompt_nexus_credentials,
    resolve_runtime_credentials,
    save_scheduler_credentials,
    scheduler_vault,
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


def test_resolve_no_prompt_without_creds_hints_env_or_login(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with pytest.raises(ConfigError, match="schedule login") as exc:
        resolve_runtime_credentials(settings, allow_prompt=False)
    assert str(exc.value) == NON_INTERACTIVE_CREDS_HINT
    assert ".env" in str(exc.value) or "NEXUS_USERNAME" in str(exc.value)


def test_scheduler_vault_roundtrip_and_resolve(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = save_scheduler_credentials(
        settings, username="sched-user", password="sched-pass"
    )
    assert path.name == SCHEDULER_VAULT_FILENAME
    assert path.stat().st_mode & 0o777 == 0o600

    loaded = scheduler_vault(settings.nexus_cache_dir).load()
    assert loaded is not None
    assert loaded.username == "sched-user"
    assert loaded.password == "sched-pass"

    resolved = resolve_runtime_credentials(settings, allow_prompt=False)
    assert resolved.nexus_username == "sched-user"
    assert resolved.nexus_password == "sched-pass"


def test_env_wins_over_scheduler_vault(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        nexus_username="env-user",
        nexus_password="env-pass",
    )
    save_scheduler_credentials(
        settings, username="sched-user", password="sched-pass"
    )
    resolved = resolve_runtime_credentials(settings, allow_prompt=False)
    assert resolved.nexus_username == "env-user"
    assert resolved.nexus_password == "env-pass"


def test_clear_scheduler_credentials(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    save_scheduler_credentials(settings, username="u", password="p")
    assert clear_scheduler_credentials(settings) is True
    assert scheduler_vault(settings.nexus_cache_dir).load() is None
    assert clear_scheduler_credentials(settings) is False


def test_scheduler_vault_survives_session_ttl_semantics(tmp_path: Path) -> None:
    """Scheduler vault ignores expires_at / session expiry."""
    settings = _settings(tmp_path)
    vault = scheduler_vault(settings.nexus_cache_dir)
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    vault.save(
        nexus_url=settings.nexus_url,
        username="keep-me",
        password="secret",
        expires_at=past,
        persistent=True,
    )
    loaded = vault.load()
    assert loaded is not None
    assert loaded.username == "keep-me"
    resolved = resolve_runtime_credentials(settings, allow_prompt=False)
    assert resolved.nexus_username == "keep-me"
