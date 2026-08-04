"""Модульные тесты кэша сессии Nexus (без сети)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from nexus_tui.models import AuthType
from nexus_tui.nexus.session import SessionStore, config_fingerprint


def test_session_cache_created(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    session = store.create(
        nexus_url="http://localhost:8081",
        username="admin",
        ttl_seconds=3600,
        auth_type=AuthType.BASIC,
    )
    assert store.session_path.is_file()
    loaded = store.load()
    assert loaded is not None
    assert loaded.username == "admin"
    assert loaded.nexus_url == "http://localhost:8081"
    assert loaded.auth_type == AuthType.BASIC
    assert loaded.config_hash == config_fingerprint("http://localhost:8081", "admin")
    assert not session.is_expired()


def test_session_cache_expires(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    session = store.create(
        nexus_url="http://localhost:8081",
        username="admin",
        ttl_seconds=1,
    )
    # Принудительно истечь срок
    session.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    store.save(session)
    loaded = store.load()
    assert loaded is not None
    assert loaded.is_expired()


def test_session_invalidated_on_url_or_user_change(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    store.create(
        nexus_url="http://localhost:8081",
        username="admin",
        ttl_seconds=3600,
    )
    loaded = store.load()
    assert loaded is not None
    assert loaded.matches("http://localhost:8081", "admin")
    assert not loaded.matches("http://other:8081", "admin")
    assert not loaded.matches("http://localhost:8081", "other")


def test_password_not_saved(tmp_path: Path) -> None:
    store = SessionStore(tmp_path)
    store.create(
        nexus_url="http://localhost:8081",
        username="admin",
        ttl_seconds=3600,
        cookies={"NXSESSIONID": "abc"},
    )
    raw = store.session_path.read_text(encoding="utf-8")
    assert "password" not in raw.lower()
    data = store.load()
    assert data is not None
    assert "password" not in data.to_dict()


def test_reject_cache_with_password_field(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    path.write_text(
        '{"schema_version":1,"nexus_url":"http://x","username":"u",'
        '"auth_type":"basic","created_at":"t","expires_at":"t",'
        '"last_verified_at":"t","config_hash":"h","password":"secret"}',
        encoding="utf-8",
    )
    store = SessionStore(tmp_path)
    assert store.load() is None
