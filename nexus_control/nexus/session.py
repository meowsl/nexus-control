"""Локальный кэш сессии для проверки аутентификации Nexus."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from nexus_control.models import AuthType
from nexus_control.utils.fs import ensure_dir, read_json, utc_now_iso, write_json

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def config_fingerprint(nexus_url: str, username: str) -> str:
    """Несекретный хеш URL + имени пользователя для обнаружения изменений конфигурации."""
    payload = f"{nexus_url.strip().rstrip('/')}|{username}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


@dataclass
class SessionCache:
    """Представление в памяти ``session.json``.

    Пароль никогда не сохраняется. Для Basic Auth кэшируется только факт
    успешной проверки учётных данных до ``expires_at``.
    """

    schema_version: int
    nexus_url: str
    username: str
    auth_type: AuthType
    created_at: str
    expires_at: str
    last_verified_at: str
    config_hash: str
    cookies: dict[str, str] = field(default_factory=dict)
    token: str | None = None  # опциональный непрозрачный токен, если будет предоставлен (не пароль)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "nexus_url": self.nexus_url,
            "username": self.username,
            "auth_type": self.auth_type.value,
            "cookies": self.cookies,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_verified_at": self.last_verified_at,
            "config_hash": self.config_hash,
        }
        # Никогда не сохранять пароль. Токен — только если есть и не похож на дамп пароля.
        if self.token:
            data["token"] = self.token
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionCache:
        if "password" in data:
            # Защита: старые/сломанные кэши не должны хранить секреты.
            logger.warning("Rejecting session cache that contains a password field")
            raise ValueError("session cache must not contain password")
        auth_raw = str(data.get("auth_type", AuthType.BASIC.value))
        try:
            auth_type = AuthType(auth_raw)
        except ValueError:
            auth_type = AuthType.BASIC
        return cls(
            schema_version=int(data.get("schema_version", 0)),
            nexus_url=str(data["nexus_url"]),
            username=str(data["username"]),
            auth_type=auth_type,
            created_at=str(data["created_at"]),
            expires_at=str(data["expires_at"]),
            last_verified_at=str(data.get("last_verified_at", data["created_at"])),
            config_hash=str(data.get("config_hash", "")),
            cookies={str(k): str(v) for k, v in (data.get("cookies") or {}).items()},
            token=data.get("token"),
        )

    def is_expired(self, now: datetime | None = None) -> bool:
        expires = _parse_dt(self.expires_at)
        if expires is None:
            return True
        return (now or _now()) >= expires

    def matches(self, nexus_url: str, username: str) -> bool:
        expected = config_fingerprint(nexus_url, username)
        if self.config_hash and self.config_hash != expected:
            return False
        return (
            self.nexus_url.rstrip("/") == nexus_url.rstrip("/")
            and self.username == username
        )


class SessionStore:
    """Загрузка / сохранение / инвалидация ``NEXUS_CACHE_DIR/session.json``."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.session_path = cache_dir / "session.json"

    def load(self) -> SessionCache | None:
        if not self.session_path.is_file():
            return None
        try:
            data = read_json(self.session_path)
            if not isinstance(data, dict):
                return None
            return SessionCache.from_dict(data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to read session cache: %s", exc)
            return None

    def save(self, session: SessionCache) -> None:
        ensure_dir(self.cache_dir, mode=0o700)
        payload = session.to_dict()
        if "password" in payload:
            raise RuntimeError("Refusing to write password into session cache")
        write_json(self.session_path, payload, mode=0o600)
        logger.info(
            "Session cache saved expires_at=%s auth_type=%s",
            session.expires_at,
            session.auth_type.value,
        )

    def invalidate(self) -> None:
        try:
            if self.session_path.exists():
                self.session_path.unlink()
                logger.info("Session cache invalidated")
        except OSError as exc:
            logger.warning("Failed to remove session cache: %s", exc)

    def create(
        self,
        *,
        nexus_url: str,
        username: str,
        ttl_seconds: int,
        auth_type: AuthType = AuthType.BASIC,
        cookies: dict[str, str] | None = None,
        token: str | None = None,
    ) -> SessionCache:
        now = _now()
        expires = now + timedelta(seconds=max(1, ttl_seconds))
        session = SessionCache(
            schema_version=SCHEMA_VERSION,
            nexus_url=nexus_url.rstrip("/"),
            username=username,
            auth_type=auth_type,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            last_verified_at=now.isoformat(),
            config_hash=config_fingerprint(nexus_url, username),
            cookies=cookies or {},
            token=token,
        )
        self.save(session)
        return session

    def touch(self, session: SessionCache) -> SessionCache:
        session.last_verified_at = utc_now_iso()
        self.save(session)
        return session
