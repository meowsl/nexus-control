"""Интерактивный ввод и шифрованное хранение учётных данных Nexus.

Пароль **не** пишется в ``session.json``. Пока активна Nexus-сессия (тот же TTL),
учётные данные лежат в ``credentials.vault`` (Fernet, файл ``0o600``), ключ —
в ``.vault_key`` (``0o600``). После истечения / invalidate vault очищается.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from nexus_control.config import ConfigError, Settings
from nexus_control.nexus.session import SessionStore, config_fingerprint
from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

VAULT_FILENAME = "credentials.vault"
KEY_FILENAME = ".vault_key"


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


@dataclass(slots=True)
class StoredCredentials:
    nexus_url: str
    username: str
    password: str
    expires_at: str
    config_hash: str

    def is_expired(self, now: datetime | None = None) -> bool:
        expires = _parse_dt(self.expires_at)
        if expires is None:
            return True
        return (now or _now()) >= expires

    def matches(self, nexus_url: str, username: str | None = None) -> bool:
        if self.nexus_url.rstrip("/") != nexus_url.rstrip("/"):
            return False
        if username is not None and self.username != username:
            return False
        expected = config_fingerprint(nexus_url, self.username)
        if self.config_hash and self.config_hash != expected:
            return False
        return True


class CredentialVault:
    """Шифрованное хранилище username/password на время Nexus-сессии."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.vault_path = cache_dir / VAULT_FILENAME
        self.key_path = cache_dir / KEY_FILENAME

    def save(
        self,
        *,
        nexus_url: str,
        username: str,
        password: str,
        expires_at: str,
    ) -> None:
        ensure_dir(self.cache_dir, mode=0o700)
        payload = {
            "nexus_url": nexus_url.rstrip("/"),
            "username": username,
            "password": password,
            "expires_at": expires_at,
            "config_hash": config_fingerprint(nexus_url, username),
        }
        token = self._fernet().encrypt(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )
        self._write_bytes(self.vault_path, token)
        logger.info(
            "Encrypted credentials saved until %s (user=%s)",
            expires_at,
            username,
        )

    def load(self) -> StoredCredentials | None:
        if not self.vault_path.is_file() or not self.key_path.is_file():
            return None
        try:
            raw = self.vault_path.read_bytes()
            data = json.loads(self._fernet().decrypt(raw).decode("utf-8"))
        except (OSError, InvalidToken, json.JSONDecodeError, UnicodeError) as exc:
            logger.warning("Failed to read credential vault: %s", exc)
            self.clear()
            return None
        if not isinstance(data, dict):
            self.clear()
            return None
        if "password" not in data or not data.get("username"):
            self.clear()
            return None
        creds = StoredCredentials(
            nexus_url=str(data["nexus_url"]),
            username=str(data["username"]),
            password=str(data["password"]),
            expires_at=str(data.get("expires_at") or ""),
            config_hash=str(data.get("config_hash") or ""),
        )
        if creds.is_expired():
            logger.info("Credential vault expired; clearing")
            self.clear()
            return None
        return creds

    def clear(self) -> None:
        for path in (self.vault_path,):
            try:
                if path.exists():
                    path.unlink()
                    logger.info("Credential vault cleared: %s", path.name)
            except OSError as exc:
                logger.warning("Failed to remove %s: %s", path, exc)

    def clear_all(self) -> None:
        """Удалить vault и локальный ключ шифрования."""
        self.clear()
        try:
            if self.key_path.exists():
                self.key_path.unlink()
        except OSError as exc:
            logger.warning("Failed to remove vault key: %s", exc)

    def _fernet(self) -> Fernet:
        key = self._load_or_create_key()
        return Fernet(key)

    def _load_or_create_key(self) -> bytes:
        ensure_dir(self.cache_dir, mode=0o700)
        if self.key_path.is_file():
            key = self.key_path.read_bytes().strip()
            if key:
                return key
        key = Fernet.generate_key()
        self._write_bytes(self.key_path, key)
        return key

    @staticmethod
    def _write_bytes(path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, data)
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
        finally:
            os.close(fd)


def prompt_nexus_credentials(default_username: str = "") -> tuple[str, str]:
    """Запросить username/password в терминале (до старта Textual)."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ConfigError(
            "NEXUS_USERNAME and NEXUS_PASSWORD are required in non-interactive "
            "mode (no TTY). Set them in the environment or .env for CI."
        )
    print("Nexus authentication", file=sys.stderr)
    print(
        "Credentials are stored encrypted until the Nexus session expires "
        f"(see NEXUS_SESSION_TTL / {VAULT_FILENAME}).",
        file=sys.stderr,
    )
    hint = f" [{default_username}]" if default_username else ""
    username = input(f"Username{hint}: ").strip() or default_username.strip()
    if not username:
        raise ConfigError("Username is required")
    password = getpass.getpass("Password: ")
    if not password:
        raise ConfigError("Password is required")
    return username, password


def resolve_runtime_credentials(settings: Settings) -> Settings:
    """Вернуть Settings с заполненными username/password.

    Порядок:
    1. Активная Nexus-сессия + неистёкший encrypted vault
    2. ``NEXUS_USERNAME`` + ``NEXUS_PASSWORD`` из env / .env (CI)
    3. Интерактивный prompt (TTY)
    """
    vault = CredentialVault(settings.nexus_cache_dir)
    store = SessionStore(settings.nexus_cache_dir)
    session = store.load()

    if session is not None and session.is_expired():
        logger.info("Nexus session expired; clearing session + credential vault")
        store.invalidate()
        vault.clear()
        session = None

    if (
        session is not None
        and not session.is_expired()
        and session.nexus_url.rstrip("/") == settings.nexus_url.rstrip("/")
    ):
        creds = vault.load()
        if (
            creds is not None
            and not creds.is_expired()
            and creds.matches(settings.nexus_url, session.username)
        ):
            logger.info(
                "Restored credentials from encrypted vault (user=%s, until=%s)",
                creds.username,
                creds.expires_at,
            )
            return settings.model_copy(
                update={
                    "nexus_username": creds.username,
                    "nexus_password": creds.password,
                }
            )
        # Сессия без валидного vault — не можем ходить в API с Basic Auth.
        logger.info("Session cache present but vault missing/invalid; clearing session")
        store.invalidate()
        vault.clear()

    env_user = (settings.nexus_username or "").strip()
    env_password = settings.nexus_password or ""
    if env_user and env_password:
        logger.info("Using Nexus credentials from environment / .env")
        return settings.model_copy(
            update={"nexus_username": env_user, "nexus_password": env_password}
        )

    username, password = prompt_nexus_credentials(default_username=env_user)
    return settings.model_copy(
        update={"nexus_username": username, "nexus_password": password}
    )
