"""Интерактивный ввод и шифрованное хранение учётных данных Nexus.

Пароль **не** пишется в ``session.json``.

Два vault'а (Fernet, файлы ``0o600``, общий ключ ``.vault_key``):

* ``credentials.vault`` — session vault, TTL = Nexus-сессия; очищается
  при logout / expire / invalidate.
* ``credentials.scheduler.vault`` — долгоживущий vault для scheduler /
  non-interactive CLI; не привязан к session TTL; пишется через
  ``nexus-control-cli schedule login``, сброс — ``schedule logout``.
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
SCHEDULER_VAULT_FILENAME = "credentials.scheduler.vault"
KEY_FILENAME = ".vault_key"

NON_INTERACTIVE_CREDS_HINT = (
    "Nexus username/password are required for non-interactive use. "
    "Set NEXUS_USERNAME and NEXUS_PASSWORD in the environment or .env, "
    "or run: nexus-control-cli schedule login"
)


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
    """Шифрованное хранилище username/password.

    По умолчанию — session vault (с TTL). Для scheduler передайте
    ``filename=SCHEDULER_VAULT_FILENAME`` и ``persistent=True`` при save.
    """

    def __init__(
        self,
        cache_dir: Path,
        *,
        filename: str = VAULT_FILENAME,
    ) -> None:
        self.cache_dir = cache_dir
        self.vault_path = cache_dir / filename
        self.key_path = cache_dir / KEY_FILENAME
        self._persistent_file = filename == SCHEDULER_VAULT_FILENAME

    def save(
        self,
        *,
        nexus_url: str,
        username: str,
        password: str,
        expires_at: str = "",
        persistent: bool | None = None,
    ) -> None:
        ensure_dir(self.cache_dir, mode=0o700)
        is_persistent = (
            self._persistent_file if persistent is None else bool(persistent)
        )
        payload = {
            "nexus_url": nexus_url.rstrip("/"),
            "username": username,
            "password": password,
            "expires_at": expires_at,
            "config_hash": config_fingerprint(nexus_url, username),
            "persistent": is_persistent,
        }
        token = self._fernet().encrypt(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )
        self._write_bytes(self.vault_path, token)
        if is_persistent:
            logger.info(
                "Encrypted scheduler credentials saved (user=%s, file=%s)",
                username,
                self.vault_path.name,
            )
        else:
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
        is_persistent = bool(data.get("persistent")) or self._persistent_file
        if not is_persistent and creds.is_expired():
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
        """Удалить этот vault и локальный ключ шифрования."""
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


def scheduler_vault(cache_dir: Path) -> CredentialVault:
    """Долгоживущий vault для scheduler / non-interactive CLI."""
    return CredentialVault(cache_dir, filename=SCHEDULER_VAULT_FILENAME)


def prompt_nexus_credentials(default_username: str = "") -> tuple[str, str]:
    """Запросить username/password в терминале (до старта Textual)."""
    from nexus_control.i18n import _

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ConfigError(
            "NEXUS_USERNAME and NEXUS_PASSWORD are required in non-interactive "
            "mode (no TTY). Set them in the environment, config.toml, or legacy .env."
        )
    print(_("Nexus authentication"), file=sys.stderr)
    print(
        _(
            "Credentials are stored encrypted until the Nexus session expires "
            "(see NEXUS_SESSION_TTL / {vault}).",
            vault=VAULT_FILENAME,
        ),
        file=sys.stderr,
    )
    hint = f" [{default_username}]" if default_username else ""
    username = input(f"{_('Username')}{hint}: ").strip() or default_username.strip()
    if not username:
        raise ConfigError(_("Username is required"))
    password = getpass.getpass(_("Password: "))
    if not password:
        raise ConfigError(_("Password is required"))
    return username, password


def resolve_runtime_credentials(
    settings: Settings,
    *,
    allow_prompt: bool = True,
) -> Settings:
    """Вернуть Settings с заполненными username/password.

    Порядок:
    1. Активная Nexus-сессия + неистёкший session vault
    2. ``NEXUS_USERNAME`` + ``NEXUS_PASSWORD`` из env / .env (CI)
    3. Долгоживущий scheduler vault (``credentials.scheduler.vault``)
    4. Интерактивный prompt (TTY), если ``allow_prompt``
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
        logger.info("Using Nexus credentials from environment / config")
        return settings.model_copy(
            update={"nexus_username": env_user, "nexus_password": env_password}
        )

    persistent = scheduler_vault(settings.nexus_cache_dir).load()
    if persistent is not None and persistent.matches(
        settings.nexus_url,
        env_user or None,
    ):
        logger.info(
            "Restored credentials from scheduler vault (user=%s)",
            persistent.username,
        )
        return settings.model_copy(
            update={
                "nexus_username": persistent.username,
                "nexus_password": persistent.password,
            }
        )

    if not allow_prompt:
        raise ConfigError(NON_INTERACTIVE_CREDS_HINT)

    username, password = prompt_nexus_credentials(default_username=env_user)
    return settings.model_copy(
        update={"nexus_username": username, "nexus_password": password}
    )


def save_scheduler_credentials(
    settings: Settings,
    *,
    username: str,
    password: str,
) -> Path:
    """Сохранить долгоживущие креды для scheduler (без session TTL)."""
    vault = scheduler_vault(settings.nexus_cache_dir)
    vault.save(
        nexus_url=settings.nexus_url,
        username=username,
        password=password,
        expires_at="",
        persistent=True,
    )
    return vault.vault_path


def clear_scheduler_credentials(settings: Settings) -> bool:
    """Удалить scheduler vault. True если файл был."""
    vault = scheduler_vault(settings.nexus_cache_dir)
    existed = vault.vault_path.is_file()
    vault.clear()
    return existed
