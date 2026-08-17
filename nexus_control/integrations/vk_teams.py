"""Тонкий sync-клиент VK Teams Bot API (httpx) + Fernet-vault токена."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography.fernet import Fernet, InvalidToken

from nexus_control.config import Settings
from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

# Тот же `.vault_key`, что у Nexus credentials.vault.
VAULT_FILENAME = "vk-teams.vault"
KEY_FILENAME = ".vault_key"


class VkTeamsError(RuntimeError):
    """Ошибка вызова Bot API."""


@dataclass(slots=True)
class VkTeamsSecrets:
    token: str
    chat_id: str = ""


class VkTeamsVault:
    """Шифрованное хранилище bot token (+ опционально chat_id)."""

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = Path(cache_dir)
        self.vault_path = self.cache_dir / VAULT_FILENAME
        self.key_path = self.cache_dir / KEY_FILENAME

    @classmethod
    def from_settings(cls, settings: Settings) -> VkTeamsVault | None:
        cache = getattr(settings, "nexus_cache_dir", None)
        if not isinstance(cache, (str, Path)):
            return None
        try:
            return cls(Path(cache))
        except (TypeError, ValueError):
            return None

    def save(self, token: str, chat_id: str = "") -> None:
        token = (token or "").strip()
        if not token:
            raise ValueError("VK Teams token must not be empty")
        ensure_dir(self.cache_dir, mode=0o700)
        payload = {
            "token": token,
            "chat_id": (chat_id or "").strip(),
        }
        blob = self._fernet().encrypt(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )
        self._write_bytes(self.vault_path, blob)
        logger.info("VK Teams vault saved: %s", self.vault_path)

    def load(self) -> VkTeamsSecrets | None:
        if not self.vault_path.is_file():
            return None
        try:
            raw = self.vault_path.read_bytes()
            if not raw:
                return None
            payload = json.loads(self._fernet().decrypt(raw).decode("utf-8"))
        except (OSError, InvalidToken, ValueError, TypeError) as exc:
            logger.warning("Failed to read VK Teams vault: %s", exc)
            return None
        if not isinstance(payload, dict):
            return None
        token = str(payload.get("token") or "").strip()
        if not token:
            return None
        return VkTeamsSecrets(
            token=token,
            chat_id=str(payload.get("chat_id") or "").strip(),
        )

    def exists(self) -> bool:
        return self.vault_path.is_file()

    def clear(self) -> None:
        """Удалить только vk-teams.vault; `.vault_key` общий с Nexus."""
        try:
            if self.vault_path.exists():
                self.vault_path.unlink()
                logger.info("VK Teams vault cleared: %s", self.vault_path)
        except OSError as exc:
            logger.warning("Failed to remove VK Teams vault: %s", exc)

    def _fernet(self) -> Fernet:
        return Fernet(self._load_or_create_key())

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


def apply_vk_teams_vault(settings: Settings) -> Settings:
    """Подставить token/chat_id из vault, если в Settings пусто."""
    if not isinstance(settings, Settings):
        return settings
    token = (settings.vk_teams_token or "").strip()
    chat_id = (settings.vk_teams_chat_id or "").strip()
    if token and chat_id:
        return settings
    vault = VkTeamsVault.from_settings(settings)
    stored = vault.load() if vault is not None else None
    if stored is None:
        return settings
    update: dict[str, str] = {}
    if not token and stored.token:
        update["vk_teams_token"] = stored.token
    if not chat_id and stored.chat_id:
        update["vk_teams_chat_id"] = stored.chat_id
    if not update:
        return settings
    return settings.model_copy(update=update)


def vk_teams_token_source(settings: Settings) -> str:
    """Откуда взят токен: env | config | vault | missing (без раскрытия секрета)."""
    env_tok = (
        os.environ.get("VK_TEAMS_TOKEN") or os.environ.get("vk_teams_token") or ""
    ).strip()
    if env_tok:
        return "env"
    if (getattr(settings, "vk_teams_token", "") or "").strip():
        return "config"
    vault = VkTeamsVault.from_settings(settings)
    stored = vault.load() if vault is not None else None
    if stored is not None and stored.token:
        return "vault"
    return "missing"


@dataclass(slots=True)
class VkTeamsEvent:
    event_id: int
    type: str
    payload: dict[str, Any]


@dataclass(slots=True)
class VkTeamsClient:
    """Минимальный клиент: sendText / getEvents / answerCallback / editText."""

    token: str
    api_url: str
    verify_ssl: bool = True
    timeout: float = 30.0

    @classmethod
    def from_settings(cls, settings: Settings) -> VkTeamsClient:
        cfg = apply_vk_teams_vault(settings)
        return cls(
            token=cfg.vk_teams_token.strip(),
            api_url=cfg.vk_teams_api_url.rstrip("/"),
            verify_ssl=bool(cfg.vk_teams_verify_ssl),
            timeout=float(cfg.vk_teams_timeout),
        )

    def _client(self, *, timeout: float | None = None) -> httpx.Client:
        return httpx.Client(
            base_url=self.api_url,
            timeout=timeout if timeout is not None else self.timeout,
            verify=self.verify_ssl,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        query = {"token": self.token}
        if params:
            query.update({k: v for k, v in params.items() if v is not None})
        try:
            with self._client(timeout=timeout) as client:
                response = client.request(method, path, params=query, data=data)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise VkTeamsError(f"VK Teams HTTP error: {exc}") from exc
        except ValueError as exc:
            raise VkTeamsError(f"VK Teams invalid JSON: {exc}") from exc
        if not isinstance(body, dict):
            raise VkTeamsError(f"VK Teams unexpected response: {body!r}")
        if body.get("ok") is False:
            raise VkTeamsError(
                f"VK Teams API error: {body.get('description') or body}"
            )
        return body

    def send_text(
        self,
        chat_id: str,
        text: str,
        *,
        parse_mode: str | None = "HTML",
        inline_keyboard: list[list[dict[str, str]]] | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "chatId": chat_id,
            "text": text,
        }
        if parse_mode:
            data["parseMode"] = parse_mode
        if inline_keyboard is not None:
            data["inlineKeyboardMarkup"] = json.dumps(
                inline_keyboard,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        return self._request("POST", "/messages/sendText", data=data)

    def edit_text(
        self,
        chat_id: str,
        msg_id: str | int,
        text: str,
        *,
        parse_mode: str | None = "HTML",
        inline_keyboard: list[list[dict[str, str]]] | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "chatId": chat_id,
            "msgId": str(msg_id),
            "text": text,
        }
        if parse_mode:
            data["parseMode"] = parse_mode
        if inline_keyboard is not None:
            data["inlineKeyboardMarkup"] = json.dumps(
                inline_keyboard,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        else:
            # Empty keyboard removes buttons.
            data["inlineKeyboardMarkup"] = "[]"
        return self._request("POST", "/messages/editText", data=data)

    def answer_callback_query(
        self,
        query_id: str,
        *,
        text: str | None = None,
        show_alert: bool = False,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"queryId": query_id}
        if text:
            data["text"] = text
        if show_alert:
            data["showAlert"] = "true"
        return self._request("GET", "/messages/answerCallbackQuery", params=data)

    def get_events(
        self,
        last_event_id: int = 0,
        *,
        poll_time: int = 25,
    ) -> list[VkTeamsEvent]:
        # Long-poll: timeout must exceed pollTime.
        http_timeout = float(max(self.timeout, poll_time + 5))
        body = self._request(
            "GET",
            "/events/get",
            params={
                "lastEventId": last_event_id,
                "pollTime": max(1, int(poll_time)),
            },
            timeout=http_timeout,
        )
        raw = body.get("events") or []
        out: list[VkTeamsEvent] = []
        if not isinstance(raw, list):
            return out
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                event_id = int(item.get("eventId") or 0)
            except (TypeError, ValueError):
                continue
            etype = str(item.get("type") or "")
            payload = item.get("payload")
            if not isinstance(payload, dict):
                payload = {}
            out.append(
                VkTeamsEvent(event_id=event_id, type=etype, payload=payload)
            )
        return out


def upload_keyboard(callback_data: str, *, label: str = "Загрузить в Nexus") -> list[
    list[dict[str, str]]
]:
    """Одна кнопка «Загрузить в Nexus» с callbackData ``up:<token>``."""
    return [[{"text": label, "callbackData": callback_data}]]
