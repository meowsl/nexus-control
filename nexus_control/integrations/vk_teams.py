"""Тонкий sync-клиент VK Teams Bot API (httpx)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from nexus_control.config import Settings

logger = logging.getLogger(__name__)


class VkTeamsError(RuntimeError):
    """Ошибка вызова Bot API."""


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
        return cls(
            token=settings.vk_teams_token.strip(),
            api_url=settings.vk_teams_api_url.rstrip("/"),
            verify_ssl=bool(settings.vk_teams_verify_ssl),
            timeout=float(settings.vk_teams_timeout),
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


def upload_keyboard(callback_data: str, *, label: str = "Upload") -> list[
    list[dict[str, str]]
]:
    """Одна кнопка Upload с callbackData ``up:<token>``."""
    return [[{"text": label, "callbackData": callback_data}]]
