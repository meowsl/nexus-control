"""Исключения REST API клиента Nexus."""

from __future__ import annotations


class NexusAPIError(Exception):
    """Базовая ошибка Nexus API с опциональным HTTP-статусом."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class NexusAuthError(NexusAPIError):
    """Ошибка аутентификации / авторизации."""


class NexusNotFoundError(NexusAPIError):
    """Ресурс не найден."""


class NexusNetworkError(NexusAPIError):
    """Ошибка подключения / транспорта."""
