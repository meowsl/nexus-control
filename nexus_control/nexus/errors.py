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


def is_ssl_certificate_error(exc: BaseException) -> bool:
    """True, если цепочка исключений указывает на ошибку проверки TLS-сертификата."""
    markers = (
        "certificate verify failed",
        "certificate_verify_failed",
        "sslcertverificationerror",
        "ssl: certificate_verify_failed",
        "unable to get local issuer certificate",
        "self signed certificate",
        "self-signed certificate",
        "cert verification",
    )
    type_names = {
        "SSLCertVerificationError",
        "CertificateError",
        "SSLError",
    }
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if type(current).__name__ in type_names:
            return True
        text = str(current).lower()
        if any(marker in text for marker in markers):
            return True
        # httpx иногда кладёт причину в ``.reason`` у ConnectError
        reason = getattr(current, "reason", None)
        if isinstance(reason, BaseException) and id(reason) not in seen:
            current = reason
            continue
        current = current.__cause__ or current.__context__
    return False
