"""Детект SSL certificate errors."""

from __future__ import annotations

import ssl

import httpx

from nexus_control.nexus.errors import NexusNetworkError, is_ssl_certificate_error


def test_detects_ssl_cert_verification_error() -> None:
    cause = ssl.SSLCertVerificationError("certificate verify failed")
    wrapped = NexusNetworkError("Network error talking to Nexus: …")
    wrapped.__cause__ = cause
    assert is_ssl_certificate_error(wrapped)


def test_detects_message_markers() -> None:
    exc = httpx.ConnectError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
    )
    assert is_ssl_certificate_error(exc)


def test_ignores_plain_network_errors() -> None:
    assert not is_ssl_certificate_error(NexusNetworkError("Connection refused"))
    assert not is_ssl_certificate_error(TimeoutError("timed out"))


def test_detects_self_signed_in_cause_chain() -> None:
    reason = ssl.SSLCertVerificationError("self signed certificate")
    chain = NexusNetworkError("Network error talking to Nexus")
    chain.__cause__ = reason
    assert is_ssl_certificate_error(chain)
