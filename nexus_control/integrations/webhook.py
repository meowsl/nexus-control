"""Generic webhook: POST compact verify results to a user-configured URL.

Auth (optional): Bearer token, HTTP Basic (login/password), or a custom header.
Secrets live in env / encrypted vault — never in ``config.toml``.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import httpx
from cryptography.fernet import Fernet, InvalidToken

from nexus_control import __version__
from nexus_control.config import Settings
from nexus_control.models import AssetPipelineResult, PipelineSummary, ScanStatus
from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

VAULT_FILENAME = "webhook.vault"
KEY_FILENAME = ".vault_key"
EVENT_VERIFY = "verify.completed"
EVENT_TEST = "webhook.test"
USER_AGENT = f"nexus-control/{__version__}"
MAX_VULNS_PER_SCANNER = 20
MAX_DESCRIPTION = 500
VALID_AUTH: frozenset[str] = frozenset({"none", "bearer", "basic", "header"})
WebhookAuth = Literal["none", "bearer", "basic", "header"]

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(slots=True)
class WebhookPushResult:
    status_code: int | None = None
    skipped: bool = False
    error: str | None = None
    event: str = EVENT_VERIFY


class WebhookVault:
    """Шифрованное хранилище секретов вебхука (Fernet, ``0o600``).

    Использует тот же ``.vault_key``, что и Nexus / DefectDojo vault.
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.vault_path = cache_dir / VAULT_FILENAME
        self.key_path = cache_dir / KEY_FILENAME

    def save(
        self,
        *,
        url: str,
        auth: str = "none",
        token: str = "",
        username: str = "",
        password: str = "",
        header_name: str = "",
        header_value: str = "",
    ) -> None:
        ensure_dir(self.cache_dir, mode=0o700)
        payload = {
            "url": url.rstrip("/"),
            "auth": _normalize_auth(auth),
            "token": token,
            "username": username,
            "password": password,
            "header_name": header_name,
            "header_value": header_value,
        }
        token_bytes = self._fernet().encrypt(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )
        self._write_bytes(self.vault_path, token_bytes)
        logger.info("Webhook secrets saved to %s", self.vault_path.name)

    def load(self) -> dict[str, str] | None:
        """Вернуть dict с url/auth/секретами или ``None``."""
        if not self.vault_path.is_file() or not self.key_path.is_file():
            return None
        try:
            raw = self.vault_path.read_bytes()
            data = json.loads(self._fernet().decrypt(raw).decode("utf-8"))
        except (OSError, InvalidToken, json.JSONDecodeError, UnicodeError) as exc:
            logger.warning("Failed to read webhook vault: %s", exc)
            self.clear()
            return None
        if not isinstance(data, dict):
            self.clear()
            return None
        return {
            "url": str(data.get("url") or "").strip().rstrip("/"),
            "auth": _normalize_auth(str(data.get("auth") or "none")),
            "token": str(data.get("token") or ""),
            "username": str(data.get("username") or ""),
            "password": str(data.get("password") or ""),
            "header_name": str(data.get("header_name") or "").strip(),
            "header_value": str(data.get("header_value") or ""),
        }

    def clear(self) -> None:
        try:
            if self.vault_path.exists():
                self.vault_path.unlink()
                logger.info("Webhook vault cleared: %s", self.vault_path.name)
        except OSError as exc:
            logger.warning("Failed to remove %s: %s", self.vault_path, exc)

    def _fernet(self) -> Fernet:
        return Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        ensure_dir(self.cache_dir, mode=0o700)
        if self.key_path.is_file():
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        self._write_bytes(self.key_path, key)
        return key

    @staticmethod
    def _write_bytes(path: Path, data: bytes) -> None:
        path.write_bytes(data)
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _normalize_auth(value: str) -> str:
    text = (value or "none").strip().lower()
    if text in {"password", "login", "login-password", "userpass"}:
        return "basic"
    if text not in VALID_AUTH:
        return "none"
    return text


def resolve_webhook_settings(settings: Settings) -> Settings:
    """Подставить URL/секреты из env (уже в Settings) или из vault."""
    if not settings.webhook_enabled:
        return settings
    loaded = WebhookVault(settings.nexus_cache_dir).load()
    if loaded is None:
        return settings
    updates: dict[str, object] = {}
    if not (settings.webhook_url or "").strip() and loaded["url"]:
        updates["webhook_url"] = loaded["url"]
    if _normalize_auth(settings.webhook_auth) == "none" and loaded["auth"] != "none":
        updates["webhook_auth"] = loaded["auth"]
    if not (settings.webhook_token or "").strip() and loaded["token"]:
        updates["webhook_token"] = loaded["token"]
    if not (settings.webhook_username or "").strip() and loaded["username"]:
        updates["webhook_username"] = loaded["username"]
    if not (settings.webhook_password or "").strip() and loaded["password"]:
        updates["webhook_password"] = loaded["password"]
    if not (settings.webhook_header_name or "").strip() and loaded["header_name"]:
        updates["webhook_header_name"] = loaded["header_name"]
    if not (settings.webhook_header_value or "").strip() and loaded["header_value"]:
        updates["webhook_header_value"] = loaded["header_value"]
    if not updates:
        return settings
    return settings.model_copy(update=updates)


def build_auth(
    settings: Settings,
) -> tuple[dict[str, str], tuple[str, str] | None, str | None]:
    """``(headers, basic_tuple, error)``. error — если auth неполный."""
    auth = _normalize_auth(settings.webhook_auth)
    headers: dict[str, str] = {}
    if auth == "none":
        return headers, None, None
    if auth == "bearer":
        token = (settings.webhook_token or "").strip()
        if not token:
            return {}, None, "webhook auth=bearer but token is empty"
        headers["Authorization"] = f"Bearer {token}"
        return headers, None, None
    if auth == "basic":
        user = (settings.webhook_username or "").strip()
        password = settings.webhook_password or ""
        if not user:
            return {}, None, "webhook auth=basic but username is empty"
        return headers, (user, password), None
    name = (settings.webhook_header_name or "").strip()
    value = settings.webhook_header_value or ""
    if not name or not value:
        return {}, None, "webhook auth=header needs header name and value"
    if not _HEADER_NAME_RE.match(name):
        return {}, None, f"invalid webhook header name: {name!r}"
    headers[name] = value
    return headers, None, None


def _iso(value: object) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()  # type: ignore[no-any-return]
    text = str(value).strip()
    return text or None


def _vuln_dict(vuln: Any) -> dict[str, Any]:
    desc = vuln.description
    if desc and len(desc) > MAX_DESCRIPTION:
        desc = desc[: MAX_DESCRIPTION - 1] + "…"
    return {
        "id": vuln.id,
        "severity": vuln.severity.value,
        "package_name": vuln.package_name,
        "package_version": vuln.package_version,
        "fix_version": vuln.fix_version,
        "description": desc,
    }


def _asset_dict(result: AssetPipelineResult) -> dict[str, Any]:
    scans: dict[str, Any] = {}
    for name, scan in result.scans.items():
        scans[name] = {
            "status": scan.status.value,
            "verdict": scan.verdict.value,
            "counts": asdict(scan.counts),
            "vulnerabilities": [
                _vuln_dict(v) for v in scan.vulnerabilities[:MAX_VULNS_PER_SCANNER]
            ],
            "scanner": scan.scanner or name,
            "scanner_version": scan.scanner_version or scan.grype_version,
            "error": scan.error,
        }
    return {
        "path": result.asset_path,
        "kind": result.kind.value,
        "verdict": result.verdict.value,
        "scans": scans,
    }


def build_payload(
    summary: PipelineSummary,
    *,
    event: str = EVENT_VERIFY,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Компактный JSON для получателя вебхука (без native scanner dumps)."""
    skipped = sum(
        1
        for result in summary.results
        if result.scans
        and all(scan.status == ScanStatus.SKIPPED for scan in result.scans.values())
    )
    payload: dict[str, Any] = {
        "event": event,
        "source": "nexus-control",
        "version": __version__,
        "repository": summary.repository,
        "started_at": _iso(summary.started_at),
        "finished_at": _iso(summary.finished_at),
        "cancelled": bool(summary.cancelled),
        "scanners": list(summary.scanners),
        "scanner_versions": dict(summary.scanner_versions),
        "totals": {
            "assets": len(summary.results),
            "scanned": summary.total_scanned,
            "passed": summary.total_passed,
            "failed": summary.total_failed,
            "errors": summary.total_errors,
            "copied": summary.total_copied,
            "skipped": skipped,
        },
        "assets": [_asset_dict(result) for result in summary.results],
    }
    if extra:
        payload.update(extra)
    return payload


def build_test_payload() -> dict[str, Any]:
    return {
        "event": EVENT_TEST,
        "source": "nexus-control",
        "version": __version__,
        "message": "Webhook connectivity test from nexus-control",
    }


def post_webhook(
    settings: Settings,
    payload: dict[str, Any],
    *,
    event: str | None = None,
) -> WebhookPushResult:
    """POST JSON. Не бросает наружу — ошибка в ``WebhookPushResult.error``."""
    cfg = resolve_webhook_settings(settings)
    if not cfg.webhook_enabled:
        return WebhookPushResult(skipped=True, event=event or str(payload.get("event") or ""))
    url = (cfg.webhook_url or "").strip()
    if not url:
        return WebhookPushResult(
            skipped=True,
            error="webhook enabled but URL is empty",
            event=event or str(payload.get("event") or ""),
        )
    extra_headers, basic, auth_error = build_auth(cfg)
    if auth_error:
        return WebhookPushResult(
            skipped=True,
            error=auth_error,
            event=event or str(payload.get("event") or ""),
        )
    event_name = event or str(payload.get("event") or EVENT_VERIFY)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "X-Nexus-Control-Event": event_name,
        **extra_headers,
    }
    timeout = float(cfg.webhook_timeout or 15.0)
    try:
        with httpx.Client(
            timeout=timeout,
            verify=cfg.webhook_verify_ssl,
            follow_redirects=False,
        ) as client:
            response = client.post(
                url,
                json=payload,
                headers=headers,
                auth=basic,
            )
    except httpx.HTTPError as exc:
        logger.warning("Webhook POST failed: %s", exc)
        return WebhookPushResult(error=str(exc), event=event_name)
    if response.status_code >= 400:
        snippet = (response.text or "")[:300]
        logger.warning(
            "Webhook POST %s → HTTP %s: %s",
            url,
            response.status_code,
            snippet,
        )
        return WebhookPushResult(
            status_code=response.status_code,
            error=f"HTTP {response.status_code}: {snippet}",
            event=event_name,
        )
    logger.info("Webhook POST %s → HTTP %s", url, response.status_code)
    return WebhookPushResult(status_code=response.status_code, event=event_name)


def push_pipeline_results(
    settings: Settings,
    summary: PipelineSummary,
    *,
    extra: dict[str, Any] | None = None,
) -> WebhookPushResult:
    payload = build_payload(summary, extra=extra)
    return post_webhook(settings, payload, event=EVENT_VERIFY)


def push_test(settings: Settings) -> WebhookPushResult:
    return post_webhook(settings, build_test_payload(), event=EVENT_TEST)
