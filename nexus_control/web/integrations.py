"""Persist web-managed integrations in Postgres and overlay onto Settings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from nexus_control.config import Settings
from nexus_control.config_wizard import normalize_nexus_url
from nexus_control.integrations.defectdojo import resolve_defectdojo_settings
from nexus_control.integrations.vk_notify import vk_teams_configured
from nexus_control.integrations.vk_teams import apply_vk_teams_vault
from nexus_control.integrations.webhook import VALID_AUTH, resolve_webhook_settings
from nexus_control.web.crypto import decrypt_secret, encrypt_secret
from nexus_control.web.deps import secret_key
from nexus_control.web.orm import IntegrationConfig


def _load_json(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _decrypt_secrets(blob: str) -> dict[str, str]:
    if not (blob or "").strip():
        return {}
    try:
        data = json.loads(decrypt_secret(secret_key(), blob))
    except (ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) if v is not None else "" for k, v in data.items()}


def _encrypt_secrets(values: dict[str, str]) -> str:
    payload = {k: v for k, v in values.items() if (v or "").strip()}
    if not payload:
        return ""
    return encrypt_secret(secret_key(), json.dumps(payload, separators=(",", ":")))


def get_row(db: Session, integration_id: str) -> IntegrationConfig | None:
    return db.get(IntegrationConfig, integration_id)


def apply_web_integrations(settings: Settings, db: Session) -> Settings:
    """Overlay web DB rows onto Settings. Missing rows leave env/toml/vault as-is."""
    updates: dict[str, Any] = {}
    for row in db.query(IntegrationConfig).all():
        if row.id == "defectdojo":
            updates.update(_defectdojo_updates(row))
        elif row.id == "webhook":
            updates.update(_webhook_updates(row))
        elif row.id == "vk_teams":
            updates.update(_vk_updates(row))
    if not updates:
        return settings
    return settings.model_copy(update=updates)


def runtime_settings(
    db: Session,
    *,
    username: str = "",
    password: str = "",
    run_wizard: bool = False,
) -> Settings:
    from nexus_control.config import load_settings

    cfg = load_settings(run_wizard=run_wizard)
    if username:
        cfg = cfg.model_copy(
            update={"nexus_username": username, "nexus_password": password}
        )
    return apply_web_integrations(cfg, db)


def _defectdojo_updates(row: IntegrationConfig) -> dict[str, Any]:
    cfg = _load_json(row.config_json)
    secrets = _decrypt_secrets(row.secrets_blob)
    out: dict[str, Any] = {
        "defectdojo_enabled": bool(row.enabled),
        "defectdojo_url": str(cfg.get("url") or "").strip(),
        "defectdojo_verify_ssl": bool(cfg.get("verify_ssl", True)),
        "defectdojo_product_name": str(cfg.get("product_name") or "nexus-control"),
        "defectdojo_engagement_name": str(cfg.get("engagement_name") or ""),
        "defectdojo_product_type_name": str(cfg.get("product_type_name") or "Nexus"),
    }
    if secrets.get("api_key"):
        out["defectdojo_api_key"] = secrets["api_key"]
    return out


def _webhook_updates(row: IntegrationConfig) -> dict[str, Any]:
    cfg = _load_json(row.config_json)
    secrets = _decrypt_secrets(row.secrets_blob)
    auth = str(cfg.get("auth") or "none").strip().lower()
    if auth not in VALID_AUTH:
        auth = "none"
    out: dict[str, Any] = {
        "webhook_enabled": bool(row.enabled),
        "webhook_url": str(cfg.get("url") or "").strip(),
        "webhook_auth": auth,
        "webhook_verify_ssl": bool(cfg.get("verify_ssl", True)),
        "webhook_timeout": float(cfg.get("timeout") or 15),
        "webhook_header_name": str(cfg.get("header_name") or ""),
    }
    for src, dst in (
        ("token", "webhook_token"),
        ("username", "webhook_username"),
        ("password", "webhook_password"),
        ("header_value", "webhook_header_value"),
    ):
        if secrets.get(src):
            out[dst] = secrets[src]
    return out


def _vk_updates(row: IntegrationConfig) -> dict[str, Any]:
    cfg = _load_json(row.config_json)
    secrets = _decrypt_secrets(row.secrets_blob)
    notify = str(cfg.get("notify") or "off").strip().lower()
    if notify not in {"off", "always", "failures"}:
        notify = "off"
    if not row.enabled:
        notify = "off"
    out: dict[str, Any] = {
        "vk_teams_notify": notify,
        "vk_teams_api_url": str(
            cfg.get("api_url") or "https://myteam.mail.ru/bot/v1"
        ).rstrip("/"),
        "vk_teams_chat_id": str(cfg.get("chat_id") or ""),
        "vk_teams_upload_button": bool(cfg.get("upload_button", True)),
        "vk_teams_verify_ssl": bool(cfg.get("verify_ssl", True)),
    }
    timeout = cfg.get("timeout")
    if timeout is not None:
        try:
            out["vk_teams_timeout"] = float(timeout)
        except (TypeError, ValueError):
            pass
    if secrets.get("token"):
        out["vk_teams_token"] = secrets["token"]
    return out


def snapshot(db: Session, settings: Settings) -> dict[str, Any]:
    """Public (no secrets) view of all integrations."""
    effective = apply_web_integrations(settings, db)
    return {
        "defectdojo": _snapshot_defectdojo(db, effective),
        "webhook": _snapshot_webhook(db, effective),
        "vk_teams": _snapshot_vk(db, effective),
    }


def _source(db: Session, integration_id: str) -> str:
    row = get_row(db, integration_id)
    return "web" if row is not None else "env"


def _snapshot_defectdojo(db: Session, settings: Settings) -> dict[str, Any]:
    cfg = resolve_defectdojo_settings(settings)
    row = get_row(db, "defectdojo")
    return {
        "id": "defectdojo",
        "source": _source(db, "defectdojo"),
        "enabled": bool(cfg.defectdojo_enabled),
        "url": cfg.defectdojo_url or "",
        "verify_ssl": bool(cfg.defectdojo_verify_ssl),
        "product_name": cfg.defectdojo_product_name or "nexus-control",
        "engagement_name": cfg.defectdojo_engagement_name or "",
        "product_type_name": cfg.defectdojo_product_type_name or "Nexus",
        "api_key_set": bool((cfg.defectdojo_api_key or "").strip()),
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
        "updated_by": row.updated_by if row else "",
    }


def _snapshot_webhook(db: Session, settings: Settings) -> dict[str, Any]:
    cfg = resolve_webhook_settings(settings)
    row = get_row(db, "webhook")
    return {
        "id": "webhook",
        "source": _source(db, "webhook"),
        "enabled": bool(cfg.webhook_enabled),
        "url": cfg.webhook_url or "",
        "auth": cfg.webhook_auth,
        "verify_ssl": bool(cfg.webhook_verify_ssl),
        "timeout": cfg.webhook_timeout,
        "header_name": cfg.webhook_header_name or "",
        "username": cfg.webhook_username or "",
        "token_set": bool((cfg.webhook_token or "").strip()),
        "password_set": bool(cfg.webhook_password),
        "header_value_set": bool(cfg.webhook_header_value),
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
        "updated_by": row.updated_by if row else "",
    }


def _snapshot_vk(db: Session, settings: Settings) -> dict[str, Any]:
    cfg = apply_vk_teams_vault(settings)
    row = get_row(db, "vk_teams")
    enabled = bool(row.enabled) if row is not None else vk_teams_configured(cfg)
    return {
        "id": "vk_teams",
        "source": _source(db, "vk_teams"),
        "enabled": enabled,
        "notify": cfg.vk_teams_notify,
        "api_url": cfg.vk_teams_api_url or "",
        "chat_id": cfg.vk_teams_chat_id or "",
        "upload_button": bool(cfg.vk_teams_upload_button),
        "verify_ssl": bool(cfg.vk_teams_verify_ssl),
        "timeout": cfg.vk_teams_timeout,
        "token_set": bool((cfg.vk_teams_token or "").strip()),
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
        "updated_by": row.updated_by if row else "",
    }


def _upsert(
    db: Session,
    integration_id: str,
    *,
    enabled: bool,
    config: dict[str, Any],
    new_secrets: dict[str, str],
    username: str,
) -> IntegrationConfig:
    row = get_row(db, integration_id)
    if row is None:
        row = IntegrationConfig(id=integration_id)
        db.add(row)
    existing = _decrypt_secrets(row.secrets_blob)
    merged = dict(existing)
    for key, value in new_secrets.items():
        if value.strip():
            merged[key] = value.strip()
    row.enabled = enabled
    row.config_json = json.dumps(config, ensure_ascii=False)
    row.secrets_blob = _encrypt_secrets(merged)
    row.updated_by = username
    row.updated_at = datetime.now(timezone.utc)
    db.flush()
    return row


def save_defectdojo(
    db: Session,
    body: dict[str, Any],
    *,
    username: str,
) -> IntegrationConfig:
    url = str(body.get("url") or "").strip()
    if body.get("enabled") and url:
        url = normalize_nexus_url(url)
    return _upsert(
        db,
        "defectdojo",
        enabled=bool(body.get("enabled")),
        config={
            "url": url,
            "verify_ssl": bool(body.get("verify_ssl", True)),
            "product_name": str(body.get("product_name") or "nexus-control").strip()
            or "nexus-control",
            "engagement_name": str(body.get("engagement_name") or "").strip(),
            "product_type_name": str(body.get("product_type_name") or "Nexus").strip()
            or "Nexus",
        },
        new_secrets={"api_key": str(body.get("api_key") or "")},
        username=username,
    )


def save_webhook(
    db: Session,
    body: dict[str, Any],
    *,
    username: str,
) -> IntegrationConfig:
    url = str(body.get("url") or "").strip()
    if body.get("enabled") and url:
        url = normalize_nexus_url(url)
    auth = str(body.get("auth") or "none").strip().lower()
    if auth not in VALID_AUTH:
        raise ValueError("auth must be none|bearer|basic|header")
    timeout = float(body.get("timeout") or 15)
    if timeout < 1 or timeout > 120:
        raise ValueError("timeout must be 1–120")
    return _upsert(
        db,
        "webhook",
        enabled=bool(body.get("enabled")),
        config={
            "url": url,
            "auth": auth,
            "verify_ssl": bool(body.get("verify_ssl", True)),
            "timeout": timeout,
            "header_name": str(body.get("header_name") or "").strip(),
        },
        new_secrets={
            "token": str(body.get("token") or ""),
            "username": str(body.get("username") or ""),
            "password": str(body.get("password") or ""),
            "header_value": str(body.get("header_value") or ""),
        },
        username=username,
    )


def save_vk_teams(
    db: Session,
    body: dict[str, Any],
    *,
    username: str,
) -> IntegrationConfig:
    notify = str(body.get("notify") or "off").strip().lower()
    if notify not in {"off", "always", "failures"}:
        raise ValueError("notify must be off|always|failures")
    enabled = bool(body.get("enabled", notify != "off"))
    if not enabled:
        notify = "off"
    elif notify == "off":
        notify = "always"
    api_url = str(body.get("api_url") or "https://myteam.mail.ru/bot/v1").strip()
    if api_url:
        api_url = normalize_nexus_url(api_url)
    return _upsert(
        db,
        "vk_teams",
        enabled=enabled,
        config={
            "notify": notify,
            "api_url": api_url,
            "chat_id": str(body.get("chat_id") or "").strip(),
            "upload_button": bool(body.get("upload_button", True)),
            "verify_ssl": bool(body.get("verify_ssl", True)),
            "timeout": float(body.get("timeout") or 30),
        },
        new_secrets={"token": str(body.get("token") or "")},
        username=username,
    )
