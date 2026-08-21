"""Shared helpers for the console API."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Cookie, Depends, HTTPException
from sqlalchemy.orm import Session

from nexus_control.config import Settings, load_settings
from nexus_control.nexus.client import NexusClient
from nexus_control.web.crypto import decrypt_secret, encrypt_secret
from nexus_control.web.db import get_db
from nexus_control.web.orm import AuthSession, Label, RepoLabel


def secret_key() -> str:
    key = os.environ.get("NEXUS_CONTROL_SECRET", "").strip()
    if not key or key == "change-me":
        # Dev fallback; compose must override.
        return "dev-only-insecure-secret-key-change-me"
    return key


def cookie_secure() -> bool:
    return os.environ.get("NEXUS_CONTROL_COOKIE_SECURE", "false").lower() in {
        "1",
        "true",
        "yes",
    }


def settings_for(username: str, password: str, db: Session | None = None) -> Settings:
    base = load_settings(run_wizard=False)
    cfg = base.model_copy(
        update={"nexus_username": username, "nexus_password": password}
    )
    if db is not None:
        from nexus_control.web.integrations import apply_web_integrations

        cfg = apply_web_integrations(cfg, db)
    return cfg


def open_client(username: str, password: str) -> NexusClient:
    client = NexusClient(settings_for(username, password))
    client.open()
    return client


def pack_creds(username: str, password: str) -> str:
    payload = json.dumps({"u": username, "p": password}, separators=(",", ":"))
    return encrypt_secret(secret_key(), payload)


def unpack_creds(blob: str) -> tuple[str, str]:
    raw = json.loads(decrypt_secret(secret_key(), blob))
    return str(raw["u"]), str(raw["p"])


def current_session(
    nx_session: str | None = Cookie(default=None, alias="nx_session"),
    db: Session = Depends(get_db),
) -> AuthSession:
    if not nx_session:
        raise HTTPException(status_code=401, detail="Not signed in")
    row = db.get(AuthSession, nx_session)
    now = datetime.now(timezone.utc)
    if row is None or row.expires_at < now:
        if row is not None:
            db.delete(row)
        raise HTTPException(status_code=401, detail="Session expired")
    row.expires_at = now + timedelta(hours=12)
    return row


def labels_for_repos(db: Session, names: list[str]) -> dict[str, list[dict[str, Any]]]:
    if not names:
        return {}
    rows = (
        db.query(RepoLabel, Label)
        .join(Label, RepoLabel.label_id == Label.id)
        .filter(RepoLabel.repo_name.in_(names))
        .all()
    )
    out: dict[str, list[dict[str, Any]]] = {n: [] for n in names}
    for rl, label in rows:
        out.setdefault(rl.repo_name, []).append(
            {
                "id": label.id,
                "name": label.name,
                "color": label.color,
                "description": label.description,
            }
        )
    return out


def repos_for_label_name(db: Session, label_name: str) -> list[str]:
    rows = (
        db.query(RepoLabel.repo_name)
        .join(Label, RepoLabel.label_id == Label.id)
        .filter(Label.name == label_name)
        .all()
    )
    return [r[0] for r in rows]


def expand_repo_selectors(db: Session, selectors: list[str]) -> list[str]:
    """Resolve ``label:name`` selectors to repository names."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in selectors:
        item = (raw or "").strip()
        if not item:
            continue
        if item.lower().startswith("label:"):
            names = repos_for_label_name(db, item.split(":", 1)[1].strip())
        else:
            names = [item]
        for name in names:
            if name not in seen:
                seen.add(name)
                out.append(name)
    return out
