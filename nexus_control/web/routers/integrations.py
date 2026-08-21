"""Configure DefectDojo, webhook, and VK Teams from the web UI."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from nexus_control.config import ConfigError
from nexus_control.web.db import get_db
from nexus_control.web.deps import current_session
from nexus_control.web.integrations import (
    runtime_settings,
    save_defectdojo,
    save_vk_teams,
    save_webhook,
    snapshot,
)
from nexus_control.web.orm import AuthSession

router = APIRouter(tags=["integrations"])


class DefectDojoIn(BaseModel):
    enabled: bool = False
    url: str = ""
    verify_ssl: bool = True
    product_name: str = "nexus-control"
    engagement_name: str = ""
    product_type_name: str = "Nexus"
    api_key: str = ""


class WebhookIn(BaseModel):
    enabled: bool = False
    url: str = ""
    auth: str = "none"
    verify_ssl: bool = True
    timeout: float = Field(default=15.0, ge=1.0, le=120.0)
    header_name: str = ""
    username: str = ""
    token: str = ""
    password: str = ""
    header_value: str = ""


class VkTeamsIn(BaseModel):
    enabled: bool = False
    notify: str = "off"
    api_url: str = "https://myteam.mail.ru/bot/v1"
    chat_id: str = ""
    upload_button: bool = True
    verify_ssl: bool = True
    timeout: float = Field(default=30.0, ge=1.0)
    token: str = ""


@router.get("/integrations")
def get_integrations(
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    settings = runtime_settings(
        db, username=session.username, password="", run_wizard=False
    )
    return snapshot(db, settings)


@router.put("/integrations/defectdojo")
def put_defectdojo(
    body: DefectDojoIn,
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    try:
        save_defectdojo(db, body.model_dump(), username=session.username)
    except (ValueError, ConfigError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    settings = runtime_settings(db, run_wizard=False)
    return snapshot(db, settings)["defectdojo"]


@router.put("/integrations/webhook")
def put_webhook(
    body: WebhookIn,
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    try:
        save_webhook(db, body.model_dump(), username=session.username)
    except (ValueError, ConfigError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    settings = runtime_settings(db, run_wizard=False)
    return snapshot(db, settings)["webhook"]


@router.put("/integrations/vk-teams")
def put_vk_teams(
    body: VkTeamsIn,
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    try:
        save_vk_teams(db, body.model_dump(), username=session.username)
    except (ValueError, ConfigError) as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    settings = runtime_settings(db, run_wizard=False)
    return snapshot(db, settings)["vk_teams"]


@router.post("/integrations/defectdojo/test")
def test_defectdojo(
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    from nexus_control.integrations.defectdojo import ping_defectdojo

    settings = runtime_settings(db, run_wizard=False)
    result = ping_defectdojo(settings)
    ok = result.error is None and not result.skipped
    if not ok:
        raise HTTPException(
            status_code=400, detail=result.error or "DefectDojo is not configured"
        )
    return {"ok": True, "status_code": result.status_code}


@router.post("/integrations/webhook/test")
def test_webhook(
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    from nexus_control.integrations.webhook import push_test, resolve_webhook_settings

    settings = resolve_webhook_settings(runtime_settings(db, run_wizard=False))
    result = push_test(settings)
    ok = result.error is None and not result.skipped
    if not ok:
        raise HTTPException(
            status_code=400, detail=result.error or "Webhook is not configured"
        )
    return {"ok": True, "status_code": result.status_code}


@router.post("/integrations/vk-teams/test")
def test_vk_teams(
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    from nexus_control.integrations.vk_teams import (
        VkTeamsClient,
        VkTeamsError,
        apply_vk_teams_vault,
    )

    cfg = apply_vk_teams_vault(runtime_settings(db, run_wizard=False))
    if not cfg.vk_teams_token.strip() or not cfg.vk_teams_chat_id.strip():
        raise HTTPException(status_code=400, detail="VK Teams is not configured")
    try:
        VkTeamsClient.from_settings(cfg).send_text(
            cfg.vk_teams_chat_id,
            "🔍 <b>Nexus Control</b>\nПроверка связи из веб-интерфейса — всё работает.",
            parse_mode="HTML",
        )
    except VkTeamsError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "chat_id": cfg.vk_teams_chat_id}
