"""Login against the configured Nexus instance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from nexus_control.nexus.errors import NexusAuthError, NexusNetworkError
from nexus_control.web.db import get_db
from nexus_control.web.deps import (
    cookie_secure,
    current_session,
    open_client,
    pack_creds,
)
from nexus_control.web.orm import AuthSession

router = APIRouter(tags=["auth"])
COOKIE = "nx_session"


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


@router.post("/auth/login")
def login(body: LoginBody, response: Response, db: Session = Depends(get_db)) -> dict:
    client = None
    try:
        client = open_client(body.username.strip(), body.password)
        client.list_repositories()
    except NexusAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except NexusNetworkError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        if client is not None:
            client.close()

    row = AuthSession(
        username=body.username.strip(),
        creds_blob=pack_creds(body.username.strip(), body.password),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=12),
    )
    db.add(row)
    db.flush()
    response.set_cookie(
        COOKIE,
        row.id,
        httponly=True,
        samesite="lax",
        secure=cookie_secure(),
        max_age=12 * 3600,
        path="/",
    )
    return {"username": row.username}


@router.post("/auth/logout")
def logout(
    response: Response,
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    db.delete(session)
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/me")
def me(session: AuthSession = Depends(current_session)) -> dict[str, str]:
    return {"username": session.username}
