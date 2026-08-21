"""Harbor-like labels stored in our database."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from nexus_control.web.db import get_db
from nexus_control.web.deps import current_session
from nexus_control.web.orm import AuthSession, Label, RepoLabel

router = APIRouter(tags=["labels"])
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")
COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


class LabelIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    color: str = Field(default="#3D7EA6", max_length=16)
    description: str = Field(default="", max_length=256)


class RepoLabelsIn(BaseModel):
    label_ids: list[str] = Field(default_factory=list)


def _label_json(row: Label) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "color": row.color,
        "description": row.description,
    }


@router.get("/labels")
def list_labels(
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> list[dict]:
    rows = db.query(Label).order_by(Label.name.asc()).all()
    return [_label_json(r) for r in rows]


@router.post("/labels", status_code=201)
def create_label(
    body: LabelIn,
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> dict:
    name = body.name.strip()
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid label name")
    color = body.color.strip() or "#3D7EA6"
    if not COLOR_RE.match(color):
        raise HTTPException(status_code=400, detail="color must be #RRGGBB")
    if db.query(Label).filter(Label.name == name).first():
        raise HTTPException(status_code=409, detail="label already exists")
    row = Label(name=name, color=color, description=body.description.strip())
    db.add(row)
    db.flush()
    return _label_json(row)


@router.delete("/labels/{label_id}")
def delete_label(
    label_id: str,
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> dict[str, bool]:
    row = db.get(Label, label_id)
    if row is None:
        raise HTTPException(status_code=404, detail="label not found")
    db.delete(row)
    return {"ok": True}


@router.put("/repos/{repo_name}/labels")
def set_repo_labels(
    repo_name: str,
    body: RepoLabelsIn,
    db: Session = Depends(get_db),
    _session: AuthSession = Depends(current_session),
) -> dict:
    db.query(RepoLabel).filter(RepoLabel.repo_name == repo_name).delete()
    for lid in body.label_ids:
        if db.get(Label, lid) is None:
            raise HTTPException(status_code=400, detail=f"unknown label {lid}")
        db.add(RepoLabel(repo_name=repo_name, label_id=lid))
    db.flush()
    return {"ok": True, "count": len(body.label_ids)}
