"""Repository list synced from Nexus + our labels."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from nexus_control.models import Repository
from nexus_control.web.db import get_db
from nexus_control.web.deps import current_session, labels_for_repos, open_client, unpack_creds
from nexus_control.web.orm import AuthSession

router = APIRouter(tags=["repos"])


def _repo_json(r: Repository, labels: list[dict[str, Any]]) -> dict:
    return {
        "name": r.name,
        "format": r.format,
        "type": r.type,
        "url": r.url,
        "support": r.support_level,
        "labels": labels,
    }


@router.get("/repos")
def list_repos(
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> list[dict]:
    user, password = unpack_creds(session.creds_blob)
    client = open_client(user, password)
    try:
        repos = client.list_repositories()
    finally:
        client.close()
    labels = labels_for_repos(db, [r.name for r in repos])
    return [_repo_json(r, labels.get(r.name, [])) for r in repos]


@router.get("/repos/{name}")
def get_repo(
    name: str,
    session: AuthSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> dict:
    user, password = unpack_creds(session.creds_blob)
    client = open_client(user, password)
    try:
        repo = client.get_repository(name)
    finally:
        client.close()
    if repo is None:
        raise HTTPException(status_code=404, detail="repository not found")
    labels = labels_for_repos(db, [repo.name])
    return _repo_json(repo, labels.get(repo.name, []))


@router.get("/repos/{name}/assets")
def list_assets(
    name: str,
    continuation: str | None = Query(default=None),
    session: AuthSession = Depends(current_session),
) -> dict:
    from nexus_control.nexus.assets import parse_assets_page

    user, password = unpack_creds(session.creds_blob)
    client = open_client(user, password)
    try:
        repo = client.get_repository(name)
        if repo is None:
            raise HTTPException(status_code=404, detail="repository not found")
        params: dict = {"repository": name}
        if continuation:
            params["continuationToken"] = continuation
        data = client._request_json("GET", "/service/rest/v1/assets", params=params)
        items, token = parse_assets_page(data)
    finally:
        client.close()
    return {
        "repository": name,
        "continuation": token,
        "items": [
            {
                "path": a.path,
                "format": a.format,
                "file_size": a.file_size,
                "last_modified": a.last_modified,
            }
            for a in items
        ],
    }
