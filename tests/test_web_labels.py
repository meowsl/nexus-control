"""Labels uniqueness and ``label:`` selector expansion (sqlite tempfile)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker


def _session_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    url = f"sqlite:///{tmp_path / 'console.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    from nexus_control.web import db as dbmod
    from nexus_control.web import orm  # noqa: F401

    engine = create_engine(url, connect_args={"check_same_thread": False})
    dbmod.ENGINE = engine
    dbmod.SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    dbmod.init_db()
    return dbmod.SessionLocal


def test_label_create_uniqueness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    SessionLocal = _session_local(tmp_path, monkeypatch)
    from nexus_control.web.orm import Label

    db = SessionLocal()
    try:
        db.add(Label(name="prod", color="#ff0000", description="a"))
        db.commit()
        db.add(Label(name="prod", color="#00ff00", description="b"))
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.close()


def test_expand_repo_selectors_label_foo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    SessionLocal = _session_local(tmp_path, monkeypatch)
    from nexus_control.web.deps import expand_repo_selectors
    from nexus_control.web.orm import Label, RepoLabel

    db = SessionLocal()
    try:
        label = Label(name="foo", color="#3D7EA6", description="")
        db.add(label)
        db.flush()
        db.add(RepoLabel(repo_name="maven-hosted", label_id=label.id))
        db.add(RepoLabel(repo_name="npm-hosted", label_id=label.id))
        db.commit()
        assert expand_repo_selectors(db, ["label:foo"]) == [
            "maven-hosted",
            "npm-hosted",
        ]
        assert expand_repo_selectors(db, ["raw-hosted", "label:foo"]) == [
            "raw-hosted",
            "maven-hosted",
            "npm-hosted",
        ]
        assert expand_repo_selectors(db, ["label:missing"]) == []
    finally:
        db.close()
