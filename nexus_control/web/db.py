"""SQLAlchemy engine/session for the operator console."""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def default_sqlite_url() -> str:
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    root = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    path = (root / "nexus-control" / "console.db").resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path}"


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip() or default_sqlite_url()


def _connect_args(url: str) -> dict:
    if url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


ENGINE = create_engine(
    database_url(),
    pool_pre_ping=True,
    connect_args=_connect_args(database_url()),
)
SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False)


def init_db() -> None:
    from nexus_control.web import orm  # noqa: F401

    Base.metadata.create_all(bind=ENGINE)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
