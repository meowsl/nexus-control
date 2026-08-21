"""ORM tables: labels, jobs, schedule rules, sessions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from nexus_control.web.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Label(Base):
    __tablename__ = "labels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    color: Mapped[str] = mapped_column(String(16), nullable=False, default="#3D7EA6")
    description: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    repos: Mapped[list[RepoLabel]] = relationship(
        back_populates="label", cascade="all, delete-orphan"
    )


class RepoLabel(Base):
    __tablename__ = "repo_labels"
    __table_args__ = (UniqueConstraint("repo_name", "label_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    label_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("labels.id", ondelete="CASCADE"), nullable=False
    )

    label: Mapped[Label] = relationship(back_populates="repos")


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="verify")
    repository: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    scan_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="incremental")
    upload: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    target: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    scanners: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    path_prefixes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    excluded_prefixes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    progress_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    creds_blob: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScheduleRuleRow(Base):
    __tablename__ = "schedule_rules"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    cron: Mapped[str] = mapped_column(String(64), nullable=False)
    repos: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    description: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(32), nullable=False, default="verify_upload")
    upload: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    target: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    scanners: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    path_prefixes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    excluded_prefixes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    scan_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="incremental")
    last_fire: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class IntegrationConfig(Base):
    """Web-managed integration (DefectDojo / webhook / VK Teams)."""

    __tablename__ = "integration_configs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    secrets_blob: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_by: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    creds_blob: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
