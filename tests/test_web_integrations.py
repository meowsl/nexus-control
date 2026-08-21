"""Web-managed integrations overlay Settings and keep secrets encrypted."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _session_local(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    url = f"sqlite:///{tmp_path / 'console.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("NEXUS_URL", "http://nexus.example:8081")
    monkeypatch.setenv("NEXUS_CONTROL_SECRET", "unit-test-secret-not-for-prod")
    monkeypatch.setenv("DEFECTDOJO_ENABLED", "true")
    monkeypatch.setenv("DEFECTDOJO_URL", "http://dd.example:8080")
    monkeypatch.setenv("DEFECTDOJO_API_KEY", "env-key")
    from nexus_control.web import db as dbmod
    from nexus_control.web import orm  # noqa: F401

    engine = create_engine(url, connect_args={"check_same_thread": False})
    dbmod.ENGINE = engine
    dbmod.SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    dbmod.init_db()
    return dbmod.SessionLocal


def test_web_defectdojo_overrides_env_and_keeps_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    SessionLocal = _session_local(tmp_path, monkeypatch)
    from nexus_control.web.integrations import (
        apply_web_integrations,
        runtime_settings,
        save_defectdojo,
        snapshot,
    )

    db = SessionLocal()
    try:
        save_defectdojo(
            db,
            {
                "enabled": True,
                "url": "https://dojo.internal",
                "verify_ssl": False,
                "product_name": "nexus",
                "api_key": "web-secret-key",
            },
            username="admin",
        )
        db.commit()
        cfg = apply_web_integrations(runtime_settings(db, run_wizard=False), db)
        assert cfg.defectdojo_enabled is True
        assert cfg.defectdojo_url == "https://dojo.internal"
        assert cfg.defectdojo_api_key == "web-secret-key"
        assert cfg.defectdojo_verify_ssl is False

        save_defectdojo(
            db,
            {
                "enabled": True,
                "url": "https://dojo.internal",
                "verify_ssl": False,
                "product_name": "nexus",
                "api_key": "",
            },
            username="admin",
        )
        db.commit()
        cfg = apply_web_integrations(runtime_settings(db, run_wizard=False), db)
        assert cfg.defectdojo_api_key == "web-secret-key"

        public = snapshot(db, cfg)
        assert "web-secret-key" not in str(public)
        assert public["defectdojo"]["api_key_set"] is True
        assert public["defectdojo"]["source"] == "web"
    finally:
        db.close()


def test_web_disable_defectdojo_beats_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    SessionLocal = _session_local(tmp_path, monkeypatch)
    from nexus_control.web.integrations import apply_web_integrations, runtime_settings, save_defectdojo

    db = SessionLocal()
    try:
        save_defectdojo(
            db,
            {"enabled": False, "url": "https://dojo.internal", "api_key": ""},
            username="admin",
        )
        db.commit()
        cfg = apply_web_integrations(runtime_settings(db, run_wizard=False), db)
        assert cfg.defectdojo_enabled is False
    finally:
        db.close()
