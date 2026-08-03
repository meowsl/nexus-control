"""Конфигурация приложения, загружаемая из окружения / ``.env``."""

from __future__ import annotations

import logging
import shlex
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from nexus_tui.utils.fs import ensure_dir, ensure_parent_dir

logger = logging.getLogger(__name__)

GrypeDockerMode = Literal["auto", "true", "false"]


def _expand_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


class Settings(BaseSettings):
    """Проверенные настройки выполнения для nexus-tui.

    Приоритет (сверху вниз): переменные окружения ОС, затем ``.env`` в CWD,
    затем значения по умолчанию полей.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Обязательные
    nexus_url: str = Field(..., description="Базовый URL Nexus")
    nexus_username: str = Field(..., description="Имя пользователя Nexus")
    nexus_password: str = Field(..., description="Пароль Nexus")

    # Клиент Nexus
    nexus_verify_ssl: bool = True
    nexus_timeout: float = 30.0
    nexus_session_ttl: int = 3600
    nexus_cache_dir: Path = Path("~/.cache/nexus-tui")
    nexus_docker_registry: str = ""

    # Пути
    download_root: Path = Path("~/nexus-automation/downloads")
    reports_root: Path = Path("~/nexus-automation/reports")
    verified_root: Path = Path("~/nexus-automation")

    # Grype
    grype_binary: str = "grype"
    grype_use_docker: GrypeDockerMode = "auto"
    grype_docker_image: str = "anchore/grype:latest"
    grype_extra_args: str = ""

    # Docker / skopeo
    docker_binary: str = "docker"
    skopeo_binary: str = "skopeo"

    # Логирование
    log_level: str = "INFO"
    log_file: Path = Path("~/nexus-automation/logs/nexus-tui.log")

    # Перезапись
    overwrite_downloads: bool = False
    overwrite_verified: bool = False

    @field_validator(
        "nexus_cache_dir",
        "download_root",
        "reports_root",
        "verified_root",
        "log_file",
        mode="before",
    )
    @classmethod
    def _expand_paths(cls, value: object) -> Path:
        if value is None or value == "":
            raise ValueError("path value must not be empty")
        return _expand_path(str(value))

    @field_validator("nexus_url", mode="before")
    @classmethod
    def _normalize_url(cls, value: object) -> str:
        if not value or not str(value).strip():
            raise ValueError("NEXUS_URL is required")
        return str(value).strip().rstrip("/")

    @field_validator("nexus_username", "nexus_password", mode="before")
    @classmethod
    def _require_non_empty(cls, value: object, info) -> str:  # type: ignore[no-untyped-def]
        if value is None or not str(value).strip():
            raise ValueError(f"{info.field_name.upper()} is required")
        return str(value)

    @field_validator("grype_use_docker", mode="before")
    @classmethod
    def _normalize_grype_docker(cls, value: object) -> str:
        text = str(value).strip().lower()
        if text in {"1", "yes", "on"}:
            return "true"
        if text in {"0", "no", "off"}:
            return "false"
        if text not in {"auto", "true", "false"}:
            raise ValueError("GRYPE_USE_DOCKER must be auto, true, or false")
        return text

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> str:
        level = str(value or "INFO").strip().upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"Invalid LOG_LEVEL: {value}")
        return level

    @model_validator(mode="after")
    def _post_init_dirs(self) -> Settings:
        ensure_dir(self.download_root)
        ensure_dir(self.reports_root)
        ensure_dir(self.verified_root)
        ensure_parent_dir(self.log_file)
        ensure_dir(self.nexus_cache_dir, mode=0o700)
        if not self.nexus_verify_ssl:
            logger.warning(
                "NEXUS_VERIFY_SSL=false — TLS certificate verification is disabled. "
                "Use only in trusted lab environments."
            )
        return self

    @property
    def rest_base(self) -> str:
        """Базовый URL Nexus REST v1."""
        return f"{self.nexus_url}/service/rest/v1"

    @property
    def grype_extra_args_list(self) -> list[str]:
        """Безопасный разбор GRYPE_EXTRA_ARGS (без shell)."""
        if not self.grype_extra_args.strip():
            return []
        return shlex.split(self.grype_extra_args)

    def verified_repo_dir(self, repository_name: str) -> Path:
        """Вернуть ``VERIFIED_ROOT/<repository>-verified``."""
        from nexus_tui.utils.safe_path import sanitize_repo_name

        safe = sanitize_repo_name(repository_name)
        return self.verified_root / f"{safe}-verified"

    def masked_dict(self) -> dict[str, object]:
        """Снимок настроек, безопасный для логирования (пароль скрыт)."""
        return {
            "nexus_url": self.nexus_url,
            "nexus_username": self.nexus_username,
            "nexus_password": "***",
            "nexus_verify_ssl": self.nexus_verify_ssl,
            "nexus_timeout": self.nexus_timeout,
            "nexus_session_ttl": self.nexus_session_ttl,
            "nexus_cache_dir": str(self.nexus_cache_dir),
            "download_root": str(self.download_root),
            "reports_root": str(self.reports_root),
            "verified_root": str(self.verified_root),
            "grype_binary": self.grype_binary,
            "grype_use_docker": self.grype_use_docker,
            "log_level": self.log_level,
            "log_file": str(self.log_file),
        }


class ConfigError(Exception):
    """Выбрасывается, когда конфигурацию не удалось загрузить."""


def load_settings(env_file: str | Path | None = ".env") -> Settings:
    """Загрузить настройки из ``.env`` в CWD и окружения ОС.

    Переменные окружения ОС имеют приоритет над ``.env`` (python-dotenv
    ``override=False`` + приоритет env в pydantic-settings).
    """
    if env_file is not None:
        path = Path(env_file)
        if path.is_file():
            # Не переопределять уже заданные переменные окружения ОС.
            load_dotenv(path, override=False)

    try:
        return Settings()  # type: ignore[call-arg]
    except Exception as exc:
        raise ConfigError(
            "Failed to load configuration. Ensure NEXUS_URL, NEXUS_USERNAME, "
            f"and NEXUS_PASSWORD are set in .env or the environment.\nDetails: {exc}"
        ) from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Кэшированный доступ к настройкам для внедрения зависимостей."""
    return load_settings()


def clear_settings_cache() -> None:
    """Очистить кэш настроек (тесты / перезагрузка)."""
    get_settings.cache_clear()
