"""Конфигурация приложения: env, legacy ``.env``, XDG ``config.toml``."""

from __future__ import annotations

import logging
import shlex
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from nexus_control.config_paths import resolve_config_path
from nexus_control.utils.fs import ensure_dir, ensure_parent_dir

logger = logging.getLogger(__name__)

ScannerDockerMode = Literal["auto", "true", "false"]
GrypeDockerMode = ScannerDockerMode  # совместимость

# Путь TOML для settings_customise_sources (задаётся в load_settings).
_active_toml_path: Path | None = None


def _expand_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


class Settings(BaseSettings):
    """Проверенные настройки выполнения для nexus-control.

    Приоритет (сверху вниз): init kwargs → OS env → CWD ``.env`` →
    XDG ``config.toml`` → значения по умолчанию полей.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # Обязательный URL. Username/password опциональны:
    # при отсутствии запрашиваются при старте и хранятся зашифрованно
    # до истечения Nexus-сессии (см. nexus.credentials).
    nexus_url: str = Field(..., description="Базовый URL Nexus")
    nexus_username: str = Field(default="", description="Имя пользователя Nexus")
    nexus_password: str = Field(default="", description="Пароль Nexus")

    # Клиент Nexus
    nexus_verify_ssl: bool = True
    nexus_timeout: float = 30.0
    nexus_session_ttl: int = 3600
    nexus_cache_dir: Path = Path("~/.cache/nexus-control")
    nexus_docker_registry: str = ""
    # Кэш списка ассетов (сек). 0 = выкл.
    # Свежий кэш (возраст ≤ ttl) — открытие без сети.
    # Просроченный — всё равно показываем сразу, затем обновление в фоне.
    # ``r`` всегда тянет свежий список с сервера.
    assets_cache_ttl: int = 86400

    # UI language: en | ru (env: NEXUS_CONTROL_LOCALE or locale)
    locale: str = Field(
        default="ru",
        description="UI language en|ru",
        validation_alias=AliasChoices("locale", "NEXUS_CONTROL_LOCALE"),
    )

    # Пути
    download_root: Path = Path("~/nexus-control/downloads")
    reports_root: Path = Path("~/nexus-control/reports")
    verified_root: Path = Path("~/nexus-control")
    # tar.gz после disk-pressure reclaim (downloads purge).
    archive_root: Path = Path("~/nexus-control/archive")

    # Сканеры (через запятую: grype, trivy, osv). Можно менять в TUI (клавиша s).
    scanners: str = "grype"
    # Параллельная обработка ассетов в pipeline (download/scan/verify).
    # 0 = auto от CPU/RAM; 1 = строго последовательно; явные 2–8 — override.
    pipeline_workers: int = Field(default=0, ge=0)
    # Глобальный лимит одновременных процессов сканеров (все ассеты × сканеры).
    # 0 = auto от CPU/RAM (формула в resource_governor).
    max_scanner_procs: int = Field(default=0, ge=0)
    # Disk-pressure: pause new downloads at high, resume after reclaim below low.
    disk_high_watermark: float = Field(default=0.80, ge=0.01, le=0.99)
    disk_low_watermark: float = Field(default=0.70, ge=0.01, le=0.99)
    disk_critical_watermark: float = Field(default=0.95, ge=0.01, le=0.99)
    disk_reclaim_enabled: bool = True
    # PASS checkpoint для неизменённых локальных ассетов. После TTL скан
    # выполняется заново, чтобы учитывать обновления vulnerability DB.
    scan_checkpoint_ttl: int = Field(default=86400, ge=0)
    # Сколько последних verify-прогонов хранить в истории (TUI h / CLI history).
    # 0 = не писать историю.
    scan_history_keep: int = Field(default=50, ge=0)

    # Grype
    grype_binary: str = "grype"
    grype_use_docker: ScannerDockerMode = "auto"
    grype_docker_image: str = "anchore/grype:latest"
    grype_extra_args: str = ""

    # Trivy
    trivy_binary: str = "trivy"
    trivy_use_docker: ScannerDockerMode = "auto"
    trivy_docker_image: str = "aquasec/trivy:latest"
    trivy_extra_args: str = ""

    # OSV-Scanner
    osv_binary: str = "osv-scanner"
    osv_use_docker: ScannerDockerMode = "auto"
    osv_docker_image: str = "ghcr.io/google/osv-scanner:latest"
    osv_extra_args: str = ""
    # NuGet .nupkg: прямой OSV API (ecosystem NuGet), без osv-scanner CLI.
    osv_api_url: str = "https://api.osv.dev"
    osv_api_timeout: float = Field(default=30.0, ge=1.0)

    # Docker / skopeo
    docker_binary: str = "docker"
    skopeo_binary: str = "skopeo"

    # Логирование
    log_level: str = "INFO"
    log_file: Path = Path("~/nexus-control/logs/nexus-control.log")

    # Перезапись
    overwrite_downloads: bool = False
    overwrite_verified: bool = False

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        sources: list[PydanticBaseSettingsSource] = [
            init_settings,
            env_settings,
            dotenv_settings,
        ]
        toml_path = _active_toml_path
        if toml_path is not None and toml_path.is_file():
            sources.append(
                TomlConfigSettingsSource(settings_cls, toml_file=toml_path)
            )
        sources.append(file_secret_settings)
        return tuple(sources)

    @field_validator(
        "nexus_cache_dir",
        "download_root",
        "reports_root",
        "verified_root",
        "archive_root",
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
    def _coerce_optional_secret(cls, value: object) -> str:
        if value is None:
            return ""
        return str(value)

    @field_validator(
        "grype_use_docker", "trivy_use_docker", "osv_use_docker", mode="before"
    )
    @classmethod
    def _normalize_scanner_docker(cls, value: object) -> str:
        text = str(value).strip().lower()
        if text in {"1", "yes", "on"}:
            return "true"
        if text in {"0", "no", "off"}:
            return "false"
        if text not in {"auto", "true", "false"}:
            raise ValueError("scanner USE_DOCKER must be auto, true, or false")
        return text

    @field_validator("scanners", mode="before")
    @classmethod
    def _normalize_scanners(cls, value: object) -> str:
        from nexus_control.services.scan_common import parse_scanner_names

        names = parse_scanner_names(str(value if value is not None else "grype"))
        return ",".join(names)

    @field_validator("locale", mode="before")
    @classmethod
    def _normalize_locale(cls, value: object) -> str:
        from nexus_control.i18n import normalize_locale

        return normalize_locale(str(value if value is not None else "ru"))

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> str:
        level = str(value or "INFO").strip().upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"Invalid LOG_LEVEL: {value}")
        return level

    @model_validator(mode="after")
    def _post_init_dirs(self) -> Settings:
        if self.disk_low_watermark >= self.disk_high_watermark:
            raise ValueError(
                "disk_low_watermark must be < disk_high_watermark"
            )
        if self.disk_high_watermark >= self.disk_critical_watermark:
            raise ValueError(
                "disk_high_watermark must be < disk_critical_watermark"
            )
        ensure_dir(self.download_root)
        ensure_dir(self.reports_root)
        ensure_dir(self.verified_root)
        # archive_root создаётся лениво при первом reclaim
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
    def scanners_list(self) -> list[str]:
        """Включённые сканеры по умолчанию (из ``SCANNERS``)."""
        from nexus_control.services.scan_common import parse_scanner_names

        return parse_scanner_names(self.scanners)

    @property
    def grype_extra_args_list(self) -> list[str]:
        """Безопасный разбор GRYPE_EXTRA_ARGS (без shell)."""
        if not self.grype_extra_args.strip():
            return []
        return shlex.split(self.grype_extra_args)

    @property
    def trivy_extra_args_list(self) -> list[str]:
        """Безопасный разбор TRIVY_EXTRA_ARGS (без shell)."""
        if not self.trivy_extra_args.strip():
            return []
        return shlex.split(self.trivy_extra_args)

    @property
    def osv_extra_args_list(self) -> list[str]:
        """Безопасный разбор OSV_EXTRA_ARGS (без shell)."""
        if not self.osv_extra_args.strip():
            return []
        return shlex.split(self.osv_extra_args)

    def verified_repo_dir(self, repository_name: str) -> Path:
        """Вернуть ``VERIFIED_ROOT/<repository>-verified``."""
        from nexus_control.utils.safe_path import sanitize_repo_name

        safe = sanitize_repo_name(repository_name)
        return self.verified_root / f"{safe}-verified"

    def masked_dict(self) -> dict[str, object]:
        """Снимок настроек, безопасный для логирования (пароль скрыт)."""
        return {
            "nexus_url": self.nexus_url,
            "nexus_username": self.nexus_username,
            "nexus_password": "***",
            "nexus_verify_ssl": self.nexus_verify_ssl,
            "locale": self.locale,
            "nexus_timeout": self.nexus_timeout,
            "nexus_session_ttl": self.nexus_session_ttl,
            "nexus_cache_dir": str(self.nexus_cache_dir),
            "download_root": str(self.download_root),
            "reports_root": str(self.reports_root),
            "verified_root": str(self.verified_root),
            "archive_root": str(self.archive_root),
            "scanners": self.scanners,
            "pipeline_workers": self.pipeline_workers,
            "max_scanner_procs": self.max_scanner_procs,
            "disk_high_watermark": self.disk_high_watermark,
            "disk_low_watermark": self.disk_low_watermark,
            "disk_critical_watermark": self.disk_critical_watermark,
            "disk_reclaim_enabled": self.disk_reclaim_enabled,
            "scan_checkpoint_ttl": self.scan_checkpoint_ttl,
            "scan_history_keep": self.scan_history_keep,
            "grype_binary": self.grype_binary,
            "grype_use_docker": self.grype_use_docker,
            "trivy_binary": self.trivy_binary,
            "trivy_use_docker": self.trivy_use_docker,
            "osv_binary": self.osv_binary,
            "osv_use_docker": self.osv_use_docker,
            "osv_api_url": self.osv_api_url,
            "osv_api_timeout": self.osv_api_timeout,
            "log_level": self.log_level,
            "log_file": str(self.log_file),
        }


class ConfigError(Exception):
    """Выбрасывается, когда конфигурацию не удалось загрузить."""


def load_settings(
    env_file: str | Path | None = ".env",
    *,
    config_path: str | Path | None = None,
    run_wizard: bool = True,
) -> Settings:
    """Загрузить настройки: wizard (при необходимости) → env / .env / TOML.

    Переменные окружения ОС имеют приоритет над ``.env`` и ``config.toml``.
    """
    global _active_toml_path

    from nexus_control.config_wizard import ensure_configured

    resolved = resolve_config_path(config_path)
    ensure_configured(
        config_path=resolved,
        env_file=env_file,
        run_wizard=run_wizard,
    )

    if env_file is not None:
        path = Path(env_file)
        if path.is_file():
            # Не переопределять уже заданные переменные окружения ОС.
            load_dotenv(path, override=False)

    _active_toml_path = resolved if resolved.is_file() else None
    try:
        # _env_file=None: legacy .env уже в os.environ через load_dotenv выше;
        # иначе pydantic снова прочитал бы CWD .env даже при env_file=None.
        return Settings(_env_file=None)  # type: ignore[call-arg]
    except Exception as exc:
        raise ConfigError(
            "Failed to load configuration. Ensure NEXUS_URL is set via first-run "
            f"setup ({resolved}), the environment, or a legacy .env. "
            "Username/password may be omitted and will be prompted interactively.\n"
            f"Details: {exc}"
        ) from exc
    finally:
        _active_toml_path = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Кэшированный доступ к настройкам для внедрения зависимостей."""
    return load_settings()


def clear_settings_cache() -> None:
    """Очистить кэш настроек (тесты / перезагрузка)."""
    get_settings.cache_clear()
