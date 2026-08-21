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
VerifiedLinkMode = Literal["auto", "copy"]
WebhookAuthMode = Literal["none", "bearer", "basic", "header"]

# Путь TOML для settings_customise_sources (задаётся в load_settings).
_active_toml_path: Path | None = None
# WARNING про отключённый TLS — один раз за процесс, не на каждый Settings().
_ssl_disabled_warned: bool = False


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

    # Сканеры (через запятую: grype, trivy, osv). Можно менять в TUI (клавиша s).
    scanners: str = "grype"
    # Минимальная severity, которая даёт FAIL (этот уровень и выше).
    # negligible = любая находка (историческое поведение). Unknown всегда FAIL.
    severity: str = Field(
        default="negligible",
        description=(
            "Fail verify on this severity and above: "
            "critical | high | medium | low | negligible"
        ),
        validation_alias=AliasChoices(
            "severity",
            "SEVERITY",
            "fail_on_severity",
        ),
    )
    # Параллельная обработка ассетов в pipeline (download/scan/verify).
    # 0 = auto от CPU/RAM; 1 = строго последовательно; явные 2–8 — override.
    pipeline_workers: int = Field(default=0, ge=0)
    # Глобальный лимит одновременных процессов сканеров (все ассеты × сканеры).
    # 0 = auto от CPU/RAM (формула в resource_governor).
    max_scanner_procs: int = Field(default=0, ge=0)
    # Stop new downloads if the data volume is this full (scan local only).
    disk_critical_watermark: float = Field(default=0.95, ge=0.50, le=0.99)
    # PASS checkpoint. 0 = never skip. Incremental mode ignores age TTL;
    # use scan_mode=full (CLI/schedule) to rescan everything.
    scan_checkpoint_ttl: int = Field(default=86400, ge=0)
    # Сколько последних verify-прогонов хранить в истории (TUI h / CLI history).
    # 0 = не писать историю.
    scan_history_keep: int = Field(default=50, ge=0)

    # VK Teams (VK Workspace) — уведомления scheduler + кнопка Upload.
    vk_teams_token: str = Field(
        default="",
        description="Bot API token from Metabot /newbot",
        validation_alias=AliasChoices("vk_teams_token", "VK_TEAMS_TOKEN"),
    )
    vk_teams_api_url: str = Field(
        default="https://myteam.mail.ru/bot/v1",
        description="VK Teams Bot API base URL",
        validation_alias=AliasChoices("vk_teams_api_url", "VK_TEAMS_API_URL"),
    )
    vk_teams_chat_id: str = Field(
        default="",
        description="chatId / nick / stamp for notifications",
        validation_alias=AliasChoices("vk_teams_chat_id", "VK_TEAMS_CHAT_ID"),
    )
    vk_teams_notify: Literal["off", "always", "failures"] = Field(
        default="off",
        description="When to notify: off | always | failures",
        validation_alias=AliasChoices("vk_teams_notify", "VK_TEAMS_NOTIFY"),
    )
    vk_teams_upload_button: bool = Field(
        default=True,
        description="Show Upload button for verify-only scheduler rules",
        validation_alias=AliasChoices(
            "vk_teams_upload_button",
            "VK_TEAMS_UPLOAD_BUTTON",
        ),
    )
    vk_teams_verify_ssl: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "vk_teams_verify_ssl",
            "VK_TEAMS_VERIFY_SSL",
        ),
    )
    vk_teams_timeout: float = Field(
        default=30.0,
        ge=1.0,
        validation_alias=AliasChoices("vk_teams_timeout", "VK_TEAMS_TIMEOUT"),
    )

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
    # Корень кэша offline DB (внутри: osv-scalibr/<Eco>/all.zip).
    # Env: OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY (как у osv-scanner docs).
    osv_local_db_cache_dir: Path | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "osv_local_db_cache_dir",
            "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
            "OSV_LOCAL_DB_CACHE_DIR",
        ),
    )

    # Docker / skopeo
    docker_binary: str = "docker"
    skopeo_binary: str = "skopeo"

    # Логирование
    log_level: str = "INFO"
    log_file: Path = Path("~/nexus-control/logs/nexus-control.log")

    # DefectDojo (опционально). API-ключ — только env / vault, не TOML.
    defectdojo_enabled: bool = False
    defectdojo_url: str = ""
    defectdojo_api_key: str = Field(
        default="",
        description="DefectDojo API token (env DEFECTDOJO_API_KEY or vault)",
        validation_alias=AliasChoices(
            "defectdojo_api_key",
            "DEFECTDOJO_API_KEY",
        ),
    )
    defectdojo_verify_ssl: bool = True
    defectdojo_product_name: str = "nexus-control"
    # Пусто → engagement = имя репозитория Nexus.
    defectdojo_engagement_name: str = ""
    defectdojo_product_type_name: str = "Nexus"

    # Generic webhook after verify (TUI / CLI / scheduler).
    # Secrets (token / password / header value) — env or vault, not TOML.
    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_auth: WebhookAuthMode = "none"
    webhook_token: str = Field(
        default="",
        description="Bearer token (env WEBHOOK_TOKEN or vault)",
        validation_alias=AliasChoices("webhook_token", "WEBHOOK_TOKEN"),
    )
    webhook_username: str = Field(
        default="",
        validation_alias=AliasChoices("webhook_username", "WEBHOOK_USERNAME"),
    )
    webhook_password: str = Field(
        default="",
        validation_alias=AliasChoices("webhook_password", "WEBHOOK_PASSWORD"),
    )
    webhook_header_name: str = ""
    webhook_header_value: str = Field(
        default="",
        validation_alias=AliasChoices(
            "webhook_header_value",
            "WEBHOOK_HEADER_VALUE",
        ),
    )
    webhook_verify_ssl: bool = True
    webhook_timeout: float = Field(default=15.0, ge=1.0, le=120.0)

    # Перезапись
    overwrite_downloads: bool = False
    overwrite_verified: bool = False
    # PASS → *-verified: auto = hardlink (same FS) else copy; copy = всегда copy2.
    verified_link_mode: VerifiedLinkMode = Field(
        default="auto",
        validation_alias=AliasChoices(
            "verified_link_mode",
            "VERIFIED_LINK_MODE",
        ),
    )

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
        "log_file",
        mode="before",
    )
    @classmethod
    def _expand_paths(cls, value: object) -> Path:
        if value is None or value == "":
            raise ValueError("path value must not be empty")
        return _expand_path(str(value))

    @field_validator("osv_local_db_cache_dir", mode="before")
    @classmethod
    def _expand_optional_cache_dir(cls, value: object) -> Path | None:
        if value is None or value == "":
            return None
        return _expand_path(str(value))

    @field_validator("nexus_url", mode="before")
    @classmethod
    def _normalize_url(cls, value: object) -> str:
        if not value or not str(value).strip():
            raise ValueError("NEXUS_URL is required")
        return str(value).strip().rstrip("/")

    @field_validator(
        "nexus_username",
        "nexus_password",
        "defectdojo_api_key",
        "webhook_token",
        "webhook_username",
        "webhook_password",
        "webhook_header_value",
        mode="before",
    )
    @classmethod
    def _coerce_optional_secret(cls, value: object) -> str:
        if value is None:
            return ""
        return str(value)

    @field_validator("defectdojo_url", "webhook_url", mode="before")
    @classmethod
    def _normalize_optional_http_url(cls, value: object) -> str:
        if value is None:
            return ""
        text = str(value).strip().rstrip("/")
        if not text:
            return ""
        if "://" not in text:
            raise ValueError(
                f"Invalid URL {text!r}: expected scheme, "
                "e.g. https://hooks.example.com/scan"
            )
        return text

    @field_validator("webhook_auth", mode="before")
    @classmethod
    def _normalize_webhook_auth(cls, value: object) -> str:
        text = str(value or "none").strip().lower()
        if text in {"password", "login", "login-password", "userpass"}:
            return "basic"
        if text not in {"none", "bearer", "basic", "header"}:
            raise ValueError(
                f"Invalid webhook_auth={text!r}; expected none|bearer|basic|header"
            )
        return text

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

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity_threshold(cls, value: object) -> str:
        from nexus_control.services.scan_common import parse_severity_threshold

        return parse_severity_threshold(value)

    @field_validator("locale", mode="before")
    @classmethod
    def _normalize_locale(cls, value: object) -> str:
        from nexus_control.i18n import normalize_locale

        return normalize_locale(str(value if value is not None else "ru"))

    @field_validator("vk_teams_notify", mode="before")
    @classmethod
    def _normalize_vk_teams_notify(cls, value: object) -> str:
        text = str(value if value is not None else "off").strip().lower()
        if text in {"0", "no", "false", ""}:
            return "off"
        if text in {"1", "yes", "true", "on"}:
            return "always"
        if text not in {"off", "always", "failures"}:
            raise ValueError(
                "vk_teams_notify must be off, always, or failures"
            )
        return text

    @field_validator("vk_teams_api_url", mode="before")
    @classmethod
    def _normalize_vk_teams_api_url(cls, value: object) -> str:
        text = str(value or "https://myteam.mail.ru/bot/v1").strip().rstrip("/")
        if not text:
            return "https://myteam.mail.ru/bot/v1"
        return text

    @field_validator(
        "vk_teams_token",
        "vk_teams_chat_id",
        mode="before",
    )
    @classmethod
    def _coerce_vk_teams_str(cls, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> str:
        level = str(value or "INFO").strip().upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"Invalid LOG_LEVEL: {value}")
        return level

    @field_validator("verified_link_mode", mode="before")
    @classmethod
    def _normalize_verified_link_mode(cls, value: object) -> str:
        text = str(value if value is not None else "auto").strip().lower()
        if text not in {"auto", "copy"}:
            raise ValueError("verified_link_mode must be auto or copy")
        return text

    @model_validator(mode="after")
    def _post_init_dirs(self) -> Settings:
        ensure_dir(self.download_root)
        ensure_dir(self.reports_root)
        ensure_dir(self.verified_root)
        ensure_parent_dir(self.log_file)
        ensure_dir(self.nexus_cache_dir, mode=0o700)
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
            "scanners": self.scanners,
            "severity": self.severity,
            "pipeline_workers": self.pipeline_workers,
            "max_scanner_procs": self.max_scanner_procs,
            "disk_critical_watermark": self.disk_critical_watermark,
            "scan_checkpoint_ttl": self.scan_checkpoint_ttl,
            "scan_history_keep": self.scan_history_keep,
            "vk_teams_notify": self.vk_teams_notify,
            "vk_teams_chat_id": self.vk_teams_chat_id or "",
            "vk_teams_api_url": self.vk_teams_api_url,
            "vk_teams_token": "***" if self.vk_teams_token else "",
            "vk_teams_upload_button": self.vk_teams_upload_button,
            "grype_binary": self.grype_binary,
            "grype_use_docker": self.grype_use_docker,
            "trivy_binary": self.trivy_binary,
            "trivy_use_docker": self.trivy_use_docker,
            "osv_binary": self.osv_binary,
            "osv_use_docker": self.osv_use_docker,
            "log_level": self.log_level,
            "log_file": str(self.log_file),
            "defectdojo_enabled": self.defectdojo_enabled,
            "defectdojo_url": self.defectdojo_url,
            "defectdojo_api_key": "***" if self.defectdojo_api_key else "",
            "defectdojo_verify_ssl": self.defectdojo_verify_ssl,
            "defectdojo_product_name": self.defectdojo_product_name,
            "defectdojo_engagement_name": self.defectdojo_engagement_name,
            "defectdojo_product_type_name": self.defectdojo_product_type_name,
            "webhook_enabled": self.webhook_enabled,
            "webhook_url": self.webhook_url,
            "webhook_auth": self.webhook_auth,
            "webhook_token": "***" if self.webhook_token else "",
            "webhook_username": self.webhook_username,
            "webhook_password": "***" if self.webhook_password else "",
            "webhook_header_name": self.webhook_header_name,
            "webhook_header_value": "***" if self.webhook_header_value else "",
            "webhook_verify_ssl": self.webhook_verify_ssl,
            "webhook_timeout": self.webhook_timeout,
            "overwrite_downloads": self.overwrite_downloads,
            "overwrite_verified": self.overwrite_verified,
            "verified_link_mode": self.verified_link_mode,
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
    global _ssl_disabled_warned
    get_settings.cache_clear()
    _ssl_disabled_warned = False


def warn_if_ssl_unverified(settings: Settings) -> None:
    """Один WARNING, если TLS к Nexus выключен (не для status/monitor)."""
    global _ssl_disabled_warned
    if settings.nexus_verify_ssl or _ssl_disabled_warned:
        return
    _ssl_disabled_warned = True
    logger.warning(
        "NEXUS_VERIFY_SSL=false — TLS certificate verification is disabled. "
        "Use only in trusted lab environments."
    )
