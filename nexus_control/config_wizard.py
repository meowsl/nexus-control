"""First-run wizard: запрос языка, Nexus URL и запись XDG config.toml."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from dotenv import dotenv_values

from nexus_control.config_io import (
    peek_nexus_url_from_toml,
    write_toml_atomic,
)
from nexus_control.config_paths import resolve_config_path
from nexus_control.i18n import _, normalize_locale, set_locale

logger = logging.getLogger(__name__)


def _config_error(message: str) -> Exception:
    """Ленивый импорт ConfigError, чтобы избежать циклов на уровне модуля."""
    from nexus_control.config import ConfigError

    return ConfigError(message)


def peek_nexus_url(
    *,
    config_path: Path | None = None,
    env_file: str | Path | None = ".env",
) -> str | None:
    """Найти Nexus URL без полной загрузки Settings.

    Порядок: OS env → CWD ``.env`` → ``config.toml``.
    """
    env_url = (os.environ.get("NEXUS_URL") or "").strip()
    if env_url:
        return env_url.rstrip("/")

    if env_file is not None:
        dotenv_path = Path(env_file)
        if dotenv_path.is_file():
            values = dotenv_values(dotenv_path)
            raw = (values.get("NEXUS_URL") or "").strip()
            if raw:
                return raw.rstrip("/")

    path = config_path if config_path is not None else resolve_config_path()
    return peek_nexus_url_from_toml(path)


def needs_setup(
    *,
    config_path: Path | None = None,
    env_file: str | Path | None = ".env",
) -> bool:
    """True, если ``nexus_url`` нигде не задан."""
    return peek_nexus_url(config_path=config_path, env_file=env_file) is None


def normalize_nexus_url(value: str) -> str:
    """Нормализовать URL (как validator Settings)."""
    text = value.strip().rstrip("/")
    if not text:
        raise _config_error("NEXUS_URL is required")
    if "://" not in text:
        raise _config_error(
            f"Invalid NEXUS_URL {text!r}: expected scheme, e.g. http://localhost:8081"
        )
    return text


def run_first_run_wizard(
    *,
    config_path: Path | None = None,
) -> Path:
    """Интерактивно запросить язык, URL (+ опции) и записать ``config.toml``.

    Returns:
        Путь записанного файла.
    """
    path = config_path if config_path is not None else resolve_config_path()

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise _config_error(
            "No configuration found and no TTY for first-run setup.\n"
            "Set NEXUS_URL in the environment, create "
            f"{path}, or run interactively.\n"
            "Example: export NEXUS_URL=http://localhost:8081"
        )

    # Язык — до остальных вопросов, чтобы подсказки уже были локализованы.
    lang_raw = input("Language / Язык [ru/en]: ").strip()
    locale = normalize_locale(lang_raw or "ru")
    set_locale(locale)

    print(_("nexus-control — first-run setup"), file=sys.stderr)
    print(_("Config will be saved to: {path}", path=path), file=sys.stderr)
    print(
        _(
            "Username/password are not stored here — you will be prompted next "
            "(encrypted vault until session TTL)."
        ),
        file=sys.stderr,
    )

    while True:
        raw = input(_("Nexus URL [{default}]", default="http://localhost:8081") + ": ").strip()
        if not raw:
            raw = "http://localhost:8081"
        try:
            url = normalize_nexus_url(raw)
            break
        except Exception as exc:  # ConfigError
            print(f"  {exc}", file=sys.stderr)

    verify_raw = input(_("Verify TLS certificates? [Y/n]") + ": ").strip().lower()
    verify_ssl = verify_raw not in {"n", "no", "0", "false", "off", "н", "нет"}

    scanners_raw = input(_("Scanners (grype, trivy, or both) [grype]") + ": ").strip()
    scanners = scanners_raw or "grype"

    data: dict[str, object] = {
        "locale": locale,
        "nexus_url": url,
        "nexus_verify_ssl": verify_ssl,
        "scanners": scanners,
    }
    write_toml_atomic(path, data)
    print(_("Wrote {path}", path=path), file=sys.stderr)
    return path


def ensure_configured(
    *,
    config_path: Path | None = None,
    env_file: str | Path | None = ".env",
    run_wizard: bool = True,
) -> Path:
    """Убедиться, что ``nexus_url`` доступен; при необходимости запустить wizard.

    Returns:
        Путь к config.toml (даже если URL пришёл из env/.env).
    """
    path = config_path if config_path is not None else resolve_config_path()
    if not needs_setup(config_path=path, env_file=env_file):
        return path
    if not run_wizard:
        raise _config_error(
            "NEXUS_URL is required. Set it in the environment, "
            f"in {path}, or in a legacy .env file."
        )
    run_first_run_wizard(config_path=path)
    return path
