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

    scanners_raw = input(
        _("Scanners (grype, trivy, osv — comma-separated) [grype]") + ": "
    ).strip()
    scanners = scanners_raw or "grype"

    dd_enabled, dd_url, dd_api_key, dd_verify_ssl = _prompt_defectdojo()

    data: dict[str, object] = {
        "locale": locale,
        "nexus_url": url,
        "nexus_verify_ssl": verify_ssl,
        "scanners": scanners,
        "defectdojo_enabled": dd_enabled,
    }
    if dd_enabled:
        data["defectdojo_url"] = dd_url
        data["defectdojo_verify_ssl"] = dd_verify_ssl

    write_toml_atomic(path, data)
    if dd_enabled and dd_api_key:
        _save_defectdojo_vault(url=dd_url, api_key=dd_api_key)
    print(_("Wrote {path}", path=path), file=sys.stderr)
    return path


def _prompt_yes_no(prompt: str, *, default_yes: bool = False) -> bool:
    hint = "[Y/n]" if default_yes else "[y/N]"
    raw = input(f"{prompt} {hint}: ").strip().lower()
    if not raw:
        return default_yes
    return raw in {"y", "yes", "1", "true", "on", "д", "да"}


def _prompt_defectdojo() -> tuple[bool, str, str, bool]:
    """Спросить про DefectDojo. Возвращает (enabled, url, api_key, verify_ssl)."""
    import getpass

    print("", file=sys.stderr)
    print(
        _(
            "DefectDojo can receive vulnerability findings after each verify "
            "(FAIL assets → Generic Findings Import)."
        ),
        file=sys.stderr,
    )
    if not _prompt_yes_no(_("Enable DefectDojo integration?"), default_yes=False):
        return False, "", "", True

    while True:
        raw = input(
            _("DefectDojo URL [{default}]", default="http://localhost:8080") + ": "
        ).strip()
        if not raw:
            raw = "http://localhost:8080"
        try:
            dd_url = normalize_nexus_url(raw)
            break
        except Exception as exc:  # ConfigError
            print(f"  {exc}", file=sys.stderr)

    verify_raw = input(_("Verify DefectDojo TLS certificates? [Y/n]") + ": ").strip().lower()
    dd_verify_ssl = verify_raw not in {"n", "no", "0", "false", "off", "н", "нет"}

    print(
        _(
            "API key: DefectDojo → profile (top right) → API Key "
            "(or create a dedicated user + token)."
        ),
        file=sys.stderr,
    )
    while True:
        api_key = getpass.getpass(_("DefectDojo API key: "))
        if api_key.strip():
            break
        print(_("API key is required"), file=sys.stderr)

    return True, dd_url, api_key.strip(), dd_verify_ssl


def _save_defectdojo_vault(*, url: str, api_key: str) -> None:
    """Сохранить API-ключ в vault (каталог кэша по умолчанию / из env)."""
    from nexus_control.integrations.defectdojo import DefectDojoVault

    cache_raw = (os.environ.get("NEXUS_CACHE_DIR") or "~/.cache/nexus-control").strip()
    cache_dir = Path(cache_raw).expanduser().resolve()
    DefectDojoVault(cache_dir).save(url=url, api_key=api_key)
    print(
        _("DefectDojo API key saved (encrypted) under {path}", path=cache_dir),
        file=sys.stderr,
    )


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
