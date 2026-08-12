"""CLI: configure / status / disable DefectDojo integration."""

from __future__ import annotations

import getpass
import json
import sys
from argparse import Namespace
from pathlib import Path

from rich.console import Console

from nexus_control.config import ConfigError, load_settings
from nexus_control.config_io import read_toml, update_toml_key, write_toml_atomic
from nexus_control.config_paths import resolve_config_path
from nexus_control.config_wizard import normalize_nexus_url
from nexus_control.i18n import _, set_locale
from nexus_control.integrations.defectdojo import (
    DefectDojoVault,
    resolve_defectdojo_settings,
)

console = Console(stderr=True)


def run_defectdojo(args: Namespace) -> int:
    action = getattr(args, "defectdojo_action", "status") or "status"
    if action == "configure":
        return _configure(args)
    if action == "disable":
        return _disable(args)
    return _status(args)


def _status(args: Namespace) -> int:
    settings = load_settings(run_wizard=False)
    set_locale(settings.locale)
    cfg = resolve_defectdojo_settings(settings)
    vault = DefectDojoVault(cfg.nexus_cache_dir)
    vault_data = vault.load()
    payload = {
        "enabled": cfg.defectdojo_enabled,
        "url": cfg.defectdojo_url or (vault_data[0] if vault_data else ""),
        "api_key_set": bool((cfg.defectdojo_api_key or "").strip()),
        "api_key_in_vault": vault_data is not None,
        "verify_ssl": cfg.defectdojo_verify_ssl,
        "product_name": cfg.defectdojo_product_name,
        "engagement_name": cfg.defectdojo_engagement_name or "(repository name)",
        "product_type_name": cfg.defectdojo_product_type_name,
        "vault_path": str(vault.vault_path),
    }
    if args.json:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    if cfg.defectdojo_enabled:
        console.print("DefectDojo: [green]enabled[/green]")
    else:
        console.print("DefectDojo: [yellow]disabled[/yellow]")
    console.print(f"  URL: {payload['url'] or '(not set)'}")
    console.print(
        f"  API key: {'set' if payload['api_key_set'] else 'missing'}"
        + (" (vault)" if payload["api_key_in_vault"] else "")
    )
    console.print(f"  Product: {payload['product_name']}")
    console.print(f"  Engagement: {payload['engagement_name']}")
    console.print(f"  Product type: {payload['product_type_name']}")
    if not cfg.defectdojo_enabled:
        console.print(
            "[dim]Configure: nexus-control-cli defectdojo configure[/dim]"
        )
    return 0


def _configure(args: Namespace) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ConfigError(
            "defectdojo configure requires a TTY. "
            "Or set DEFECTDOJO_ENABLED=true, DEFECTDOJO_URL, DEFECTDOJO_API_KEY."
        )

    path = resolve_config_path()
    # Locale from existing config if possible
    try:
        settings = load_settings(run_wizard=False)
        set_locale(settings.locale)
        cache_dir = settings.nexus_cache_dir
        default_url = settings.defectdojo_url or "http://localhost:8080"
        default_verify = settings.defectdojo_verify_ssl
    except ConfigError:
        set_locale("ru")
        cache_dir = (Path.home() / ".cache" / "nexus-control").resolve()
        default_url = "http://localhost:8080"
        default_verify = True
        if not path.is_file():
            raise ConfigError(
                f"No config at {path}. Run nexus-control once (first-run wizard) "
                "or set NEXUS_URL, then retry defectdojo configure."
            ) from None

    console.print(_("DefectDojo setup"))
    while True:
        raw = input(
            _("DefectDojo URL [{default}]", default=default_url) + ": "
        ).strip()
        if not raw:
            raw = default_url
        try:
            url = normalize_nexus_url(raw)
            break
        except Exception as exc:  # ConfigError
            console.print(f"  {exc}")

    verify_raw = input(_("Verify DefectDojo TLS certificates? [Y/n]") + ": ").strip().lower()
    if not verify_raw:
        verify_ssl = default_verify
    else:
        verify_ssl = verify_raw not in {"n", "no", "0", "false", "off", "н", "нет"}

    console.print(
        _(
            "API key: DefectDojo → profile (top right) → API Key "
            "(or create a dedicated user + token)."
        )
    )
    while True:
        api_key = getpass.getpass(_("DefectDojo API key: "))
        if api_key.strip():
            break
        console.print(_("API key is required"))

    data = read_toml(path)
    data["defectdojo_enabled"] = True
    data["defectdojo_url"] = url
    data["defectdojo_verify_ssl"] = verify_ssl
    # Never persist api key in toml
    data.pop("defectdojo_api_key", None)
    write_toml_atomic(path, data)
    DefectDojoVault(cache_dir).save(url=url, api_key=api_key.strip())
    console.print(
        _("DefectDojo enabled. Config: {path}; API key vault: {vault}",
          path=path,
          vault=cache_dir / "defectdojo.vault")
    )
    return 0


def _disable(args: Namespace) -> int:
    path = resolve_config_path()
    settings = load_settings(run_wizard=False)
    set_locale(settings.locale)
    if path.is_file():
        update_toml_key(path, "defectdojo_enabled", False)
    vault = DefectDojoVault(settings.nexus_cache_dir)
    if getattr(args, "clear_vault", False):
        vault.clear()
    console.print(_("DefectDojo disabled") + f" ({path})")
    return 0
