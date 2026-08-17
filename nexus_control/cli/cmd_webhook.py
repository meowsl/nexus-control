"""CLI: configure / status / disable / test generic webhook."""

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
from nexus_control.integrations.webhook import (
    VALID_AUTH,
    WebhookVault,
    push_test,
    resolve_webhook_settings,
)

console = Console(stderr=True)

_AUTH_CHOICES = ("none", "bearer", "basic", "header")


def run_webhook(args: Namespace) -> int:
    action = getattr(args, "webhook_action", "status") or "status"
    if action == "configure":
        return _configure(args)
    if action == "disable":
        return _disable(args)
    if action == "test":
        return _test(args)
    return _status(args)


def _status(args: Namespace) -> int:
    settings = load_settings(run_wizard=False)
    set_locale(settings.locale)
    cfg = resolve_webhook_settings(settings)
    vault = WebhookVault(cfg.nexus_cache_dir)
    vault_data = vault.load()
    payload = {
        "enabled": cfg.webhook_enabled,
        "url": cfg.webhook_url or ((vault_data or {}).get("url") or ""),
        "auth": cfg.webhook_auth,
        "token_set": bool((cfg.webhook_token or "").strip()),
        "username_set": bool((cfg.webhook_username or "").strip()),
        "password_set": bool(cfg.webhook_password),
        "header_name": cfg.webhook_header_name or "",
        "header_value_set": bool(cfg.webhook_header_value),
        "secrets_in_vault": vault_data is not None,
        "verify_ssl": cfg.webhook_verify_ssl,
        "timeout": cfg.webhook_timeout,
        "vault_path": str(vault.vault_path),
    }
    if args.json:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    if cfg.webhook_enabled:
        console.print("Webhook: [green]enabled[/green]")
    else:
        console.print("Webhook: [yellow]disabled[/yellow]")
    console.print(f"  URL: {payload['url'] or '(not set)'}")
    console.print(f"  Auth: {payload['auth']}")
    if payload["auth"] == "bearer":
        console.print(
            f"  Token: {'set' if payload['token_set'] else 'missing'}"
            + (" (vault)" if payload["secrets_in_vault"] else "")
        )
    elif payload["auth"] == "basic":
        console.print(
            f"  Username: {cfg.webhook_username or '(missing)'}  "
            f"password: {'set' if payload['password_set'] else 'missing'}"
        )
    elif payload["auth"] == "header":
        console.print(
            f"  Header: {payload['header_name'] or '(missing)'}  "
            f"value: {'set' if payload['header_value_set'] else 'missing'}"
        )
    console.print(f"  TLS verify: {payload['verify_ssl']}  timeout={payload['timeout']}s")
    if not cfg.webhook_enabled:
        console.print("[dim]Configure: nexus-control-cli webhook configure[/dim]")
    return 0


def _configure(args: Namespace) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ConfigError(
            "webhook configure requires a TTY. "
            "Or set WEBHOOK_ENABLED=true, WEBHOOK_URL, and auth env vars."
        )

    path = resolve_config_path()
    try:
        settings = load_settings(run_wizard=False)
        set_locale(settings.locale)
        cache_dir = settings.nexus_cache_dir
        default_url = settings.webhook_url or "https://hooks.example.com/scan"
        default_verify = settings.webhook_verify_ssl
        default_auth = settings.webhook_auth or "none"
        default_header = settings.webhook_header_name or "X-Api-Key"
    except ConfigError:
        set_locale("ru")
        cache_dir = (Path.home() / ".cache" / "nexus-control").resolve()
        default_url = "https://hooks.example.com/scan"
        default_verify = True
        default_auth = "none"
        default_header = "X-Api-Key"
        if not path.is_file():
            raise ConfigError(
                f"No config at {path}. Run nexus-control once (first-run wizard) "
                "or set NEXUS_URL, then retry webhook configure."
            ) from None

    console.print(_("Webhook setup"))
    url, verify_ssl, auth, token, username, password, header_name, header_value = (
        _prompt_webhook_fields(
            default_url=default_url,
            default_verify=default_verify,
            default_auth=default_auth,
            default_header=default_header,
        )
    )

    data = read_toml(path)
    data["webhook_enabled"] = True
    data["webhook_url"] = url
    data["webhook_auth"] = auth
    data["webhook_verify_ssl"] = verify_ssl
    if auth == "header":
        data["webhook_header_name"] = header_name
    else:
        data.pop("webhook_header_name", None)
    for secret in (
        "webhook_token",
        "webhook_username",
        "webhook_password",
        "webhook_header_value",
    ):
        data.pop(secret, None)
    write_toml_atomic(path, data)
    WebhookVault(cache_dir).save(
        url=url,
        auth=auth,
        token=token,
        username=username,
        password=password,
        header_name=header_name,
        header_value=header_value,
    )
    console.print(
        _(
            "Webhook enabled. Config: {path}; secrets vault: {vault}",
            path=path,
            vault=cache_dir / "webhook.vault",
        )
    )
    return 0


def _prompt_webhook_fields(
    *,
    default_url: str,
    default_verify: bool,
    default_auth: str,
    default_header: str,
) -> tuple[str, bool, str, str, str, str, str, str]:
    """URL, verify_ssl, auth, token, username, password, header_name, header_value."""
    while True:
        raw = input(_("Webhook URL [{default}]", default=default_url) + ": ").strip()
        if not raw:
            raw = default_url
        try:
            url = normalize_nexus_url(raw)
            break
        except Exception as exc:  # ConfigError
            console.print(f"  {exc}")

    verify_raw = input(_("Verify webhook TLS certificates? [Y/n]") + ": ").strip().lower()
    if not verify_raw:
        verify_ssl = default_verify
    else:
        verify_ssl = verify_raw not in {"n", "no", "0", "false", "off", "н", "нет"}

    console.print(
        _(
            "Auth: none (no credentials) | bearer (token) | "
            "basic (login/password) | header (custom HTTP header)"
        )
    )
    while True:
        auth_raw = input(
            _("Webhook auth [{default}]", default=default_auth) + ": "
        ).strip().lower()
        if not auth_raw:
            auth_raw = default_auth
        if auth_raw in {"password", "login", "login-password", "userpass"}:
            auth_raw = "basic"
        if auth_raw in VALID_AUTH:
            auth = auth_raw
            break
        console.print(_("Choose: none, bearer, basic, or header"))

    token = username = password = header_name = header_value = ""
    if auth == "bearer":
        while True:
            token = getpass.getpass(_("Webhook Bearer token: "))
            if token.strip():
                token = token.strip()
                break
            console.print(_("Token is required"))
    elif auth == "basic":
        while True:
            username = input(_("Webhook username: ")).strip()
            if username:
                break
            console.print(_("Username is required"))
        password = getpass.getpass(_("Webhook password: "))
    elif auth == "header":
        raw_name = input(
            _("Custom header name [{default}]", default=default_header) + ": "
        ).strip()
        header_name = raw_name or default_header
        while True:
            header_value = getpass.getpass(_("Custom header value: "))
            if header_value:
                break
            console.print(_("Header value is required"))

    return url, verify_ssl, auth, token, username, password, header_name, header_value


def _disable(args: Namespace) -> int:
    path = resolve_config_path()
    settings = load_settings(run_wizard=False)
    set_locale(settings.locale)
    if path.is_file():
        update_toml_key(path, "webhook_enabled", False)
    vault = WebhookVault(settings.nexus_cache_dir)
    if getattr(args, "clear_vault", False):
        vault.clear()
    console.print(_("Webhook disabled") + f" ({path})")
    return 0


def _test(args: Namespace) -> int:
    settings = load_settings(run_wizard=False)
    set_locale(settings.locale)
    cfg = resolve_webhook_settings(settings)
    if not cfg.webhook_enabled or not (cfg.webhook_url or "").strip():
        console.print(
            "[red]Webhook is not configured. Run: nexus-control-cli webhook configure[/red]"
        )
        return 2
    result = push_test(cfg)
    if args.json:
        json.dump(
            {
                "ok": result.error is None and not result.skipped,
                "status_code": result.status_code,
                "skipped": result.skipped,
                "error": result.error,
                "event": result.event,
            },
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        sys.stdout.write("\n")
    elif result.error:
        console.print(f"[red]Webhook test failed:[/red] {result.error}")
    elif result.skipped:
        console.print(f"[yellow]Webhook test skipped:[/yellow] {result.error or 'disabled'}")
    else:
        console.print(f"[green]Webhook test OK[/green] (HTTP {result.status_code})")
    if result.error or result.skipped:
        return 1
    return 0
