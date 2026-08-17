"""CLI command: VK Teams / VK Workspace bot — configure / status / test / disable."""

from __future__ import annotations

import getpass
import json
import sys
from argparse import Namespace

from rich.console import Console

from nexus_control.config import Settings, load_settings
from nexus_control.config_io import read_toml, write_toml_atomic
from nexus_control.config_paths import resolve_config_path
from nexus_control.i18n import set_locale
from nexus_control.integrations.vk_notify import vk_teams_configured
from nexus_control.integrations.vk_teams import (
    VkTeamsClient,
    VkTeamsError,
    VkTeamsVault,
    apply_vk_teams_vault,
    vk_teams_token_source,
)

console = Console(stderr=True)

_NOTIFY_CHOICES = ("off", "always", "failures")


def run_vk_teams(args: Namespace) -> int:
    action = getattr(args, "vk_action", None)
    if action == "configure":
        return _configure()
    if action == "status":
        return _status(json_out=bool(getattr(args, "json", False)))
    if action == "test":
        return _test()
    if action == "disable":
        return _disable(clear_vault=bool(getattr(args, "clear_vault", False)))
    console.print(f"[red]Unknown vk-teams action: {action}[/red]")
    return 2


def _load_raw_settings() -> Settings:
    cfg = load_settings()
    set_locale(cfg.locale)
    return cfg


def _configure() -> int:
    path = resolve_config_path()
    if not path.is_file():
        console.print(
            f"[red]No config.toml at {path}.[/red] "
            "Run nexus-control once to create it."
        )
        return 2

    raw = _load_raw_settings()
    cfg = apply_vk_teams_vault(raw)
    vault = VkTeamsVault(cfg.nexus_cache_dir)

    api_url = _prompt(
        "VK Teams API URL",
        cfg.vk_teams_api_url or "https://myteam.mail.ru/bot/v1",
    ).rstrip("/")
    chat_id = _prompt("Chat ID (nick / stamp / …@chat.agent)", cfg.vk_teams_chat_id)
    notify = _prompt_choice(
        "Notify policy (off / always / failures)",
        _NOTIFY_CHOICES,
        cfg.vk_teams_notify if cfg.vk_teams_notify != "off" else "always",
    )
    upload_button = _prompt_yes_no(
        "Show Upload button for verify-only rules?",
        default=bool(cfg.vk_teams_upload_button),
    )

    keep_hint = " (leave empty to keep current)" if vault.load() is not None else ""
    token = getpass.getpass(f"Bot token{keep_hint}: ").strip()
    if not token:
        stored = vault.load()
        if stored is None or not stored.token:
            console.print("[red]Bot token is required.[/red]")
            return 2
        token = stored.token
        console.print("Keeping existing vault token.")

    if not chat_id:
        console.print("[red]Chat ID is required.[/red]")
        return 2

    data = read_toml(path)
    data["vk_teams_api_url"] = api_url
    data["vk_teams_chat_id"] = chat_id
    data["vk_teams_notify"] = notify
    data["vk_teams_upload_button"] = upload_button
    data.pop("vk_teams_token", None)
    write_toml_atomic(path, data)
    vault.save(token, chat_id=chat_id)
    console.print(f"Wrote {path}")
    console.print(f"Token saved to {vault.vault_path} (encrypted).")
    return 0


def _status(*, json_out: bool) -> int:
    raw = _load_raw_settings()
    source = vk_teams_token_source(raw)
    cfg = apply_vk_teams_vault(raw)
    vault = VkTeamsVault.from_settings(raw)
    vault_present = bool(vault is not None and vault.exists())
    configured = vk_teams_configured(cfg)
    payload = {
        "configured": configured,
        "notify": cfg.vk_teams_notify,
        "api_url": cfg.vk_teams_api_url,
        "chat_id": cfg.vk_teams_chat_id or "",
        "upload_button": bool(cfg.vk_teams_upload_button),
        "token_source": source,
        "token_present": source != "missing",
        "vault_present": vault_present,
        "vault_path": str(vault.vault_path) if vault is not None else "",
    }
    if json_out:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    state = "enabled" if configured else "disabled"
    console.print(f"[bold]VK Teams:[/bold] {state}")
    console.print(f"  api_url:        {payload['api_url']}")
    console.print(f"  chat_id:        {payload['chat_id'] or '(empty)'}")
    console.print(f"  notify:         {payload['notify']}")
    console.print(f"  upload_button:  {payload['upload_button']}")
    console.print(f"  token:          {source}")
    console.print(
        f"  vault:          {'present' if vault_present else 'absent'}"
        + (f" ({payload['vault_path']})" if payload["vault_path"] else "")
    )
    return 0


def _test() -> int:
    raw = _load_raw_settings()
    cfg = apply_vk_teams_vault(raw)
    if not cfg.vk_teams_token.strip() or not cfg.vk_teams_chat_id.strip():
        console.print(
            "[red]VK Teams is not configured.[/red] "
            "Run: nexus-control-cli vk-teams configure"
        )
        return 2
    bot = VkTeamsClient.from_settings(cfg)
    try:
        bot.send_text(
            cfg.vk_teams_chat_id,
            "🔍 <b>nexus-control</b>\nПроверка связи с VK Teams — всё работает.",
            parse_mode="HTML",
        )
    except VkTeamsError as exc:
        console.print(f"[red]VK Teams test failed:[/red] {exc}")
        return 1
    console.print(f"Sent connectivity test to {cfg.vk_teams_chat_id}")
    return 0


def _disable(*, clear_vault: bool) -> int:
    path = resolve_config_path()
    if not path.is_file():
        console.print(f"[red]No config.toml at {path}.[/red]")
        return 2
    data = read_toml(path)
    data["vk_teams_notify"] = "off"
    data.pop("vk_teams_token", None)
    write_toml_atomic(path, data)
    if clear_vault:
        raw = _load_raw_settings()
        vault = VkTeamsVault.from_settings(raw)
        if vault is not None:
            vault.clear()
            console.print(f"Cleared {vault.vault_path}")
    console.print("VK Teams notifications disabled (notify=off).")
    return 0


def _prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{label}{suffix}: ").strip()
    return raw if raw else default


def _prompt_choice(label: str, choices: tuple[str, ...], default: str) -> str:
    while True:
        raw = _prompt(label, default).strip().lower()
        if raw in choices:
            return raw
        print(f"  Expected one of: {', '.join(choices)}", file=sys.stderr)


def _prompt_yes_no(label: str, *, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{label} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw not in {"n", "no", "0", "false", "off", "н", "нет"}
