"""CLI: status / update offline OSV vulnerability databases."""

from __future__ import annotations

import json
import sys
from argparse import Namespace

from rich.console import Console

from nexus_control.config import load_settings
from nexus_control.i18n import set_locale
from nexus_control.services.osv_offline_db import (
    DEFAULT_UPDATE_ECOSYSTEMS,
    download_offline_databases,
    ecosystem_db_path,
    fetch_ecosystems_list,
    list_installed_ecosystems,
    osv_db_cache_root,
    preferred_ecosystem_db_path,
)

console = Console(stderr=True)


def run_osv_db(args: Namespace) -> int:
    action = getattr(args, "osv_db_action", "status") or "status"
    settings = load_settings()
    set_locale(settings.locale)
    root = osv_db_cache_root(settings)

    if action == "status":
        installed = list_installed_ecosystems(root)
        payload = {
            "cache_root": str(root),
            "ecosystems": installed,
            "paths": {
                eco: str(ecosystem_db_path(root, eco) or preferred_ecosystem_db_path(root, eco))
                for eco in installed
            },
        }
        if args.json:
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
        else:
            console.print(f"OSV offline DB cache: [bold]{root}[/bold]")
            if not installed:
                console.print(
                    "[yellow]No ecosystems installed. "
                    "Run: nexus-control-cli osv-db update --ecosystem NuGet[/yellow]"
                )
            else:
                for eco in installed:
                    real = (
                        ecosystem_db_path(root, eco)
                        or preferred_ecosystem_db_path(root, eco)
                    )
                    size = real.stat().st_size if real.is_file() else 0
                    console.print(f"  {eco}: {real} ({size} bytes)")
        return 0

    if action == "update":
        if getattr(args, "ecosystem", None):
            ecosystems = [str(args.ecosystem).strip()]
        elif getattr(args, "all_ecosystems", False):
            console.print("Fetching ecosystems list…")
            ecosystems = fetch_ecosystems_list()
        else:
            ecosystems = list(DEFAULT_UPDATE_ECOSYSTEMS)
            console.print(
                "[dim]Default ecosystems: "
                f"{', '.join(ecosystems)} (use --ecosystem or --all)[/dim]"
            )
        console.print(f"Downloading OSV offline DB into [bold]{root}[/bold]…")
        try:

            def on_progress(eco: str) -> None:
                console.print(f"  … {eco}")

            paths = download_offline_databases(
                settings,
                ecosystems=ecosystems,
                on_progress=on_progress,
            )
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Download failed:[/red] {exc}")
            return 1
        if args.json:
            json.dump(
                {
                    "cache_root": str(root),
                    "downloaded": [str(p) for p in paths],
                },
                sys.stdout,
                ensure_ascii=False,
                indent=2,
            )
            sys.stdout.write("\n")
        else:
            console.print(f"[green]Downloaded {len(paths)} ecosystem DB(s).[/green]")
        return 0

    console.print(f"[red]Unknown osv-db action:[/red] {action}")
    return 2
