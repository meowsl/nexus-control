"""CLI command: list repositories."""

from __future__ import annotations

import json
import sys
from argparse import Namespace

from rich.console import Console
from rich.table import Table

from nexus_control.cli.bootstrap import open_cli_client


def run_repos(args: Namespace) -> int:
    with open_cli_client() as ctx:
        repos = ctx.client.list_repositories()
        if args.json:
            payload = [
                {
                    "name": r.name,
                    "format": r.format,
                    "type": r.type,
                    "url": r.url,
                    "support": r.support_level,
                }
                for r in repos
            ]
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return 0

        table = Table(title=f"Repositories ({len(repos)})")
        table.add_column("Name")
        table.add_column("Format")
        table.add_column("Type")
        table.add_column("Support")
        for r in repos:
            table.add_row(r.name, r.format, r.type, r.support_level)
        Console(stderr=True).print(table)
        return 0
