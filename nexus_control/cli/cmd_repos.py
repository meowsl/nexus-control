"""CLI command: list repositories."""

from __future__ import annotations

import json
import sys
from argparse import Namespace

from rich.console import Console
from rich.table import Table

from nexus_control.cli.bootstrap import open_cli_client


def run_repos(args: Namespace) -> int:
    label_filter = (getattr(args, "label", None) or "").strip()
    with open_cli_client() as ctx:
        repos = ctx.client.list_repositories()
        labels_map: dict[str, list[str]] = {}
        try:
            from nexus_control.web.db import SessionLocal, init_db
            from nexus_control.web.deps import labels_for_repos

            init_db()
            db = SessionLocal()
            try:
                labels_map = {
                    name: [x["name"] for x in items]
                    for name, items in labels_for_repos(
                        db, [r.name for r in repos]
                    ).items()
                }
            finally:
                db.close()
        except Exception:
            labels_map = {}
        if label_filter:
            repos = [r for r in repos if label_filter in labels_map.get(r.name, [])]
        if args.json:
            payload = [
                {
                    "name": r.name,
                    "format": r.format,
                    "type": r.type,
                    "url": r.url,
                    "support": r.support_level,
                    "labels": labels_map.get(r.name, []),
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
        table.add_column("Labels")
        for r in repos:
            table.add_row(
                r.name,
                r.format,
                r.type,
                r.support_level,
                ", ".join(labels_map.get(r.name, [])),
            )
        Console(stderr=True).print(table)
        return 0
