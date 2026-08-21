"""CLI: manage Harbor-like labels (same DB as the web console)."""

from __future__ import annotations

import json
import sys
from argparse import Namespace

from rich.console import Console
from rich.table import Table

from nexus_control.web.db import SessionLocal, init_db
from nexus_control.web.orm import Label, RepoLabel

console = Console(stderr=True)


def run_labels(args: Namespace) -> int:
    init_db()
    action = getattr(args, "labels_action", None) or "list"
    db = SessionLocal()
    try:
        if action == "list":
            rows = db.query(Label).order_by(Label.name.asc()).all()
            if args.json:
                json.dump(
                    [
                        {
                            "id": r.id,
                            "name": r.name,
                            "color": r.color,
                            "description": r.description,
                        }
                        for r in rows
                    ],
                    sys.stdout,
                    ensure_ascii=False,
                    indent=2,
                )
                sys.stdout.write("\n")
                return 0
            table = Table(title=f"Labels ({len(rows)})")
            table.add_column("Name")
            table.add_column("Color")
            table.add_column("Description")
            for r in rows:
                table.add_row(r.name, r.color, r.description)
            console.print(table)
            return 0

        if action == "create":
            name = (getattr(args, "name", None) or "").strip()
            if not name:
                console.print("[red]name required[/red]")
                return 2
            if db.query(Label).filter(Label.name == name).first():
                console.print(f"[red]exists:[/red] {name}")
                return 1
            db.add(
                Label(
                    name=name,
                    color=(getattr(args, "color", None) or "#3D7EA6").strip(),
                    description=(getattr(args, "description", None) or "").strip(),
                )
            )
            db.commit()
            console.print(f"[green]created[/green] {name}")
            return 0

        if action == "delete":
            name = (getattr(args, "name", None) or "").strip()
            row = db.query(Label).filter(Label.name == name).first()
            if row is None:
                console.print(f"[red]not found:[/red] {name}")
                return 1
            db.delete(row)
            db.commit()
            console.print(f"[green]deleted[/green] {name}")
            return 0

        if action == "attach":
            repo = (getattr(args, "repo", None) or "").strip()
            name = (getattr(args, "name", None) or "").strip()
            label = db.query(Label).filter(Label.name == name).first()
            if label is None:
                console.print(f"[red]label not found:[/red] {name}")
                return 1
            exists = (
                db.query(RepoLabel)
                .filter(RepoLabel.repo_name == repo, RepoLabel.label_id == label.id)
                .first()
            )
            if exists:
                return 0
            db.add(RepoLabel(repo_name=repo, label_id=label.id))
            db.commit()
            console.print(f"[green]attached[/green] {name} → {repo}")
            return 0

        if action == "detach":
            repo = (getattr(args, "repo", None) or "").strip()
            name = (getattr(args, "name", None) or "").strip()
            label = db.query(Label).filter(Label.name == name).first()
            if label is None:
                return 1
            db.query(RepoLabel).filter(
                RepoLabel.repo_name == repo, RepoLabel.label_id == label.id
            ).delete()
            db.commit()
            console.print(f"[green]detached[/green] {name} from {repo}")
            return 0

        console.print(f"[red]unknown action[/red] {action}")
        return 2
    finally:
        db.close()
