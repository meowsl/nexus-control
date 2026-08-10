"""CLI command: scan history list / show."""

from __future__ import annotations

import json
import sys
from argparse import Namespace

from rich.console import Console
from rich.table import Table

from nexus_control.cli.bootstrap import load_cli_settings
from nexus_control.services.scan_history import (
    format_history_when,
    list_runs,
    load_run,
)

console = Console(stderr=True)


def run_history(args: Namespace) -> int:
    settings = load_cli_settings(allow_prompt=False)
    action = getattr(args, "history_action", None) or "list"

    if action == "show":
        run_id = getattr(args, "run_id", None)
        if not run_id:
            console.print("[red]run_id required for show[/red]")
            return 2
        summary = load_run(settings, run_id)
        if summary is None:
            console.print(f"[red]Run not found:[/red] {run_id}")
            return 1
        if args.json:
            payload = {
                "run_id": run_id,
                "repository": summary.repository,
                "started_at": summary.started_at.isoformat(),
                "finished_at": (
                    summary.finished_at.isoformat() if summary.finished_at else None
                ),
                "scanners": summary.scanners,
                "totals": {
                    "scanned": summary.total_scanned,
                    "passed": summary.total_passed,
                    "failed": summary.total_failed,
                    "errors": summary.total_errors,
                    "copied": summary.total_copied,
                },
                "assets": [
                    {
                        "path": r.asset_path,
                        "verdict": r.verdict.value,
                        "download": r.download.status.value,
                        "vulns": r.scan.vulnerability_count,
                        "verified": (
                            str(r.verify.verified_path)
                            if r.verify.verified_path
                            else None
                        ),
                    }
                    for r in summary.results
                ],
            }
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return 0

        console.print(
            f"[bold]{summary.repository}[/bold]  "
            f"scanners={'+'.join(summary.scanners) or '-'}  "
            f"PASS={summary.total_passed} FAIL={summary.total_failed} "
            f"ERROR={summary.total_errors} copied={summary.total_copied}"
        )
        # Meta (incl. checkpoint_skipped) may live only in index/snapshot meta.
        from nexus_control.services.scan_history import load_run_meta

        meta = load_run_meta(settings, run_id)
        if meta is not None and meta.totals.checkpoint_skipped:
            console.print(
                f"[dim]skipped={meta.totals.checkpoint_skipped} "
                "(unchanged, already verified)[/dim]"
            )
        if not summary.results:
            console.print("[yellow]No assets in this run snapshot.[/yellow]")
            return 0
        table = Table(title=f"Assets ({len(summary.results)})")
        table.add_column("Path")
        table.add_column("Verdict")
        table.add_column("Download")
        table.add_column("Vulns")
        table.add_column("Verified")
        for result in summary.results:
            table.add_row(
                result.asset_path,
                result.verdict.value,
                result.download.status.value,
                str(result.scan.vulnerability_count),
                str(result.verify.verified_path or "-"),
            )
        console.print(table)
        return 0

    # list
    limit = args.limit if args.limit is not None else 20
    runs = list_runs(settings, repository=args.repo, limit=limit)
    if args.json:
        payload = [
            {
                "run_id": m.run_id,
                "repository": m.repository,
                "started_at": m.started_at,
                "finished_at": m.finished_at,
                "source": m.source,
                "rule_id": m.rule_id,
                "scanners": m.scanners,
                "totals": {
                    "total": m.totals.total,
                    "scanned": m.totals.scanned,
                    "passed": m.totals.passed,
                    "failed": m.totals.failed,
                    "errors": m.totals.errors,
                    "skipped": m.totals.skipped,
                    "copied": m.totals.copied,
                    "checkpoint_skipped": m.totals.checkpoint_skipped,
                },
            }
            for m in runs
        ]
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    if not runs:
        console.print("[yellow]No scan history yet.[/yellow]")
        return 0

    table = Table(title=f"Scan history ({len(runs)})")
    table.add_column("When", no_wrap=True, width=16)
    table.add_column("Repo")
    table.add_column("Source")
    table.add_column("Total")
    table.add_column("PASS")
    table.add_column("FAIL")
    table.add_column("ERROR")
    table.add_column("Copied")
    table.add_column("Skipped")
    table.add_column("Run id")
    for meta in runs:
        table.add_row(
            format_history_when(meta.finished_at, meta.started_at),
            meta.repository,
            meta.source + (f"/{meta.rule_id}" if meta.rule_id else ""),
            str(meta.totals.total),
            str(meta.totals.passed),
            str(meta.totals.failed),
            str(meta.totals.errors),
            str(meta.totals.copied),
            str(meta.totals.checkpoint_skipped),
            meta.run_id,
        )
    console.print(table)
    return 0
