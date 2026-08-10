"""CLI command: verify repository (download + scan + verified copy [+ upload])."""

from __future__ import annotations

import json
import logging
import sys
from argparse import Namespace
from datetime import datetime, timezone

from rich.console import Console

from nexus_control.cli.assets import (
    AssetSelectionStats,
    require_non_docker_repo,
    select_assets_for_cli,
)
from nexus_control.cli.bootstrap import open_cli_client
from nexus_control.cli.progress import ProgressPrinter
from nexus_control.models import PipelineSummary
from nexus_control.services.pipeline import PipelineService
from nexus_control.services.scan_common import parse_scanner_names
from nexus_control.services.scan_history import record_scan_run
from nexus_control.services.verified_uploader import VerifiedUploader

logger = logging.getLogger(__name__)
console = Console(stderr=True)


def run_verify(args: Namespace) -> int:
    repo_name = args.repo.strip()
    if args.limit is not None and args.limit < 1:
        console.print("[red]--limit must be >= 1[/red]")
        return 2
    scan_limit = getattr(args, "scan_limit", None)
    if scan_limit is not None and scan_limit < 1:
        console.print("[red]--scan-limit must be >= 1[/red]")
        return 2
    scanners = (
        parse_scanner_names(args.scanners)
        if args.scanners
        else None
    )

    with open_cli_client(allow_prompt=getattr(args, "allow_prompt", None)) as ctx:
        repo = ctx.client.get_repository(repo_name)
        if repo is None:
            console.print(f"[red]Repository not found:[/red] {repo_name}")
            return 2
        require_non_docker_repo(repo)

        enabled_scanners = scanners or list(ctx.settings.scanners_list)
        pipeline = PipelineService(ctx.settings, ctx.client)
        scanner_versions = pipeline.scanner_versions(enabled_scanners)
        progress = getattr(args, "on_progress", None) or ProgressPrinter()
        console.print(
            f"Selecting assets for [bold]{repo_name}[/bold] "
            "(Nexus list / cache + local inspect & checkpoints)…"
        )

        def on_select_progress(
            listed: int,
            stats: AssetSelectionStats,
            source: str,
        ) -> None:
            progress.status(
                f"Selecting ({source}): listed={listed} "
                f"download={stats.download_needed} "
                f"scan-only={stats.scan_only} "
                f"checkpoint-skip={stats.checkpoint_skipped}"
            )

        items, listed_total, selection = select_assets_for_cli(
            ctx.client,
            ctx.settings,
            repo_name,
            path_prefix=args.path_prefix,
            limit=args.limit,
            scan_limit=scan_limit,
            refresh=bool(args.refresh),
            scanners=enabled_scanners,
            scanner_versions=scanner_versions,
            # Upload строится из текущего summary; checkpoint-only assets в него
            # не входят, поэтому для --upload выполняем scan-only pipeline.
            use_checkpoints=not bool(args.upload),
            on_progress=on_select_progress,
        )
        progress.status(
            f"Selecting done: listed={listed_total} "
            f"download={selection.download_needed} "
            f"scan-only={selection.scan_only} "
            f"checkpoint-skip={selection.checkpoint_skipped}",
            final=True,
        )
        if not items:
            history_source = getattr(args, "history_source", None) or "cli"
            empty = PipelineSummary(
                repository=repo_name,
                scanners=list(enabled_scanners),
                scanner_versions=dict(scanner_versions),
                finished_at=datetime.now(timezone.utc),
            )
            record_scan_run(
                ctx.settings,
                empty,
                source=history_source,  # type: ignore[arg-type]
                rule_id=getattr(args, "history_rule_id", None),
                path_prefix=args.path_prefix,
                workers=args.workers,
                checkpoint_skipped=selection.checkpoint_skipped,
            )
            if args.json:
                json.dump(
                    {
                        "repository": repo_name,
                        "listed": listed_total,
                        "selected": 0,
                        "selection": {
                            "download_needed": selection.download_needed,
                            "scan_only": selection.scan_only,
                            "checkpoint_skipped": selection.checkpoint_skipped,
                        },
                    },
                    sys.stdout,
                    ensure_ascii=False,
                    indent=2,
                )
                sys.stdout.write("\n")
            if selection.checkpoint_skipped:
                console.print(
                    "[green]All matching assets are unchanged and already "
                    f"verified ({selection.checkpoint_skipped} skipped).[/green]"
                )
            else:
                console.print("[yellow]No assets matched filters.[/yellow]")
            return 0

        workers = args.workers
        if workers is not None and workers < 1:
            console.print("[red]--workers must be >= 1[/red]")
            return 2

        effective_workers = (
            workers if workers is not None else ctx.settings.pipeline_workers
        )
        selected_mains = selection.download_needed + selection.scan_only
        selected_sidecars = max(0, len(items) - selected_mains)
        console.print(
            f"Verifying [bold]{repo_name}[/bold]: mains={selected_mains} "
            f"sidecars={selected_sidecars} (of {listed_total} listed), "
            f"download={selection.download_needed} "
            f"scan-only={selection.scan_only} "
            f"checkpoint-skip={selection.checkpoint_skipped}, "
            f"workers={effective_workers}"
        )
        summary = pipeline.run(
            repository=repo_name,
            items=items,
            download=True,
            scan=True,
            verify=True,
            scanners=scanners,
            workers=workers,
            discover_sidecars=args.limit is not None or scan_limit is not None,
            on_progress=progress,
            history_source=getattr(args, "history_source", None) or "cli",
            history_rule_id=getattr(args, "history_rule_id", None),
            history_path_prefix=args.path_prefix,
            history_checkpoint_skipped=selection.checkpoint_skipped,
        )

        upload_info: dict | None = None
        if args.upload:
            uploader = VerifiedUploader(ctx.client)
            up = uploader.upload(
                summary,
                target_repository=args.target,
                on_progress=progress,
            )
            upload_info = {
                "target": up.target_repository,
                "uploaded": up.uploaded,
                "skipped": up.skipped,
                "failed": up.failed,
                "created_repository": up.created_repository,
            }
            console.print(
                f"Upload → {up.target_repository}: "
                f"uploaded={up.uploaded} skipped={up.skipped} failed={up.failed}"
            )

        payload = {
            "repository": summary.repository,
            "scanners": summary.scanners,
            "started_at": summary.started_at.isoformat(),
            "finished_at": (
                summary.finished_at or datetime.now(timezone.utc)
            ).isoformat(),
            "total": summary.total_scanned,
            "passed": summary.total_passed,
            "failed": summary.total_failed,
            "errors": summary.total_errors,
            "copied": summary.total_copied,
            "selection": {
                "download_needed": selection.download_needed,
                "scan_only": selection.scan_only,
                "checkpoint_skipped": selection.checkpoint_skipped,
            },
            "upload": upload_info,
        }

        if args.json:
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
        else:
            console.print(
                f"[bold]Done[/bold] total={payload['total']} "
                f"PASS={payload['passed']} FAIL={payload['failed']} "
                f"ERROR={payload['errors']} copied={payload['copied']}"
            )

        if summary.total_failed or summary.total_errors:
            return 1
        if upload_info and upload_info["failed"]:
            return 1
        return 0
