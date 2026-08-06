"""CLI command: verify repository (download + scan + verified copy [+ upload])."""

from __future__ import annotations

import json
import logging
import sys
from argparse import Namespace
from datetime import datetime, timezone

from rich.console import Console

from nexus_control.cli.assets import (
    require_non_docker_repo,
    select_assets_for_cli,
)
from nexus_control.cli.bootstrap import open_cli_client
from nexus_control.cli.progress import ProgressPrinter
from nexus_control.services.pipeline import PipelineService
from nexus_control.services.scan_common import parse_scanner_names
from nexus_control.services.verified_uploader import VerifiedUploader

logger = logging.getLogger(__name__)
console = Console(stderr=True)


def run_verify(args: Namespace) -> int:
    repo_name = args.repo.strip()
    scanners = (
        parse_scanner_names(args.scanners)
        if args.scanners
        else None
    )

    with open_cli_client() as ctx:
        repo = ctx.client.get_repository(repo_name)
        if repo is None:
            console.print(f"[red]Repository not found:[/red] {repo_name}")
            return 2
        require_non_docker_repo(repo)

        items, listed_total = select_assets_for_cli(
            ctx.client,
            ctx.settings,
            repo_name,
            path_prefix=args.path_prefix,
            limit=args.limit,
            refresh=bool(args.refresh),
        )
        if not items:
            console.print("[yellow]No assets matched filters.[/yellow]")
            return 0

        workers = args.workers
        if workers is not None and workers < 1:
            console.print("[red]--workers must be >= 1[/red]")
            return 2

        effective_workers = (
            workers if workers is not None else ctx.settings.pipeline_workers
        )
        console.print(
            f"Verifying [bold]{repo_name}[/bold]: {len(items)} asset(s) "
            f"(of {listed_total} listed), workers={effective_workers}"
        )
        progress = ProgressPrinter()
        pipeline = PipelineService(ctx.settings, ctx.client)
        summary = pipeline.run(
            repository=repo_name,
            items=items,
            download=True,
            scan=True,
            verify=True,
            scanners=scanners,
            workers=workers,
            on_progress=progress,
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
