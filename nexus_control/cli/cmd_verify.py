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
from nexus_control.services.osv_offline_db import EnsureStatus, ensure_osv_offline_db
from nexus_control.services.pipeline import PipelineService
from nexus_control.services.resource_governor import DiskPressureError, resolve_limits
from nexus_control.services.resource_pipeline import run_resourced_pipeline
from nexus_control.services.scan_checkpoint import parse_scan_mode
from nexus_control.services.scan_common import parse_scanner_names, parse_severity_threshold
from nexus_control.utils.path_prefixes import format_path_filters, normalize_path_prefixes
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
    max_scanner_procs = getattr(args, "max_scanner_procs", None)
    if max_scanner_procs is not None and max_scanner_procs < 1:
        console.print("[red]--max-scanner-procs must be >= 1[/red]")
        return 2

    with open_cli_client(allow_prompt=getattr(args, "allow_prompt", None)) as ctx:
        repo = ctx.client.get_repository(repo_name)
        if repo is None:
            console.print(f"[red]Repository not found:[/red] {repo_name}")
            return 2
        require_non_docker_repo(repo)

        enabled_scanners = scanners or list(ctx.settings.scanners_list)
        # Offline OSV DB preflight (nuget всегда нужен osv; иначе — если osv в scanners).
        allow_prompt = getattr(args, "allow_prompt", None)
        interactive = (allow_prompt is not False) and sys.stdin.isatty()
        ensure = ensure_osv_offline_db(
            ctx.settings,
            repo_format=repo.format,
            enabled_scanners=list(enabled_scanners),
            interactive=interactive,
        )
        if ensure.status == EnsureStatus.CANCELLED:
            console.print(f"[yellow]{ensure.message}[/yellow]")
            return 1
        if ensure.status == EnsureStatus.ERROR:
            console.print(f"[red]{ensure.message}[/red]")
            return 1
        run_settings = ensure.settings or ctx.settings
        if ensure.status == EnsureStatus.OK and ensure.message:
            console.print(f"[dim]{ensure.message}[/dim]")

        try:
            scan_mode = parse_scan_mode(getattr(args, "scan_mode", None))
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            return 2
        use_checkpoints = scan_mode == "incremental"
        ignore_checkpoint_ttl = scan_mode == "incremental"
        scan_include_prefixes = normalize_path_prefixes(args.path_prefix) or None
        scan_exclude_prefixes = (
            normalize_path_prefixes(getattr(args, "exclude_prefix", None)) or None
        )

        severity_arg = getattr(args, "severity", None)
        if severity_arg:
            try:
                parsed_severity = parse_severity_threshold(severity_arg)
            except ValueError as exc:
                console.print(f"[red]{exc}[/red]")
                return 2
            run_settings = run_settings.model_copy(
                update={"severity": parsed_severity}
            )

        pipeline = PipelineService(run_settings, ctx.client)
        # NuGet всегда гоняет osv identity; версия нужна для PASS-checkpoint.
        version_names = list(enabled_scanners)
        if "osv" not in version_names:
            version_names.append("osv")
        scanner_versions = pipeline.scanner_versions(version_names)
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
            run_settings,
            repo_name,
            path_prefix=args.path_prefix,
            exclude_prefix=getattr(args, "exclude_prefix", None),
            limit=args.limit,
            scan_limit=scan_limit,
            refresh=bool(args.refresh),
            scanners=enabled_scanners,
            scanner_versions=scanner_versions,
            use_checkpoints=use_checkpoints,
            ignore_checkpoint_ttl=ignore_checkpoint_ttl,
            on_progress=on_select_progress,
        )
        progress.status(
            f"Selecting done: listed={listed_total} "
            f"download={selection.download_needed} "
            f"scan-only={selection.scan_only} "
            f"checkpoint-skip={selection.checkpoint_skipped}",
            final=True,
        )
        extra_pass = selection.checkpoint_pass_results()
        if not items:
            history_source = getattr(args, "history_source", None) or "cli"
            history_prefix = format_path_filters(
                args.path_prefix,
                getattr(args, "exclude_prefix", None),
            )
            if args.upload and extra_pass:
                uploader = VerifiedUploader(ctx.client)
                summary = PipelineSummary(
                    repository=repo_name,
                    scanners=list(enabled_scanners),
                    scanner_versions=dict(scanner_versions),
                    scan_mode=scan_mode,
                )
                summary.results.extend(extra_pass)
                console.print(
                    f"Uploading [bold]{repo_name}[/bold]: "
                    f"checkpoint-skip={selection.checkpoint_skipped} "
                    f"(scan_mode={scan_mode}, no rescan)"
                )
                upload_summary = uploader.upload(
                    summary,
                    target_repository=args.target,
                    on_progress=progress,
                )
                pipeline.finalize_summary(
                    summary,
                    verify=True,
                    history_source=history_source,
                    history_rule_id=getattr(args, "history_rule_id", None),
                    history_path_prefix=history_prefix,
                    history_workers=args.workers,
                    history_checkpoint_skipped=selection.checkpoint_skipped,
                    skip_defectdojo=True,
                    scan_include_prefixes=scan_include_prefixes,
                    scan_exclude_prefixes=scan_exclude_prefixes,
                )
                upload_info = {
                    "target": upload_summary.target_repository,
                    "uploaded": upload_summary.uploaded,
                    "skipped": upload_summary.skipped,
                    "deleted": upload_summary.deleted,
                    "delete_failed": upload_summary.delete_failed,
                    "failed": upload_summary.failed,
                    "batches": 1,
                }
                console.print(
                    f"Upload → {upload_info['target']}: "
                    f"uploaded={upload_info['uploaded']} "
                    f"skipped={upload_info['skipped']} "
                    f"deleted={upload_info['deleted']} "
                    f"failed={upload_info['failed']}"
                )
                payload = {
                    "repository": repo_name,
                    "scan_mode": scan_mode,
                    "listed": listed_total,
                    "selected": 0,
                    "selection": {
                        "download_needed": selection.download_needed,
                        "scan_only": selection.scan_only,
                        "checkpoint_skipped": selection.checkpoint_skipped,
                    },
                    "passed": summary.total_passed,
                    "upload": upload_info,
                }
                if args.json:
                    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
                    sys.stdout.write("\n")
                else:
                    console.print(
                        "[green]All matching assets reused from checkpoints "
                        f"({selection.checkpoint_skipped} skipped).[/green]"
                    )
                return 1 if upload_summary.failed else 0

            empty = PipelineSummary(
                repository=repo_name,
                scanners=list(enabled_scanners),
                scanner_versions=dict(scanner_versions),
                finished_at=datetime.now(timezone.utc),
                scan_mode=scan_mode,
            )
            record_scan_run(
                run_settings,
                empty,
                source=history_source,  # type: ignore[arg-type]
                rule_id=getattr(args, "history_rule_id", None),
                path_prefix=history_prefix,
                workers=args.workers,
                checkpoint_skipped=selection.checkpoint_skipped,
            )
            if args.json:
                json.dump(
                    {
                        "repository": repo_name,
                        "scan_mode": scan_mode,
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

        limits = resolve_limits(
            run_settings,
            scanner_count=len(enabled_scanners),
            workers_override=workers,
            max_scanner_procs_override=max_scanner_procs,
        )
        selected_mains = selection.download_needed + selection.scan_only
        selected_sidecars = max(0, len(items) - selected_mains)
        console.print(
            f"Verifying [bold]{repo_name}[/bold]: mains={selected_mains} "
            f"sidecars={selected_sidecars} (of {listed_total} listed), "
            f"download={selection.download_needed} "
            f"scan-only={selection.scan_only} "
            f"checkpoint-skip={selection.checkpoint_skipped}, "
            f"scan_mode={scan_mode}, "
            f"workers={limits.pipeline_workers} "
            f"scanners_procs={limits.max_scanner_procs} "
            f"severity={run_settings.severity}"
        )

        uploader = VerifiedUploader(ctx.client) if args.upload else None

        def do_upload(summary: PipelineSummary):
            assert uploader is not None
            return uploader.upload(
                summary,
                target_repository=args.target,
                on_progress=progress,
            )

        def on_status(msg: str) -> None:
            console.print(f"[cyan]{msg}[/cyan]")

        try:
            summary, upload_parts = run_resourced_pipeline(
                pipeline,
                repository=repo_name,
                items=items,
                download=True,
                scan=True,
                verify=True,
                scanners=scanners,
                workers=workers,
                max_scanner_procs=max_scanner_procs,
                discover_sidecars=args.limit is not None or scan_limit is not None,
                on_progress=progress,
                on_status=on_status,
                do_upload=do_upload if args.upload else None,
                history_source=getattr(args, "history_source", None) or "cli",
                history_rule_id=getattr(args, "history_rule_id", None),
                history_path_prefix=format_path_filters(
                    args.path_prefix,
                    getattr(args, "exclude_prefix", None),
                ),
                history_checkpoint_skipped=selection.checkpoint_skipped,
                extra_pass_results=extra_pass,
                scan_mode=scan_mode,
                scan_include_prefixes=scan_include_prefixes,
                scan_exclude_prefixes=scan_exclude_prefixes,
            )
        except DiskPressureError as exc:
            console.print(f"[red]Disk pressure:[/red] {exc}")
            return 1

        upload_info: dict | None = None
        if args.upload:
            uploaded = sum(u.uploaded for u in upload_parts)
            skipped = sum(u.skipped for u in upload_parts)
            deleted = sum(u.deleted for u in upload_parts)
            delete_failed = sum(u.delete_failed for u in upload_parts)
            failed = sum(u.failed for u in upload_parts)
            target = (
                upload_parts[-1].target_repository
                if upload_parts
                else (args.target or f"{repo_name}-verified")
            )
            upload_info = {
                "target": target,
                "uploaded": uploaded,
                "skipped": skipped,
                "deleted": deleted,
                "delete_failed": delete_failed,
                "failed": failed,
                "batches": len(upload_parts),
            }
            console.print(
                f"Upload → {target}: "
                f"uploaded={uploaded} skipped={skipped} "
                f"deleted={deleted} failed={failed}"
            )

        payload = {
            "repository": summary.repository,
            "scanners": summary.scanners,
            "severity": run_settings.severity,
            "scan_mode": scan_mode,
            "started_at": summary.started_at.isoformat(),
            "finished_at": (
                summary.finished_at or datetime.now(timezone.utc)
            ).isoformat(),
            "total": summary.total_scanned,
            "passed": summary.total_passed,
            "failed": summary.total_failed,
            "errors": summary.total_errors,
            "copied": summary.total_copied,
            "resources": {
                "workers": limits.pipeline_workers,
                "max_scanner_procs": limits.max_scanner_procs,
                "disk_critical_watermark": limits.disk_critical_watermark,
            },
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
