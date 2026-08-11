"""CLI command: upload local *-verified tree to Nexus."""

from __future__ import annotations

import json
import logging
import sys
from argparse import Namespace
from pathlib import Path

from rich.console import Console

from nexus_control.cli.assets import require_non_docker_repo
from nexus_control.cli.bootstrap import open_cli_client
from nexus_control.cli.progress import ProgressPrinter
from nexus_control.config import Settings
from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    PipelineSummary,
    ScanResult,
    ScanStatus,
    Verdict,
    VerifyResult,
)
from nexus_control.nexus.uploads import (
    is_uploadable_asset,
    is_verified_local_sidecar,
)
from nexus_control.services.verified_uploader import VerifiedUploader

logger = logging.getLogger(__name__)
console = Console(stderr=True)


def _summary_from_verified_dir(
    settings: Settings,
    repository: str,
    *,
    fmt: str,
) -> PipelineSummary:
    """Собрать PipelineSummary из локального ``<repo>-verified`` для upload."""
    root = settings.verified_repo_dir(repository)
    if not root.is_dir():
        raise SystemExit(f"Local verified directory not found: {root}")

    summary = PipelineSummary(repository=repository, scanners=["cli"])
    skipped_non_package = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if is_verified_local_sidecar(rel):
            continue
        # Report JSON / manifest at verified root
        name = Path(rel).name
        if name.endswith("_report.json") or name in {
            "verified-manifest.json",
            "unverified_assets.txt",
        }:
            continue
        if not is_uploadable_asset(fmt, rel):
            skipped_non_package += 1
            continue
        summary.results.append(
            AssetPipelineResult(
                asset_path=rel,
                kind=AssetKind.FILE,
                download=DownloadResult(
                    status=DownloadStatus.SKIPPED_EXISTING,
                    local_path=path,
                ),
                scans={
                    "cli": ScanResult(
                        status=ScanStatus.SKIPPED,
                        verdict=Verdict.PASS,
                        scanner="cli",
                    )
                },
                verify=VerifyResult(
                    copied=True,
                    verified_path=path,
                ),
            )
        )
    if skipped_non_package:
        logger.info(
            "Ignored %d non-package file(s) under %s for format=%s",
            skipped_non_package,
            root,
            fmt,
        )
    return summary


def run_upload(args: Namespace) -> int:
    repo_name = args.repo.strip()
    with open_cli_client(allow_prompt=getattr(args, "allow_prompt", None)) as ctx:
        repo = ctx.client.get_repository(repo_name)
        if repo is None:
            console.print(f"[red]Source repository not found:[/red] {repo_name}")
            return 2
        require_non_docker_repo(repo)

        summary = _summary_from_verified_dir(
            ctx.settings, repo_name, fmt=repo.format
        )
        if not summary.results:
            console.print(
                f"[yellow]No uploadable packages under verified dir for "
                f"{repo_name} (format={repo.format}).[/yellow]"
            )
            if repo.format.lower() == "nuget":
                console.print(
                    "[yellow]NuGet upload expects .nupkg/.snupkg in "
                    f"{ctx.settings.verified_repo_dir(repo_name)}. "
                    "V3 registration/*.json is metadata and is skipped. "
                    "Re-run verify so only packages land in *-verified.[/yellow]"
                )
            return 0

        console.print(
            f"Uploading {len(summary.results)} local verified package(s) "
            f"for {repo_name} (format={repo.format})"
        )
        progress = getattr(args, "on_progress", None) or ProgressPrinter()
        uploader = VerifiedUploader(ctx.client)
        up = uploader.upload(
            summary,
            target_repository=args.target,
            on_progress=progress,
        )

        payload = {
            "source": up.source_repository,
            "target": up.target_repository,
            "format": up.source_format,
            "uploaded": up.uploaded,
            "skipped": up.skipped,
            "failed": up.failed,
            "created_repository": up.created_repository,
        }
        if args.json:
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
        else:
            console.print(
                f"[bold]Done[/bold] → {up.target_repository} "
                f"uploaded={up.uploaded} skipped={up.skipped} failed={up.failed}"
            )
        return 1 if up.failed else 0
