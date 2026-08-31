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
    is_maven_repo_root_path,
    is_uploadable_asset,
    is_verified_local_sidecar,
)
from nexus_control.services.scan_common import main_asset_path_for_sidecar
from nexus_control.services.verified_uploader import VerifiedUploader

logger = logging.getLogger(__name__)
console = Console(stderr=True)

MANIFEST_NAME = "verified-manifest.json"


def _read_manifest(verified_dir: Path) -> dict:
    path = verified_dir / MANIFEST_NAME
    if not path.is_file():
        raise FileNotFoundError(str(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {MANIFEST_NAME}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{MANIFEST_NAME} root must be an object")
    return data


def _manifest_asset_paths(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("asset_path") or "").replace("\\", "/").lstrip("/")
        if not rel or rel in seen:
            continue
        seen.add(rel)
        out.append(rel)
    return out


def load_manifest_passed_paths(verified_dir: Path) -> list[str]:
    """Пути PASS из последнего ``verified-manifest.json`` (нормализованные).

    Raises:
        FileNotFoundError: нет manifest.
        ValueError: битый / пустой manifest без PASS и без FAIL.
    """
    data = _read_manifest(verified_dir)
    out = _manifest_asset_paths(data.get("passed_assets"))
    if out:
        return out
    failed = _manifest_asset_paths(data.get("failed_assets"))
    if failed:
        return []
    raise ValueError(f"{MANIFEST_NAME} has no passed_assets (run verify first)")


def load_manifest_failed_paths(verified_dir: Path) -> list[str]:
    """FAIL-пути из последнего manifest (для revoke в remote ``*-verified``)."""
    try:
        data = _read_manifest(verified_dir)
    except FileNotFoundError:
        return []
    return _manifest_asset_paths(data.get("failed_assets"))


def _path_allowed_by_manifest(rel: str, allowed: set[str]) -> bool:
    """PASS из manifest, либо checksum sidecar рядом с таким PASS."""
    key = rel.replace("\\", "/").lstrip("/")
    if key in allowed:
        return True
    if is_maven_repo_root_path(key):
        return True
    main = main_asset_path_for_sidecar(key)
    return bool(main and main.replace("\\", "/").lstrip("/") in allowed)


def _summary_from_verified_dir(
    settings: Settings,
    repository: str,
    *,
    fmt: str,
) -> tuple[PipelineSummary, int]:
    """Собрать PipelineSummary только из PASS последнего verify (manifest).

    Returns:
        ``(summary, skipped_not_in_manifest)`` — файлы на диске вне manifest.
    """
    root = settings.verified_repo_dir(repository)
    if not root.is_dir():
        raise SystemExit(f"Local verified directory not found: {root}")

    try:
        allowed = set(load_manifest_passed_paths(root))
    except FileNotFoundError as exc:
        raise SystemExit(
            f"No {MANIFEST_NAME} in {root}. Run verify first, then upload."
        ) from exc
    except ValueError as exc:
        raise SystemExit(f"{exc}. Run verify first, then upload.") from exc

    summary = PipelineSummary(repository=repository, scanners=["cli"])
    skipped_non_package = 0
    skipped_not_in_manifest = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if is_verified_local_sidecar(rel):
            continue
        name = Path(rel).name
        if name.endswith("_report.json") or name in {
            MANIFEST_NAME,
            "unverified_assets.txt",
        }:
            continue
        if not is_uploadable_asset(fmt, rel):
            skipped_non_package += 1
            continue
        key = rel.replace("\\", "/").lstrip("/")
        if not _path_allowed_by_manifest(key, allowed):
            skipped_not_in_manifest += 1
            logger.info(
                "Skip upload %s: not in last %s (stale or failed last verify)",
                rel,
                MANIFEST_NAME,
            )
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

    uploaded_keys = {
        r.asset_path.replace("\\", "/").lstrip("/") for r in summary.results
    }
    for rel in sorted(allowed - uploaded_keys):
        logger.warning(
            "Manifest lists %s but file missing under %s — skip",
            rel,
            root,
        )

    if skipped_non_package:
        logger.info(
            "Ignored %d non-package file(s) under %s for format=%s",
            skipped_non_package,
            root,
            fmt,
        )
    if skipped_not_in_manifest:
        logger.info(
            "Skipped %d file(s) not in last %s under %s",
            skipped_not_in_manifest,
            MANIFEST_NAME,
            root,
        )
    return summary, skipped_not_in_manifest


def run_upload(args: Namespace) -> int:
    repo_name = args.repo.strip()
    with open_cli_client(allow_prompt=getattr(args, "allow_prompt", None)) as ctx:
        repo = ctx.client.get_repository(repo_name)
        if repo is None:
            console.print(f"[red]Source repository not found:[/red] {repo_name}")
            return 2
        require_non_docker_repo(repo)

        summary, skipped_stale = _summary_from_verified_dir(
            ctx.settings, repo_name, fmt=repo.format
        )
        extra_revoke = load_manifest_failed_paths(
            ctx.settings.verified_repo_dir(repo_name)
        )
        if skipped_stale:
            console.print(
                f"[dim]Skipped {skipped_stale} local file(s) not in last "
                f"{MANIFEST_NAME} (stale or failed last verify).[/dim]"
            )
        if not summary.results and not extra_revoke:
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
            + (
                f", revoke FAIL={len(extra_revoke)}"
                if extra_revoke
                else ""
            )
        )
        progress = getattr(args, "on_progress", None) or ProgressPrinter()
        uploader = VerifiedUploader(ctx.client)
        up = uploader.upload(
            summary,
            target_repository=args.target,
            extra_revoke_paths=extra_revoke,
            on_progress=progress,
        )

        payload = {
            "source": up.source_repository,
            "target": up.target_repository,
            "format": up.source_format,
            "uploaded": up.uploaded,
            "skipped": up.skipped,
            "skipped_not_in_manifest": skipped_stale,
            "deleted": up.deleted,
            "delete_failed": up.delete_failed,
            "failed": up.failed,
            "created_repository": up.created_repository,
        }
        if args.json:
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
        else:
            console.print(
                f"[bold]Done[/bold] → {up.target_repository} "
                f"uploaded={up.uploaded} skipped={up.skipped} "
                f"deleted={up.deleted} failed={up.failed}"
            )
        return 1 if up.failed else 0
