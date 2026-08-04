"""Копирование артефактов PASS в ``<repo>-verified`` и запись манифеста."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from nexus_tui.config import Settings
from nexus_tui.models import (
    AssetPipelineResult,
    PipelineSummary,
    Verdict,
    VerifyResult,
)
from nexus_tui.utils.fs import copy_file, ensure_dir, prepare_asset_destination, write_json
from nexus_tui.utils.safe_path import UnsafePathError, asset_verified_path

logger = logging.getLogger(__name__)


class Verifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def verified_dir(self, repository: str) -> Path:
        return self.settings.verified_repo_dir(repository)

    def copy_if_pass(
        self,
        *,
        repository: str,
        asset_path: str,
        local_path: Path,
        is_docker: bool = False,
        tag: str | None = None,
    ) -> VerifyResult:
        try:
            if is_docker and tag is not None:
                # Повторить структуру загрузки: images/<tag>.tar под verified root.
                from nexus_tui.utils.safe_path import sanitize_filename

                safe_tag = sanitize_filename(tag.replace(":", "_").replace("/", "_"))
                dest = asset_verified_path(
                    self.settings.verified_root,
                    repository,
                    f"images/{safe_tag}.tar",
                )
            else:
                dest = asset_verified_path(
                    self.settings.verified_root,
                    repository,
                    asset_path,
                )
        except UnsafePathError as exc:
            return VerifyResult(error=f"Unsafe verified path: {exc}")

        dest = prepare_asset_destination(dest)
        try:
            copied, skipped = copy_file(
                local_path,
                dest,
                overwrite=self.settings.overwrite_verified,
            )
        except OSError as exc:
            logger.error("Failed to copy to verified: %s", exc)
            return VerifyResult(error=f"Copy failed: {exc}")

        if skipped:
            return VerifyResult(
                copied=False,
                skipped_existing=True,
                verified_path=dest,
            )
        logger.info("Verified copy: %s -> %s", local_path, dest)
        return VerifyResult(copied=True, verified_path=dest)

    def write_manifest(self, summary: PipelineSummary) -> Path:
        repo_dir = self.verified_dir(summary.repository)
        ensure_dir(repo_dir)
        passed = [r for r in summary.results if r.verdict == Verdict.PASS]
        manifest = {
            "repository": summary.repository,
            "scanned_at": (summary.finished_at or datetime.now(timezone.utc)).isoformat(),
            "grype_version": summary.grype_version,
            "total_scanned": summary.total_scanned,
            "total_passed": summary.total_passed,
            "total_failed": summary.total_failed,
            "total_errors": summary.total_errors,
            "passed_assets": [
                {
                    "asset_path": r.asset_path,
                    "local_downloaded_path": (
                        str(r.download.local_path) if r.download.local_path else None
                    ),
                    "verified_path": (
                        str(r.verify.verified_path) if r.verify.verified_path else None
                    ),
                    "size": r.download.bytes_written,
                    "scan_report_path": (
                        str(r.scan.json_report_path) if r.scan.json_report_path else None
                    ),
                    "vulnerability_count": 0,
                }
                for r in passed
                if r.verify.copied or r.verify.skipped_existing
            ],
        }
        path = repo_dir / "verified-manifest.json"
        write_json(path, manifest)
        logger.info("Wrote verified manifest %s", path)
        return path

    def write_unverified_list(self, summary: PipelineSummary) -> Path | None:
        """Записать ``unverified_assets.txt`` — по одному asset_path на строку.

        В список попадают ассеты с verdict FAIL или ERROR (не прошедшие проверку).
        Если таких нет — файл не создаётся, возвращается ``None``.
        """
        failed_paths = [
            r.asset_path
            for r in summary.results
            if r.verdict in {Verdict.FAIL, Verdict.ERROR}
        ]
        if not failed_paths:
            return None

        repo_dir = self.verified_dir(summary.repository)
        ensure_dir(repo_dir)
        path = repo_dir / "unverified_assets.txt"
        # Стабильный порядок + уникальность на случай дублей в summary.
        lines = sorted(dict.fromkeys(failed_paths))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info(
            "Wrote unverified assets list %s (%d entries)",
            path,
            len(lines),
        )
        return path


def apply_verify_for_result(
    verifier: Verifier,
    repository: str,
    result: AssetPipelineResult,
    *,
    is_docker: bool = False,
    tag: str | None = None,
) -> AssetPipelineResult:
    """Изменить/вернуть result с применённым шагом verify, когда verdict — PASS."""
    if result.verdict != Verdict.PASS:
        return result
    if not result.download.local_path:
        result.verify = VerifyResult(error="No local path to copy")
        return result
    result.verify = verifier.copy_if_pass(
        repository=repository,
        asset_path=result.asset_path,
        local_path=result.download.local_path,
        is_docker=is_docker,
        tag=tag,
    )
    return result
