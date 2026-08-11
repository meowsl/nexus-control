"""Копирование артефактов PASS в ``<repo>-verified`` и запись манифеста."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nexus_control.config import Settings
from nexus_control.models import (
    AssetPipelineResult,
    PipelineSummary,
    ScanResult,
    Verdict,
    VerifyResult,
)
from nexus_control.utils.fs import (
    copy_file,
    ensure_dir,
    prepare_asset_destination,
    read_json,
    write_json
)
from nexus_control.utils.safe_path import (
    UnsafePathError,
    asset_verified_path,
    verified_scanner_report_path,
)

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
                from nexus_control.utils.safe_path import sanitize_filename

                safe_tag = sanitize_filename(tag.replace(":", "_").replace("/", "_"))
                dest = asset_verified_path(
                    self.settings.verified_root,
                    repository,
                    f"images/{safe_tag}.tar",
                )
            else:
                from nexus_control.nexus.uploads import normalize_storage_asset_path

                dest = asset_verified_path(
                    self.settings.verified_root,
                    repository,
                    normalize_storage_asset_path(asset_path),
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

        if not is_docker:
            self._copy_companion_sidecars(local_path, dest)

        if skipped:
            return VerifyResult(
                copied=False,
                skipped_existing=True,
                verified_path=dest,
            )
        logger.info("Verified copy: %s -> %s", local_path, dest)
        return VerifyResult(copied=True, verified_path=dest)

    def _copy_companion_sidecars(self, local_path: Path, dest: Path) -> None:
        """Скопировать ``.md5``/``.sha1``/… рядом с PASS-артефактом, если они уже скачаны."""
        from nexus_control.services.scan_common import (
            is_scan_ignored_path,
            iter_local_companion_sidecars,
        )

        # Не цеплять sidecar'ы к самому sidecar-файлу.
        if is_scan_ignored_path(local_path.name):
            return

        for side_src in iter_local_companion_sidecars(local_path):
            side_dest = prepare_asset_destination(dest.parent / side_src.name)
            try:
                copied, skipped = copy_file(
                    side_src,
                    side_dest,
                    overwrite=self.settings.overwrite_verified,
                )
            except OSError as exc:
                logger.warning(
                    "Failed to copy sidecar %s -> %s: %s",
                    side_src,
                    side_dest,
                    exc,
                )
                continue
            if copied:
                logger.info("Verified sidecar copy: %s -> %s", side_src, side_dest)
            elif skipped:
                logger.debug("Verified sidecar already present: %s", side_dest)

    def write_scanner_reports(self, summary: PipelineSummary) -> dict[str, Path]:
        """Записать сводные ``{scanner}_report.json`` в ``<repo>-verified/``.

        Один файл на сканер: список всех артефактов с вердиктом, counts,
        уязвимостями и полным native JSON-отчётом сканера (если есть).
        """
        scanner_names = _scanner_names_for_summary(summary)
        written: dict[str, Path] = {}
        scanned_at = (summary.finished_at or datetime.now(timezone.utc)).isoformat()

        for scanner in scanner_names:
            assets: list[dict[str, Any]] = []
            version: str | None = summary.scanner_versions.get(scanner)
            for result in summary.results:
                scan = result.scans.get(scanner)
                if scan is None:
                    continue
                if version is None:
                    version = scan.scanner_version or scan.grype_version
                assets.append(_scanner_asset_entry(result, scan))

            if not assets:
                continue

            try:
                path = verified_scanner_report_path(
                    self.settings.verified_root,
                    summary.repository,
                    scanner,
                )
            except UnsafePathError as exc:
                logger.warning(
                    "Skip scanner report %s for %s: unsafe path (%s)",
                    scanner,
                    summary.repository,
                    exc,
                )
                continue

            payload = {
                "repository": summary.repository,
                "scanner": scanner,
                "scanner_version": version,
                "scanned_at": scanned_at,
                "totals": _verdict_totals(assets),
                "assets": assets,
            }
            try:
                ensure_dir(path.parent)
                write_json(path, payload)
            except OSError as exc:
                logger.error("Failed to write scanner report %s: %s", path, exc)
                continue
            written[scanner] = path
            logger.info(
                "Wrote scanner report %s (%d assets)",
                path,
                len(assets),
            )
        return written

    def write_manifest(self, summary: PipelineSummary) -> Path:
        repo_dir = self.verified_dir(summary.repository)
        ensure_dir(repo_dir)
        passed = [r for r in summary.results if r.verdict == Verdict.PASS]
        manifest = {
            "repository": summary.repository,
            "scanned_at": (summary.finished_at or datetime.now(timezone.utc)).isoformat(),
            "scanners": list(summary.scanners),
            "scanner_versions": dict(summary.scanner_versions),
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
                    "scan_reports": {
                        name: str(sc.json_report_path)
                        for name, sc in r.scans.items()
                        if sc.json_report_path is not None
                    },
                    "scan_report_path": next(
                        (
                            str(sc.json_report_path)
                            for sc in r.scans.values()
                            if sc.json_report_path is not None
                        ),
                        None,
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


def _scanner_names_for_summary(summary: PipelineSummary) -> list[str]:
    if summary.scanners:
        return list(summary.scanners)
    names: list[str] = []
    seen: set[str] = set()
    for result in summary.results:
        for name in result.scans:
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names


def _verdict_totals(assets: list[dict[str, Any]]) -> dict[str, int]:
    totals = {"assets": len(assets), "pass": 0, "fail": 0, "error": 0, "skipped": 0}
    for asset in assets:
        key = str(asset.get("verdict", "")).lower()
        if key in totals:
            totals[key] += 1
    return totals


def _scanner_asset_entry(
    result: AssetPipelineResult,
    scan: ScanResult,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "asset_path": result.asset_path,
        "verdict": scan.verdict.value,
        "status": scan.status.value,
        "vulnerability_count": scan.vulnerability_count,
        "counts": {
            "critical": scan.counts.critical,
            "high": scan.counts.high,
            "medium": scan.counts.medium,
            "low": scan.counts.low,
            "negligible": scan.counts.negligible,
            "unknown": scan.counts.unknown,
        },
        "vulnerabilities": [
            {
                "id": vuln.id,
                "severity": vuln.severity.value,
                "package_name": vuln.package_name,
                "package_version": vuln.package_version,
                "fix_version": vuln.fix_version,
                "description": vuln.description,
            }
            for vuln in scan.vulnerabilities
        ],
        "error": scan.error,
        "json_report_path": (
            str(scan.json_report_path) if scan.json_report_path is not None else None
        ),
    }
    raw = _load_native_report(scan)
    if raw is not None:
        entry["report"] = raw
    return entry


def _load_native_report(scan: ScanResult) -> Any | None:
    if scan.raw is not None:
        return scan.raw
    path = scan.json_report_path
    if path is None or not path.is_file():
        return None
    try:
        return read_json(path)
    except (OSError, ValueError) as exc:
        logger.debug("Cannot embed native report from %s: %s", path, exc)
        return None


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
