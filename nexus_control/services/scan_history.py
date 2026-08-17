"""История сканирований: index + компактные run-snapshots."""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from nexus_control.config import Settings
from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    PipelineSummary,
    ScanResult,
    ScanStatus,
    Severity,
    SeverityCounts,
    Verdict,
    VerifyResult,
    Vulnerability,
)
from nexus_control.utils.fs import ensure_dir, write_json
from nexus_control.utils.safe_path import sanitize_repo_name

logger = logging.getLogger(__name__)

HistorySource = Literal["tui", "cli", "scheduler"]
MAX_VULNS_PER_SCANNER = 20
INDEX_FILENAME = "index.json"
RUNS_DIRNAME = "runs"


@dataclass(slots=True)
class ScanRunTotals:
    scanned: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    copied: int = 0
    checkpoint_skipped: int = 0

    @property
    def total(self) -> int:
        """Артефакты, учтённые в прогоне: отсканированные + checkpoint-skip."""
        scanned_like = self.scanned
        if scanned_like == 0 and (self.passed or self.failed or self.errors):
            scanned_like = self.passed + self.failed + self.errors
        return scanned_like + self.checkpoint_skipped


@dataclass(slots=True)
class ScanRunMeta:
    run_id: str
    repository: str
    started_at: str
    finished_at: str | None
    source: HistorySource
    scanners: list[str] = field(default_factory=list)
    totals: ScanRunTotals = field(default_factory=ScanRunTotals)
    rule_id: str | None = None
    path_prefix: str | None = None
    workers: int | None = None
    cancelled: bool = False
    defectdojo_engagement_id: int | None = None


def history_root(settings: Settings) -> Path:
    return Path(settings.nexus_cache_dir).expanduser().resolve() / "scan-history"


def index_path(settings: Settings) -> Path:
    return history_root(settings) / INDEX_FILENAME


def runs_dir(settings: Settings) -> Path:
    return history_root(settings) / RUNS_DIRNAME


def run_snapshot_path(settings: Settings, run_id: str) -> Path:
    safe = sanitize_repo_name(run_id).replace("/", "_")
    return runs_dir(settings) / f"{safe}.json"


def record_scan_run(
    settings: Settings,
    summary: PipelineSummary,
    *,
    source: HistorySource,
    rule_id: str | None = None,
    path_prefix: str | None = None,
    workers: int | None = None,
    checkpoint_skipped: int = 0,
    defectdojo_engagement_id: int | None = None,
) -> str | None:
    """Сохранить компактный snapshot + обновить index. None если выключено/ошибка."""
    keep = int(getattr(settings, "scan_history_keep", 50) or 0)
    if keep <= 0:
        return None
    try:
        run_id = _new_run_id(summary.repository)
        meta = _meta_from_summary(
            summary,
            run_id=run_id,
            source=source,
            rule_id=rule_id,
            path_prefix=path_prefix,
            workers=workers,
            checkpoint_skipped=checkpoint_skipped,
            defectdojo_engagement_id=defectdojo_engagement_id,
        )
        snapshot = {
            "meta": _meta_to_dict(meta),
            "scanner_versions": dict(summary.scanner_versions),
            "assets": [_asset_to_dict(result) for result in summary.results],
        }
        ensure_dir(runs_dir(settings), mode=0o700)
        path = run_snapshot_path(settings, run_id)
        write_json(path, snapshot, mode=0o600)
        _update_index(settings, meta, keep=keep)
        logger.info(
            "Recorded scan history run_id=%s repo=%s source=%s assets=%d "
            "checkpoint_skipped=%d",
            run_id,
            summary.repository,
            source,
            len(summary.results),
            checkpoint_skipped,
        )
        return run_id
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to record scan history: %s", exc)
        return None


def list_runs(
    settings: Settings,
    *,
    repository: str | None = None,
    limit: int | None = None,
) -> list[ScanRunMeta]:
    entries = _load_index(settings)
    if repository:
        repo = repository.strip()
        entries = [e for e in entries if e.repository == repo]
    if limit is not None:
        entries = entries[: max(0, limit)]
    return entries


def load_run(settings: Settings, run_id: str) -> PipelineSummary | None:
    path = run_snapshot_path(settings, run_id)
    if not path.is_file():
        return None
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read scan history %s: %s", path, exc)
        return None
    if not isinstance(data, dict):
        return None
    try:
        return summary_from_snapshot(data)
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Invalid scan history snapshot %s: %s", path, exc)
        return None


def load_run_meta(settings: Settings, run_id: str) -> ScanRunMeta | None:
    """Meta из snapshot или index."""
    path = run_snapshot_path(settings, run_id)
    if path.is_file():
        try:
            import json

            data = json.loads(path.read_text(encoding="utf-8"))
            meta_raw = data.get("meta") if isinstance(data, dict) else None
            if isinstance(meta_raw, dict) and meta_raw.get("run_id"):
                return _meta_from_dict(meta_raw)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
    for entry in _load_index(settings):
        if entry.run_id == run_id:
            return entry
    return None


def latest_run_for_repo(settings: Settings, repository: str) -> ScanRunMeta | None:
    runs = list_runs(settings, repository=repository, limit=1)
    return runs[0] if runs else None


def summary_from_snapshot(data: dict[str, Any]) -> PipelineSummary:
    meta_raw = data.get("meta") or {}
    if not isinstance(meta_raw, dict):
        raise ValueError("meta must be an object")
    repository = str(meta_raw.get("repository") or "").strip()
    if not repository:
        raise ValueError("repository required")
    scanners = [str(s) for s in (meta_raw.get("scanners") or [])]
    versions_raw = data.get("scanner_versions") or {}
    versions: dict[str, str | None] = {}
    if isinstance(versions_raw, dict):
        for key, value in versions_raw.items():
            versions[str(key)] = str(value) if value is not None else None

    assets_raw = data.get("assets") or []
    results: list[AssetPipelineResult] = []
    if isinstance(assets_raw, list):
        for item in assets_raw:
            if isinstance(item, dict):
                results.append(_asset_from_dict(item))

    started = _parse_dt(meta_raw.get("started_at")) or datetime.now(timezone.utc)
    finished = _parse_dt(meta_raw.get("finished_at"))
    return PipelineSummary(
        repository=repository,
        results=results,
        started_at=started,
        finished_at=finished,
        scanners=scanners,
        scanner_versions=versions,
        cancelled=bool(meta_raw.get("cancelled", False)),
    )


def _new_run_id(repository: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    repo = sanitize_repo_name(repository)[:40] or "repo"
    short = uuid.uuid4().hex[:8]
    return f"{stamp}_{repo}_{short}"


def _meta_from_summary(
    summary: PipelineSummary,
    *,
    run_id: str,
    source: HistorySource,
    rule_id: str | None,
    path_prefix: str | None,
    workers: int | None,
    checkpoint_skipped: int = 0,
    defectdojo_engagement_id: int | None = None,
) -> ScanRunMeta:
    skipped = sum(1 for r in summary.results if r.verdict == Verdict.SKIPPED)
    return ScanRunMeta(
        run_id=run_id,
        repository=summary.repository,
        started_at=summary.started_at.isoformat(),
        finished_at=(
            summary.finished_at.isoformat() if summary.finished_at else None
        ),
        source=source,
        scanners=list(summary.scanners),
        totals=ScanRunTotals(
            scanned=summary.total_scanned,
            passed=summary.total_passed,
            failed=summary.total_failed,
            errors=summary.total_errors,
            skipped=skipped,
            copied=summary.total_copied,
            checkpoint_skipped=max(0, int(checkpoint_skipped)),
        ),
        rule_id=rule_id,
        path_prefix=path_prefix,
        workers=workers,
        cancelled=summary.cancelled,
        defectdojo_engagement_id=defectdojo_engagement_id,
    )


def _meta_to_dict(meta: ScanRunMeta) -> dict[str, Any]:
    return {
        "run_id": meta.run_id,
        "repository": meta.repository,
        "started_at": meta.started_at,
        "finished_at": meta.finished_at,
        "source": meta.source,
        "scanners": list(meta.scanners),
        "totals": asdict(meta.totals),
        "rule_id": meta.rule_id,
        "path_prefix": meta.path_prefix,
        "workers": meta.workers,
        "cancelled": meta.cancelled,
        "defectdojo_engagement_id": meta.defectdojo_engagement_id,
    }


def _meta_from_dict(data: dict[str, Any]) -> ScanRunMeta:
    totals_raw = data.get("totals") or {}
    if not isinstance(totals_raw, dict):
        totals_raw = {}
    totals = ScanRunTotals(
        scanned=int(totals_raw.get("scanned") or 0),
        passed=int(totals_raw.get("passed") or 0),
        failed=int(totals_raw.get("failed") or 0),
        errors=int(totals_raw.get("errors") or 0),
        skipped=int(totals_raw.get("skipped") or 0),
        copied=int(totals_raw.get("copied") or 0),
        checkpoint_skipped=int(totals_raw.get("checkpoint_skipped") or 0),
    )
    source = str(data.get("source") or "cli")
    if source not in {"tui", "cli", "scheduler"}:
        source = "cli"
    return ScanRunMeta(
        run_id=str(data.get("run_id") or ""),
        repository=str(data.get("repository") or ""),
        started_at=str(data.get("started_at") or ""),
        finished_at=(
            str(data["finished_at"]) if data.get("finished_at") is not None else None
        ),
        source=source,  # type: ignore[arg-type]
        scanners=[str(s) for s in (data.get("scanners") or [])],
        totals=totals,
        rule_id=(
            str(data["rule_id"]) if data.get("rule_id") is not None else None
        ),
        path_prefix=(
            str(data["path_prefix"]) if data.get("path_prefix") is not None else None
        ),
        workers=(
            int(data["workers"]) if data.get("workers") is not None else None
        ),
        cancelled=bool(data.get("cancelled", False)),
        defectdojo_engagement_id=_maybe_int_field(data.get("defectdojo_engagement_id")),
    )


def _maybe_int_field(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _asset_to_dict(result: AssetPipelineResult) -> dict[str, Any]:
    scans: dict[str, Any] = {}
    for name, scan in result.scans.items():
        vulns = [
            {
                "id": v.id,
                "severity": v.severity.value,
                "package_name": v.package_name,
                "package_version": v.package_version,
                "fix_version": v.fix_version,
                "description": v.description,
            }
            for v in scan.vulnerabilities[:MAX_VULNS_PER_SCANNER]
        ]
        scans[name] = {
            "status": scan.status.value,
            "verdict": scan.verdict.value,
            "counts": asdict(scan.counts),
            "vulnerabilities": vulns,
            "json_report_path": (
                str(scan.json_report_path) if scan.json_report_path else None
            ),
            "text_report_path": (
                str(scan.text_report_path) if scan.text_report_path else None
            ),
            "scanner": scan.scanner or name,
            "scanner_version": scan.scanner_version or scan.grype_version,
            "error": scan.error,
        }
    return {
        "asset_path": result.asset_path,
        "kind": result.kind.value,
        "download": {
            "status": result.download.status.value,
            "local_path": (
                str(result.download.local_path) if result.download.local_path else None
            ),
            "bytes_written": result.download.bytes_written,
            "error": result.download.error,
            "source": result.download.source,
        },
        "scans": scans,
        "verify": {
            "copied": result.verify.copied,
            "skipped_existing": result.verify.skipped_existing,
            "verified_path": (
                str(result.verify.verified_path)
                if result.verify.verified_path
                else None
            ),
            "error": result.verify.error,
        },
    }


def _asset_from_dict(data: dict[str, Any]) -> AssetPipelineResult:
    kind_raw = str(data.get("kind") or "file")
    try:
        kind = AssetKind(kind_raw)
    except ValueError:
        kind = AssetKind.FILE

    dl_raw = data.get("download") or {}
    if not isinstance(dl_raw, dict):
        dl_raw = {}
    try:
        dl_status = DownloadStatus(str(dl_raw.get("status") or "error"))
    except ValueError:
        dl_status = DownloadStatus.ERROR
    local = dl_raw.get("local_path")
    download = DownloadResult(
        status=dl_status,
        local_path=Path(local) if local else None,
        bytes_written=int(dl_raw.get("bytes_written") or 0),
        error=dl_raw.get("error"),
        source=str(dl_raw.get("source") or "nexus-rest"),
    )

    scans: dict[str, ScanResult] = {}
    scans_raw = data.get("scans") or {}
    if isinstance(scans_raw, dict):
        for name, scan_raw in scans_raw.items():
            if not isinstance(scan_raw, dict):
                continue
            scans[str(name)] = _scan_from_dict(str(name), scan_raw)

    vr_raw = data.get("verify") or {}
    if not isinstance(vr_raw, dict):
        vr_raw = {}
    verified = vr_raw.get("verified_path")
    verify = VerifyResult(
        copied=bool(vr_raw.get("copied", False)),
        skipped_existing=bool(vr_raw.get("skipped_existing", False)),
        verified_path=Path(verified) if verified else None,
        error=vr_raw.get("error"),
    )
    return AssetPipelineResult(
        asset_path=str(data.get("asset_path") or ""),
        kind=kind,
        download=download,
        scans=scans,
        verify=verify,
    )


def _scan_from_dict(name: str, data: dict[str, Any]) -> ScanResult:
    try:
        status = ScanStatus(str(data.get("status") or "error"))
    except ValueError:
        status = ScanStatus.ERROR
    try:
        verdict = Verdict(str(data.get("verdict") or "ERROR"))
    except ValueError:
        verdict = Verdict.ERROR
    counts_raw = data.get("counts") or {}
    if not isinstance(counts_raw, dict):
        counts_raw = {}
    counts = SeverityCounts(
        critical=int(counts_raw.get("critical") or 0),
        high=int(counts_raw.get("high") or 0),
        medium=int(counts_raw.get("medium") or 0),
        low=int(counts_raw.get("low") or 0),
        negligible=int(counts_raw.get("negligible") or 0),
        unknown=int(counts_raw.get("unknown") or 0),
    )
    vulns: list[Vulnerability] = []
    for item in data.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        try:
            severity = Severity(str(item.get("severity") or "Unknown"))
        except ValueError:
            severity = Severity.UNKNOWN
        vulns.append(
            Vulnerability(
                id=str(item.get("id") or ""),
                severity=severity,
                package_name=str(item.get("package_name") or ""),
                package_version=str(item.get("package_version") or ""),
                fix_version=item.get("fix_version"),
                description=item.get("description"),
            )
        )
    json_path = data.get("json_report_path")
    text_path = data.get("text_report_path")
    version = data.get("scanner_version")
    return ScanResult(
        status=status,
        verdict=verdict,
        vulnerabilities=vulns,
        counts=counts,
        json_report_path=Path(json_path) if json_path else None,
        text_report_path=Path(text_path) if text_path else None,
        scanner=str(data.get("scanner") or name),
        scanner_version=str(version) if version is not None else None,
        grype_version=str(version) if name == "grype" and version else None,
        error=data.get("error"),
    )


def _load_index(settings: Settings) -> list[ScanRunMeta]:
    path = index_path(settings)
    if not path.is_file():
        return []
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read scan history index: %s", exc)
        return []
    if not isinstance(data, dict):
        return []
    runs = data.get("runs") or []
    if not isinstance(runs, list):
        return []
    out: list[ScanRunMeta] = []
    for item in runs:
        if isinstance(item, dict) and item.get("run_id"):
            out.append(_meta_from_dict(item))
    return out


def _update_index(settings: Settings, meta: ScanRunMeta, *, keep: int) -> None:
    entries = _load_index(settings)
    entries = [e for e in entries if e.run_id != meta.run_id]
    entries.insert(0, meta)
    dropped = entries[keep:]
    entries = entries[:keep]
    ensure_dir(history_root(settings), mode=0o700)
    write_json(
        index_path(settings),
        {"version": 1, "runs": [_meta_to_dict(e) for e in entries]},
        mode=0o600,
    )
    for old in dropped:
        snap = run_snapshot_path(settings, old.run_id)
        try:
            snap.unlink(missing_ok=True)
        except OSError as exc:
            logger.debug("Failed to prune history snapshot %s: %s", snap, exc)


def _parse_dt(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    text = str(value)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def format_history_when(*candidates: str | None) -> str:
    """Human-readable When column: ``DD.MM.YYYY HH:mm`` in local time."""
    for raw in candidates:
        if not raw:
            continue
        dt = _parse_dt(raw)
        if dt is None:
            continue
        return dt.astimezone().strftime("%d.%m.%Y %H:%M")
    return "-"
