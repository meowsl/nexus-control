"""PASS-checkpoint неизменённых ассетов для incremental CLI verify."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nexus_control.config import Settings
from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    NexusAsset,
    ScanResult,
    ScanStatus,
    Verdict,
    VerifyResult,
)
from nexus_control.utils.fs import write_json
from nexus_control.utils.hashing import hash_file, remote_identity_unchanged

_VERSION = 1
SCAN_MODES = ("incremental", "full")
DEFAULT_SCAN_MODE = "incremental"


def parse_scan_mode(value: object | None) -> str:
    """``incremental`` (default) or ``full``."""
    text = str(value if value is not None else DEFAULT_SCAN_MODE).strip().lower()
    if not text:
        return DEFAULT_SCAN_MODE
    if text not in SCAN_MODES:
        raise ValueError("scan_mode must be incremental or full")
    return text


def checkpoint_path(local_path: Path) -> Path:
    return local_path.parent / f"{local_path.name}.scan-checkpoint.json"


def scan_policy_hash(settings: Settings, scanners: Sequence[str]) -> str:
    """Fingerprint настроек, способных изменить результат сканирования."""
    parts: list[str] = [f"severity={settings.severity}"]
    for name in sorted(scanners):
        if name == "grype":
            parts.append(
                "|".join(
                    (
                        "grype",
                        settings.grype_binary,
                        settings.grype_use_docker,
                        settings.grype_docker_image,
                        settings.grype_extra_args,
                    )
                )
            )
        elif name == "trivy":
            parts.append(
                "|".join(
                    (
                        "trivy",
                        settings.trivy_binary,
                        settings.trivy_use_docker,
                        settings.trivy_docker_image,
                        settings.trivy_extra_args,
                    )
                )
            )
        elif name == "osv":
            parts.append(
                "|".join(
                    (
                        "osv",
                        settings.osv_binary,
                        settings.osv_use_docker,
                        settings.osv_docker_image,
                        settings.osv_extra_args,
                    )
                )
            )
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def checkpoint_is_valid(
    *,
    settings: Settings,
    asset: NexusAsset,
    local_path: Path,
    scanners: Sequence[str],
    scanner_versions: Mapping[str, str | None],
    ignore_ttl: bool = False,
) -> bool:
    """Проверить PASS-checkpoint, remote/local identity и (опционально) TTL.

    ``scan_checkpoint_ttl = 0`` полностью выключает skip.
    ``ignore_ttl=True`` (scan_mode=incremental) не протухает по возрасту —
    полный rescan делается отдельным ``scan_mode=full``.
    """
    ttl = settings.scan_checkpoint_ttl
    if ttl <= 0:
        return False
    path = checkpoint_path(local_path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        stat = local_path.stat()
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict) or raw.get("version") != _VERSION:
        return False
    if raw.get("repository") != asset.repository or raw.get("asset_path") != asset.path:
        return False
    if raw.get("verdict") != Verdict.PASS.value:
        return False

    try:
        scanned_at = datetime.fromisoformat(str(raw["scanned_at"]))
        if scanned_at.tzinfo is None:
            scanned_at = scanned_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - scanned_at).total_seconds()
        local = raw["local"]
        if age < 0:
            return False
        if not ignore_ttl and age > ttl:
            return False
        if stat.st_size != int(local["size"]):
            return False
        if stat.st_mtime_ns != int(local["mtime_ns"]):
            return False
    except (KeyError, TypeError, ValueError):
        return False

    expected_scanners = sorted(scanners)
    if raw.get("scanners") != expected_scanners:
        return False
    if raw.get("scanner_versions") != {
        name: scanner_versions.get(name) for name in expected_scanners
    }:
        return False
    if raw.get("policy_hash") != scan_policy_hash(settings, scanners):
        return False

    remote = raw.get("remote")
    if not isinstance(remote, dict):
        return False
    identity = remote_identity_unchanged(
        asset.checksum,
        remote_last_modified=asset.last_modified,
        sidecar={
            "checksum": remote.get("checksum"),
            "last_modified": remote.get("last_modified"),
        },
    )
    if identity is not True:
        return False

    verified_data = raw.get("verified")
    if not isinstance(verified_data, dict) or not verified_data.get("path"):
        return False
    try:
        verified = Path(str(verified_data["path"]))
        verified_stat = verified.stat()
        if not verified.is_file():
            return False
        if verified_stat.st_size != int(verified_data["size"]):
            return False
        if verified_stat.st_mtime_ns != int(verified_data["mtime_ns"]):
            return False
        if verified_stat.st_size != stat.st_size:
            return False
    except (KeyError, TypeError, ValueError, OSError):
        return False
    return True


def load_pass_checkpoint(local_path: Path) -> dict[str, Any] | None:
    """Прочитать ``*.scan-checkpoint.json`` или ``None``."""
    path = checkpoint_path(local_path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or raw.get("version") != _VERSION:
        return None
    return raw


def result_from_pass_checkpoint(
    asset: NexusAsset,
    local_path: Path,
    raw: Mapping[str, Any],
) -> AssetPipelineResult | None:
    """Синтетический PASS-result для upload/manifest без повторного скана."""
    verified_data = raw.get("verified")
    if not isinstance(verified_data, dict) or not verified_data.get("path"):
        return None
    verified = Path(str(verified_data["path"]))
    if not verified.is_file():
        return None
    names = raw.get("scanners")
    scanners = [str(n) for n in names] if isinstance(names, list) and names else ["checkpoint"]
    return AssetPipelineResult(
        asset_path=asset.path,
        kind=AssetKind.FILE,
        download=DownloadResult(
            status=DownloadStatus.SKIPPED_EXISTING,
            local_path=local_path,
        ),
        scans={
            name: ScanResult(
                status=ScanStatus.SKIPPED,
                verdict=Verdict.PASS,
                scanner=name,
            )
            for name in scanners
        },
        verify=VerifyResult(
            copied=False,
            skipped_existing=True,
            verified_path=verified,
        ),
    )


def write_pass_checkpoint(
    *,
    settings: Settings,
    asset: NexusAsset,
    result: AssetPipelineResult,
    scanners: Sequence[str],
    scanner_versions: Mapping[str, str | None],
) -> Path | None:
    """Записать checkpoint только для полностью завершённого PASS + verified."""
    local_path = result.download.local_path
    verified_path = result.verify.verified_path
    if (
        result.verdict != Verdict.PASS
        or local_path is None
        or verified_path is None
        or not (result.verify.copied or result.verify.skipped_existing)
        or any(scan.status != ScanStatus.SUCCESS for scan in result.scans.values())
    ):
        return None
    try:
        stat = local_path.stat()
        verified_stat = verified_path.stat()
    except OSError:
        return None
    if result.verify.skipped_existing:
        try:
            if hash_file(local_path) != hash_file(verified_path):
                return None
        except OSError:
            return None
    names = sorted(scanners)
    payload: dict[str, Any] = {
        "version": _VERSION,
        "repository": asset.repository,
        "asset_path": asset.path,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "verdict": Verdict.PASS.value,
        "remote": {
            "checksum": dict(asset.checksum),
            "last_modified": asset.last_modified,
        },
        "local": {
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        },
        "verified": {
            "path": str(verified_path),
            "size": verified_stat.st_size,
            "mtime_ns": verified_stat.st_mtime_ns,
        },
        "scanners": names,
        "scanner_versions": {
            name: scanner_versions.get(name) for name in names
        },
        "policy_hash": scan_policy_hash(settings, scanners),
    }
    path = checkpoint_path(local_path)
    try:
        write_json(path, payload)
    except OSError:
        return None
    return path
