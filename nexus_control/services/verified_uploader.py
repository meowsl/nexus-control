"""Загрузка локально проверенных (PASS) ассетов в Nexus ``<repo>-verified``."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from nexus_control.models import AssetPipelineResult, NexusAsset, PipelineSummary, Verdict
from nexus_control.nexus.client import NexusAPIError, NexusClient
from nexus_control.nexus.uploads import is_uploadable_asset
from nexus_control.services.scan_common import (
    is_scan_ignored_path,
    iter_local_companion_sidecars,
    main_asset_path_for_sidecar,
)
from nexus_control.utils.hashing import local_matches_remote
from nexus_control.utils.safe_path import sanitize_repo_name

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, float, str], None]


@dataclass
class UploadItemResult:
    asset_path: str
    ok: bool
    skipped: bool = False
    error: str | None = None


@dataclass
class UploadSummary:
    source_repository: str
    target_repository: str
    source_format: str = ""
    created_repository: bool = False
    results: list[UploadItemResult] = field(default_factory=list)

    @property
    def uploaded(self) -> int:
        return sum(1 for r in self.results if r.ok and not r.skipped)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.skipped)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.ok and not r.skipped)


def verified_repo_name(source_repository: str) -> str:
    """Имя целевого репозитория по умолчанию: ``<source>-verified``."""
    return normalize_upload_repo_name(f"{sanitize_repo_name(source_repository)}-verified")


def normalize_upload_repo_name(name: str) -> str:
    """Санитизировать пользовательское имя hosted-репозитория для upload."""
    cleaned = sanitize_repo_name(name)
    return cleaned[:200]


def _normalize_asset_path_key(asset_path: str) -> str:
    return str(asset_path).replace("\\", "/").lstrip("/")


def index_remote_assets(assets: list[NexusAsset]) -> dict[str, NexusAsset]:
    """Индекс remote-ассетов по нормализованному path (последний wins)."""
    out: dict[str, NexusAsset] = {}
    for asset in assets:
        key = _normalize_asset_path_key(asset.path)
        if key:
            out[key] = asset
    return out


def _verified_copy_ok(result: AssetPipelineResult) -> bool:
    return (
        result.verify.verified_path is not None
        and (result.verify.copied or result.verify.skipped_existing)
    )


def is_upload_result_candidate(
    result: AssetPipelineResult,
    *,
    passed_mains: set[str],
) -> bool:
    """PASS-пакеты и checksum/signature sidecar'ы рядом с таким PASS.

    Sidecar'ы не сканируются (вердикт ``SKIPPED``), но в Nexus ``*-verified``
    их нужно заливать вместе с прошедшим артефактом — и только с ним.
    """
    if not _verified_copy_ok(result):
        return False
    key = _normalize_asset_path_key(result.asset_path)
    if result.verdict == Verdict.PASS:
        return True
    if result.verdict != Verdict.SKIPPED or not is_scan_ignored_path(key):
        return False
    main = main_asset_path_for_sidecar(key)
    return bool(main and _normalize_asset_path_key(main) in passed_mains)


def collect_upload_items(summary: PipelineSummary) -> list[tuple[str, Path]]:
    """Пары ``(asset_path, local verified file)`` для загрузки в Nexus.

    Берёт PASS из pipeline и sidecar'ы (из results или файлы рядом с PASS).
    """
    items: list[tuple[str, Path]] = []
    seen: set[str] = set()
    passed_mains = {
        _normalize_asset_path_key(result.asset_path)
        for result in summary.results
        if result.verdict == Verdict.PASS and _verified_copy_ok(result)
    }

    def add(asset_path: str, local: Path) -> None:
        key = _normalize_asset_path_key(asset_path)
        if not key or key in seen or not local.is_file():
            return
        seen.add(key)
        items.append((key, local))

    for result in summary.results:
        if not is_upload_result_candidate(result, passed_mains=passed_mains):
            continue
        local = result.verify.verified_path
        if local is None:
            continue
        add(result.asset_path, local)

    for result in summary.results:
        if result.verdict != Verdict.PASS or not _verified_copy_ok(result):
            continue
        if is_scan_ignored_path(result.asset_path):
            continue
        local = result.verify.verified_path
        if local is None:
            continue
        main_key = _normalize_asset_path_key(result.asset_path)
        for side in iter_local_companion_sidecars(local):
            suffix = side.name[len(local.name):]
            add(main_key + suffix, side)

    return items


def should_skip_unchanged_upload(local_path: Path, remote: NexusAsset | None) -> bool:
    """True, если remote уже есть и локальный файл совпадает (checksum/size)."""
    if remote is None:
        return False
    match = local_matches_remote(
        local_path,
        remote.checksum,
        file_size=remote.file_size,
    )
    return match is True


class VerifiedUploader:
    """Создать hosted-репозиторий того же format и залить PASS-ассеты."""

    def __init__(self, client: NexusClient) -> None:
        self.client = client

    def upload(
        self,
        summary: PipelineSummary,
        *,
        target_repository: str | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> UploadSummary:
        if target_repository and target_repository.strip():
            target = normalize_upload_repo_name(target_repository)
        else:
            target = verified_repo_name(summary.repository)
        source = self.client.get_repository(summary.repository)
        if source is None:
            raise NexusAPIError(
                f"Source repository {summary.repository!r} not found in Nexus"
            )
        fmt = source.format.lower().strip()

        items = collect_upload_items(summary)
        out = UploadSummary(
            source_repository=summary.repository,
            target_repository=target,
            source_format=fmt,
        )
        if not items:
            logger.warning("No verified PASS assets to upload for %s", summary.repository)
            return out

        existed = self.client.get_repository(target) is not None
        self.client.ensure_hosted(target, fmt)
        out.created_repository = not existed

        remote_by_path: dict[str, NexusAsset] = {}
        if existed:
            try:
                remote_by_path = index_remote_assets(self.client.list_assets(target))
                logger.info(
                    "Indexed %d existing asset(s) in %s for upload skip",
                    len(remote_by_path),
                    target,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Cannot list assets in %s for skip check (%s); uploading all",
                    target,
                    exc,
                )

        total = max(len(items), 1)
        for index, (path, local) in enumerate(items):
            if on_progress:
                on_progress(path, index / total, "upload")
            try:
                if not is_uploadable_asset(fmt, path):
                    logger.info(
                        "Skip upload of non-package asset for %s: %s",
                        fmt,
                        path,
                    )
                    out.results.append(
                        UploadItemResult(
                            asset_path=path,
                            ok=True,
                            skipped=True,
                            error=f"not an uploadable {fmt} package asset",
                        )
                    )
                elif not local.is_file():
                    raise NexusAPIError(f"Verified file missing: {local}")
                elif should_skip_unchanged_upload(
                    local,
                    remote_by_path.get(_normalize_asset_path_key(path)),
                ):
                    logger.info("Skip unchanged remote asset: %s → %s", path, target)
                    out.results.append(
                        UploadItemResult(
                            asset_path=path,
                            ok=True,
                            skipped=True,
                            error="already present and unchanged",
                        )
                    )
                else:
                    self.client.upload_asset(target, fmt, path, local)
                    out.results.append(UploadItemResult(asset_path=path, ok=True))
            except Exception as exc:  # noqa: BLE001
                logger.error("Upload failed for %s: %s", path, exc)
                out.results.append(
                    UploadItemResult(asset_path=path, ok=False, error=str(exc))
                )
            if on_progress:
                on_progress(path, (index + 1) / total, "upload")

        logger.info(
            "Upload to %s (%s) finished: uploaded=%d skipped=%d failed=%d created=%s",
            target,
            fmt,
            out.uploaded,
            out.skipped,
            out.failed,
            out.created_repository,
        )
        return out
