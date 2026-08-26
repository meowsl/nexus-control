"""Загрузка PASS и отзыв FAIL из Nexus ``<repo>-verified``."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from nexus_control.models import AssetPipelineResult, NexusAsset, PipelineSummary, Verdict
from nexus_control.nexus.client import NexusAPIError, NexusClient
from nexus_control.nexus.uploads import (
    is_nuget_package_path,
    is_uploadable_asset,
    is_verified_local_sidecar,
    normalize_storage_asset_path,
)
from nexus_control.services.scan_common import (
    SCAN_IGNORE_SUFFIXES,
    is_scan_ignored_path,
    iter_local_companion_sidecars,
    main_asset_path_for_sidecar,
)
from nexus_control.utils.hashing import local_matches_remote
from nexus_control.utils.safe_path import (
    UnsafePathError,
    asset_verified_path,
    sanitize_repo_name,
)

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, float, str], None]

_SHARED_METADATA_NAMES = frozenset({"maven-metadata.xml", "archetype-catalog.xml"})


@dataclass
class UploadItemResult:
    asset_path: str
    ok: bool
    skipped: bool = False
    deleted: bool = False
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
        return sum(
            1 for r in self.results if r.ok and not r.skipped and not r.deleted
        )

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.skipped)

    @property
    def deleted(self) -> int:
        return sum(1 for r in self.results if r.deleted and r.ok)

    @property
    def delete_failed(self) -> int:
        return sum(1 for r in self.results if r.deleted and not r.ok)

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


def is_shared_metadata_path(asset_path: str) -> bool:
    """True для maven-metadata / archetype-catalog (и их checksum sidecar'ов)."""
    name = PurePosixPath(_normalize_asset_path_key(asset_path)).name.lower()
    while True:
        main = main_asset_path_for_sidecar(name)
        if main is None:
            break
        name = PurePosixPath(main).name.lower()
    return name in _SHARED_METADATA_NAMES


def index_remote_assets(assets: list[NexusAsset]) -> dict[str, NexusAsset]:
    """Индекс remote-ассетов по нормализованному path (последний wins)."""
    out: dict[str, NexusAsset] = {}
    for asset in assets:
        key = _normalize_asset_path_key(asset.path)
        if key:
            out[key] = asset
    return out


def collect_revoke_mains(
    summary: PipelineSummary,
    extra_paths: Iterable[str] | None = None,
) -> list[str]:
    """Основные FAIL-артефакты, которые нельзя оставлять в ``*-verified``.

    ERROR не отзываем: сбой сканера не должен снимать ранее хороший пакет.
    Checksum sidecar'ы и maven-metadata сами по себе не являются причиной revoke.
    """
    mains: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        key = _normalize_asset_path_key(path)
        if not key or key in seen:
            return
        if is_scan_ignored_path(key) or is_shared_metadata_path(key):
            return
        if is_verified_local_sidecar(key):
            return
        seen.add(key)
        mains.append(key)

    for result in summary.results:
        if result.verdict == Verdict.FAIL:
            add(result.asset_path)
    if extra_paths:
        for path in extra_paths:
            add(path)
    return mains


def expand_revoke_keys(mains: Iterable[str], *, fmt: str = "") -> list[str]:
    """Пути основного артефакта, nuget-варианты и checksum/signature sidecar'ы."""
    keys: list[str] = []
    seen: set[str] = set()
    fmt_l = (fmt or "").lower().strip()

    def add(path: str) -> None:
        key = _normalize_asset_path_key(path)
        if not key or key in seen or is_shared_metadata_path(key):
            return
        if is_verified_local_sidecar(key):
            return
        seen.add(key)
        keys.append(key)

    for main in mains:
        variants = [_normalize_asset_path_key(main)]
        storage = _normalize_asset_path_key(
            normalize_storage_asset_path(main, fmt=fmt_l or None)
        )
        if storage and storage not in variants:
            variants.append(storage)
        if fmt_l == "nuget" and is_nuget_package_path(storage):
            parts = PurePosixPath(storage).parts
            if len(parts) >= 2:
                hosted = "/".join(parts[:2])
                if hosted not in variants:
                    variants.append(hosted)
        for variant in variants:
            add(variant)
            for suffix in SCAN_IGNORE_SUFFIXES:
                add(variant + suffix)
            if fmt_l == "pypi":
                add(variant + ".metadata")
    return keys


def remote_assets_to_revoke(
    remote_by_path: dict[str, NexusAsset],
    revoke_keys: Iterable[str],
) -> list[NexusAsset]:
    """Remote-ассеты, чьи path совпали с ключами revoke (уникальные id)."""
    out: list[NexusAsset] = []
    seen_ids: set[str] = set()
    for key in revoke_keys:
        asset = remote_by_path.get(_normalize_asset_path_key(key))
        if asset is None or asset.id in seen_ids:
            continue
        seen_ids.add(asset.id)
        out.append(asset)
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
    """Создать hosted ``<repo>-verified``, залить PASS и снять FAIL (+ sidecar'ы)."""

    def __init__(self, client: NexusClient) -> None:
        self.client = client

    def upload(
        self,
        summary: PipelineSummary,
        *,
        target_repository: str | None = None,
        extra_revoke_paths: Iterable[str] | None = None,
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
        revoke_mains = collect_revoke_mains(summary, extra_revoke_paths)
        revoke_keys = expand_revoke_keys(revoke_mains, fmt=fmt)
        out = UploadSummary(
            source_repository=summary.repository,
            target_repository=target,
            source_format=fmt,
        )
        if not items and not revoke_mains:
            logger.warning("No verified PASS assets to upload for %s", summary.repository)
            return out

        existed = self.client.get_repository(target) is not None
        if not existed and not items:
            logger.info(
                "Skip remote revoke for %s: target %s does not exist and there "
                "is nothing to upload",
                summary.repository,
                target,
            )
            self._unlink_local_verified(summary.repository, revoke_keys)
            return out

        if items:
            self.client.ensure_hosted(target, fmt)
            out.created_repository = not existed

        remote_by_path: dict[str, NexusAsset] = {}
        if existed:
            try:
                remote_by_path = index_remote_assets(self.client.list_assets(target))
                logger.info(
                    "Indexed %d existing asset(s) in %s for upload skip / revoke",
                    len(remote_by_path),
                    target,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Cannot list assets in %s for skip/revoke (%s); "
                    "uploading without remote index",
                    target,
                    exc,
                )

        self._revoke_remote(
            target,
            remote_by_path,
            revoke_keys,
            out,
            on_progress=on_progress,
        )
        self._unlink_local_verified(summary.repository, revoke_keys)
        for key in revoke_keys:
            remote_by_path.pop(key, None)

        if not items:
            logger.info(
                "Upload to %s (%s) finished: uploaded=0 skipped=0 failed=%d "
                "deleted=%d delete_failed=%d created=%s",
                target,
                fmt,
                out.failed,
                out.deleted,
                out.delete_failed,
                out.created_repository,
            )
            return out

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
            "Upload to %s (%s) finished: uploaded=%d skipped=%d failed=%d "
            "deleted=%d delete_failed=%d created=%s",
            target,
            fmt,
            out.uploaded,
            out.skipped,
            out.failed,
            out.deleted,
            out.delete_failed,
            out.created_repository,
        )
        return out

    def _revoke_remote(
        self,
        target: str,
        remote_by_path: dict[str, NexusAsset],
        revoke_keys: list[str],
        out: UploadSummary,
        *,
        on_progress: ProgressCallback | None,
    ) -> None:
        assets = remote_assets_to_revoke(remote_by_path, revoke_keys)
        if not assets:
            if revoke_keys:
                logger.info(
                    "No remote assets in %s matched %d FAIL path(s) for revoke",
                    target,
                    len(revoke_keys),
                )
            return
        total = max(len(assets), 1)
        for index, asset in enumerate(assets):
            path = _normalize_asset_path_key(asset.path)
            if on_progress:
                on_progress(path, index / total, "revoke")
            try:
                self.client.delete_asset(asset.id)
                logger.info("Revoked from %s: %s", target, path)
                out.results.append(
                    UploadItemResult(asset_path=path, ok=True, deleted=True)
                )
            except Exception as exc:  # noqa: BLE001
                logger.error("Revoke failed for %s in %s: %s", path, target, exc)
                out.results.append(
                    UploadItemResult(
                        asset_path=path,
                        ok=False,
                        deleted=True,
                        error=str(exc),
                    )
                )
            if on_progress:
                on_progress(path, (index + 1) / total, "revoke")

    def _unlink_local_verified(self, repository: str, keys: Iterable[str]) -> None:
        settings = getattr(self.client, "settings", None)
        if settings is None:
            return
        verified_root = getattr(settings, "verified_root", None)
        if verified_root is None:
            return
        seen: set[Path] = set()
        for key in keys:
            try:
                dest = asset_verified_path(
                    verified_root,
                    repository,
                    normalize_storage_asset_path(key),
                )
            except UnsafePathError as exc:
                logger.warning("Skip local revoke of %s: %s", key, exc)
                continue
            candidates = [dest, *iter_local_companion_sidecars(dest)]
            for path in candidates:
                if path in seen:
                    continue
                seen.add(path)
                if not path.is_file():
                    continue
                try:
                    path.unlink()
                    logger.info("Removed local verified copy %s", path)
                except OSError as exc:
                    logger.warning(
                        "Failed to remove local verified copy %s: %s", path, exc
                    )
