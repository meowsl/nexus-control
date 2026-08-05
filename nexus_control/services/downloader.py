"""Сервис загрузки артефактов с безопасными путями и sidecar-метаданными."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from nexus_control.config import Settings
from nexus_control.models import DownloadResult, DownloadStatus, DockerTag, NexusAsset
from nexus_control.nexus.client import NexusClient, NexusAPIError
from nexus_control.utils.fs import (
    disable_execute_bit_best_effort,
    prepare_asset_destination,
    utc_now_iso,
    write_json,
)
from nexus_control.utils.hashing import (
    checksum_is_authoritative,
    checksums_mismatch,
    hashers_for_expected,
    local_matches_remote,
    remote_identity_unchanged,
    soft_checksum_warning,
)
from nexus_control.utils.safe_path import (
    UnsafePathError,
    asset_download_path,
    docker_archive_path,
    resolve_storage_path,
)

logger = logging.getLogger(__name__)


class Downloader:
    def __init__(self, settings: Settings, client: NexusClient) -> None:
        self.settings = settings
        self.client = client

    def download_asset(self, asset: NexusAsset) -> DownloadResult:
        try:
            dest = asset_download_path(
                self.settings.download_root,
                asset.repository,
                asset.path,
            )
        except UnsafePathError as exc:
            logger.error("Unsafe asset path skipped: %s (%s)", asset.path, exc)
            return DownloadResult(
                status=DownloadStatus.ERROR,
                error=f"Unsafe path: {exc}",
            )

        # Учесть уже созданный каталог на месте файла (npm metadata vs tarball).
        existing = resolve_storage_path(dest)
        if existing.is_file() and not self.settings.overwrite_downloads:
            skip = _should_skip_existing(existing, asset)
            if skip:
                meta = self._write_metadata(
                    existing,
                    repository=asset.repository,
                    asset_path=asset.path,
                    download_url=asset.download_url,
                    size=existing.stat().st_size,
                    checksum=asset.checksum,
                    source="nexus-rest",
                    skipped=True,
                    extra={"last_modified": asset.last_modified},
                )
                logger.debug("Skip download: %s -> %s", asset.path, existing)
                return DownloadResult(
                    status=DownloadStatus.SKIPPED_EXISTING,
                    local_path=existing,
                    metadata_path=meta,
                    bytes_written=existing.stat().st_size,
                    source="nexus-rest",
                )
            logger.info(
                "Re-downloading changed asset %s (local differs from remote)",
                asset.path,
            )

        url = self.client.resolve_download_url(asset)
        # npm и др.: path может быть и файлом, и префиксом каталога.
        dest = prepare_asset_destination(dest)
        tmp = dest.with_suffix(dest.suffix + ".partial")
        hasher = hashers_for_expected(asset.checksum)
        written = 0
        try:
            with self.client.stream_download(url) as response:
                with tmp.open("wb") as fh:
                    for chunk in response.iter_bytes(chunk_size=1024 * 64):
                        if not chunk:
                            continue
                        fh.write(chunk)
                        hasher.update(chunk)
                        written += len(chunk)
            tmp.replace(dest)
            disable_execute_bit_best_effort(dest)
        except NexusAPIError as exc:
            _cleanup(tmp)
            logger.error("Download failed for %s: %s", asset.path, exc)
            return DownloadResult(status=DownloadStatus.ERROR, error=str(exc))
        except OSError as exc:
            _cleanup(tmp)
            logger.error("Filesystem error downloading %s: %s", asset.path, exc)
            return DownloadResult(
                status=DownloadStatus.ERROR,
                error=f"Filesystem error (disk full?): {exc}",
            )

        digests = hasher.hexdigests()
        authoritative = checksum_is_authoritative(asset)
        mismatch = checksums_mismatch(
            asset.checksum,
            digests,
            authoritative=authoritative,
        )
        if mismatch:
            logger.warning("Checksum mismatch for %s: %s", asset.path, mismatch)
            # Оставить файл, но вернуть ERROR — не притворяться, что целостность OK.
            return DownloadResult(
                status=DownloadStatus.ERROR,
                local_path=dest,
                bytes_written=written,
                error=mismatch,
                source="nexus-rest",
            )
        if not authoritative:
            warn = soft_checksum_warning(asset.checksum, digests)
            if warn:
                logger.warning("%s: %s", asset.path, warn)

        meta = self._write_metadata(
            dest,
            repository=asset.repository,
            asset_path=asset.path,
            download_url=url,
            size=written,
            checksum=asset.checksum or {"sha256": digests["sha256"]},
            source="nexus-rest",
            extra={
                "last_modified": asset.last_modified,
                "content_checksum": digests,
            },
        )
        logger.info("Downloaded %s -> %s (%s bytes)", asset.path, dest, written)
        return DownloadResult(
            status=DownloadStatus.SUCCESS,
            local_path=dest,
            metadata_path=meta,
            bytes_written=written,
            source="nexus-rest",
        )

    def download_docker_tag(self, tag: DockerTag) -> DownloadResult:
        from nexus_control.services.docker_assets import DockerAssetService

        try:
            dest = docker_archive_path(
                self.settings.download_root,
                tag.repository,
                tag.tag,
            )
        except UnsafePathError as exc:
            return DownloadResult(status=DownloadStatus.ERROR, error=str(exc))

        if dest.exists() and not self.settings.overwrite_downloads:
            if _docker_local_matches(dest, tag):
                meta = self._write_metadata(
                    dest,
                    repository=tag.repository,
                    asset_path=tag.path,
                    download_url=tag.image_ref,
                    size=dest.stat().st_size,
                    checksum={},
                    source="docker-archive",
                    skipped=True,
                    extra={
                        "tag": tag.tag,
                        "image_reference": tag.image_ref,
                        "digest": tag.digest,
                    },
                )
                return DownloadResult(
                    status=DownloadStatus.SKIPPED_EXISTING,
                    local_path=dest,
                    metadata_path=meta,
                    bytes_written=dest.stat().st_size,
                    source="docker-archive",
                )
            logger.info(
                "Re-pulling docker tag %s (digest/local archive changed)",
                tag.image_ref,
            )

        service = DockerAssetService(self.settings)
        try:
            tool = service.pull_to_archive(tag, dest)
        except Exception as exc:  # noqa: BLE001
            logger.error("Docker pull failed for %s: %s", tag.image_ref, exc)
            return DownloadResult(status=DownloadStatus.ERROR, error=str(exc))

        size = dest.stat().st_size if dest.exists() else 0
        meta = self._write_metadata(
            dest,
            repository=tag.repository,
            asset_path=f"images/{tag.tag}",
            download_url=tag.image_ref,
            size=size,
            checksum={},
            source=tool,
            extra={
                "tag": tag.tag,
                "image_reference": tag.image_ref,
                "downloader_tool": tool,
                "digest": tag.digest,
            },
        )
        return DownloadResult(
            status=DownloadStatus.SUCCESS,
            local_path=dest,
            metadata_path=meta,
            bytes_written=size,
            source=tool,
        )

    def _write_metadata(
        self,
        dest: Path,
        *,
        repository: str,
        asset_path: str,
        download_url: str | None,
        size: int,
        checksum: dict[str, str],
        source: str,
        skipped: bool = False,
        extra: dict | None = None,
    ) -> Path:
        meta_path = dest.parent / f"{dest.name}.metadata.json"
        payload = {
            "repository": repository,
            "asset_path": asset_path,
            "download_url": download_url,
            "size": size,
            "checksum": checksum,
            "downloaded_at": utc_now_iso(),
            "source": source,
            "local_path": str(dest),
            "skipped_existing": skipped,
        }
        if extra:
            payload.update(extra)
        write_json(meta_path, payload)
        return meta_path


def _cleanup(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def _sidecar_path(dest: Path) -> Path:
    return dest.parent / f"{dest.name}.metadata.json"


def _read_sidecar(dest: Path) -> dict | None:
    meta_path = _sidecar_path(dest)
    if not meta_path.is_file():
        return None
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _should_skip_existing(existing: Path, asset: NexusAsset) -> bool:
    """Решить, можно ли не качать локальный файл повторно."""
    authoritative = checksum_is_authoritative(asset)
    sidecar = _read_sidecar(existing)

    if not authoritative:
        # npm metadata: API sha1 часто врёт → смотрим, менялся ли remote identity.
        identity = remote_identity_unchanged(
            asset.checksum,
            remote_last_modified=asset.last_modified,
            sidecar=sidecar,
        )
        if identity is True:
            return True
        if identity is False:
            return False
        # Нет sidecar / не с чем сравнить — не гоняем вечный re-download.
        logger.debug(
            "Skip non-authoritative asset without identity delta: %s",
            asset.path,
        )
        return True

    match = local_matches_remote(
        existing,
        asset.checksum,
        file_size=asset.file_size,
    )
    if match is True:
        return True
    if match is False:
        return False
    # Нет checksum/size — оставляем локальный файл.
    return True


def _docker_local_matches(dest: Path, tag: DockerTag) -> bool:
    """Skip docker re-pull при совпадении digest с sidecar; иначе при digest — перекачать."""
    meta_path = dest.parent / f"{dest.name}.metadata.json"
    stored_digest: str | None = None
    if meta_path.is_file():
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            raw = data.get("digest")
            if raw:
                stored_digest = str(raw).strip().lower()
        except (OSError, json.JSONDecodeError, TypeError):
            stored_digest = None

    if tag.digest:
        remote = tag.digest.strip().lower()
        if stored_digest and stored_digest == remote:
            return True
        # Digest известен и отличается / отсутствует в meta → перекачать.
        return False

    # Нет remote digest — оставляем локальный archive (старое поведение).
    return True
