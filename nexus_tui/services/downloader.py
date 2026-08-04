"""Сервис загрузки артефактов с безопасными путями и sidecar-метаданными."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from nexus_tui.config import Settings
from nexus_tui.models import DownloadResult, DownloadStatus, DockerTag, NexusAsset
from nexus_tui.nexus.client import NexusClient, NexusAPIError
from nexus_tui.utils.fs import (
    disable_execute_bit_best_effort,
    prepare_asset_destination,
    utc_now_iso,
    write_json,
)
from nexus_tui.utils.safe_path import (
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
            meta = self._write_metadata(
                existing,
                repository=asset.repository,
                asset_path=asset.path,
                download_url=asset.download_url,
                size=existing.stat().st_size,
                checksum=asset.checksum,
                source="nexus-rest",
                skipped=True,
            )
            return DownloadResult(
                status=DownloadStatus.SKIPPED_EXISTING,
                local_path=existing,
                metadata_path=meta,
                bytes_written=existing.stat().st_size,
                source="nexus-rest",
            )

        url = self.client.resolve_download_url(asset)
        # npm и др.: path может быть и файлом, и префиксом каталога.
        dest = prepare_asset_destination(dest)
        tmp = dest.with_suffix(dest.suffix + ".partial")
        hasher = hashlib.sha256()
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

        mismatch = _checksum_mismatch(asset.checksum, hasher.hexdigest())
        if mismatch:
            logger.warning("Checksum mismatch for %s: %s", asset.path, mismatch)
            # Оставить файл, но сообщить об ошибке — безопаснее, чем притворяться, что целостность OK.
            return DownloadResult(
                status=DownloadStatus.ERROR,
                local_path=dest,
                bytes_written=written,
                error=mismatch,
                source="nexus-rest",
            )

        meta = self._write_metadata(
            dest,
            repository=asset.repository,
            asset_path=asset.path,
            download_url=url,
            size=written,
            checksum=asset.checksum or {"sha256": hasher.hexdigest()},
            source="nexus-rest",
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
        from nexus_tui.services.docker_assets import DockerAssetService

        try:
            dest = docker_archive_path(
                self.settings.download_root,
                tag.repository,
                tag.tag,
            )
        except UnsafePathError as exc:
            return DownloadResult(status=DownloadStatus.ERROR, error=str(exc))

        if dest.exists() and not self.settings.overwrite_downloads:
            meta = self._write_metadata(
                dest,
                repository=tag.repository,
                asset_path=tag.path,
                download_url=tag.image_ref,
                size=dest.stat().st_size,
                checksum={},
                source="docker-archive",
                skipped=True,
                extra={"tag": tag.tag, "image_reference": tag.image_ref},
            )
            return DownloadResult(
                status=DownloadStatus.SKIPPED_EXISTING,
                local_path=dest,
                metadata_path=meta,
                bytes_written=dest.stat().st_size,
                source="docker-archive",
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


def _checksum_mismatch(expected: dict[str, str], sha256_hex: str) -> str | None:
    if not expected:
        return None
    # Nexus обычно предоставляет sha1 / sha256 / md5
    if "sha256" in expected and expected["sha256"].lower() != sha256_hex.lower():
        return (
            f"SHA256 mismatch: expected {expected['sha256']}, got {sha256_hex}"
        )
    return None
