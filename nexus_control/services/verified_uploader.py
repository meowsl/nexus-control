"""Загрузка локально проверенных (PASS) ассетов в Nexus ``<repo>-verified``."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from nexus_control.models import PipelineSummary, Verdict
from nexus_control.nexus.client import NexusAPIError, NexusClient
from nexus_control.nexus.uploads import is_uploadable_asset
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
    """Имя целевого репозитория: ``<source>-verified`` (safe для Nexus)."""
    base = sanitize_repo_name(source_repository)
    name = f"{base}-verified"
    return name[:200]


class VerifiedUploader:
    """Создать hosted ``<repo>-verified`` того же format и залить PASS-ассеты."""

    def __init__(self, client: NexusClient) -> None:
        self.client = client

    def upload(
        self,
        summary: PipelineSummary,
        *,
        on_progress: ProgressCallback | None = None,
    ) -> UploadSummary:
        target = verified_repo_name(summary.repository)
        source = self.client.get_repository(summary.repository)
        if source is None:
            raise NexusAPIError(
                f"Source repository {summary.repository!r} not found in Nexus"
            )
        fmt = source.format.lower().strip()

        candidates = [
            r
            for r in summary.results
            if r.verdict == Verdict.PASS
            and r.verify.verified_path is not None
            and (r.verify.copied or r.verify.skipped_existing)
        ]
        out = UploadSummary(
            source_repository=summary.repository,
            target_repository=target,
            source_format=fmt,
        )
        if not candidates:
            logger.warning("No verified PASS assets to upload for %s", summary.repository)
            return out

        existed = self.client.get_repository(target) is not None
        self.client.ensure_hosted(target, fmt)
        out.created_repository = not existed

        total = max(len(candidates), 1)
        for index, result in enumerate(candidates):
            path = result.asset_path
            local = result.verify.verified_path
            assert local is not None
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
