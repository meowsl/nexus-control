"""Offline DB для osv-scanner: проверка, скачивание, preflight перед verify."""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import httpx

from nexus_control.config import Settings
from nexus_control.utils.subprocess_runner import which

logger = logging.getLogger(__name__)

OSV_VULNS_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
OFFLINE_FLAGS = ("--offline", "--offline-vulnerabilities")
# Типичные ecosystem для nexus-control (полный список — ``fetch_ecosystems_list``).
DEFAULT_UPDATE_ECOSYSTEMS = ("NuGet", "Maven", "npm", "PyPI", "Go")
# osv-scanner 2.x (scalibr) + legacy docs layout
_DB_LAYOUTS = ("osv-scalibr", "osv-scanner")


class OsvOfflineDbError(RuntimeError):
    pass


class EnsureStatus(str, Enum):
    OK = "ok"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class EnsureResult:
    status: EnsureStatus
    message: str = ""
    settings: Settings | None = None


def default_user_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    if xdg:
        return Path(xdg).expanduser()
    return Path.home() / ".cache"


def osv_db_cache_root(settings: Settings | None = None) -> Path:
    """Корень кэша, внутри которого лежат ``osv-scalibr/<Eco>/all.zip``."""
    if settings is not None and settings.osv_local_db_cache_dir is not None:
        return Path(settings.osv_local_db_cache_dir).expanduser()
    env = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "").strip()
    if env:
        return Path(env).expanduser()
    return default_user_cache_dir()


def ecosystem_db_path(cache_root: Path, ecosystem: str) -> Path | None:
    """Путь к существующему ``all.zip`` для ecosystem, либо ``None``."""
    for layout in _DB_LAYOUTS:
        path = cache_root / layout / ecosystem / "all.zip"
        if path.is_file() and path.stat().st_size > 0:
            return path
    return None


def preferred_ecosystem_db_path(cache_root: Path, ecosystem: str) -> Path:
    """Куда скачивать DB (layout osv-scalibr, как у osv-scanner 2.x)."""
    return cache_root / "osv-scalibr" / ecosystem / "all.zip"


def list_installed_ecosystems(cache_root: Path) -> list[str]:
    found: set[str] = set()
    for layout in _DB_LAYOUTS:
        base = cache_root / layout
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if child.is_dir() and (child / "all.zip").is_file():
                found.add(child.name)
    return sorted(found)


def missing_osv_ecosystems(cache_root: Path, ecosystems: list[str]) -> list[str]:
    return [eco for eco in ecosystems if ecosystem_db_path(cache_root, eco) is None]


def osv_is_needed(repo_format: str | None, enabled_scanners: list[str]) -> bool:
    if "osv" in enabled_scanners:
        return True
    return (repo_format or "").lower().strip() == "nuget"


def ecosystems_required_for_verify(
    repo_format: str | None,
    enabled_scanners: list[str],
) -> list[str] | None:
    """``None`` — osv не нужен; иначе список обязательных ecosystem (может быть пустым = any)."""
    if not osv_is_needed(repo_format, enabled_scanners):
        return None
    if (repo_format or "").lower().strip() == "nuget":
        return ["NuGet"]
    # Общий osv: достаточно любого all.zip; пустой список = «any ecosystem».
    return []


def offline_db_ready(cache_root: Path, required: list[str]) -> bool:
    if required:
        return not missing_osv_ecosystems(cache_root, required)
    return bool(list_installed_ecosystems(cache_root))


def with_osv_offline_flags(settings: Settings) -> Settings:
    """Добавить ``--offline --offline-vulnerabilities`` в ``osv_extra_args`` при отсутствии."""
    parts = list(settings.osv_extra_args_list)
    lower = {p.lower() for p in parts}
    for flag in OFFLINE_FLAGS:
        if flag.lower() not in lower:
            parts.append(flag)
    new_args = " ".join(parts)
    if new_args == settings.osv_extra_args:
        return settings
    return settings.model_copy(update={"osv_extra_args": new_args})


def osv_scanner_environ(settings: Settings) -> dict[str, str]:
    """Env для subprocess osv-scanner: кэш offline DB под нашим root."""
    env = dict(os.environ)
    root = osv_db_cache_root(settings)
    env["XDG_CACHE_HOME"] = str(root)
    env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(root)
    return env


def download_ecosystem_db(
    ecosystem: str,
    *,
    cache_root: Path,
    timeout: float = 300.0,
) -> Path:
    """Скачать ``{ecosystem}/all.zip`` с GCS HTTP mirror."""
    dest = preferred_ecosystem_db_path(cache_root, ecosystem)
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"{OSV_VULNS_BASE}/{ecosystem}/all.zip"
    tmp = dest.with_suffix(".zip.partial")
    logger.info("Downloading OSV offline DB %s → %s", url, dest)
    try:
        with httpx.stream("GET", url, follow_redirects=True, timeout=timeout) as response:
            response.raise_for_status()
            with tmp.open("wb") as fh:
                for chunk in response.iter_bytes():
                    fh.write(chunk)
        tmp.replace(dest)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise
    return dest


def fetch_ecosystems_list(*, timeout: float = 60.0) -> list[str]:
    url = f"{OSV_VULNS_BASE}/ecosystems.txt"
    response = httpx.get(url, follow_redirects=True, timeout=timeout)
    response.raise_for_status()
    return [line.strip() for line in response.text.splitlines() if line.strip()]


def download_offline_databases(
    settings: Settings,
    *,
    ecosystems: list[str] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> list[Path]:
    """Скачать offline DB для указанных ecosystem (или всех из ecosystems.txt)."""
    cache_root = osv_db_cache_root(settings)
    cache_root.mkdir(parents=True, exist_ok=True)
    if ecosystems is None:
        ecosystems = fetch_ecosystems_list()
    if not ecosystems:
        raise OsvOfflineDbError("No ecosystems to download")
    paths: list[Path] = []
    for eco in ecosystems:
        if on_progress:
            on_progress(eco)
        paths.append(download_ecosystem_db(eco, cache_root=cache_root))
    return paths


def prompt_download_offline_db(message: str) -> bool:
    """TTY prompt; ``True`` если пользователь согласен скачать."""
    if not sys.stdin.isatty():
        return False
    sys.stderr.write(message.rstrip() + "\n")
    sys.stderr.write("Download OSV offline database now? [y/N] ")
    sys.stderr.flush()
    try:
        answer = sys.stdin.readline()
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


def ensure_osv_offline_db(
    settings: Settings,
    *,
    repo_format: str | None,
    enabled_scanners: list[str],
    interactive: bool,
    ask: Callable[[], bool] | None = None,
    download: Callable[[], object] | None = None,
) -> EnsureResult:
    """Preflight: при необходимости osv проверить offline DB; иначе cancel.

    ``ask`` / ``download`` — для тестов и TUI (по умолчанию TTY prompt + HTTP download).
    """
    required = ecosystems_required_for_verify(repo_format, enabled_scanners)
    if required is None:
        return EnsureResult(status=EnsureStatus.SKIPPED, message="osv not needed")

    cache_root = osv_db_cache_root(settings)
    if offline_db_ready(cache_root, required):
        updated = with_osv_offline_flags(settings)
        installed = list_installed_ecosystems(cache_root)
        return EnsureResult(
            status=EnsureStatus.OK,
            message=f"OSV offline DB ready at {cache_root} ({', '.join(installed) or 'ok'})",
            settings=updated,
        )

    if required:
        missing = missing_osv_ecosystems(cache_root, required)
        detail = (
            f"Missing OSV offline DB for: {', '.join(missing)}\n"
            f"Expected e.g. {preferred_ecosystem_db_path(cache_root, missing[0])}"
        )
        to_download = list(missing)
    else:
        detail = (
            f"No OSV offline databases found under {cache_root}/osv-scalibr/\n"
            "Need at least one <ecosystem>/all.zip for osv-scanner --offline."
        )
        # Не тянем все 40+ ecosystem в интерактиве — типичный набор.
        to_download = list(DEFAULT_UPDATE_ECOSYSTEMS)

    if not interactive:
        return EnsureResult(
            status=EnsureStatus.CANCELLED,
            message=(
                f"{detail}\n"
                "Scanning cancelled: local OSV offline DB is required. "
                "Run `nexus-control-cli osv-db update` on a networked host "
                "(or answer yes to the download prompt in an interactive TTY)."
            ),
        )

    ask_fn = ask or (
        lambda: prompt_download_offline_db(
            f"{detail}\nWithout a local DB, osv-scanner would use remote OSV API."
        )
    )
    if not ask_fn():
        return EnsureResult(
            status=EnsureStatus.CANCELLED,
            message="Scanning cancelled: OSV offline database download declined.",
        )

    download_fn = download or (
        lambda: download_offline_databases(settings, ecosystems=to_download)
    )
    try:
        download_fn()
    except Exception as exc:  # noqa: BLE001
        logger.exception("OSV offline DB download failed")
        return EnsureResult(
            status=EnsureStatus.ERROR,
            message=f"Failed to download OSV offline DB: {exc}",
        )

    if not offline_db_ready(cache_root, required):
        return EnsureResult(
            status=EnsureStatus.ERROR,
            message=(
                f"OSV offline DB still missing after download under {cache_root}"
            ),
        )

    updated = with_osv_offline_flags(settings)
    return EnsureResult(
        status=EnsureStatus.OK,
        message=f"OSV offline DB downloaded under {cache_root}",
        settings=updated,
    )


def osv_binary_available(settings: Settings) -> bool:
    return which(settings.osv_binary) is not None
