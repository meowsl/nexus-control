"""Создание hosted-репозиториев и загрузка компонентов по format."""

from __future__ import annotations

import logging
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from nexus_control.models import Repository
from nexus_control.nexus.errors import NexusAPIError, NexusAuthError

logger = logging.getLogger(__name__)

# format из Assets/Repositories API → сегмент path в Repositories API
_FORMAT_API_SLUG: dict[str, str] = {
    "maven2": "maven",
    "npm": "npm",
    "pypi": "pypi",
    "raw": "raw",
    "nuget": "nuget",
    "rubygems": "rubygems",
    "yum": "yum",
    "apt": "apt",
    "helm": "helm",
    "go": "go",
    "huggingface": "huggingface",
}

_NPM_PACKAGE_SUFFIXES = (".tgz", ".tar.gz")
_PYPI_PACKAGE_SUFFIXES = (".whl", ".tar.gz", ".zip", ".egg")
_MAVEN_PUT_SUFFIXES = (
    ".jar",
    ".war",
    ".ear",
    ".pom",
    ".aar",
    ".zip",
    ".tar.gz",
    ".tgz",
    ".module",
)
_MAVEN_SIDE_SUFFIXES = (".md5", ".sha1", ".sha256", ".sha512", ".asc")

# Локальные sidecar-файлы в ``*-verified`` — не загружать в Nexus.
_VERIFIED_SIDECAR_NAMES = frozenset(
    {
        "verified-manifest.json",
        "unverified_assets.txt",
    }
)


def format_api_slug(fmt: str) -> str | None:
    """Вернуть API-slug для ``POST /repositories/{slug}/hosted`` или ``None``."""
    return _FORMAT_API_SLUG.get(fmt.lower().strip())


def is_verified_local_sidecar(asset_path: str) -> bool:
    """Локальный sidecar в ``*-verified`` (отчёты, манифест) — не для Nexus."""
    path = asset_path.replace("\\", "/").lstrip("/")
    if not path:
        return False
    posix = PurePosixPath(path)
    name = posix.name.lower()
    if name in _VERIFIED_SIDECAR_NAMES:
        return True
    # Сводные отчёты сканеров: grype_report.json, trivy_report.json, …
    if name.endswith("_report.json"):
        return True
    return False


def is_uploadable_asset(fmt: str, asset_path: str) -> bool:
    """Подходит ли локальный PASS-ассет для загрузки в hosted ``fmt``."""
    if is_verified_local_sidecar(asset_path):
        return False

    path = asset_path.replace("\\", "/").lstrip("/").lower()
    name = PurePosixPath(path).name
    fmt_l = fmt.lower().strip()

    if fmt_l == "raw":
        return bool(name) and name not in {"(metadata)", }
    if fmt_l == "npm":
        return path.endswith(_NPM_PACKAGE_SUFFIXES) or "/-/" in path and name.endswith(".tgz")
    if fmt_l == "pypi":
        return path.endswith(_PYPI_PACKAGE_SUFFIXES)
    if fmt_l == "maven2":
        # Nexus при HTTP PUT отдельных файлов сам maven-metadata не генерирует —
        # нужно заливать metadata (+ checksum sidecars) вместе с артефактами.
        if name == "maven-metadata.xml" or name.startswith("maven-metadata.xml."):
            return True
        if path.endswith(_MAVEN_PUT_SUFFIXES):
            return True
        if path.endswith(_MAVEN_SIDE_SUFFIXES):
            return True
        return False
    if fmt_l == "docker":
        return False
    # Прочие форматы — пробуем как файл с именем.
    return bool(name) and not name.startswith(".")


def build_hosted_create_payload(name: str, fmt: str) -> dict:
    """JSON body для создания hosted-репозитория нужного format."""
    fmt_l = fmt.lower().strip()
    storage = {
        "blobStoreName": "default",
        "strictContentTypeValidation": False,
        "writePolicy": "ALLOW",
    }
    payload: dict = {
        "name": name,
        "online": True,
        "storage": storage,
        "component": {"proprietaryComponents": False},
    }
    if fmt_l == "maven2":
        payload["maven"] = {
            "versionPolicy": "MIXED",
            "layoutPolicy": "PERMISSIVE",
            "contentDisposition": "ATTACHMENT",
        }
    elif fmt_l == "raw":
        payload["raw"] = {"contentDisposition": "ATTACHMENT"}
    return payload


def parse_maven_coordinates(asset_path: str) -> tuple[str, str, str, str] | None:
    """Извлечь ``(groupId, artifactId, version, extension)`` из Maven layout path."""
    posix = PurePosixPath(str(asset_path).replace("\\", "/").lstrip("/"))
    parts = posix.parts
    if len(parts) < 4:
        return None
    filename = parts[-1]
    version = parts[-2]
    artifact_id = parts[-3]
    group_parts = parts[:-3]
    if not group_parts:
        return None
    group_id = ".".join(group_parts)

    # filename: artifact-version[-classifier].ext
    ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
    if not ext:
        return None
    return group_id, artifact_id, version, ext


class RepositoryUploader:
    """Создание hosted ``<repo>-verified`` того же format и upload ассетов."""

    def __init__(self, client: httpx.Client, *, timeout: float = 30.0) -> None:
        self.client = client
        self.timeout = timeout

    def ensure_hosted(self, name: str, fmt: str, *, get_repository) -> Repository:
        """Вернуть hosted ``name`` format=``fmt``, создав при отсутствии.

        ``get_repository`` — callable ``(name) -> Repository | None`` с клиента Nexus.
        """
        fmt_l = fmt.lower().strip()
        slug = format_api_slug(fmt_l)
        if slug is None:
            raise NexusAPIError(
                f"Unsupported repository format {fmt!r} for verified upload"
            )
        if fmt_l == "docker":
            raise NexusAPIError(
                "Docker verified upload is not supported via Components API; "
                "use a registry push workflow instead"
            )

        existing = get_repository(name)
        if existing is not None:
            if existing.type.lower() != "hosted":
                raise NexusAPIError(
                    f"Repository {name!r} exists but is type={existing.type!r}, "
                    "expected hosted"
                )
            if existing.format.lower() != fmt_l:
                raise NexusAPIError(
                    f"Repository {name!r} exists with format={existing.format!r}, "
                    f"expected {fmt_l!r}. Delete the old repository (e.g. leftover "
                    f"raw {name!r}) and retry Upload verified."
                )
            return existing

        payload = build_hosted_create_payload(name, fmt_l)
        endpoint = f"/service/rest/v1/repositories/{slug}/hosted"
        logger.info("Creating %s hosted repository %s", fmt_l, name)
        response = self.client.post(endpoint, json=payload, timeout=self.timeout)
        if response.status_code not in {200, 201, 204}:
            detail = _safe_body(response)
            if response.status_code in {401, 403}:
                raise NexusAuthError(
                    f"Cannot create repository {name!r}: {detail}",
                    response.status_code,
                )
            raise NexusAPIError(
                f"Failed to create {fmt_l} repository {name!r} "
                f"(HTTP {response.status_code}): {detail}",
                response.status_code,
            )
        created = get_repository(name)
        if created is None:
            raise NexusAPIError(f"Repository {name!r} created but not visible via API")
        return created

    def upload_asset(
        self,
        *,
        repository: str,
        fmt: str,
        asset_path: str,
        local_path: Path,
    ) -> None:
        if not local_path.is_file():
            raise NexusAPIError(f"Local file missing for upload: {local_path}")
        if not is_uploadable_asset(fmt, asset_path):
            raise NexusAPIError(
                f"Asset {asset_path!r} is not uploadable to {fmt} repository"
            )

        fmt_l = fmt.lower().strip()
        if fmt_l == "raw":
            self._upload_raw(repository, asset_path, local_path)
        elif fmt_l == "npm":
            self._upload_npm(repository, local_path)
        elif fmt_l == "pypi":
            self._upload_pypi(repository, local_path)
        elif fmt_l == "maven2":
            self._upload_maven(repository, asset_path, local_path)
        else:
            raise NexusAPIError(f"Upload not implemented for format {fmt_l!r}")

    def _upload_raw(self, repository: str, asset_path: str, local_path: Path) -> None:
        posix = PurePosixPath(str(asset_path).replace("\\", "/").lstrip("/"))
        filename = posix.name or local_path.name
        parent = str(posix.parent)
        directory = "/" if parent in {"", "."} else f"/{parent}"
        logger.info(
            "Uploading %s -> raw://%s%s/%s",
            local_path,
            repository,
            directory.rstrip("/"),
            filename,
        )
        with local_path.open("rb") as fh:
            response = self.client.post(
                "/service/rest/v1/components",
                params={"repository": repository},
                data={
                    "raw.directory": directory,
                    "raw.asset1.filename": filename,
                },
                files={"raw.asset1": (filename, fh)},
                timeout=max(self.timeout, 120.0),
            )
        self._raise_upload(response, repository, asset_path)

    def _upload_npm(self, repository: str, local_path: Path) -> None:
        filename = local_path.name
        logger.info("Uploading %s -> npm://%s", local_path, repository)
        with local_path.open("rb") as fh:
            response = self.client.post(
                "/service/rest/v1/components",
                params={"repository": repository},
                files={
                    "npm.asset": (filename, fh, "application/octet-stream"),
                },
                timeout=max(self.timeout, 120.0),
            )
        self._raise_upload(response, repository, filename)

    def _upload_pypi(self, repository: str, local_path: Path) -> None:
        filename = local_path.name
        logger.info("Uploading %s -> pypi://%s", local_path, repository)
        with local_path.open("rb") as fh:
            response = self.client.post(
                "/service/rest/v1/components",
                params={"repository": repository},
                files={
                    "pypi.asset": (filename, fh, "application/octet-stream"),
                },
                timeout=max(self.timeout, 120.0),
            )
        self._raise_upload(response, repository, filename)

    def _upload_maven(
        self,
        repository: str,
        asset_path: str,
        local_path: Path,
    ) -> None:
        """Maven: предпочитаем PUT по исходному path (сохраняет layout)."""
        rel = str(asset_path).replace("\\", "/").lstrip("/")
        encoded = quote(rel, safe="/")
        url = f"/repository/{quote(repository, safe='')}/{encoded}"
        logger.info("Uploading %s -> maven://%s/%s", local_path, repository, rel)
        response = self.client.put(
            url,
            content=local_path.read_bytes(),
            headers={"Content-Type": "application/octet-stream"},
            timeout=max(self.timeout, 120.0),
        )
        if response.status_code in {200, 201, 204}:
            return
        # metadata / checksums — только PUT, Components API их не принимает.
        lower_name = PurePosixPath(rel).name.lower()
        if (
            lower_name == "maven-metadata.xml"
            or lower_name.startswith("maven-metadata.xml.")
            or lower_name.endswith(_MAVEN_SIDE_SUFFIXES)
        ):
            self._raise_upload(response, repository, asset_path)
            return
        # Fallback: Components API с координатами из path.
        coords = parse_maven_coordinates(asset_path)
        if coords is None:
            self._raise_upload(response, repository, asset_path)
            return
        group_id, artifact_id, version, extension = coords
        logger.info(
            "PUT failed (%s); falling back to components API for %s:%s:%s",
            response.status_code,
            group_id,
            artifact_id,
            version,
        )
        with local_path.open("rb") as fh:
            response = self.client.post(
                "/service/rest/v1/components",
                params={"repository": repository},
                data={
                    "maven2.groupId": group_id,
                    "maven2.artifactId": artifact_id,
                    "maven2.version": version,
                    "maven2.generate-pom": "true",
                    "maven2.asset1.extension": extension,
                },
                files={
                    "maven2.asset1": (local_path.name, fh, "application/octet-stream"),
                },
                timeout=max(self.timeout, 120.0),
            )
        self._raise_upload(response, repository, asset_path)

    def _raise_upload(
        self,
        response: httpx.Response,
        repository: str,
        asset_path: str,
    ) -> None:
        if response.status_code in {200, 201, 204}:
            return
        detail = _safe_body(response)
        # Повторная загрузка того же компонента часто даёт 400 — считаем OK, если уже есть.
        if response.status_code == 400 and _looks_like_already_exists(detail):
            logger.info(
                "Asset already present in %s: %s (%s)",
                repository,
                asset_path,
                detail,
            )
            return
        if response.status_code in {401, 403}:
            raise NexusAuthError(
                f"Upload unauthorized to {repository!r}: {detail}",
                response.status_code,
            )
        raise NexusAPIError(
            f"Upload failed for {asset_path!r} to {repository!r} "
            f"(HTTP {response.status_code}): {detail}",
            response.status_code,
        )


def _safe_body(response: httpx.Response) -> str:
    try:
        text = response.text.strip()
    except Exception:  # noqa: BLE001
        return f"HTTP {response.status_code}"
    return text[:500] if text else f"HTTP {response.status_code}"


def _looks_like_already_exists(detail: str) -> bool:
    lowered = detail.lower()
    patterns = (
        "already exists",
        "repository does not allow updating",
        "cannot be updated",
        "asset already exists",
        "component already exists",
    )
    return any(p in lowered for p in patterns)
