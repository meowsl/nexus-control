"""npm package identity → temporary lockfile staging for Trivy / Grype / osv.

Сырой ``.tgz`` / ``.tar.gz`` (npm pack) Trivy и Grype не разбирают как пакет:
``trivy fs file.tgz`` → 0 language files. Распаковка package/ тоже не помогает —
нужен lockfile с identity. Пишем минимальный ``package-lock.json`` (v2) во
временный каталог и сканируем его.
"""

from __future__ import annotations

import json
import logging
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path

from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

NPM_ECOSYSTEM = "npm"
_NPM_TARBALL_SUFFIXES = (".tgz", ".tar.gz")
_PKG_JSON_CANDIDATES = (
    "package/package.json",
    "./package/package.json",
)


class NpmIdentityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class NpmPackageIdentity:
    name: str
    version: str

    @property
    def node_modules_relpath(self) -> str:
        """``node_modules/lodash`` или ``node_modules/@scope/pkg``."""
        return f"node_modules/{self.name}"


def is_npm_package_tarball(path: Path) -> bool:
    """True, если локальный файл похож на npm pack archive (``.tgz`` / ``.tar.gz``)."""
    name = path.name.lower()
    return name.endswith(_NPM_TARBALL_SUFFIXES)


def extract_npm_identity(tarball: Path) -> NpmPackageIdentity:
    """Прочитать ``name`` / ``version`` из ``package/package.json`` внутри tarball."""
    if not tarball.is_file():
        raise NpmIdentityError(f"npm tarball not found: {tarball}")
    try:
        with tarfile.open(tarball, mode="r:*") as tf:
            member = _find_package_json_member(tf)
            if member is None:
                raise NpmIdentityError(
                    f"no package/package.json inside {tarball.name}"
                )
            handle = tf.extractfile(member)
            if handle is None:
                raise NpmIdentityError(f"cannot read {member.name} from {tarball.name}")
            raw = handle.read()
    except (tarfile.TarError, OSError) as exc:
        raise NpmIdentityError(f"invalid npm tarball: {tarball.name}") from exc

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NpmIdentityError(f"invalid package.json in {tarball.name}") from exc

    if not isinstance(data, dict):
        raise NpmIdentityError(f"package.json root must be object in {tarball.name}")
    name = str(data.get("name") or "").strip()
    version = str(data.get("version") or "").strip()
    if not name or not version:
        raise NpmIdentityError(
            f"package.json missing name/version in {tarball.name} "
            f"(name={name!r}, version={version!r})"
        )
    if not _valid_npm_name(name):
        raise NpmIdentityError(f"invalid npm package name {name!r} in {tarball.name}")
    return NpmPackageIdentity(name=name, version=version)


def prepare_npm_identity_staging(
    tarball: Path,
    staging_dir: Path,
) -> tuple[NpmPackageIdentity, Path]:
    """Создать каталог с ``package.json`` + ``package-lock.json`` для сканеров.

    Returns:
        ``(identity, staging_dir)``.
    """
    identity = extract_npm_identity(tarball)
    ensure_dir(staging_dir)
    package_json = {
        "name": "nexus-control-npm-scan",
        "version": "0.0.0",
        "private": True,
        "dependencies": {identity.name: identity.version},
    }
    resolved = (
        f"https://registry.npmjs.org/{identity.name}/-/"
        f"{_tarball_basename(identity)}-{identity.version}.tgz"
    )
    # lockfileVersion 2 — Trivy и Grype стабильно читают.
    lock = {
        "name": "nexus-control-npm-scan",
        "version": "0.0.0",
        "lockfileVersion": 2,
        "requires": True,
        "packages": {
            "": {
                "name": "nexus-control-npm-scan",
                "version": "0.0.0",
                "dependencies": {identity.name: identity.version},
            },
            identity.node_modules_relpath: {
                "version": identity.version,
                "resolved": resolved,
                "integrity": "",
            },
        },
        "dependencies": {
            identity.name: {
                "version": identity.version,
                "resolved": resolved,
                "integrity": "",
            }
        },
    }
    (staging_dir / "package.json").write_text(
        json.dumps(package_json, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (staging_dir / "package-lock.json").write_text(
        json.dumps(lock, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    logger.info(
        "npm identity staging %s@%s → %s",
        identity.name,
        identity.version,
        staging_dir,
    )
    return identity, staging_dir


def npm_staging_dir(reports_root: Path, repository: str, asset_path: str) -> Path:
    """Стабильный путь staging под reports (как nuget lockfiles)."""
    flat = re.sub(r"[^\w.\-]+", "__", asset_path.strip("/"))
    return reports_root / repository / "_npm_identity_scan" / flat


def write_npm_osv_identity_lockfile(
    identity: NpmPackageIdentity,
    path: Path,
) -> Path:
    """Custom lockfile для ``osv-scanner --lockfile osv-scanner:<path>``."""
    from nexus_control.utils.fs import ensure_parent_dir, write_json

    payload = {
        "results": [
            {
                "packages": [
                    {
                        "package": {
                            "name": identity.name,
                            "version": identity.version,
                            "ecosystem": NPM_ECOSYSTEM,
                        }
                    }
                ]
            }
        ]
    }
    ensure_parent_dir(path)
    write_json(path, payload)
    return path


def _find_package_json_member(tf: tarfile.TarFile) -> tarfile.TarInfo | None:
    names = {m.name: m for m in tf.getmembers() if m.isfile()}
    for candidate in _PKG_JSON_CANDIDATES:
        if candidate in names:
            return names[candidate]
    # fallback: единственный */package.json на глубине 2
    matches = [
        m
        for name, m in names.items()
        if name.endswith("/package.json") or name == "package.json"
    ]
    if len(matches) == 1:
        return matches[0]
    for m in matches:
        # предпочесть package/package.json
        if m.name.rstrip("/").endswith("package/package.json") or m.name in {
            "package/package.json",
            "./package/package.json",
        }:
            return m
    return matches[0] if matches else None


def _tarball_basename(identity: NpmPackageIdentity) -> str:
    """Имя файла в registry URL: ``lodash`` или ``core`` для ``@scope/core``."""
    if identity.name.startswith("@") and "/" in identity.name:
        return identity.name.split("/", 1)[1]
    return identity.name


def _valid_npm_name(name: str) -> bool:
    if not name or " " in name:
        return False
    if name.startswith("@"):
        parts = name.split("/")
        return len(parts) == 2 and bool(parts[0]) and bool(parts[1])
    return True
