"""PyPI package identity → staging for Grype / Trivy / osv-scanner.

Сырой ``.whl`` Grype/Trivy видят как файл без Python-пакета (0 CVE).
Читаем ``Name``/``Version`` из METADATA (wheel) или PKG-INFO (sdist) и
сканируем каталог с ``requirements.txt``, либо custom lockfile для osv.
"""

from __future__ import annotations

import logging
import re
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from nexus_control.utils.fs import ensure_dir, ensure_parent_dir, write_json

logger = logging.getLogger(__name__)

PYPI_ECOSYSTEM = "PyPI"
_WHEEL_EGG_SUFFIXES = (".whl", ".egg")
_SDIST_SUFFIXES = (".tar.gz", ".zip")
_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")


class PypiIdentityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PypiPackageIdentity:
    name: str
    version: str


def is_pypi_package_file(path: Path) -> bool:
    """True для wheel / egg / sdist (не npm ``.tgz``)."""
    name = path.name.lower()
    if name.endswith(_WHEEL_EGG_SUFFIXES):
        return True
    if name.endswith(".tgz"):
        return False
    return name.endswith(_SDIST_SUFFIXES)


def extract_pypi_identity(package_path: Path) -> PypiPackageIdentity:
    """Прочитать Name/Version из METADATA или PKG-INFO внутри архива."""
    if not package_path.is_file():
        raise PypiIdentityError(f"PyPI package not found: {package_path}")
    name = package_path.name.lower()
    try:
        if name.endswith(".whl") or name.endswith((".egg", ".zip")):
            text = _read_from_zip(package_path)
        elif name.endswith(".tar.gz"):
            text = _read_from_tar(package_path)
        else:
            raise PypiIdentityError(f"unsupported PyPI package: {package_path.name}")
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        raise PypiIdentityError(
            f"invalid PyPI archive: {package_path.name}"
        ) from exc

    pkg_name, version = _parse_pkginfo(text)
    if not pkg_name or not version:
        raise PypiIdentityError(
            f"METADATA/PKG-INFO missing Name/Version in {package_path.name} "
            f"(name={pkg_name!r}, version={version!r})"
        )
    if not _NAME_RE.fullmatch(pkg_name) or " " in version or "\n" in version:
        raise PypiIdentityError(
            f"invalid PyPI identity {pkg_name!r}=={version!r} in {package_path.name}"
        )
    return PypiPackageIdentity(name=pkg_name, version=version)


def prepare_pypi_identity_staging(
    package_path: Path,
    staging_dir: Path,
) -> tuple[PypiPackageIdentity, Path]:
    """Каталог с ``requirements.txt`` (``Name==Version``) для Grype/Trivy."""
    identity = extract_pypi_identity(package_path)
    ensure_dir(staging_dir)
    (staging_dir / "requirements.txt").write_text(
        f"{identity.name}=={identity.version}\n",
        encoding="utf-8",
    )
    logger.info(
        "PyPI identity staging %s==%s → %s",
        identity.name,
        identity.version,
        staging_dir,
    )
    return identity, staging_dir


def pypi_staging_dir(reports_root: Path, repository: str, asset_path: str) -> Path:
    """Стабильный путь staging под reports."""
    flat = re.sub(r"[^\w.\-]+", "__", asset_path.strip("/"))
    return reports_root / repository / "_pypi_identity_scan" / flat


def write_pypi_osv_identity_lockfile(
    identity: PypiPackageIdentity,
    path: Path,
) -> Path:
    """Custom lockfile для ``osv-scanner --lockfile osv-scanner:<path>``."""
    payload = {
        "results": [
            {
                "packages": [
                    {
                        "package": {
                            "name": identity.name,
                            "version": identity.version,
                            "ecosystem": PYPI_ECOSYSTEM,
                        }
                    }
                ]
            }
        ]
    }
    ensure_parent_dir(path)
    write_json(path, payload)
    return path


def build_pypi_osv_args(lockfile_path: Path, extra: list[str]) -> list[str]:
    """Argv osv-scanner (без бинарника) для PyPI identity lockfile."""
    return [
        "scan",
        "source",
        f"--lockfile=osv-scanner:{lockfile_path.resolve()}",
        "--format=json",
        *extra,
    ]


def _read_from_zip(path: Path) -> str:
    with zipfile.ZipFile(path) as zf:
        member = _find_metadata_zip_member(zf.namelist())
        if member is None:
            raise PypiIdentityError(f"no METADATA/PKG-INFO inside {path.name}")
        return zf.read(member).decode("utf-8", errors="replace")


def _read_from_tar(path: Path) -> str:
    with tarfile.open(path, mode="r:*") as tf:
        member = _find_metadata_tar_member(tf)
        if member is None:
            raise PypiIdentityError(f"no PKG-INFO/METADATA inside {path.name}")
        handle = tf.extractfile(member)
        if handle is None:
            raise PypiIdentityError(f"cannot read {member.name} from {path.name}")
        return handle.read().decode("utf-8", errors="replace")


def _find_metadata_zip_member(names: list[str]) -> str | None:
    lowered = {n: n for n in names}
    dist_info = [
        n
        for n in names
        if n.replace("\\", "/").lower().endswith(".dist-info/metadata")
        and n.replace("\\", "/").count("/") <= 1
    ]
    if dist_info:
        return dist_info[0]
    for candidate in ("PKG-INFO", "METADATA"):
        if candidate in lowered:
            return candidate
    matches = [
        n
        for n in names
        if n.replace("\\", "/").rsplit("/", 1)[-1].upper() in {"PKG-INFO", "METADATA"}
    ]
    return matches[0] if matches else None


def _find_metadata_tar_member(tf: tarfile.TarFile) -> tarfile.TarInfo | None:
    files = [m for m in tf.getmembers() if m.isfile()]
    for member in files:
        posix = member.name.replace("\\", "/").lstrip("./")
        leaf = posix.rsplit("/", 1)[-1].upper()
        depth = posix.count("/")
        if leaf == "PKG-INFO" and depth <= 1:
            return member
        if leaf == "METADATA" and ".dist-info/" in posix.lower() and depth <= 2:
            return member
    for member in files:
        leaf = member.name.replace("\\", "/").rsplit("/", 1)[-1].upper()
        if leaf in {"PKG-INFO", "METADATA"}:
            return member
    return None


def _parse_pkginfo(text: str) -> tuple[str, str]:
    name = ""
    version = ""
    for raw in text.splitlines():
        if raw.startswith((" ", "\t")) or ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        key_l = key.strip().lower()
        value = value.strip()
        if key_l == "name" and not name:
            name = value
        elif key_l == "version" and not version:
            version = value
        if name and version:
            break
    return name, version
