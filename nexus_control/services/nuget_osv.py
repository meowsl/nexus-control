"""NuGet-aware scan helpers: nuspec identity → temporary lockfile for osv-scanner.

``.nupkg`` сам по себе osv-scanner не разбирает. Мы извлекаем Id+Version из
``.nuspec`` и кормим CLI через custom lockfile ``osv-scanner:<path>``.
"""

from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET

from nexus_control.utils.fs import ensure_parent_dir, write_json

logger = logging.getLogger(__name__)

NUGET_ECOSYSTEM = "NuGet"
_NUGET_PACKAGE_SUFFIXES = (".nupkg", ".snupkg")


class NugetOsvError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class NugetPackageIdentity:
    package_id: str
    version: str


def is_nupkg_local_path(path: Path) -> bool:
    """True, если локальный файл выглядит как NuGet package archive."""
    name = path.name.lower()
    return name.endswith(_NUGET_PACKAGE_SUFFIXES)


def extract_nupkg_identity(nupkg_path: Path) -> NugetPackageIdentity:
    """Прочитать ``id`` / ``version`` из ``.nuspec`` внутри ``.nupkg``."""
    if not nupkg_path.is_file():
        raise NugetOsvError(f"nupkg not found: {nupkg_path}")
    try:
        with zipfile.ZipFile(nupkg_path) as zf:
            nuspec_name = _find_nuspec_member(zf)
            if nuspec_name is None:
                raise NugetOsvError(f"no .nuspec inside {nupkg_path.name}")
            raw = zf.read(nuspec_name)
    except zipfile.BadZipFile as exc:
        raise NugetOsvError(f"invalid nupkg zip: {nupkg_path.name}") from exc

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise NugetOsvError(f"invalid nuspec XML in {nupkg_path.name}") from exc

    package_id = _nuspec_text(root, "id")
    version = _nuspec_text(root, "version")
    if not package_id or not version:
        raise NugetOsvError(
            f"nuspec missing id/version in {nupkg_path.name} "
            f"(id={package_id!r}, version={version!r})"
        )
    return NugetPackageIdentity(package_id=package_id, version=version)


def write_nuget_identity_lockfile(
    identity: NugetPackageIdentity,
    path: Path,
) -> Path:
    """Записать custom lockfile для ``osv-scanner --lockfile osv-scanner:<path>``."""
    payload = {
        "results": [
            {
                "packages": [
                    {
                        "package": {
                            "name": identity.package_id,
                            "version": identity.version,
                            "ecosystem": NUGET_ECOSYSTEM,
                        }
                    }
                ]
            }
        ]
    }
    ensure_parent_dir(path)
    write_json(path, payload)
    return path


def build_nuget_osv_args(lockfile_path: Path, extra: list[str]) -> list[str]:
    """Argv osv-scanner (без бинарника) для NuGet identity lockfile."""
    return [
        "scan",
        "source",
        f"--lockfile=osv-scanner:{lockfile_path.resolve()}",
        "--format=json",
        *extra,
    ]


def _find_nuspec_member(zf: zipfile.ZipFile) -> str | None:
    members = [n for n in zf.namelist() if n.lower().endswith(".nuspec")]
    if not members:
        return None
    root = [n for n in members if "/" not in n.rstrip("/") and "\\" not in n]
    return (root or members)[0]


def _nuspec_text(root: ET.Element, local_name: str) -> str:
    for elem in root.iter():
        if _xml_local(elem.tag) != "metadata":
            continue
        for child in elem:
            if _xml_local(child.tag) == local_name and child.text:
                return child.text.strip()
    for elem in root.iter():
        if _xml_local(elem.tag) == local_name and elem.text:
            return elem.text.strip()
    return ""


def _xml_local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag
