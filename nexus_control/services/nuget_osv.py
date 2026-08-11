"""NuGet-aware vulnerability scan: nuspec identity → OSV API (ecosystem NuGet).

Grype / Trivy / osv-scanner CLI не извлекают Id+Version из ``.nupkg``, поэтому
для NuGet используем прямой запрос к api.osv.dev.
"""

from __future__ import annotations

import json
import logging
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import httpx

from nexus_control.config import Settings
from nexus_control.models import (
    ScanResult,
    ScanStatus,
    SeverityCounts,
    Verdict,
    Vulnerability,
)
from nexus_control.services.osv_scanner import SCANNER_NAME, _from_osv_vuln
from nexus_control.services.scan_common import format_text_report
from nexus_control.utils.fs import ensure_parent_dir, write_json
from nexus_control.utils.safe_path import report_paths

logger = logging.getLogger(__name__)

NUGET_ECOSYSTEM = "NuGet"
NUGET_OSV_SCANNER_VERSION = "osv.dev API (NuGet)"
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


def query_osv_nuget(
    identity: NugetPackageIdentity,
    *,
    api_url: str,
    timeout: float,
    client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    """Запросить OSV ``/v1/query`` для NuGet пакета; вернуть список vuln-объектов."""
    base = api_url.rstrip("/")
    url = f"{base}/v1/query"
    payload = {
        "package": {
            "name": identity.package_id,
            "ecosystem": NUGET_ECOSYSTEM,
        },
        "version": identity.version,
    }
    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        raise NugetOsvError(f"OSV API request failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise NugetOsvError(f"OSV API returned invalid JSON: {exc}") from exc
    finally:
        if owns_client:
            http.close()

    if not isinstance(data, dict):
        raise NugetOsvError("OSV API response must be a JSON object")
    vulns = data.get("vulns") or []
    if not isinstance(vulns, list):
        raise NugetOsvError("OSV API 'vulns' must be a list")
    return [v for v in vulns if isinstance(v, dict)]


def vulns_to_findings(
    raw_vulns: list[dict[str, Any]],
    *,
    package_id: str,
    version: str,
) -> list[Vulnerability]:
    """Смапить OSV vuln-объекты в ``Vulnerability`` (с дедупом по id/aliases)."""
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_vulns:
        key_ids = _alias_ids(item)
        if key_ids & seen:
            continue
        seen |= key_ids
        selected.append(item)

    out: list[Vulnerability] = []
    for item in selected:
        vuln = _from_osv_vuln(item, pkg_name=package_id, pkg_version=version)
        if vuln is not None:
            out.append(vuln)
    return out


def scan_nupkg_via_osv_api(
    *,
    settings: Settings,
    repository: str,
    asset_path: str,
    local_path: Path,
) -> ScanResult:
    """Полный NuGet-скан: nuspec → OSV API → отчёты + ``ScanResult`` (scanner=osv)."""
    json_path, txt_path = report_paths(
        settings.reports_root,
        repository,
        asset_path,
        scanner=SCANNER_NAME,
    )
    ensure_parent_dir(json_path)
    version_label = NUGET_OSV_SCANNER_VERSION

    try:
        identity = extract_nupkg_identity(local_path)
        raw_vulns = query_osv_nuget(
            identity,
            api_url=settings.osv_api_url,
            timeout=settings.osv_api_timeout,
        )
    except NugetOsvError as exc:
        logger.warning("NuGet OSV scan failed for %s: %s", asset_path, exc)
        _write_text(txt_path, f"SCAN_ERROR\n{exc}\n")
        write_json(json_path, {"error": str(exc), "mode": "nuget-osv-api"})
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            json_report_path=json_path,
            text_report_path=txt_path,
            error=str(exc),
            scanner_version=version_label,
        )

    findings = vulns_to_findings(
        raw_vulns,
        package_id=identity.package_id,
        version=identity.version,
    )
    counts = SeverityCounts()
    for vuln in findings:
        counts.increment(vuln.severity)
    verdict = Verdict.PASS if counts.total == 0 else Verdict.FAIL
    raw = {
        "mode": "nuget-osv-api",
        "package": {
            "name": identity.package_id,
            "version": identity.version,
            "ecosystem": NUGET_ECOSYSTEM,
        },
        "vulns": raw_vulns,
    }
    write_json(json_path, raw)
    result = ScanResult(
        status=ScanStatus.SUCCESS,
        verdict=verdict,
        vulnerabilities=findings,
        counts=counts,
        scanner=SCANNER_NAME,
        scanner_version=version_label,
        json_report_path=json_path,
        text_report_path=txt_path,
        raw=raw,
    )
    _write_text(
        txt_path,
        format_text_report(result, asset_path, local_path, scanner=SCANNER_NAME),
    )
    logger.info(
        "NuGet OSV scan %s %s@%s → %s (%d vulns)",
        asset_path,
        identity.package_id,
        identity.version,
        verdict.value,
        counts.total,
    )
    return result


def _find_nuspec_member(zf: zipfile.ZipFile) -> str | None:
    members = [n for n in zf.namelist() if n.lower().endswith(".nuspec")]
    if not members:
        return None
    # Предпочесть nuspec в корне архива.
    root = [n for n in members if "/" not in n.rstrip("/") and "\\" not in n]
    return (root or members)[0]


def _nuspec_text(root: ET.Element, local_name: str) -> str:
    for elem in root.iter():
        if _xml_local(elem.tag) != "metadata":
            continue
        for child in elem:
            if _xml_local(child.tag) == local_name and child.text:
                return child.text.strip()
    # Fallback: любой элемент с нужным local-name.
    for elem in root.iter():
        if _xml_local(elem.tag) == local_name and elem.text:
            return elem.text.strip()
    return ""


def _xml_local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _alias_ids(item: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    if item.get("id"):
        ids.add(str(item["id"]))
    aliases = item.get("aliases") or []
    if isinstance(aliases, list):
        ids.update(str(a) for a in aliases if a)
    return ids


def _write_text(path: Path, text: str) -> None:
    ensure_parent_dir(path)
    path.write_text(text, encoding="utf-8")
