"""Интеграция с DefectDojo: vault API-ключа и push findings после verify.

После verify для ассетов с вердиктом FAIL собирается JSON
``Generic Findings Import`` и отправляется через
``POST /api/v2/reimport-scan/`` (auto_create_context).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography.fernet import Fernet, InvalidToken

from nexus_control.config import Settings
from nexus_control.models import (
    AssetPipelineResult,
    PipelineSummary,
    Severity,
    Verdict,
    Vulnerability,
)
from nexus_control.utils.fs import ensure_dir

logger = logging.getLogger(__name__)

VAULT_FILENAME = "defectdojo.vault"
KEY_FILENAME = ".vault_key"
SCAN_TYPE = "Generic Findings Import"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


@dataclass(slots=True)
class DefectDojoPushResult:
    """Итог одной отправки в DefectDojo."""

    findings: int
    status_code: int | None = None
    skipped: bool = False
    error: str | None = None
    test_id: int | None = None
    engagement_id: int | None = None


class DefectDojoVault:
    """Шифрованное хранилище API-ключа DefectDojo (Fernet, ``0o600``).

    Использует тот же ``.vault_key``, что и Nexus credentials vault.
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.vault_path = cache_dir / VAULT_FILENAME
        self.key_path = cache_dir / KEY_FILENAME

    def save(self, *, url: str, api_key: str) -> None:
        ensure_dir(self.cache_dir, mode=0o700)
        payload = {
            "url": url.rstrip("/"),
            "api_key": api_key,
        }
        token = self._fernet().encrypt(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )
        self._write_bytes(self.vault_path, token)
        logger.info("DefectDojo API key saved to %s", self.vault_path.name)

    def load(self) -> tuple[str, str] | None:
        """Вернуть ``(url, api_key)`` или ``None``."""
        if not self.vault_path.is_file() or not self.key_path.is_file():
            return None
        try:
            raw = self.vault_path.read_bytes()
            data = json.loads(self._fernet().decrypt(raw).decode("utf-8"))
        except (OSError, InvalidToken, json.JSONDecodeError, UnicodeError) as exc:
            logger.warning("Failed to read DefectDojo vault: %s", exc)
            self.clear()
            return None
        if not isinstance(data, dict):
            self.clear()
            return None
        api_key = str(data.get("api_key") or "").strip()
        url = str(data.get("url") or "").strip().rstrip("/")
        if not api_key:
            self.clear()
            return None
        return url, api_key

    def clear(self) -> None:
        try:
            if self.vault_path.exists():
                self.vault_path.unlink()
                logger.info("DefectDojo vault cleared: %s", self.vault_path.name)
        except OSError as exc:
            logger.warning("Failed to remove %s: %s", self.vault_path, exc)

    def _fernet(self) -> Fernet:
        return Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        ensure_dir(self.cache_dir, mode=0o700)
        if self.key_path.is_file():
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        self._write_bytes(self.key_path, key)
        return key

    @staticmethod
    def _write_bytes(path: Path, data: bytes) -> None:
        path.write_bytes(data)
        try:
            path.chmod(0o600)
        except OSError:
            pass


def resolve_defectdojo_settings(settings: Settings) -> Settings:
    """Подставить API-ключ из env (уже в Settings) или из vault."""
    if not settings.defectdojo_enabled:
        return settings
    if (settings.defectdojo_api_key or "").strip():
        return settings
    loaded = DefectDojoVault(settings.nexus_cache_dir).load()
    if loaded is None:
        return settings
    vault_url, api_key = loaded
    updates: dict[str, object] = {"defectdojo_api_key": api_key}
    if not (settings.defectdojo_url or "").strip() and vault_url:
        updates["defectdojo_url"] = vault_url
    return settings.model_copy(update=updates)


def map_severity(severity: Severity) -> str:
    """DefectDojo: Critical / High / Medium / Low / Info."""
    if severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}:
        return severity.value
    return "Info"


def nexus_asset_title(repository: str, asset_path: str) -> str:
    """Путь ассета в Nexus: ``repo/path/to/file``."""
    repo = (repository or "").strip().strip("/")
    path = (asset_path or "").strip().lstrip("/")
    if repo and path:
        return f"{repo}/{path}"
    return repo or path or "unknown-asset"


def vulnerability_to_finding(
    vuln: Vulnerability,
    *,
    repository: str,
    asset_path: str,
    scanner: str,
) -> dict[str, Any]:
    """Один finding для Generic Findings Import."""
    pkg = (vuln.package_name or "").strip()
    ver = (vuln.package_version or "").strip()
    # Title = путь в Nexus (repo/asset). Уязвимости на одном ассете
    # различаются unique_id_from_tool / vuln_id_from_tool.
    title = nexus_asset_title(repository, asset_path)

    desc_lines = [
        (
            "Отчет сгенерирован автоматически при сканировании репозитория "
            f"**{repository}**."
        ),
        "",
        f"Уязвимость: {vuln.id or 'unknown'}",
        f"Сканер: {scanner}",
        f"Ассет: {title}",
    ]
    if pkg:
        desc_lines.append(f"Компонент: {pkg}" + (f"@{ver}" if ver else ""))
    if vuln.fix_version:
        desc_lines.append(f"Исправление: {vuln.fix_version}")
    if vuln.description:
        desc_lines.append("")
        desc_lines.append(vuln.description)

    finding: dict[str, Any] = {
        "title": title,
        "severity": map_severity(vuln.severity),
        "description": "\n".join(desc_lines),
        "vuln_id_from_tool": vuln.id,
        "unique_id_from_tool": f"{repository}|{asset_path}|{vuln.id}|{pkg}|{ver}",
        "file_path": title,
        "static_finding": True,
        "dynamic_finding": False,
        "active": True,
        "verified": False,
        "tags": ["nexus-control", scanner],
    }
    if pkg:
        finding["component_name"] = pkg
    if ver:
        finding["component_version"] = ver
    if vuln.fix_version:
        finding["mitigation"] = f"Upgrade to {vuln.fix_version}"

    vuln_ids: list[str] = []
    if vuln.id:
        vuln_ids.append(vuln.id)
        if _CVE_RE.match(vuln.id):
            finding["cve"] = vuln.id.upper()
    if vuln_ids:
        finding["vulnerability_ids"] = vuln_ids
    return finding


def collect_findings(summary: PipelineSummary) -> list[dict[str, Any]]:
    """Собрать findings только с FAIL-ассетов (уязвимые компоненты)."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for result in summary.results:
        if result.verdict != Verdict.FAIL:
            continue
        findings.extend(
            _findings_from_asset(result, repository=summary.repository, seen=seen)
        )
    return findings


def _findings_from_asset(
    result: AssetPipelineResult,
    *,
    repository: str,
    seen: set[str],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for scanner_name, scan in result.scans.items():
        if scan.verdict == Verdict.SKIPPED:
            continue
        for vuln in scan.vulnerabilities:
            finding = vulnerability_to_finding(
                vuln,
                repository=repository,
                asset_path=result.asset_path,
                scanner=scanner_name or scan.scanner or "unknown",
            )
            uid = str(finding.get("unique_id_from_tool") or "")
            if uid and uid in seen:
                continue
            if uid:
                seen.add(uid)
            out.append(finding)
    return out


def build_generic_report(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {"findings": findings}


class DefectDojoClient:
    """Минимальный клиент DefectDojo API v2 (reimport-scan)."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify_ssl: bool = True,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def reimport_generic_findings(
        self,
        report: dict[str, Any],
        *,
        product_name: str,
        engagement_name: str,
        product_type_name: str = "Nexus",
        test_title: str = "nexus-control",
        close_old_findings: bool = True,
    ) -> dict[str, Any]:
        payload = json.dumps(report, ensure_ascii=False).encode("utf-8")
        data = {
            "scan_type": SCAN_TYPE,
            "product_name": product_name,
            "engagement_name": engagement_name,
            "product_type_name": product_type_name,
            "test_title": test_title,
            "auto_create_context": "true",
            "active": "true",
            "verified": "false",
            "minimum_severity": "Info",
            "close_old_findings": "true" if close_old_findings else "false",
            "deduplication_on_engagement": "true",
        }
        files = {
            "file": ("nexus-control-findings.json", payload, "application/json"),
        }
        headers = {"Authorization": f"Token {self.api_key}"}
        with httpx.Client(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            response = client.post(
                "/api/v2/reimport-scan/",
                data=data,
                files=files,
                headers=headers,
            )
        if response.status_code >= 400:
            body = (response.text or "")[:500]
            raise RuntimeError(
                f"DefectDojo reimport failed HTTP {response.status_code}: {body}"
            )
        try:
            return response.json()
        except ValueError:
            return {"status_code": response.status_code}


def defectdojo_engagement_url(settings: Settings, engagement_id: int | None) -> str | None:
    """Публичный URL engagement в UI DefectDojo, если интеграция включена."""
    if engagement_id is None:
        return None
    cfg = resolve_defectdojo_settings(settings)
    if not cfg.defectdojo_enabled:
        return None
    base = (cfg.defectdojo_url or "").strip().rstrip("/")
    if not base:
        return None
    return f"{base}/engagement/{int(engagement_id)}"


def push_pipeline_findings(
    settings: Settings,
    summary: PipelineSummary,
) -> DefectDojoPushResult:
    """Отправить findings FAIL-ассетов в DefectDojo (no-op если выключено)."""
    cfg = resolve_defectdojo_settings(settings)
    if not cfg.defectdojo_enabled:
        return DefectDojoPushResult(findings=0, skipped=True)

    url = (cfg.defectdojo_url or "").strip().rstrip("/")
    api_key = (cfg.defectdojo_api_key or "").strip()
    if not url or not api_key:
        msg = (
            "DefectDojo enabled but URL/API key missing "
            "(set defectdojo_url + DEFECTDOJO_API_KEY or run: "
            "nexus-control-cli defectdojo configure)"
        )
        logger.warning(msg)
        return DefectDojoPushResult(findings=0, skipped=True, error=msg)

    findings = collect_findings(summary)
    if not findings:
        logger.info(
            "DefectDojo: no FAIL findings for repo=%s — skip push",
            summary.repository,
        )
        return DefectDojoPushResult(findings=0, skipped=True)

    product = (cfg.defectdojo_product_name or "nexus-control").strip() or "nexus-control"
    engagement = (
        (cfg.defectdojo_engagement_name or "").strip() or summary.repository
    )
    product_type = (
        (cfg.defectdojo_product_type_name or "Nexus").strip() or "Nexus"
    )
    test_title = f"nexus-control {summary.repository}"

    client = DefectDojoClient(
        base_url=url,
        api_key=api_key,
        verify_ssl=cfg.defectdojo_verify_ssl,
        timeout=max(30.0, float(cfg.nexus_timeout)),
    )
    try:
        resp = client.reimport_generic_findings(
            build_generic_report(findings),
            product_name=product,
            engagement_name=engagement,
            product_type_name=product_type,
            test_title=test_title,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("DefectDojo push failed: %s", exc)
        return DefectDojoPushResult(findings=len(findings), error=str(exc))

    test_id = _maybe_int(resp.get("test"))
    engagement_id = _maybe_int(resp.get("engagement"))
    logger.info(
        "DefectDojo: pushed %d finding(s) repo=%s product=%s engagement=%s "
        "test_id=%s",
        len(findings),
        summary.repository,
        product,
        engagement,
        test_id,
    )
    return DefectDojoPushResult(
        findings=len(findings),
        status_code=201,
        test_id=test_id,
        engagement_id=engagement_id,
    )


def _maybe_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
