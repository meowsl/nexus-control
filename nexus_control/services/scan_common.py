"""Общие хелперы для сканеров уязвимостей (Grype / Trivy / OSV)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from nexus_control.models import (
    ScanResult,
    ScanStatus,
    Severity,
    SeverityCounts,
    Verdict,
    Vulnerability,
)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.NEGLIGIBLE,
    "unknown": Severity.UNKNOWN,
    "": Severity.UNKNOWN,
}

# Fail if finding severity is this level or higher. Default matches historical
# "any finding → FAIL" (Unknown is always blocking).
SEVERITY_THRESHOLDS = ("critical", "high", "medium", "low", "negligible")
DEFAULT_SEVERITY_THRESHOLD = "negligible"

_SEVERITY_RANK = {
    Severity.UNKNOWN: 0,
    Severity.NEGLIGIBLE: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_THRESHOLD_RANK = {
    "negligible": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

KNOWN_SCANNERS = ("grype", "trivy", "osv")

# Checksum / signature sidecars — CVE-сканеры не запускаем; в verified копируем
# только вместе с PASS-артефактом (см. pipeline / verifier).
SCAN_IGNORE_SUFFIXES = (".md5", ".sha1", ".sha256", ".sha512", ".asc")


def is_scan_ignored_path(asset_path: str) -> bool:
    """True для checksum/signature sidecar'ов (``.md5``, ``.sha1``, …, ``.asc``)."""
    name = Path(str(asset_path).replace("\\", "/")).name.lower()
    return any(name.endswith(suffix) for suffix in SCAN_IGNORE_SUFFIXES)


def main_asset_path_for_sidecar(asset_path: str) -> str | None:
    """Если ``asset_path`` — sidecar, вернуть путь основного файла; иначе ``None``."""
    text = str(asset_path).replace("\\", "/")
    lower = text.lower()
    for suffix in SCAN_IGNORE_SUFFIXES:
        if lower.endswith(suffix):
            return text[: -len(suffix)]
    return None


def iter_local_companion_sidecars(local_path: Path) -> list[Path]:
    """Локальные ``{name}.md5`` / ``.sha1`` / … рядом с артефактом."""
    found: list[Path] = []
    for suffix in SCAN_IGNORE_SUFFIXES:
        candidate = local_path.parent / f"{local_path.name}{suffix}"
        if candidate.is_file():
            found.append(candidate)
    return found


def normalize_severity(value: str | None) -> Severity:
    if not value:
        return Severity.UNKNOWN
    return SEVERITY_MAP.get(str(value).strip().lower(), Severity.UNKNOWN)


def parse_severity_threshold(value: object | None) -> str:
    """Normalize ``critical|high|medium|low|negligible`` (case-insensitive)."""
    text = str(value if value is not None else DEFAULT_SEVERITY_THRESHOLD).strip().lower()
    if not text:
        return DEFAULT_SEVERITY_THRESHOLD
    if text not in _THRESHOLD_RANK:
        allowed = ", ".join(SEVERITY_THRESHOLDS)
        raise ValueError(f"severity must be one of: {allowed}")
    return text


def is_blocking_severity(severity: Severity, threshold: str) -> bool:
    """True if this finding should fail verify under ``threshold``.

    ``Unknown`` is always blocking (conservative: do not silently PASS).
    """
    if severity == Severity.UNKNOWN:
        return True
    floor = _THRESHOLD_RANK.get(threshold, _THRESHOLD_RANK[DEFAULT_SEVERITY_THRESHOLD])
    return _SEVERITY_RANK.get(severity, 0) >= floor


def verdict_from_vulnerabilities(
    vulns: Iterable[Vulnerability],
    threshold: str | None = None,
) -> Verdict:
    """PASS unless a finding meets the fail-on-severity threshold."""
    floor = parse_severity_threshold(threshold)
    for vuln in vulns:
        if is_blocking_severity(vuln.severity, floor):
            return Verdict.FAIL
    return Verdict.PASS


def format_text_report(
    result: ScanResult,
    asset_path: str,
    local_path: Path,
    *,
    scanner: str | None = None,
) -> str:
    name = scanner or result.scanner or "scanner"
    lines = [
        f"Scanner: {name}",
        f"Asset: {asset_path}",
        f"Local path: {local_path}",
        f"Verdict: {result.verdict.value}",
        f"Vulnerabilities: {result.vulnerability_count}",
        (
            f"Severity: critical={result.counts.critical} high={result.counts.high} "
            f"medium={result.counts.medium} low={result.counts.low} "
            f"negligible={result.counts.negligible} unknown={result.counts.unknown}"
        ),
        "",
    ]
    if result.error:
        lines.append(f"Error: {result.error}")
    for vuln in result.vulnerabilities[:50]:
        lines.append(
            f"- [{vuln.severity.value}] {vuln.id} "
            f"{vuln.package_name}@{vuln.package_version}"
            + (f" fix:{vuln.fix_version}" if vuln.fix_version else "")
        )
    if len(result.vulnerabilities) > 50:
        lines.append(f"... and {len(result.vulnerabilities) - 50} more")
    return "\n".join(lines) + "\n"


def aggregate_scan_results(scans: dict[str, ScanResult]) -> ScanResult:
    """Сводный результат: PASS только если все *участвующие* сканеры PASS.

    ``SKIPPED`` не участвует в вердикте (например Grype/Trivy на NuGet).
    """
    if not scans:
        return ScanResult(
            status=ScanStatus.SKIPPED,
            verdict=Verdict.SKIPPED,
            scanner="aggregate",
        )

    active = {
        name: sc
        for name, sc in scans.items()
        if sc.verdict != Verdict.SKIPPED
    }
    if not active:
        return ScanResult(
            status=ScanStatus.SKIPPED,
            verdict=Verdict.SKIPPED,
            scanner="aggregate",
            raw={"scanners": list(scans)},
        )

    verdicts = [s.verdict for s in active.values()]
    if any(v == Verdict.ERROR for v in verdicts):
        verdict = Verdict.ERROR
        status = ScanStatus.ERROR
    elif any(v == Verdict.FAIL for v in verdicts):
        verdict = Verdict.FAIL
        status = ScanStatus.SUCCESS
    elif all(v == Verdict.PASS for v in verdicts):
        verdict = Verdict.PASS
        status = ScanStatus.SUCCESS
    elif any(v == Verdict.PENDING for v in verdicts):
        verdict = Verdict.PENDING
        status = ScanStatus.PENDING
    else:
        verdict = Verdict.FAIL
        status = ScanStatus.SUCCESS

    counts = SeverityCounts()
    vulns = []
    errors: list[str] = []
    for name, sc in active.items():
        for v in sc.vulnerabilities:
            vulns.append(v)
            counts.increment(v.severity)
        if sc.error:
            errors.append(f"{name}: {sc.error}")

    versions = {
        name: sc.scanner_version or sc.grype_version
        for name, sc in active.items()
        if sc.scanner_version or sc.grype_version
    }
    return ScanResult(
        status=status,
        verdict=verdict,
        vulnerabilities=vulns,
        counts=counts,
        scanner="aggregate",
        scanner_version=", ".join(f"{k}={v}" for k, v in versions.items()) or None,
        error="; ".join(errors) if errors else None,
        raw={"scanners": list(scans)},
    )


def parse_scanner_names(value: str) -> list[str]:
    """Разобрать ``grype,trivy`` → упорядоченный список известных сканеров."""
    seen: list[str] = []
    for part in str(value or "").split(","):
        name = part.strip().lower()
        if not name:
            continue
        if name not in KNOWN_SCANNERS:
            raise ValueError(
                f"Unknown scanner {name!r}; expected one of: {', '.join(KNOWN_SCANNERS)}"
            )
        if name not in seen:
            seen.append(name)
    if not seen:
        raise ValueError(
            "At least one scanner must be enabled (grype, trivy, and/or osv)"
        )
    return seen
