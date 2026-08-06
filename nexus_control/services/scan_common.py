"""Общие хелперы для сканеров уязвимостей (Grype / Trivy)."""

from __future__ import annotations

from pathlib import Path

from nexus_control.models import (
    ScanResult,
    ScanStatus,
    Severity,
    SeverityCounts,
    Verdict,
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

KNOWN_SCANNERS = ("grype", "trivy")

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
    """Сводный результат: PASS только если все сканеры PASS."""
    if not scans:
        return ScanResult(
            status=ScanStatus.SKIPPED,
            verdict=Verdict.SKIPPED,
            scanner="aggregate",
        )

    verdicts = [s.verdict for s in scans.values()]
    if any(v == Verdict.ERROR for v in verdicts):
        verdict = Verdict.ERROR
        status = ScanStatus.ERROR
    elif any(v == Verdict.FAIL for v in verdicts):
        verdict = Verdict.FAIL
        status = ScanStatus.SUCCESS
    elif all(v == Verdict.PASS for v in verdicts):
        verdict = Verdict.PASS
        status = ScanStatus.SUCCESS
    elif all(v == Verdict.SKIPPED for v in verdicts):
        verdict = Verdict.SKIPPED
        status = ScanStatus.SKIPPED
    elif any(v == Verdict.PENDING for v in verdicts):
        verdict = Verdict.PENDING
        status = ScanStatus.PENDING
    else:
        verdict = Verdict.FAIL
        status = ScanStatus.SUCCESS

    counts = SeverityCounts()
    vulns = []
    errors: list[str] = []
    for name, sc in scans.items():
        for v in sc.vulnerabilities:
            vulns.append(v)
            counts.increment(v.severity)
        if sc.error:
            errors.append(f"{name}: {sc.error}")

    versions = {
        name: sc.scanner_version or sc.grype_version
        for name, sc in scans.items()
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
        raise ValueError("At least one scanner must be enabled (grype and/or trivy)")
    return seen
