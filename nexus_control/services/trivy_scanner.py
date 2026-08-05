"""Сканирование уязвимостей Trivy с локальным бинарником или запасным Docker."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from nexus_control.config import Settings
from nexus_control.models import (
    ScanResult,
    ScanStatus,
    SeverityCounts,
    Verdict,
    Vulnerability,
)
from nexus_control.services.scan_common import format_text_report, normalize_severity
from nexus_control.utils.fs import ensure_parent_dir, write_json
from nexus_control.utils.safe_path import report_paths
from nexus_control.utils.subprocess_runner import CommandError, CommandResult, run_command, which

logger = logging.getLogger(__name__)

SCANNER_NAME = "trivy"


class TrivyError(RuntimeError):
    pass


class TrivyScanner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._mode: str | None = None  # "local" | "docker"
        self._trivy_path: str | None = None
        self._version: str | None = None

    def resolve_backend(self) -> str:
        """Определить способ вызова trivy. Выбрасывает TrivyError, если невозможно."""
        if self._mode:
            return self._mode
        local = which(self.settings.trivy_binary)
        use_docker = self.settings.trivy_use_docker
        if local and use_docker != "true":
            self._mode = "local"
            self._trivy_path = local
            return self._mode
        if use_docker in {"auto", "true"}:
            docker = which(self.settings.docker_binary)
            if docker:
                self._mode = "docker"
                self._trivy_path = docker
                return self._mode
            if use_docker == "true":
                raise TrivyError(
                    "TRIVY_USE_DOCKER=true but docker binary was not found in PATH."
                )
        if local:
            self._mode = "local"
            self._trivy_path = local
            return self._mode
        raise TrivyError(
            "trivy is not installed and docker fallback is unavailable. "
            "Install trivy (https://github.com/aquasecurity/trivy) or docker, "
            "or set TRIVY_USE_DOCKER=true with a working docker daemon."
        )

    def get_version(self) -> str | None:
        if self._version is not None:
            return self._version
        try:
            self.resolve_backend()
            result = self._run(["--version"], timeout=60)
            text = (result.stdout or result.stderr).strip()
            match = re.search(r"Version:\s*(\S+)", text)
            if match:
                self._version = f"trivy {match.group(1)}"
            else:
                line = text.splitlines()
                self._version = line[0] if line else "unknown"
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not determine trivy version: %s", exc)
            self._version = None
        return self._version

    def scan_path(
        self,
        *,
        repository: str,
        asset_path: str,
        local_path: Path,
        target_scheme: str | None = None,
    ) -> ScanResult:
        """Сканировать локальный файл/каталог/архив и сохранить JSON + TXT отчёты."""
        try:
            self.resolve_backend()
        except TrivyError as exc:
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error=str(exc),
            )

        if not local_path.exists():
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error=f"Scan target does not exist: {local_path}",
            )

        scheme = target_scheme or _infer_scheme(local_path)
        json_path, txt_path = report_paths(
            self.settings.reports_root,
            repository,
            asset_path,
            scanner=SCANNER_NAME,
        )
        ensure_parent_dir(json_path)
        version = self.get_version()
        trivy_args = _build_trivy_args(
            local_path.resolve(),
            scheme,
            list(self.settings.trivy_extra_args_list),
        )

        try:
            result = self._run_scan(trivy_args, json_path)
        except TrivyError as exc:
            _write_text(txt_path, f"SCAN_ERROR\n{exc}\n")
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                json_report_path=json_path if json_path.exists() else None,
                text_report_path=txt_path,
                error=str(exc),
                scanner_version=version,
            )

        parsed = parse_trivy_json(result.stdout)
        try:
            raw = json.loads(result.stdout) if result.stdout.strip() else parsed.raw
        except json.JSONDecodeError:
            raw = parsed.raw
        if raw is not None:
            write_json(json_path, raw)
        else:
            json_path.write_text(result.stdout, encoding="utf-8")

        _write_text(
            txt_path,
            format_text_report(parsed, asset_path, local_path, scanner=SCANNER_NAME),
        )
        parsed.json_report_path = json_path
        parsed.text_report_path = txt_path
        parsed.scanner = SCANNER_NAME
        parsed.scanner_version = version
        return parsed

    def _run_scan(self, trivy_args: list[str], json_report_path: Path) -> CommandResult:
        try:
            return self._run(trivy_args, timeout=1800)
        except CommandError as exc:
            # trivy может вернуть ненулевой код при --exit-code; JSON в stdout всё равно валиден.
            if exc.result and exc.result.stdout.strip().startswith("{"):
                return exc.result
            stderr = (exc.result.stderr if exc.result else "") or str(exc)
            try:
                json_report_path.write_text(
                    json.dumps({"error": stderr}, indent=2),
                    encoding="utf-8",
                )
            except OSError:
                pass
            raise TrivyError(f"trivy failed: {stderr.strip()}") from exc

    def _run(self, trivy_args: list[str], timeout: float) -> CommandResult:
        mode = self.resolve_backend()
        if mode == "local":
            assert self._trivy_path
            return run_command(
                [self._trivy_path, *trivy_args],
                timeout=timeout,
                check=True,
            )

        assert self._trivy_path  # docker binary
        download_root = self.settings.download_root.resolve()
        reports_root = self.settings.reports_root.resolve()
        argv = [
            self._trivy_path,
            "run",
            "--rm",
            "-v",
            f"{download_root}:{download_root}:ro",
            "-v",
            f"{reports_root}:{reports_root}:rw",
            "-e",
            "TRIVY_CACHE_DIR=/tmp/trivy-cache",
            self.settings.trivy_docker_image,
            *trivy_args,
        ]
        return run_command(argv, timeout=timeout, check=True)


def _infer_scheme(path: Path) -> str:
    if path.is_dir():
        return "dir"
    name = path.name.lower()
    if name.endswith(".oci") or name.endswith(".oci.tar"):
        return "oci-archive"
    if name.endswith(".tar") and not name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return "docker-archive"
    return "file"


def _build_trivy_args(local_path: Path, scheme: str, extra: list[str]) -> list[str]:
    """Собрать argv trivy без имени бинарника."""
    common = ["--format", "json", "--quiet", *extra]
    if scheme in {"docker-archive", "oci-archive"}:
        return ["image", "--input", str(local_path), *common]
    return ["fs", str(local_path), *common]


def parse_trivy_json(payload: str | dict[str, Any]) -> ScanResult:
    """Парсер JSON Trivy (Results[].Vulnerabilities)."""
    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error="Empty trivy JSON output",
            )
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error=f"Failed to parse trivy JSON: {exc}",
            )
    else:
        data = payload

    if not isinstance(data, dict):
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            error="Trivy JSON root must be an object",
            raw={"raw": data},
        )

    if "error" in data and "Results" not in data:
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            error=str(data.get("error")),
            raw=data,
        )

    results = data.get("Results")
    if results is None:
        # Пустой успешный отчёт без Results — считать PASS.
        if any(k in data for k in ("SchemaVersion", "ArtifactName", "ArtifactType")):
            results = []
        else:
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error="Unrecognized trivy JSON structure (no Results)",
                raw=data,
            )
    if not isinstance(results, list):
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            error="Trivy Results must be a list",
            raw=data,
        )

    vulns: list[Vulnerability] = []
    for block in results:
        if not isinstance(block, dict):
            continue
        items = block.get("Vulnerabilities") or []
        if not isinstance(items, list):
            continue
        for item in items:
            vuln = _from_trivy_vuln(item)
            if vuln is not None:
                vulns.append(vuln)

    counts = SeverityCounts()
    for v in vulns:
        counts.increment(v.severity)

    verdict = Verdict.PASS if counts.total == 0 else Verdict.FAIL
    return ScanResult(
        status=ScanStatus.SUCCESS,
        verdict=verdict,
        vulnerabilities=vulns,
        counts=counts,
        scanner=SCANNER_NAME,
        raw=data,
    )


def _from_trivy_vuln(item: Any) -> Vulnerability | None:
    if not isinstance(item, dict):
        return None
    fix = item.get("FixedVersion")
    return Vulnerability(
        id=str(item.get("VulnerabilityID") or item.get("PkgID") or "UNKNOWN"),
        severity=normalize_severity(item.get("Severity")),
        package_name=str(item.get("PkgName") or ""),
        package_version=str(item.get("InstalledVersion") or ""),
        fix_version=str(fix) if fix else None,
        description=(str(item["Description"]) if item.get("Description") else None),
    )


def _write_text(path: Path, text: str) -> None:
    ensure_parent_dir(path)
    path.write_text(text, encoding="utf-8")
