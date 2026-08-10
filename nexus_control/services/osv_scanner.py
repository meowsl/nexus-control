"""Сканирование уязвимостей osv-scanner с локальным бинарником или запасным Docker."""

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
    Severity,
    SeverityCounts,
    Verdict,
    Vulnerability,
)
from nexus_control.services.scan_common import format_text_report, normalize_severity
from nexus_control.utils.fs import ensure_parent_dir, write_json
from nexus_control.utils.safe_path import report_paths
from nexus_control.utils.subprocess_runner import CommandError, CommandResult, run_command, which

logger = logging.getLogger(__name__)

SCANNER_NAME = "osv"
EXPERIMENTAL_PLUGINS = "directory,artifact"

# osv-scanner exit≠0 без JSON, когда в цели нет извлекаемых пакетов
# (пустой/битый jar, metadata-only и т.п.). Grype/Trivy в таких случаях
# обычно отдают пустой отчёт → PASS; выравниваем поведение.
_OSV_SOFT_EMPTY_MARKERS = (
    "no package sources found",
    "no package sources were found",
)


class OsvError(RuntimeError):
    pass


class OsvScanner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._mode: str | None = None  # "local" | "docker"
        self._osv_path: str | None = None
        self._version: str | None = None

    def resolve_backend(self) -> str:
        """Определить способ вызова osv-scanner. Выбрасывает OsvError, если невозможно."""
        if self._mode:
            return self._mode
        local = which(self.settings.osv_binary)
        use_docker = self.settings.osv_use_docker
        if local and use_docker != "true":
            self._mode = "local"
            self._osv_path = local
            return self._mode
        if use_docker in {"auto", "true"}:
            docker = which(self.settings.docker_binary)
            if docker:
                self._mode = "docker"
                self._osv_path = docker
                return self._mode
            if use_docker == "true":
                raise OsvError(
                    "OSV_USE_DOCKER=true but docker binary was not found in PATH."
                )
        if local:
            self._mode = "local"
            self._osv_path = local
            return self._mode
        raise OsvError(
            "osv-scanner is not installed and docker fallback is unavailable. "
            "Install osv-scanner (https://github.com/google/osv-scanner) or docker, "
            "or set OSV_USE_DOCKER=true with a working docker daemon."
        )

    def get_version(self) -> str | None:
        if self._version is not None:
            return self._version
        try:
            self.resolve_backend()
            result = self._run(["--version"], timeout=60)
            text = (result.stdout or result.stderr).strip()
            match = re.search(
                r"(?:osv-scanner\s+)?(?:version\s+)?v?(\d+\.\d+\.\d+\S*)",
                text,
                re.IGNORECASE,
            )
            if match:
                self._version = f"osv-scanner {match.group(1)}"
            else:
                line = text.splitlines()
                self._version = line[0] if line else "unknown"
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not determine osv-scanner version: %s", exc)
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
        except OsvError as exc:
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
        osv_args = _build_osv_args(
            local_path.resolve(),
            scheme,
            list(self.settings.osv_extra_args_list),
        )

        try:
            result = self._run_scan(osv_args, json_path)
        except OsvError as exc:
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

        parsed = parse_osv_json(result.stdout)
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

    def _run_scan(self, osv_args: list[str], json_report_path: Path) -> CommandResult:
        try:
            return self._run(osv_args, timeout=1800)
        except CommandError as exc:
            # osv-scanner возвращает 1 при найденных vulns; JSON в stdout валиден.
            if exc.result and exc.result.stdout.strip().startswith("{"):
                return exc.result
            stderr = (exc.result.stderr if exc.result else "") or str(exc)
            stdout = (exc.result.stdout if exc.result else "") or ""
            if is_osv_soft_empty(stderr, stdout):
                # Как Grype/Trivy на seed/empty jar: нечего сканировать → PASS.
                logger.info(
                    "osv-scanner reported no package sources; treating as empty PASS"
                )
                return CommandResult(
                    returncode=0,
                    stdout='{"results": []}\n',
                    stderr=stderr,
                    argv=list(exc.result.argv) if exc.result else list(osv_args),
                )
            try:
                json_report_path.write_text(
                    json.dumps({"error": stderr}, indent=2),
                    encoding="utf-8",
                )
            except OSError:
                pass
            raise OsvError(f"osv-scanner failed: {stderr.strip()}") from exc

    def _run(self, osv_args: list[str], timeout: float) -> CommandResult:
        mode = self.resolve_backend()
        if mode == "local":
            assert self._osv_path
            return run_command(
                [self._osv_path, *osv_args],
                timeout=timeout,
                check=True,
            )

        assert self._osv_path  # docker binary
        download_root = self.settings.download_root.resolve()
        reports_root = self.settings.reports_root.resolve()
        argv = [
            self._osv_path,
            "run",
            "--rm",
            "-v",
            f"{download_root}:{download_root}:ro",
            "-v",
            f"{reports_root}:{reports_root}:rw",
            self.settings.osv_docker_image,
            *osv_args,
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


def _build_osv_args(local_path: Path, scheme: str, extra: list[str]) -> list[str]:
    """Собрать argv osv-scanner без имени бинарника."""
    plugins = [
        "--format=json",
        f"--experimental-plugins={EXPERIMENTAL_PLUGINS}",
        *extra,
    ]
    if scheme in {"docker-archive", "oci-archive"}:
        return ["scan", "image", "--archive", str(local_path), *plugins]
    return ["scan", "source", str(local_path), *plugins]


def is_osv_soft_empty(stderr: str, stdout: str = "") -> bool:
    """True, если osv-scanner не нашёл источников пакетов (мягкий пустой скан)."""
    text = f"{stderr}\n{stdout}".lower()
    return any(marker in text for marker in _OSV_SOFT_EMPTY_MARKERS)


def parse_osv_json(payload: str | dict[str, Any]) -> ScanResult:
    """Парсер JSON osv-scanner (results[].packages[].vulnerabilities)."""
    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error="Empty osv-scanner JSON output",
            )
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error=f"Failed to parse osv-scanner JSON: {exc}",
            )
    else:
        data = payload

    if not isinstance(data, dict):
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            error="osv-scanner JSON root must be an object",
            raw={"raw": data},
        )

    if "error" in data and "results" not in data:
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            error=str(data.get("error")),
            raw=data,
        )

    results = data.get("results")
    if results is None:
        # Пустой успешный отчёт без results — считать PASS.
        return ScanResult(
            status=ScanStatus.SUCCESS,
            verdict=Verdict.PASS,
            vulnerabilities=[],
            counts=SeverityCounts(),
            scanner=SCANNER_NAME,
            raw=data,
        )
    if not isinstance(results, list):
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            error="osv-scanner results must be a list",
            raw=data,
        )

    vulns: list[Vulnerability] = []
    for block in results:
        if not isinstance(block, dict):
            continue
        packages = block.get("packages") or []
        if not isinstance(packages, list):
            continue
        for pkg_block in packages:
            if not isinstance(pkg_block, dict):
                continue
            vulns.extend(_vulns_from_package(pkg_block))

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


def _vulns_from_package(pkg_block: dict[str, Any]) -> list[Vulnerability]:
    pkg = pkg_block.get("package") if isinstance(pkg_block.get("package"), dict) else {}
    pkg_name = str(pkg.get("name") or "")
    pkg_version = str(pkg.get("version") or "")

    raw_vulns = pkg_block.get("vulnerabilities") or []
    if not isinstance(raw_vulns, list):
        raw_vulns = []
    by_id: dict[str, dict[str, Any]] = {}
    for item in raw_vulns:
        if isinstance(item, dict) and item.get("id"):
            by_id[str(item["id"])] = item

    groups = pkg_block.get("groups") or []
    selected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    if isinstance(groups, list) and groups:
        for group in groups:
            if not isinstance(group, dict):
                continue
            ids = group.get("ids") or []
            if not isinstance(ids, list) or not ids:
                continue
            candidates = [by_id[str(i)] for i in ids if str(i) in by_id]
            if not candidates:
                # Группа без полных объектов — синтезировать из первого id.
                chosen = {"id": str(ids[0]), "aliases": [str(x) for x in ids[1:]]}
            else:
                chosen = _prefer_cve_vuln(candidates)
            vid = str(chosen.get("id") or "")
            if vid and vid not in seen_ids:
                seen_ids.add(vid)
                selected.append(chosen)
    else:
        # Без groups: дедуп по id + aliases.
        for item in raw_vulns:
            if not isinstance(item, dict):
                continue
            key_ids = _alias_key(item)
            if key_ids & seen_ids:
                continue
            seen_ids |= key_ids
            selected.append(item)

    out: list[Vulnerability] = []
    for item in selected:
        vuln = _from_osv_vuln(item, pkg_name=pkg_name, pkg_version=pkg_version)
        if vuln is not None:
            out.append(vuln)
    return out


def _prefer_cve_vuln(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """Предпочесть запись с CVE id (или CVE в aliases)."""
    for item in candidates:
        vid = str(item.get("id") or "")
        if vid.upper().startswith("CVE-"):
            return item
    for item in candidates:
        aliases = item.get("aliases") or []
        if isinstance(aliases, list) and any(
            str(a).upper().startswith("CVE-") for a in aliases
        ):
            # Переписать id на CVE для отображения.
            cve = next(str(a) for a in aliases if str(a).upper().startswith("CVE-"))
            merged = dict(item)
            merged["id"] = cve
            return merged
    return candidates[0]


def _alias_key(item: dict[str, Any]) -> set[str]:
    ids = {str(item["id"])} if item.get("id") else set()
    aliases = item.get("aliases") or []
    if isinstance(aliases, list):
        ids.update(str(a) for a in aliases if a)
    return ids


def _from_osv_vuln(
    item: dict[str, Any],
    *,
    pkg_name: str,
    pkg_version: str,
) -> Vulnerability | None:
    if not isinstance(item, dict):
        return None
    vid = str(item.get("id") or "").strip()
    if not vid:
        return None
    # Предпочесть CVE из aliases, если основной id — GHSA/OSV.
    if not vid.upper().startswith("CVE-"):
        aliases = item.get("aliases") or []
        if isinstance(aliases, list):
            for alias in aliases:
                text = str(alias)
                if text.upper().startswith("CVE-"):
                    vid = text
                    break

    description = None
    if item.get("summary"):
        description = str(item["summary"])
    elif item.get("details"):
        description = str(item["details"])

    return Vulnerability(
        id=vid,
        severity=_osv_severity(item),
        package_name=pkg_name,
        package_version=pkg_version,
        fix_version=_osv_fix_version(item, pkg_name=pkg_name),
        description=description,
    )


def _osv_severity(item: dict[str, Any]) -> Severity:
    db = item.get("database_specific")
    if isinstance(db, dict) and db.get("severity"):
        return normalize_severity(str(db["severity"]))

    severity = item.get("severity")
    if isinstance(severity, list):
        for entry in severity:
            if not isinstance(entry, dict):
                continue
            score = str(entry.get("score") or "")
            # CVSS vector или числовой score
            num = _cvss_numeric(score)
            if num is not None:
                return _severity_from_cvss(num)
            # Иногда score уже текстовый
            mapped = normalize_severity(score)
            if mapped != Severity.UNKNOWN:
                return mapped

    ecosys = item.get("ecosystem_specific")
    if isinstance(ecosys, dict) and ecosys.get("severity"):
        return normalize_severity(str(ecosys["severity"]))

    return Severity.UNKNOWN


def _cvss_numeric(score: str) -> float | None:
    text = score.strip()
    try:
        return float(text)
    except ValueError:
        pass
    # CVSS:3.1/AV:N/... — вытащить числовой base score, если есть отдельно
    match = re.search(r"\b(\d+\.\d+)\b", text)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def _severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN


def _osv_fix_version(item: dict[str, Any], *, pkg_name: str) -> str | None:
    affected = item.get("affected")
    if not isinstance(affected, list):
        return None
    for block in affected:
        if not isinstance(block, dict):
            continue
        pkg = block.get("package") if isinstance(block.get("package"), dict) else {}
        name = str(pkg.get("name") or "")
        if pkg_name and name and name != pkg_name:
            continue
        ranges = block.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events") or []
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and event.get("fixed"):
                    return str(event["fixed"])
    return None


def _write_text(path: Path, text: str) -> None:
    ensure_parent_dir(path)
    path.write_text(text, encoding="utf-8")
