"""Сканирование уязвимостей Grype с локальным бинарником или запасным Docker."""

from __future__ import annotations

import json
import logging
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
from nexus_control.services.scan_common import (  # noqa: F401 — re-export for tests
    format_text_report,
    normalize_severity,
    verdict_from_vulnerabilities,
)
from nexus_control.utils.fs import ensure_parent_dir, write_json
from nexus_control.utils.safe_path import report_paths
from nexus_control.utils.subprocess_runner import CommandError, CommandResult, run_command, which

logger = logging.getLogger(__name__)

SCANNER_NAME = "grype"


class GrypeError(RuntimeError):
    pass


class GrypeScanner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._mode: str | None = None  # "local" | "docker"
        self._grype_path: str | None = None
        self._version: str | None = None

    def resolve_backend(self) -> str:
        """Определить способ вызова grype. Выбрасывает GrypeError, если невозможно."""
        if self._mode:
            return self._mode
        local = which(self.settings.grype_binary)
        use_docker = self.settings.grype_use_docker
        if local and use_docker != "true":
            self._mode = "local"
            self._grype_path = local
            return self._mode
        if use_docker in {"auto", "true"}:
            docker = which(self.settings.docker_binary)
            if docker:
                self._mode = "docker"
                self._grype_path = docker
                return self._mode
            if use_docker == "true":
                raise GrypeError(
                    "GRYPE_USE_DOCKER=true but docker binary was not found in PATH."
                )
        if local:
            self._mode = "local"
            self._grype_path = local
            return self._mode
        raise GrypeError(
            "grype is not installed and docker fallback is unavailable. "
            "Install grype (https://github.com/anchore/grype) or docker, "
            "or set GRYPE_USE_DOCKER=true with a working docker daemon."
        )

    def get_version(self) -> str | None:
        if self._version is not None:
            return self._version
        try:
            self.resolve_backend()
            result = self._run(["version"], timeout=60)
            # grype version выводит в stdout; docker image тоже может
            line = (result.stdout or result.stderr).strip().splitlines()
            self._version = line[0] if line else "unknown"
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not determine grype version: %s", exc)
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
        """Сканировать локальный файл/каталог/архив и сохранить JSON + TXT отчёты.

        Примеры ``target_scheme``: ``file``, ``dir``, ``docker-archive``, ``oci-archive``.
        Если не указан, выводится из пути (``.tar`` -> docker-archive, каталог -> dir, иначе file).
        """
        try:
            self.resolve_backend()
        except GrypeError as exc:
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

        from nexus_control.services.npm_identity import (
            NpmIdentityError,
            is_npm_package_tarball,
            npm_staging_dir,
            prepare_npm_identity_staging,
        )

        scan_path = local_path
        scheme = target_scheme or _infer_scheme(local_path)
        if is_npm_package_tarball(local_path) and (
            target_scheme is None or scheme == "file"
        ):
            try:
                staging = npm_staging_dir(
                    self.settings.reports_root, repository, asset_path
                )
                identity, staging = prepare_npm_identity_staging(local_path, staging)
                scan_path = staging
                scheme = "dir"
                logger.info(
                    "Grype npm identity scan %s → %s@%s",
                    asset_path,
                    identity.name,
                    identity.version,
                )
            except (NpmIdentityError, OSError, ValueError) as exc:
                logger.warning(
                    "npm identity staging failed for %s: %s — scanning tarball as-is",
                    asset_path,
                    exc,
                )

        target = f"{scheme}:{scan_path.resolve()}"
        json_path, txt_path = report_paths(
            self.settings.reports_root,
            repository,
            asset_path,
            scanner=SCANNER_NAME,
        )
        ensure_parent_dir(json_path)
        version = self.get_version()

        try:
            result = self._run_scan(target, json_path)
        except GrypeError as exc:
            _write_text(txt_path, f"SCAN_ERROR\n{exc}\n")
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                json_report_path=json_path if json_path.exists() else None,
                text_report_path=txt_path,
                error=str(exc),
                scanner_version=version,
                grype_version=version,
            )

        parsed = parse_grype_json(
            result.stdout, severity=self.settings.severity
        )
        # Предпочитать JSON из stdout; также сохранить его.
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
        parsed.grype_version = version
        return parsed

    def _run_scan(self, target: str, json_report_path: Path) -> CommandResult:
        # Всегда запрашивать JSON в stdout для разбора.
        extra = list(self.settings.grype_extra_args_list)
        # Избежать конфликта -o, если пользователь уже задал его.
        argv_tail = [target, "-o", "json", *extra]
        try:
            return self._run(argv_tail, timeout=1800)
        except CommandError as exc:
            # grype может вернуть ненулевой код при CVE, если задан --fail-on.
            # Если stdout всё ещё JSON — считать разбор успешным.
            if exc.result and exc.result.stdout.strip().startswith("{"):
                return exc.result
            stderr = (exc.result.stderr if exc.result else "") or str(exc)
            # Всё равно сохранить stderr для отладки
            try:
                json_report_path.write_text(
                    json.dumps({"error": stderr}, indent=2),
                    encoding="utf-8",
                )
            except OSError:
                pass
            raise GrypeError(f"grype failed: {stderr.strip()}") from exc

    def _run(self, grype_args: list[str], timeout: float) -> CommandResult:
        mode = self.resolve_backend()
        if mode == "local":
            assert self._grype_path
            return run_command(
                [self._grype_path, *grype_args],
                timeout=timeout,
                check=True,
            )

        assert self._grype_path  # docker binary
        download_root = self.settings.download_root.resolve()
        reports_root = self.settings.reports_root.resolve()
        # Монтировать только нужные корни; никогда весь $HOME.
        argv = [
            self._grype_path,
            "run",
            "--rm",
            "-v",
            f"{download_root}:{download_root}:ro",
            "-v",
            f"{reports_root}:{reports_root}:rw",
            "-e",
            "GRYPE_DB_CACHE_DIR=/tmp/grype-cache",
            self.settings.grype_docker_image,
            *grype_args,
        ]
        # Переписать file targets под download_root — пути идентичны
        # внутри контейнера, т.к. bind-mount тот же абсолютный путь.
        return run_command(argv, timeout=timeout, check=True)


def _infer_scheme(path: Path) -> str:
    """Выбрать схему цели Grype по типу локального пути.

    Важно: npm-пакеты приходят как ``.tgz`` / ``.tar.gz`` — это *не* docker save.
    ``docker-archive`` оставляем только для «голого» ``.tar`` (типичный ``docker save`` /
    skopeo copy). Иначе grype падает с ``invalid tar header`` на npm tarball.
    """
    if path.is_dir():
        return "dir"
    name = path.name.lower()
    if name.endswith(".oci") or name.endswith(".oci.tar"):
        return "oci-archive"
    # Только *.tar без .gz — кандидат в docker image archive.
    if name.endswith(".tar") and not name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return "docker-archive"
    return "file"


def parse_grype_json(
    payload: str | dict[str, Any],
    *,
    severity: str | None = None,
) -> ScanResult:
    """Совместимый парсер JSON Grype (matches и/или vulnerabilities)."""
    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error="Empty grype JSON output",
            )
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return ScanResult(
                status=ScanStatus.ERROR,
                verdict=Verdict.ERROR,
                scanner=SCANNER_NAME,
                error=f"Failed to parse grype JSON: {exc}",
            )
    else:
        data = payload

    if not isinstance(data, dict):
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            error="Grype JSON root must be an object",
            raw={"raw": data},
        )

    if "error" in data and not data.get("matches") and not data.get("vulnerabilities"):
        return ScanResult(
            status=ScanStatus.ERROR,
            verdict=Verdict.ERROR,
            scanner=SCANNER_NAME,
            error=str(data.get("error")),
            raw=data,
        )

    items: list[Any]
    if "matches" in data and isinstance(data["matches"], list):
        items = data["matches"]
        vulns = [_from_match(m) for m in items]
    elif "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
        items = data["vulnerabilities"]
        vulns = [_from_vulnerability(v) for v in items]
    else:
        # Явно пустая / неизвестная структура без списков → считать чистой
        # только когда matches есть и пуст, или оба отсутствуют с descriptor.
        if "matches" in data and data["matches"] is None:
            vulns = []
        elif "matches" not in data and "vulnerabilities" not in data:
            # Эвристика: если документ имеет descriptor/source типичный для grype, пусто = PASS
            if any(k in data for k in ("descriptor", "source", "distro")):
                vulns = []
            else:
                return ScanResult(
                    status=ScanStatus.ERROR,
                    verdict=Verdict.ERROR,
                    scanner=SCANNER_NAME,
                    error="Unrecognized grype JSON structure (no matches/vulnerabilities)",
                    raw=data,
                )
        else:
            vulns = []

    vulns = [v for v in vulns if v is not None]
    counts = SeverityCounts()
    for v in vulns:
        counts.increment(v.severity)

    verdict = verdict_from_vulnerabilities(vulns, severity)
    return ScanResult(
        status=ScanStatus.SUCCESS,
        verdict=verdict,
        vulnerabilities=vulns,
        counts=counts,
        scanner=SCANNER_NAME,
        raw=data,
    )


def _from_match(match: Any) -> Vulnerability | None:
    if not isinstance(match, dict):
        return None
    vuln = match.get("vulnerability") or {}
    artifact = match.get("artifact") or {}
    related = match.get("relatedVulnerabilities") or []
    vuln_id = str(vuln.get("id") or (related[0].get("id") if related else "UNKNOWN"))
    severity = normalize_severity(vuln.get("severity"))
    fix = vuln.get("fix") or {}
    versions = fix.get("versions") if isinstance(fix, dict) else None
    fix_version = versions[0] if isinstance(versions, list) and versions else None
    return Vulnerability(
        id=vuln_id,
        severity=severity,
        package_name=str(artifact.get("name") or ""),
        package_version=str(artifact.get("version") or ""),
        fix_version=str(fix_version) if fix_version else None,
        description=(str(vuln["description"]) if vuln.get("description") else None),
    )


def _from_vulnerability(item: Any) -> Vulnerability | None:
    if not isinstance(item, dict):
        return None
    return Vulnerability(
        id=str(item.get("id") or "UNKNOWN"),
        severity=normalize_severity(item.get("severity")),
        package_name=str(item.get("package") or item.get("packageName") or ""),
        package_version=str(item.get("version") or item.get("packageVersion") or ""),
        fix_version=(
            str(item["fix"]) if item.get("fix") else None
        ),
        description=(str(item["description"]) if item.get("description") else None),
    )


def _write_text(path: Path, text: str) -> None:
    ensure_parent_dir(path)
    path.write_text(text, encoding="utf-8")
