"""Доменные модели, общие для клиента Nexus, сервисов и UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class AuthType(str, Enum):
    BASIC = "basic"
    COOKIE = "cookie"
    TOKEN = "token"


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DownloadStatus(str, Enum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    SUCCESS = "success"
    SKIPPED_EXISTING = "skipped_existing"
    NOT_FOUND = "not_found"
    ERROR = "error"


class ScanStatus(str, Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    SUCCESS = "success"
    ERROR = "error"
    SKIPPED = "skipped"


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    PENDING = "PENDING"
    SKIPPED = "SKIPPED"


class AssetKind(str, Enum):
    FILE = "file"
    DIR = "dir"
    IMAGE = "image"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NEGLIGIBLE = "Negligible"
    UNKNOWN = "Unknown"


@dataclass(slots=True)
class Repository:
    name: str
    format: str
    type: str
    url: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def is_docker(self) -> bool:
        return self.format.lower() == "docker"

    @property
    def support_level(self) -> str:
        """Человекочитаемый уровень поддержки для UI артефактов."""
        fmt = self.format.lower()
        if fmt in {
            "maven2",
            "raw",
            "npm",
            "pypi",
            "nuget",
            "rubygems",
            "yum",
            "apt",
            "helm",
            "go",
            "huggingface",
        }:
            return "supported"
        if fmt == "docker":
            return "docker_adapter"
        return "partially_supported"


@dataclass(slots=True)
class NexusAsset:
    """Плоский артефакт, возвращаемый API Nexus ``/assets``."""

    id: str
    path: str
    download_url: str | None
    repository: str
    format: str | None = None
    content_type: str | None = None
    last_modified: str | None = None
    file_size: int | None = None
    checksum: dict[str, str] = field(default_factory=dict)
    uploader: str | None = None
    blob_created: str | None = None

    @property
    def name(self) -> str:
        return Path(self.path).name or self.path


@dataclass(slots=True)
class DockerTag:
    """Логический docker-тег, рассматриваемый как загружаемый/сканируемый артефакт."""

    repository: str
    tag: str
    image_ref: str
    digest: str | None = None

    @property
    def path(self) -> str:
        return f"images/{self.tag}"

    @property
    def name(self) -> str:
        return self.tag


@dataclass(slots=True)
class TreeNode:
    """Узел в дереве путей артефактов."""

    name: str
    path: str
    is_dir: bool
    children: dict[str, TreeNode] = field(default_factory=dict)
    asset: NexusAsset | None = None
    docker_tag: DockerTag | None = None
    child_count: int = 0

    @property
    def kind(self) -> AssetKind:
        if self.docker_tag is not None:
            return AssetKind.IMAGE
        if self.is_dir:
            return AssetKind.DIR
        return AssetKind.FILE


@dataclass(slots=True)
class Vulnerability:
    id: str
    severity: Severity
    package_name: str = ""
    package_version: str = ""
    fix_version: str | None = None
    description: str | None = None


@dataclass(slots=True)
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return (
            self.critical
            + self.high
            + self.medium
            + self.low
            + self.negligible
            + self.unknown
        )

    def increment(self, severity: Severity) -> None:
        mapping = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "high",
            Severity.MEDIUM: "medium",
            Severity.LOW: "low",
            Severity.NEGLIGIBLE: "negligible",
            Severity.UNKNOWN: "unknown",
        }
        attr = mapping.get(severity, "unknown")
        setattr(self, attr, getattr(self, attr) + 1)


@dataclass(slots=True)
class ScanResult:
    status: ScanStatus
    verdict: Verdict
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    counts: SeverityCounts = field(default_factory=SeverityCounts)
    json_report_path: Path | None = None
    text_report_path: Path | None = None
    scanner: str = ""
    scanner_version: str | None = None
    grype_version: str | None = None  # совместимость; дублирует scanner_version для grype
    error: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def vulnerability_count(self) -> int:
        return self.counts.total


@dataclass(slots=True)
class DownloadResult:
    status: DownloadStatus
    local_path: Path | None = None
    metadata_path: Path | None = None
    bytes_written: int = 0
    error: str | None = None
    source: str = "nexus-rest"


@dataclass(slots=True)
class VerifyResult:
    copied: bool = False
    skipped_existing: bool = False
    verified_path: Path | None = None
    error: str | None = None


@dataclass(slots=True)
class AssetPipelineResult:
    """Результат по артефакту для конвейера загрузки / сканирования / проверки."""

    asset_path: str
    kind: AssetKind
    download: DownloadResult
    scans: dict[str, ScanResult] = field(default_factory=dict)
    verify: VerifyResult = field(default_factory=VerifyResult)

    @property
    def scan(self) -> ScanResult:
        """Сводный результат по всем включённым сканерам."""
        from nexus_control.services.scan_common import aggregate_scan_results

        return aggregate_scan_results(self.scans)

    @property
    def verdict(self) -> Verdict:
        return self.scan.verdict


@dataclass(slots=True)
class PipelineSummary:
    repository: str
    results: list[AssetPipelineResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    scanners: list[str] = field(default_factory=list)
    scanner_versions: dict[str, str | None] = field(default_factory=dict)
    cancelled: bool = False

    @property
    def grype_version(self) -> str | None:
        return self.scanner_versions.get("grype")

    @property
    def total_scanned(self) -> int:
        # Checksum/signature sidecar'ы присутствуют в pipeline results, но
        # получают только SKIPPED и не запускают Grype/Trivy.
        return sum(
            1
            for result in self.results
            if any(scan.status != ScanStatus.SKIPPED for scan in result.scans.values())
        )

    @property
    def total_passed(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.PASS)

    @property
    def total_failed(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.FAIL)

    @property
    def total_errors(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.ERROR)

    @property
    def total_copied(self) -> int:
        return sum(1 for r in self.results if r.verify.copied)


@dataclass(slots=True)
class JobInfo:
    id: str
    title: str
    status: JobStatus = JobStatus.PENDING
    progress: float = 0.0
    message: str = ""
    error: str | None = None
