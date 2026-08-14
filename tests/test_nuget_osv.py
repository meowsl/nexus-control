"""Тесты NuGet identity-скана (nuspec → osv-scanner lockfile)."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock
from xml.sax.saxutils import escape

import pytest

from nexus_control.config import Settings
from nexus_control.models import ScanResult, ScanStatus, Verdict
from nexus_control.services.nuget_osv import (
    NugetOsvError,
    NugetPackageIdentity,
    build_nuget_osv_args,
    extract_nupkg_identity,
    is_nupkg_local_path,
    write_nuget_identity_lockfile,
)
from nexus_control.services.osv_scanner import OsvScanner
from nexus_control.services.pipeline import (
    _effective_scanners_for_asset,
    _is_nuget_scan_target,
)
from nexus_control.services.scan_common import aggregate_scan_results
from nexus_control.utils.subprocess_runner import CommandResult


def _make_nupkg(path: Path, package_id: str, version: str) -> Path:
    nuspec = f"""<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{escape(package_id)}</id>
    <version>{escape(version)}</version>
    <authors>test</authors>
    <description>test</description>
  </metadata>
</package>
"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{package_id}.nuspec", nuspec)
        zf.writestr(f"lib/netstandard2.0/{package_id}.txt", b"ok\n")
    path.write_bytes(buf.getvalue())
    return path


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        nexus_url="http://localhost:8081",
        nexus_username="u",
        nexus_password="p",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        archive_root=tmp_path / "archive",
        log_file=tmp_path / "log.txt",
    )


def test_is_nupkg_local_path() -> None:
    assert is_nupkg_local_path(Path("Foo.1.0.0.nupkg"))
    assert is_nupkg_local_path(Path("Foo.1.0.0.snupkg"))
    assert not is_nupkg_local_path(Path("Foo.1.0.0.jar"))


def test_extract_nupkg_identity(tmp_path: Path) -> None:
    nupkg = _make_nupkg(tmp_path / "Demo.Pkg-1.2.3.nupkg", "Demo.Pkg", "1.2.3")
    identity = extract_nupkg_identity(nupkg)
    assert identity.package_id == "Demo.Pkg"
    assert identity.version == "1.2.3"


def test_extract_nupkg_identity_missing_nuspec(tmp_path: Path) -> None:
    path = tmp_path / "broken.nupkg"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "no nuspec")
    path.write_bytes(buf.getvalue())
    with pytest.raises(NugetOsvError, match="no .nuspec"):
        extract_nupkg_identity(path)


def test_write_nuget_identity_lockfile(tmp_path: Path) -> None:
    path = tmp_path / "osv-scanner.json"
    write_nuget_identity_lockfile(
        NugetPackageIdentity("Newtonsoft.Json", "12.0.1"),
        path,
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    pkg = data["results"][0]["packages"][0]["package"]
    assert pkg == {
        "name": "Newtonsoft.Json",
        "version": "12.0.1",
        "ecosystem": "NuGet",
    }
    args = build_nuget_osv_args(path, ["--offline"])
    assert args[:2] == ["scan", "source"]
    assert args[2].startswith("--lockfile=osv-scanner:")
    assert "--format=json" in args
    assert "--offline" in args


def test_scan_nupkg_via_osv_scanner_fail(tmp_path: Path) -> None:
    nupkg = _make_nupkg(
        tmp_path / "Newtonsoft.Json-12.0.1.nupkg",
        "Newtonsoft.Json",
        "12.0.1",
    )
    settings = _settings(tmp_path)
    scanner = OsvScanner(settings)
    scanner.resolve_backend = MagicMock(return_value="local")  # type: ignore[method-assign]
    scanner.get_version = MagicMock(return_value="osv-scanner 2.5.0")  # type: ignore[method-assign]

    fake_json = {
        "results": [
            {
                "packages": [
                    {
                        "package": {
                            "name": "Newtonsoft.Json",
                            "version": "12.0.1",
                            "ecosystem": "NuGet",
                        },
                        "vulnerabilities": [
                            {
                                "id": "CVE-2024-21907",
                                "summary": "DoS",
                                "database_specific": {"severity": "HIGH"},
                            }
                        ],
                    }
                ]
            }
        ]
    }

    def fake_run_scan(osv_args: list[str], json_report_path: Path) -> CommandResult:
        assert any(a.startswith("--lockfile=osv-scanner:") for a in osv_args)
        return CommandResult(
            returncode=0,
            stdout=json.dumps(fake_json),
            stderr="",
            argv=["osv-scanner", *osv_args],
        )

    scanner._run_scan = fake_run_scan  # type: ignore[method-assign]
    result = scanner.scan_path(
        repository="test-nuget",
        asset_path="Newtonsoft.Json/12.0.1/Newtonsoft.Json-12.0.1.nupkg",
        local_path=nupkg,
    )
    assert result.verdict == Verdict.FAIL
    assert result.scanner == "osv"
    assert result.vulnerability_count == 1
    assert result.vulnerabilities[0].id == "CVE-2024-21907"
    assert result.json_report_path is not None
    raw = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    assert raw["mode"] == "nuget-osv-scanner"
    assert raw["package"]["name"] == "Newtonsoft.Json"


def test_scan_nupkg_via_osv_scanner_pass(tmp_path: Path) -> None:
    nupkg = _make_nupkg(tmp_path / "Clean.Pkg-1.0.0.nupkg", "Clean.Pkg", "1.0.0")
    settings = _settings(tmp_path)
    scanner = OsvScanner(settings)
    scanner.resolve_backend = MagicMock(return_value="local")  # type: ignore[method-assign]
    scanner.get_version = MagicMock(return_value="osv-scanner 2.5.0")  # type: ignore[method-assign]

    def fake_run_scan(osv_args: list[str], json_report_path: Path) -> CommandResult:
        return CommandResult(
            returncode=0,
            stdout='{"results": []}\n',
            stderr="",
            argv=["osv-scanner", *osv_args],
        )

    scanner._run_scan = fake_run_scan  # type: ignore[method-assign]
    result = scanner.scan_path(
        repository="test-nuget",
        asset_path="Clean.Pkg/1.0.0/Clean.Pkg-1.0.0.nupkg",
        local_path=nupkg,
    )
    assert result.verdict == Verdict.PASS
    assert result.status == ScanStatus.SUCCESS
    assert result.vulnerability_count == 0


def test_aggregate_ignores_skipped() -> None:
    scans = {
        "grype": ScanResult(
            status=ScanStatus.SKIPPED,
            verdict=Verdict.SKIPPED,
            scanner="grype",
        ),
        "osv": ScanResult(
            status=ScanStatus.SUCCESS,
            verdict=Verdict.PASS,
            scanner="osv",
        ),
    }
    assert aggregate_scan_results(scans).verdict == Verdict.PASS


def test_nuget_effective_scanners_auto_adds_osv(tmp_path: Path) -> None:
    nupkg = _make_nupkg(tmp_path / "X-1.0.0.nupkg", "X", "1.0.0")
    assert _is_nuget_scan_target(
        asset_fmt="nuget",
        asset_path="X/1.0.0",
        local_path=nupkg,
    )
    names = _effective_scanners_for_asset(
        ["grype"],
        asset_fmt="nuget",
        asset_path="X/1.0.0",
        local_path=nupkg,
    )
    assert names == ["grype", "osv"]
