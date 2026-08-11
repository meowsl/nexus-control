"""Тесты NuGet identity-скана (nuspec → OSV API)."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

import httpx
import pytest

from nexus_control.config import Settings
from nexus_control.models import ScanResult, ScanStatus, Severity, Verdict
from nexus_control.services.nuget_osv import (
    NugetOsvError,
    extract_nupkg_identity,
    is_nupkg_local_path,
    query_osv_nuget,
    scan_nupkg_via_osv_api,
    vulns_to_findings,
)
from nexus_control.services.pipeline import (
    _effective_scanners_for_asset,
    _is_nuget_scan_target,
)
from nexus_control.services.scan_common import aggregate_scan_results


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


def test_vulns_to_findings_dedup_aliases() -> None:
    raw = [
        {
            "id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2021-3121"],
            "summary": "bad",
            "database_specific": {"severity": "HIGH"},
        },
        {
            "id": "CVE-2021-3121",
            "summary": "same",
            "database_specific": {"severity": "HIGH"},
        },
    ]
    findings = vulns_to_findings(raw, package_id="Demo.Pkg", version="1.0.0")
    assert len(findings) == 1
    assert findings[0].id == "CVE-2021-3121"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].package_name == "Demo.Pkg"


def test_query_osv_nuget_uses_mock_transport() -> None:
    from nexus_control.services.nuget_osv import NugetPackageIdentity

    identity = NugetPackageIdentity("Newtonsoft.Json", "12.0.1")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/v1/query")
        body = json.loads(request.content)
        assert body["package"]["ecosystem"] == "NuGet"
        assert body["package"]["name"] == "Newtonsoft.Json"
        assert body["version"] == "12.0.1"
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "GHSA-5crp-9r3c-p9vr",
                        "aliases": ["CVE-2024-21907"],
                        "summary": "DoS",
                        "database_specific": {"severity": "HIGH"},
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    vulns = query_osv_nuget(
        identity,
        api_url="https://api.osv.dev",
        timeout=5.0,
        client=client,
    )
    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-5crp-9r3c-p9vr"


def test_scan_nupkg_via_osv_api_fail(tmp_path: Path) -> None:
    nupkg = _make_nupkg(tmp_path / "Newtonsoft.Json-12.0.1.nupkg", "Newtonsoft.Json", "12.0.1")
    settings = Settings(
        nexus_url="http://localhost:8081",
        nexus_username="u",
        nexus_password="p",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        archive_root=tmp_path / "archive",
        log_file=tmp_path / "log.txt",
        osv_api_url="https://osv.test",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "CVE-2024-21907",
                        "summary": "DoS in Newtonsoft.Json",
                        "database_specific": {"severity": "HIGH"},
                    }
                ]
            },
        )

    # monkeypatch query via transport by patching httpx.Client used inside
    import nexus_control.services.nuget_osv as mod

    real_query = mod.query_osv_nuget

    def fake_query(identity, *, api_url, timeout, client=None):
        return real_query(
            identity,
            api_url=api_url,
            timeout=timeout,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

    mod.query_osv_nuget = fake_query  # type: ignore[assignment]
    try:
        result = scan_nupkg_via_osv_api(
            settings=settings,
            repository="test-nuget",
            asset_path="Newtonsoft.Json/12.0.1/Newtonsoft.Json-12.0.1.nupkg",
            local_path=nupkg,
        )
    finally:
        mod.query_osv_nuget = real_query  # type: ignore[assignment]

    assert result.verdict == Verdict.FAIL
    assert result.scanner == "osv"
    assert result.vulnerability_count == 1
    assert result.json_report_path is not None
    assert result.json_report_path.is_file()
    raw = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    assert raw["mode"] == "nuget-osv-api"
    assert raw["package"]["name"] == "Newtonsoft.Json"


def test_scan_nupkg_via_osv_api_pass(tmp_path: Path) -> None:
    nupkg = _make_nupkg(tmp_path / "Clean.Pkg-1.0.0.nupkg", "Clean.Pkg", "1.0.0")
    settings = Settings(
        nexus_url="http://localhost:8081",
        nexus_username="u",
        nexus_password="p",
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        archive_root=tmp_path / "archive",
        log_file=tmp_path / "log.txt",
    )

    import nexus_control.services.nuget_osv as mod

    real_query = mod.query_osv_nuget

    def fake_query(*_a, **_k):
        return []

    mod.query_osv_nuget = fake_query  # type: ignore[assignment]
    try:
        result = scan_nupkg_via_osv_api(
            settings=settings,
            repository="test-nuget",
            asset_path="Clean.Pkg/1.0.0/Clean.Pkg-1.0.0.nupkg",
            local_path=nupkg,
        )
    finally:
        mod.query_osv_nuget = real_query  # type: ignore[assignment]

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
