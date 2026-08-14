"""Модульные тесты парсера JSON osv-scanner и сборки argv."""

from __future__ import annotations

from pathlib import Path

from nexus_control.models import Severity, Verdict
from nexus_control.services.osv_scanner import (
    EXPERIMENTAL_PLUGINS,
    _build_osv_args,
    is_osv_soft_empty,
    parse_osv_json,
)
from nexus_control.services.scan_common import parse_scanner_names


OSV_JSON = {
    "results": [
        {
            "source": {"path": "/tmp/go.mod", "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "github.com/gogo/protobuf",
                        "version": "1.3.1",
                        "ecosystem": "Go",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-c3h9-896r-86jm",
                            "aliases": ["CVE-2021-3121"],
                            "summary": "bad protobuf",
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {
                                    "package": {
                                        "name": "github.com/gogo/protobuf",
                                        "ecosystem": "Go",
                                    },
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "1.3.2"},
                                            ],
                                        }
                                    ],
                                }
                            ],
                        },
                        {
                            "id": "GO-2021-0053",
                            "aliases": ["CVE-2021-3121", "GHSA-c3h9-896r-86jm"],
                            "summary": "same issue via Go advisory",
                        },
                    ],
                    "groups": [
                        {
                            "ids": ["GHSA-c3h9-896r-86jm", "GO-2021-0053"],
                        }
                    ],
                }
            ],
        }
    ]
}


def test_parse_osv_vulns_dedup_by_group() -> None:
    result = parse_osv_json(OSV_JSON)
    assert result.verdict == Verdict.FAIL
    assert result.scanner == "osv"
    assert result.vulnerability_count == 1
    assert result.vulnerabilities[0].id == "CVE-2021-3121"
    assert result.vulnerabilities[0].severity == Severity.HIGH
    assert result.vulnerabilities[0].package_name == "github.com/gogo/protobuf"
    assert result.vulnerabilities[0].package_version == "1.3.1"
    assert result.vulnerabilities[0].fix_version == "1.3.2"


def test_parse_osv_clean() -> None:
    result = parse_osv_json({"results": []})
    assert result.verdict == Verdict.PASS
    assert result.vulnerability_count == 0


def test_parse_osv_missing_results_is_pass() -> None:
    result = parse_osv_json({})
    assert result.verdict == Verdict.PASS
    assert result.vulnerability_count == 0


def test_parse_osv_error_shape() -> None:
    result = parse_osv_json({"error": "boom"})
    assert result.verdict == Verdict.ERROR
    assert result.error == "boom"


def test_parse_osv_empty_string() -> None:
    result = parse_osv_json("")
    assert result.verdict == Verdict.ERROR


def test_parse_osv_without_groups_dedup_aliases() -> None:
    payload = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "regex", "version": "1.5.1"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-m5pq-gvj9-9vr8",
                                "aliases": ["CVE-2022-24713"],
                                "database_specific": {"severity": "CRITICAL"},
                            },
                            {
                                "id": "RUSTSEC-2022-0013",
                                "aliases": ["CVE-2022-24713"],
                            },
                        ],
                    }
                ]
            }
        ]
    }
    result = parse_osv_json(payload)
    assert result.verdict == Verdict.FAIL
    assert result.vulnerability_count == 1
    assert result.vulnerabilities[0].id == "CVE-2022-24713"
    assert result.counts.critical == 1


def test_build_osv_args_source_includes_plugins() -> None:
    args = _build_osv_args(Path("/tmp/proj"), "file", ["--recursive"])
    assert args[:3] == ["scan", "source", "/tmp/proj"]
    assert "--format=json" in args
    assert f"--experimental-plugins={EXPERIMENTAL_PLUGINS}" in args
    assert args[-1] == "--recursive"


def test_build_osv_args_image_archive() -> None:
    args = _build_osv_args(Path("/tmp/img.tar"), "docker-archive", [])
    assert args[:4] == ["scan", "image", "--archive", "/tmp/img.tar"]
    assert f"--experimental-plugins={EXPERIMENTAL_PLUGINS}" in args


def test_parse_scanner_names_accepts_osv() -> None:
    assert parse_scanner_names("grype,osv") == ["grype", "osv"]
    assert parse_scanner_names("osv") == ["osv"]


def test_is_osv_soft_empty_no_package_sources() -> None:
    stderr = (
        "Error during extraction: java/archive invalid archive: "
        "zip: not a valid zip file\n"
        "No package sources found, --help for usage information.\n"
    )
    assert is_osv_soft_empty(stderr) is True
    assert is_osv_soft_empty("fatal: database unavailable") is False


def test_soft_empty_parses_as_pass() -> None:
    """Синтетический пустой JSON после soft-empty → PASS, как у Grype/Trivy."""
    result = parse_osv_json('{"results": []}\n')
    assert result.verdict == Verdict.PASS
    assert result.vulnerability_count == 0
