"""Тесты выбора uploadable-ассетов и maven coordinates."""

from __future__ import annotations

from nexus_control.nexus.uploads import (
    build_hosted_create_payload,
    format_api_slug,
    is_scan_package_asset,
    is_uploadable_asset,
    is_verified_local_sidecar,
    looks_like_nuget_metadata_path,
    normalize_storage_asset_path,
    parse_maven_coordinates,
)


def test_format_api_slug() -> None:
    assert format_api_slug("maven2") == "maven"
    assert format_api_slug("npm") == "npm"
    assert format_api_slug("unknown") is None


def test_is_uploadable_by_format() -> None:
    assert is_uploadable_asset("npm", "lodash/-/lodash-4.17.21.tgz")
    assert not is_uploadable_asset("npm", "lodash")
    assert is_uploadable_asset("pypi", "packages/urllib3/urllib3-1.26.4-py2.py3-none-any.whl")
    assert not is_uploadable_asset("pypi", "simple/urllib3/")
    assert is_uploadable_asset(
        "maven2",
        "org/apache/commons/commons-text/1.9/commons-text-1.9.jar",
    )
    assert is_uploadable_asset(
        "maven2",
        "org/apache/commons/commons-text/maven-metadata.xml",
    )
    assert is_uploadable_asset(
        "maven2",
        "org/apache/commons/commons-text/maven-metadata.xml.sha1",
    )
    assert is_uploadable_asset(
        "maven2",
        "org/apache/commons/commons-text/1.9/commons-text-1.9.jar.md5",
    )
    assert is_uploadable_asset("maven2", "archetype-catalog.xml")
    assert is_uploadable_asset("maven2", "archetype-catalog.xml.sha1")
    assert is_uploadable_asset("maven2", "maven-metadata.xml")
    assert is_uploadable_asset("raw", "docs/readme.txt")
    assert not is_uploadable_asset("docker", "library/alpine/latest")
    assert is_uploadable_asset(
        "nuget",
        "v3/content/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
    )
    assert is_uploadable_asset("nuget", "Some.Package.1.0.0.snupkg")
    # Nexus hosted Components API path (no .nupkg suffix in asset.path)
    assert is_uploadable_asset("nuget", "NexusControl.Seed.Pkg003/1.0.3")
    assert is_scan_package_asset("nuget", "NexusControl.Seed.Pkg003/1.0.3")
    assert not is_uploadable_asset(
        "nuget",
        "v3/registration/newtonsoft.json/index.json",
    )
    assert not is_uploadable_asset("nuget", "newtonsoft.json.nuspec")
    assert looks_like_nuget_metadata_path(
        "v3/registration/popplernet.factories/index.json"
    )
    assert not looks_like_nuget_metadata_path(
        "v3/content/foo/1.0.0/foo.1.0.0.nupkg"
    )
    assert not is_scan_package_asset(
        "nuget", "v3/registration/popplernet.factories/index.json"
    )
    assert is_scan_package_asset(
        "nuget", "v3/content/foo/1.0.0/foo.1.0.0.nupkg"
    )
    # Without format field, nuget metadata still excluded from scan/upload.
    assert not is_uploadable_asset(
        "", "v3/registration/popplernet.factories/index.json"
    )
    assert normalize_storage_asset_path(
        "NexusControl.Seed.Pkg000/1.0.0", fmt="nuget"
    ) == (
        "NexusControl.Seed.Pkg000/1.0.0/"
        "NexusControl.Seed.Pkg000-1.0.0.nupkg"
    )


def test_verified_sidecars_not_uploadable() -> None:
    assert is_verified_local_sidecar("verified-manifest.json")
    assert is_verified_local_sidecar("unverified_assets.txt")
    assert is_verified_local_sidecar("grype_report.json")
    assert is_verified_local_sidecar("trivy_report.json")
    assert not is_verified_local_sidecar("lodash/-/lodash-4.17.21.tgz")
    assert not is_verified_local_sidecar(
        "org/apache/commons/commons-text/1.9/commons-text-1.9.jar"
    )

    # Даже для raw (где обычно проходит почти всё) sidecar'ы блокируются.
    assert not is_uploadable_asset("raw", "verified-manifest.json")
    assert not is_uploadable_asset("raw", "unverified_assets.txt")
    assert not is_uploadable_asset("raw", "grype_report.json")
    assert not is_uploadable_asset("npm", "trivy_report.json")
    assert not is_uploadable_asset("maven2", "grype_report.json")


def test_parse_maven_coordinates() -> None:
    assert parse_maven_coordinates(
        "org/apache/commons/commons-text/1.9/commons-text-1.9.jar"
    ) == ("org.apache.commons", "commons-text", "1.9", "jar")


def test_maven_create_payload_has_maven_block() -> None:
    payload = build_hosted_create_payload("x-verified", "maven2")
    assert payload["maven"]["versionPolicy"] == "MIXED"
    npm = build_hosted_create_payload("n-verified", "npm")
    assert "maven" not in npm
