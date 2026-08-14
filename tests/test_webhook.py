"""Tests for generic scan-result webhook."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nexus_control.config import Settings
from nexus_control.config_io import read_toml
from nexus_control.config_paths import resolve_config_path
from nexus_control.config_wizard import run_first_run_wizard
from nexus_control.integrations.webhook import (
    EVENT_TEST,
    EVENT_VERIFY,
    WebhookVault,
    build_auth,
    build_payload,
    post_webhook,
    push_pipeline_results,
    resolve_webhook_settings,
)
from nexus_control.models import (
    AssetKind,
    AssetPipelineResult,
    DownloadResult,
    DownloadStatus,
    PipelineSummary,
    ScanResult,
    ScanStatus,
    Severity,
    SeverityCounts,
    Verdict,
    Vulnerability,
)


def _settings(tmp_path: Path, **kwargs: object) -> Settings:
    base: dict[str, object] = dict(
        nexus_url="http://nexus:8081",
        nexus_cache_dir=tmp_path,
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "rp",
        verified_root=tmp_path / "vf",
        archive_root=tmp_path / "ar",
        log_file=tmp_path / "log.log",
    )
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def _fail_result(path: str) -> AssetPipelineResult:
    return AssetPipelineResult(
        asset_path=path,
        kind=AssetKind.FILE,
        download=DownloadResult(status=DownloadStatus.SKIPPED_EXISTING),
        scans={
            "grype": ScanResult(
                status=ScanStatus.SUCCESS,
                verdict=Verdict.FAIL,
                vulnerabilities=[
                    Vulnerability(
                        id="CVE-2024-1",
                        severity=Severity.HIGH,
                        package_name="lib",
                        package_version="1.0",
                    )
                ],
                counts=SeverityCounts(high=1),
                scanner="grype",
            )
        },
    )


def test_build_payload_includes_totals_and_assets() -> None:
    summary = PipelineSummary(
        repository="maven-hosted",
        scanners=["grype"],
        started_at=datetime(2026, 8, 14, 6, 0, tzinfo=timezone.utc),
        results=[_fail_result("com/acme/lib-1.0.jar")],
    )
    payload = build_payload(summary)
    assert payload["event"] == EVENT_VERIFY
    assert payload["source"] == "nexus-control"
    assert payload["repository"] == "maven-hosted"
    assert payload["totals"]["failed"] == 1
    assert payload["totals"]["assets"] == 1
    asset = payload["assets"][0]
    assert asset["path"] == "com/acme/lib-1.0.jar"
    assert asset["verdict"] == "FAIL"
    assert asset["scans"]["grype"]["vulnerabilities"][0]["id"] == "CVE-2024-1"


def test_build_auth_modes() -> None:
    none = _settings(Path("/tmp"), webhook_auth="none")
    headers, basic, err = build_auth(none)
    assert headers == {} and basic is None and err is None

    bearer = _settings(Path("/tmp"), webhook_auth="bearer", webhook_token="tok")
    headers, basic, err = build_auth(bearer)
    assert headers["Authorization"] == "Bearer tok"
    assert basic is None and err is None

    missing = _settings(Path("/tmp"), webhook_auth="bearer")
    _, _, err = build_auth(missing)
    assert err is not None

    basic_s = _settings(
        Path("/tmp"),
        webhook_auth="basic",
        webhook_username="alice",
        webhook_password="s3cret",
    )
    headers, basic, err = build_auth(basic_s)
    assert basic == ("alice", "s3cret")
    assert err is None

    header_s = _settings(
        Path("/tmp"),
        webhook_auth="header",
        webhook_header_name="X-Api-Key",
        webhook_header_value="abc",
    )
    headers, basic, err = build_auth(header_s)
    assert headers["X-Api-Key"] == "abc"
    assert err is None


def test_login_password_alias_becomes_basic(tmp_path: Path) -> None:
    settings = _settings(tmp_path, webhook_auth="login-password")
    assert settings.webhook_auth == "basic"


def test_vault_roundtrip_and_resolve(tmp_path: Path) -> None:
    vault = WebhookVault(tmp_path)
    vault.save(
        url="https://hooks.example.com/scan",
        auth="bearer",
        token="from-vault",
    )
    settings = _settings(
        tmp_path, webhook_enabled=True, webhook_url="", webhook_token=""
    )
    resolved = resolve_webhook_settings(settings)
    assert resolved.webhook_url == "https://hooks.example.com/scan"
    assert resolved.webhook_token == "from-vault"
    assert resolved.webhook_auth == "bearer"


def test_push_skipped_when_disabled(tmp_path: Path) -> None:
    settings = _settings(tmp_path, webhook_enabled=False)
    summary = PipelineSummary(repository="r", results=[_fail_result("x")])
    result = push_pipeline_results(settings, summary)
    assert result.skipped is True


def test_post_sends_json_and_event_header(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        webhook_enabled=True,
        webhook_url="https://hooks.example.com/scan",
        webhook_auth="bearer",
        webhook_token="tok",
    )
    summary = PipelineSummary(
        repository="npm-hosted", results=[_fail_result("pkg.tgz")]
    )
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_response.text = ""

    class _Client:
        url = ""
        kwargs: dict[str, object] = {}

        def __init__(self, **_kw: object) -> None:
            pass

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def post(self, url: str, **kwargs: object) -> MagicMock:
            self.url = url
            self.kwargs = kwargs
            return mock_response

    client = _Client()
    with patch(
        "nexus_control.integrations.webhook.httpx.Client",
        return_value=client,
    ):
        result = push_pipeline_results(settings, summary)
    assert result.error is None
    assert result.status_code == 204
    assert client.url == "https://hooks.example.com/scan"
    headers = client.kwargs["headers"]
    assert headers["Authorization"] == "Bearer tok"  # type: ignore[index]
    assert headers["X-Nexus-Control-Event"] == EVENT_VERIFY  # type: ignore[index]
    body = client.kwargs["json"]
    assert body["repository"] == "npm-hosted"  # type: ignore[index]
    assert body["event"] == EVENT_VERIFY  # type: ignore[index]


def test_post_test_event(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        webhook_enabled=True,
        webhook_url="https://hooks.example.com/scan",
    )
    mock_response = MagicMock(status_code=200, text="ok")

    class _Client:
        kwargs: dict[str, object] = {}

        def __init__(self, **_kw: object) -> None:
            pass

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def post(self, url: str, **kwargs: object) -> MagicMock:
            self.kwargs = kwargs
            return mock_response

    client = _Client()
    with patch(
        "nexus_control.integrations.webhook.httpx.Client",
        return_value=client,
    ):
        result = post_webhook(
            settings,
            {"event": EVENT_TEST, "source": "nexus-control"},
            event=EVENT_TEST,
        )
    assert result.status_code == 200
    headers = client.kwargs["headers"]
    assert headers["X-Nexus-Control-Event"] == EVENT_TEST  # type: ignore[index]


def test_wizard_webhook_bearer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.delenv("NEXUS_CONTROL_CONFIG", raising=False)
    monkeypatch.delenv("NEXUS_URL", raising=False)
    cache = tmp_path / "cache"
    monkeypatch.setenv("NEXUS_CACHE_DIR", str(cache))
    path = resolve_config_path()
    answers = iter(
        [
            "ru",
            "http://nexus:8081",
            "",
            "grype",
            "n",  # DefectDojo
            "y",  # webhook
            "https://hooks.example.com/scan",
            "",
            "bearer",
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr("getpass.getpass", lambda _prompt="": "hook-token")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    run_first_run_wizard(config_path=path)
    data = read_toml(path)
    assert data["webhook_enabled"] is True
    assert data["webhook_url"] == "https://hooks.example.com/scan"
    assert data["webhook_auth"] == "bearer"
    assert "webhook_token" not in data
    loaded = WebhookVault(cache.resolve()).load()
    assert loaded is not None
    assert loaded["token"] == "hook-token"
