"""Tests for VK Teams notify / pending upload / client helpers."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from threading import Event
from unittest.mock import MagicMock, patch
import json
import time

import pytest

from nexus_control.config import Settings
from nexus_control.integrations.vk_notify import (
    CALLBACK_PREFIX,
    PendingUpload,
    PendingUploadStore,
    build_rule_message,
    build_rule_notify_keyboard,
    format_vk_datetime,
    handle_callback,
    notify_rule_finished,
    should_notify,
    upload_in_flight,
    vk_teams_configured,
    vk_teams_should_poll,
    wait_upload_idle,
)
from nexus_control.integrations.vk_teams import (
    VkTeamsClient,
    VkTeamsError,
    VkTeamsVault,
    apply_vk_teams_vault,
    upload_keyboard,
    vk_teams_token_source,
)
from nexus_control.scheduler.models import ScheduleRule
from nexus_control.services.scan_history import ScanRunMeta, ScanRunTotals


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = {
        "nexus_url": "http://localhost:8081",
        "nexus_cache_dir": tmp_path / "cache",
        "download_root": tmp_path / "dl",
        "reports_root": tmp_path / "reports",
        "verified_root": tmp_path / "verified",
        "log_file": tmp_path / "logs" / "app.log",
        "vk_teams_token": "tok",
        "vk_teams_chat_id": "chat-1",
        "vk_teams_notify": "always",
        "vk_teams_api_url": "https://example.test/bot/v1",
        "vk_teams_upload_button": True,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def _meta(
    repo: str,
    *,
    passed: int = 0,
    failed: int = 0,
    errors: int = 0,
    copied: int = 0,
    checkpoint_skipped: int = 0,
    scanned: int = 0,
    started_at: str = "2026-08-10T10:00:00+00:00",
    finished_at: str = "2026-08-10T10:01:00+00:00",
    defectdojo_engagement_id: int | None = None,
) -> ScanRunMeta:
    return ScanRunMeta(
        run_id=f"run_{repo}",
        repository=repo,
        started_at=started_at,
        finished_at=finished_at,
        source="scheduler",
        scanners=["grype"],
        totals=ScanRunTotals(
            scanned=scanned or passed + failed + errors,
            passed=passed,
            failed=failed,
            errors=errors,
            copied=copied,
            checkpoint_skipped=checkpoint_skipped,
        ),
        rule_id="nightly",
        defectdojo_engagement_id=defectdojo_engagement_id,
    )


def test_should_notify_policies() -> None:
    ok = [_meta("r", passed=3, scanned=3)]
    bad = [_meta("r", failed=1, scanned=1)]
    assert should_notify("off", 0, bad) is False
    assert should_notify("always", 0, ok) is True
    assert should_notify("failures", 0, ok) is False
    assert should_notify("failures", 1, ok) is True
    assert should_notify("failures", 0, bad) is True


def test_vk_teams_configured_helpers(tmp_path: Path) -> None:
    s = _settings(tmp_path)
    assert vk_teams_configured(s) is True
    assert vk_teams_should_poll(s) is True
    s2 = _settings(tmp_path, vk_teams_notify="off")
    assert vk_teams_configured(s2) is False
    s3 = _settings(tmp_path, vk_teams_token="")
    assert vk_teams_configured(s3) is False
    s4 = _settings(tmp_path, vk_teams_upload_button=False)
    assert vk_teams_should_poll(s4) is False


def test_vault_roundtrip_and_not_plaintext(tmp_path: Path) -> None:
    vault = VkTeamsVault(tmp_path / "cache")
    vault.save(token="super-secret-token", chat_id="chat-vault")
    loaded = vault.load()
    assert loaded is not None
    assert loaded.token == "super-secret-token"
    assert loaded.chat_id == "chat-vault"
    raw = vault.vault_path.read_bytes()
    assert b"super-secret-token" not in raw
    assert vault.exists() is True
    vault.clear()
    assert vault.load() is None
    assert vault.key_path.is_file()


def test_apply_vault_fills_empty_settings(tmp_path: Path) -> None:
    settings = _settings(tmp_path, vk_teams_token="", vk_teams_chat_id="")
    VkTeamsVault(settings.nexus_cache_dir).save(token="vault-tok", chat_id="vault-chat")
    filled = apply_vk_teams_vault(settings)
    assert filled.vk_teams_token == "vault-tok"
    assert filled.vk_teams_chat_id == "vault-chat"
    assert vk_teams_configured(settings) is True
    assert vk_teams_token_source(settings) == "vault"


def test_settings_token_wins_over_vault(tmp_path: Path) -> None:
    settings = _settings(tmp_path, vk_teams_token="env-tok")
    VkTeamsVault(settings.nexus_cache_dir).save(token="vault-tok", chat_id="ignored")
    filled = apply_vk_teams_vault(settings)
    assert filled.vk_teams_token == "env-tok"
    assert vk_teams_token_source(settings) == "config"


def test_format_vk_datetime_moscow() -> None:
    assert format_vk_datetime("2026-08-10T03:00:00+00:00") == "10.08.2026 06:00"
    assert format_vk_datetime(None) == "—"


def test_build_rule_message_verify_only(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        defectdojo_enabled=True,
        defectdojo_url="http://localhost:8080",
    )
    rule = ScheduleRule(
        id="nightly",
        cron="0 3 * * *",
        repos=["test-pypi", "test-npm"],
        action="verify",
        description="Nightly",
    )
    text = build_rule_message(
        rule,
        {
            "test-pypi": _meta(
                "test-pypi",
                passed=0,
                failed=0,
                scanned=0,
                checkpoint_skipped=8,
                started_at="2026-08-10T03:00:00+00:00",
                finished_at="2026-08-10T03:15:00+00:00",
            ),
            "test-npm": _meta(
                "test-npm",
                passed=7,
                failed=2,
                copied=7,
                scanned=9,
                started_at="2026-08-10T03:00:00+00:00",
                finished_at="2026-08-10T03:20:00+00:00",
                defectdojo_engagement_id=42,
            ),
        },
        settings=settings,
        manual=False,
    )
    assert "Плановое сканирование" in text
    assert "<b>test-pypi</b>" in text
    assert "<b>test-npm</b>" in text
    assert "Артефакты без уязвимостей: 7" in text
    assert "Выявлено уязвимостей: 2" in text
    assert "10.08.2026 06:00 - 10.08.2026 06:15" in text
    assert "10.08.2026 06:00 - 10.08.2026 06:20" in text
    assert "DefectDojo" not in text

    keyboard = build_rule_notify_keyboard(
        settings,
        rule,
        {
            "test-pypi": _meta(
                "test-pypi",
                passed=0,
                failed=0,
                scanned=0,
                checkpoint_skipped=8,
            ),
            "test-npm": _meta(
                "test-npm",
                passed=7,
                failed=2,
                copied=7,
                scanned=9,
                defectdojo_engagement_id=42,
            ),
        },
    )
    assert keyboard is not None
    assert keyboard[-1] == [
        {"text": "Смотреть в DefectDojo", "url": "http://localhost:8080/engagement/42"}
    ]


def test_build_rule_notify_keyboard_skips_dd_without_failures(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        defectdojo_enabled=True,
        defectdojo_url="http://localhost:8080",
    )
    rule = ScheduleRule(
        id="nightly",
        cron="0 3 * * *",
        repos=["clean-repo"],
        action="verify",
    )
    assert (
        build_rule_notify_keyboard(
            settings,
            rule,
            {
                "clean-repo": _meta(
                    "clean-repo",
                    passed=10,
                    failed=0,
                    defectdojo_engagement_id=99,
                ),
            },
        )
        is None
    )


def test_notify_rule_finished_adds_defectdojo_button(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        defectdojo_enabled=True,
        defectdojo_url="http://localhost:8080",
        vk_teams_upload_button=False,
    )
    rule = ScheduleRule(
        id="nightly",
        cron="0 3 * * *",
        repos=["npm-hosted"],
        action="verify",
    )
    client = MagicMock(spec=VkTeamsClient)
    client.send_text.return_value = {"ok": True, "msgId": "99"}
    with patch(
        "nexus_control.integrations.vk_notify.latest_run_for_repo",
        return_value=_meta(
            "npm-hosted",
            passed=810,
            failed=2,
            scanned=812,
            defectdojo_engagement_id=55,
        ),
    ):
        notify_rule_finished(settings, rule, 1, client=client)

    keyboard = client.send_text.call_args[1]["inline_keyboard"]
    assert keyboard == [
        [{"text": "Смотреть в DefectDojo", "url": "http://localhost:8080/engagement/55"}]
    ]


def test_build_rule_message_manual_verify_upload(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    rule = ScheduleRule(
        id="auto",
        cron="0 3 * * *",
        repos=["r1"],
        action="verify_upload",
    )
    text = build_rule_message(
        rule,
        {"r1": None},
        settings=settings,
        manual=True,
    )
    assert "Сканирование <b>r1</b>" in text
    assert "— - —" in text
    assert "Артефакты без уязвимостей: 0" in text
    assert "Выявлено уязвимостей: 0" in text
    assert "DefectDojo" not in text


def test_pending_store_roundtrip(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = PendingUploadStore.load(settings)
    pending = PendingUpload(
        token="abc123",
        rule_id="nightly",
        repos=["a", "b"],
        targets={"a": "a-verified"},
        created_at=time.time(),
        chat_id="chat-1",
        msg_id="42",
    )
    store.put(pending)
    loaded = PendingUploadStore.load(settings)
    got = loaded.get("abc123")
    assert got is not None
    assert got.repos == ["a", "b"]
    assert got.msg_id == "42"
    popped = loaded.pop("abc123")
    assert popped is not None
    assert loaded.get("abc123") is None


def test_upload_keyboard() -> None:
    kb = upload_keyboard("up:tok")
    assert kb == [[{"text": "Загрузить в Nexus", "callbackData": "up:tok"}]]


def test_notify_rule_finished_sends_with_button(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    rule = ScheduleRule(
        id="nightly",
        cron="0 3 * * *",
        repos=["test-pypi"],
        action="verify",
    )
    client = MagicMock(spec=VkTeamsClient)
    client.send_text.return_value = {"ok": True, "msgId": "99"}

    with patch(
        "nexus_control.integrations.vk_notify.latest_run_for_repo",
        return_value=_meta("test-pypi", passed=1, scanned=1, copied=1),
    ):
        notify_rule_finished(settings, rule, 0, client=client)

    client.send_text.assert_called_once()
    kwargs = client.send_text.call_args
    assert kwargs[0][0] == "chat-1"
    assert kwargs[1]["inline_keyboard"] is not None
    store = PendingUploadStore.load(settings)
    assert len(store._items) == 1


def test_notify_rule_finished_no_button_for_verify_upload(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    rule = ScheduleRule(
        id="auto",
        cron="0 3 * * *",
        repos=["r"],
        action="verify_upload",
    )
    client = MagicMock(spec=VkTeamsClient)
    client.send_text.return_value = {"ok": True, "msgId": "1"}
    with patch(
        "nexus_control.integrations.vk_notify.latest_run_for_repo",
        return_value=_meta("r", passed=1, scanned=1),
    ):
        notify_rule_finished(settings, rule, 0, client=client)
    assert client.send_text.call_args[1]["inline_keyboard"] is None


def test_notify_failures_policy_skips_ok(tmp_path: Path) -> None:
    settings = _settings(tmp_path, vk_teams_notify="failures")
    rule = ScheduleRule(id="n", cron="0 0 * * *", repos=["r"], action="verify")
    client = MagicMock(spec=VkTeamsClient)
    with patch(
        "nexus_control.integrations.vk_notify.latest_run_for_repo",
        return_value=_meta("r", passed=2, scanned=2),
    ):
        notify_rule_finished(settings, rule, 0, client=client)
    client.send_text.assert_not_called()


def test_handle_callback_uploads(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = PendingUploadStore.load(settings)
    store.put(
        PendingUpload(
            token="tok1",
            rule_id="nightly",
            repos=["a", "b"],
            targets={"a": "a-v", "b": "b-v"},
            created_at=time.time(),
            chat_id="chat-1",
            msg_id="77",
        )
    )
    client = MagicMock(spec=VkTeamsClient)
    uploads: list[str] = []

    def fake_upload(args: Namespace) -> int:
        uploads.append(args.repo)
        return 0

    handle_callback(
        settings,
        f"{CALLBACK_PREFIX}tok1",
        "q1",
        client=client,
        run_upload_fn=fake_upload,
    )
    assert wait_upload_idle(timeout=2.0)
    assert uploads == ["a", "b"]
    client.answer_callback_query.assert_called()
    client.edit_text.assert_called_once()
    assert PendingUploadStore.load(settings).get("tok1") is None


def test_handle_callback_expired(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client = MagicMock(spec=VkTeamsClient)
    handle_callback(
        settings,
        f"{CALLBACK_PREFIX}missing",
        "q1",
        client=client,
        run_upload_fn=lambda _a: 0,
    )
    client.answer_callback_query.assert_called()
    assert client.answer_callback_query.call_args[1].get("show_alert") is True


def test_client_send_text_posts(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"ok": True, "msgId": "1"}

    class FakeClient:
        def __init__(self, *a, **k) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *a) -> None:
            return None

        def request(self, method, path, params=None, data=None):
            captured["method"] = method
            captured["path"] = path
            captured["params"] = params
            captured["data"] = data
            return FakeResponse()

    monkeypatch.setattr(
        "nexus_control.integrations.vk_teams.httpx.Client",
        FakeClient,
    )
    bot = VkTeamsClient(
        token="t",
        api_url="https://example.test/bot/v1",
    )
    out = bot.send_text(
        "chat",
        "hi",
        inline_keyboard=upload_keyboard("up:x"),
    )
    assert out["ok"] is True
    assert captured["method"] == "POST"
    assert captured["path"] == "/messages/sendText"
    assert captured["params"]["token"] == "t"
    assert captured["data"]["chatId"] == "chat"
    assert "inlineKeyboardMarkup" in captured["data"]


def test_client_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"ok": False, "description": "boom"}

    class FakeClient:
        def __init__(self, *a, **k) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *a) -> None:
            return None

        def request(self, *a, **k):
            return FakeResponse()

    monkeypatch.setattr(
        "nexus_control.integrations.vk_teams.httpx.Client",
        FakeClient,
    )
    bot = VkTeamsClient(token="t", api_url="https://example.test/bot/v1")
    with pytest.raises(VkTeamsError, match="boom"):
        bot.send_text("c", "x")


def _put_pending(
    settings: Settings,
    *,
    token: str,
    repos: list[str] | None = None,
) -> None:
    store = PendingUploadStore.load(settings)
    store.put(
        PendingUpload(
            token=token,
            rule_id="nightly",
            repos=repos or ["a"],
            targets={r: f"{r}-v" for r in (repos or ["a"])},
            created_at=time.time(),
            chat_id="chat-1",
            msg_id="77",
        )
    )


def test_handle_callback_does_not_block_poll(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _put_pending(settings, token="tok-slow", repos=["a"])
    client = MagicMock(spec=VkTeamsClient)
    started = Event()
    release = Event()

    def fake_upload(args: Namespace) -> int:
        started.set()
        assert release.wait(timeout=5)
        return 0

    handle_callback(
        settings,
        f"{CALLBACK_PREFIX}tok-slow",
        "q-slow",
        client=client,
        run_upload_fn=fake_upload,
    )
    try:
        assert started.wait(timeout=2)
        assert upload_in_flight() is True
        client.answer_callback_query.assert_called()
        text = client.answer_callback_query.call_args[1].get("text")
        assert text == "Загружаю…"
        client.edit_text.assert_not_called()
    finally:
        release.set()
        assert wait_upload_idle(timeout=2.0)
    client.edit_text.assert_called_once()


def test_handle_callback_already_running_keeps_pending(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _put_pending(settings, token="tok-a", repos=["a"])
    _put_pending(settings, token="tok-b", repos=["b"])
    client = MagicMock(spec=VkTeamsClient)
    release = Event()

    def fake_upload(args: Namespace) -> int:
        assert release.wait(timeout=5)
        return 0

    handle_callback(
        settings,
        f"{CALLBACK_PREFIX}tok-a",
        "q-a",
        client=client,
        run_upload_fn=fake_upload,
    )
    handle_callback(
        settings,
        f"{CALLBACK_PREFIX}tok-b",
        "q-b",
        client=client,
        run_upload_fn=fake_upload,
    )
    try:
        alerts = [
            c
            for c in client.answer_callback_query.call_args_list
            if c[1].get("show_alert")
        ]
        assert alerts
        assert "уже выполняется" in str(alerts[-1][1].get("text", "")).lower()
        assert PendingUploadStore.load(settings).get("tok-b") is not None
    finally:
        release.set()
        assert wait_upload_idle(timeout=2.0)


def test_execute_rule_polls_vk_while_busy(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    from nexus_control.scheduler.daemon import _execute_rule
    from nexus_control.scheduler.models import ScheduleRule
    from nexus_control.scheduler.state import SchedulerState

    settings = _settings(tmp_path)
    rule = ScheduleRule(id="x", cron="0 0 * * *", repos=["r"])
    polls: list[int] = []

    def fake_poll(_settings: object, *, poll_time: int = 25, client: object = None) -> int:
        polls.append(poll_time)
        time.sleep(0.05)
        return 0

    def fake_run(_rule: object, **_kwargs: object) -> int:
        time.sleep(0.2)
        return 0

    with patch(
        "nexus_control.scheduler.daemon.poll_and_handle_events",
        side_effect=fake_poll,
    ):
        with patch("nexus_control.scheduler.daemon.run_rule", side_effect=fake_run):
            with patch("nexus_control.scheduler.daemon.notify_rule_finished"):
                _execute_rule(
                    settings,
                    rule,
                    datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "x:202601010000",
                    SchedulerState(),
                    tmp_path / "state.json",
                )
    assert polls
    assert all(p <= 3 for p in polls)


def test_vk_teams_cli_configure_status_disable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from argparse import Namespace

    from nexus_control.cli.cmd_vk_teams import run_vk_teams
    from nexus_control.config import Settings as Cfg
    from nexus_control.config_io import read_toml, write_toml_atomic

    cfg_path = tmp_path / "config.toml"
    write_toml_atomic(
        cfg_path,
        {"nexus_url": "http://localhost:8081", "vk_teams_notify": "off"},
    )
    cache = tmp_path / "cache"
    cache.mkdir()
    settings = Cfg(
        nexus_url="http://localhost:8081",
        nexus_cache_dir=cache,
        download_root=tmp_path / "dl",
        reports_root=tmp_path / "reports",
        verified_root=tmp_path / "verified",
        log_file=tmp_path / "logs" / "app.log",
        vk_teams_token="",
        vk_teams_chat_id="",
        vk_teams_notify="off",
    )
    monkeypatch.setenv("NEXUS_CONTROL_CONFIG", str(cfg_path))
    monkeypatch.setattr(
        "nexus_control.cli.cmd_vk_teams.load_settings",
        lambda: settings,
    )
    monkeypatch.setattr(
        "nexus_control.cli.cmd_vk_teams.resolve_config_path",
        lambda: cfg_path,
    )
    answers = iter(
        [
            "https://example.test/bot/v1",
            "chat-cli",
            "always",
            "y",
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _p="": next(answers))
    monkeypatch.setattr(
        "nexus_control.cli.cmd_vk_teams.getpass.getpass",
        lambda _p="": "cli-secret-token",
    )

    assert run_vk_teams(Namespace(vk_action="configure")) == 0
    data = read_toml(cfg_path)
    assert data["vk_teams_chat_id"] == "chat-cli"
    assert data["vk_teams_notify"] == "always"
    assert data["vk_teams_upload_button"] is True
    assert "vk_teams_token" not in data
    vault = VkTeamsVault(cache)
    stored = vault.load()
    assert stored is not None
    assert stored.token == "cli-secret-token"

    filled = apply_vk_teams_vault(
        settings.model_copy(
            update={
                "vk_teams_chat_id": "chat-cli",
                "vk_teams_notify": "always",
            }
        )
    )
    monkeypatch.setattr(
        "nexus_control.cli.cmd_vk_teams.load_settings",
        lambda: filled,
    )
    code = run_vk_teams(Namespace(vk_action="status", json=True))
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["configured"] is True
    assert payload["token_present"] is True
    assert payload["chat_id"] == "chat-cli"

    assert run_vk_teams(Namespace(vk_action="disable", clear_vault=True)) == 0
    data = read_toml(cfg_path)
    assert data["vk_teams_notify"] == "off"
    assert vault.load() is None


def test_vk_teams_cli_test_sends_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from argparse import Namespace

    from nexus_control.cli.cmd_vk_teams import run_vk_teams

    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "nexus_control.cli.cmd_vk_teams.load_settings",
        lambda: settings,
    )
    client = MagicMock(spec=VkTeamsClient)
    client.send_text.return_value = {"ok": True, "msgId": "1"}
    monkeypatch.setattr(
        "nexus_control.cli.cmd_vk_teams.VkTeamsClient.from_settings",
        lambda _s: client,
    )
    assert run_vk_teams(Namespace(vk_action="test")) == 0
    client.send_text.assert_called_once()
    assert "Проверка связи" in client.send_text.call_args[0][1]
