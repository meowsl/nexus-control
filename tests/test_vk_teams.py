"""Tests for VK Teams notify / pending upload / client helpers."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch
import time

import pytest

from nexus_control.config import Settings
from nexus_control.integrations.vk_notify import (
    CALLBACK_PREFIX,
    PendingUpload,
    PendingUploadStore,
    build_rule_message,
    handle_callback,
    notify_rule_finished,
    should_notify,
    vk_teams_configured,
    vk_teams_should_poll,
)
from nexus_control.integrations.vk_teams import (
    VkTeamsClient,
    VkTeamsError,
    upload_keyboard,
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
) -> ScanRunMeta:
    return ScanRunMeta(
        run_id=f"run_{repo}",
        repository=repo,
        started_at="2026-08-10T10:00:00+00:00",
        finished_at="2026-08-10T10:01:00+00:00",
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


def test_build_rule_message_verify_only() -> None:
    rule = ScheduleRule(
        id="nightly",
        cron="0 3 * * *",
        repos=["test-pypi", "test-npm"],
        action="verify",
        description="Nightly",
    )
    text = build_rule_message(
        rule,
        0,
        {
            "test-pypi": _meta(
                "test-pypi",
                checkpoint_skipped=8,
            ),
            "test-npm": _meta("test-npm", passed=7, copied=7, scanned=7),
        },
    )
    assert "nightly" in text
    assert "test-pypi" in text
    assert "Skipped=8" in text
    assert "PASS=7" in text
    assert "verify-only" in text


def test_build_rule_message_verify_upload() -> None:
    rule = ScheduleRule(
        id="auto",
        cron="0 3 * * *",
        repos=["r1"],
        action="verify_upload",
    )
    text = build_rule_message(rule, 0, {"r1": None})
    assert "automatic" in text
    assert "no history yet" in text


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
    assert kb == [[{"text": "Upload", "callbackData": "up:tok"}]]


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
