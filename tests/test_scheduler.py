"""Tests for schedule.toml model, cron, pidfile, overlap skip."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

import pytest

from nexus_control.scheduler.cronutil import (
    CronError,
    format_iso_in_timezone,
    next_fire,
    preview_next_fires,
    validate_cron,
)
from nexus_control.scheduler.daemon import _due_rules
from nexus_control.scheduler.jobs import run_rule
from nexus_control.scheduler.models import ScheduleConfig, ScheduleRule
from nexus_control.scheduler.pidfile import PidLock, PidfileError, running_pid
from nexus_control.scheduler.state import SchedulerState, load_state, save_state
from nexus_control.scheduler.store import (
    ScheduleStoreError,
    config_to_dict,
    load_schedule,
    parse_schedule_dict,
    save_schedule,
)


def test_validate_cron_accepts_five_fields() -> None:
    assert validate_cron(" 0  3 * * 1-5 ") == "0 3 * * 1-5"


def test_system_timezone_and_local_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    from nexus_control.scheduler.cronutil import (
        LOCAL_TIMEZONE,
        effective_timezone,
        system_timezone_name,
    )

    system_timezone_name.cache_clear()
    monkeypatch.setenv("TZ", "Europe/Berlin")
    system_timezone_name.cache_clear()
    assert system_timezone_name() == "Europe/Berlin"
    assert effective_timezone("local") == "Europe/Berlin"
    assert effective_timezone("") == "Europe/Berlin"
    assert effective_timezone(LOCAL_TIMEZONE) == "Europe/Berlin"
    assert effective_timezone("UTC") == "UTC"

    cfg = ScheduleConfig()
    assert cfg.timezone == LOCAL_TIMEZONE
    assert cfg.resolved_timezone() == "Europe/Berlin"
    system_timezone_name.cache_clear()


def test_parse_missing_timezone_defaults_to_local() -> None:
    from nexus_control.scheduler.cronutil import LOCAL_TIMEZONE

    config = parse_schedule_dict({"rules": []})
    assert config.timezone == LOCAL_TIMEZONE


def test_find_preset_by_key_and_cron() -> None:
    from nexus_control.scheduler.cronutil import find_preset

    p1 = find_preset("1")
    assert p1 is not None
    assert p1.cron == "0 3 * * *"
    assert find_preset("0 3 * * 1-5") is not None
    assert find_preset("nope") is None


def test_validate_cron_rejects_bad() -> None:
    with pytest.raises(CronError):
        validate_cron("0 3 * *")
    with pytest.raises(CronError):
        validate_cron("not a cron")


def test_next_fire_timezone() -> None:
    after = datetime(2026, 8, 10, 2, 0, tzinfo=ZoneInfo("Europe/Moscow"))
    nxt = next_fire("0 3 * * *", timezone="Europe/Moscow", after=after)
    assert nxt.hour == 3
    assert nxt.tzinfo is not None
    fires = preview_next_fires(
        "0 3 * * 1-5", timezone="UTC", count=2, after=after.astimezone(ZoneInfo("UTC"))
    )
    assert len(fires) == 2
    assert fires[0] < fires[1]


def test_format_iso_in_timezone() -> None:
    assert (
        format_iso_in_timezone(
            "2026-08-14T03:05:01.554728+00:00",
            "Europe/Moscow",
        )
        == "2026-08-14T06:05:01+03:00"
    )
    assert format_iso_in_timezone("", "Europe/Moscow") == ""
    assert format_iso_in_timezone("not-a-date", "Europe/Moscow") == "not-a-date"


def test_parse_and_roundtrip_schedule(tmp_path: Path) -> None:
    data = {
        "scheduler": {"timezone": "Europe/Moscow", "overlap": "skip"},
        "rules": [
            {
                "id": "nightly-core",
                "enabled": True,
                "cron": "0 3 * * 1-5",
                "description": "core",
                "repos": ["maven-hosted", "npm-hosted"],
                "action": "verify_upload",
            },
            {
                "id": "weekend",
                "cron": "30 4 * * 6",
                "repos": ["raw-hosted"],
                "action": "verify",
                "upload": True,
                "path_prefix": "com/example",
                "workers": 2,
                "limit": 10,
                "scan_limit": 5,
            },
        ],
    }
    config = parse_schedule_dict(data)
    assert config.timezone == "Europe/Moscow"
    assert len(config.rules) == 2
    assert config.rules[0].wants_upload()
    assert config.rules[1].wants_verify()
    assert config.rules[1].wants_upload()
    assert config.rules[1].scan_limit == 5
    assert config.get_rule("weekend") is not None

    path = tmp_path / "schedule.toml"
    save_schedule(config, path)
    loaded = load_schedule(path)
    assert loaded.timezone == "Europe/Moscow"
    assert [r.id for r in loaded.rules] == ["nightly-core", "weekend"]
    assert loaded.rules[1].path_prefixes == ["com/example"]
    assert loaded.rules[1].path_prefix == "com/example"
    assert loaded.rules[1].workers == 2
    assert loaded.rules[1].scan_limit == 5


def test_parse_path_prefixes_string_and_list(tmp_path: Path) -> None:
    as_string = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "s",
                    "cron": "0 1 * * *",
                    "repos": ["r"],
                    "path_prefix": "/com/example",
                }
            ]
        }
    )
    assert as_string.rules[0].path_prefixes == ["com/example"]

    as_list = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "m",
                    "cron": "0 1 * * *",
                    "repos": ["r"],
                    "path_prefixes": ["com/", "org/", "/com/"],
                }
            ]
        }
    )
    assert as_list.rules[0].path_prefixes == ["com/", "org/"]
    assert as_list.rules[0].path_prefix == "com/,org/"

    merged = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "both",
                    "cron": "0 1 * * *",
                    "repos": ["r"],
                    "path_prefix": "com/",
                    "path_prefixes": ["org/", "net/"],
                }
            ]
        }
    )
    assert merged.rules[0].path_prefixes == ["com/", "org/", "net/"]

    out = tmp_path / "s.toml"
    save_schedule(as_list, out)
    text = out.read_text(encoding="utf-8")
    assert "path_prefixes" in text
    reloaded = load_schedule(out)
    assert reloaded.rules[0].path_prefixes == ["com/", "org/"]


def test_parse_excluded_prefixes_string_and_list(tmp_path: Path) -> None:
    as_string = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "s",
                    "cron": "0 1 * * *",
                    "repos": ["r"],
                    "excluded_prefix": "/com/",
                }
            ]
        }
    )
    assert as_string.rules[0].excluded_prefixes == ["com/"]
    assert as_string.rules[0].path_prefixes == []

    as_list = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "m",
                    "cron": "0 1 * * *",
                    "repos": ["r"],
                    "path_prefixes": ["com/", "org/"],
                    "excluded_prefixes": ["com/internal/", "/org/exp/"],
                }
            ]
        }
    )
    assert as_list.rules[0].path_prefixes == ["com/", "org/"]
    assert as_list.rules[0].excluded_prefixes == ["com/internal/", "org/exp/"]

    out = tmp_path / "s.toml"
    save_schedule(as_list, out)
    text = out.read_text(encoding="utf-8")
    assert "excluded_prefixes" in text
    reloaded = load_schedule(out)
    assert reloaded.rules[0].excluded_prefixes == ["com/internal/", "org/exp/"]


def test_parse_rejects_duplicate_ids() -> None:
    with pytest.raises(ScheduleStoreError, match="Duplicate"):
        parse_schedule_dict(
            {
                "rules": [
                    {"id": "a", "cron": "0 1 * * *", "repos": ["r1"]},
                    {"id": "a", "cron": "0 2 * * *", "repos": ["r2"]},
                ]
            }
        )


def test_parse_rejects_bad_overlap_and_action() -> None:
    with pytest.raises(ScheduleStoreError, match="overlap"):
        parse_schedule_dict({"scheduler": {"overlap": "nope"}, "rules": []})
    with pytest.raises(ScheduleStoreError, match="action"):
        parse_schedule_dict(
            {"rules": [{"id": "x", "cron": "0 1 * * *", "repos": ["r"], "action": "scan"}]}
        )


def test_empty_schedule_missing_file(tmp_path: Path) -> None:
    from nexus_control.scheduler.cronutil import LOCAL_TIMEZONE

    missing = tmp_path / "missing.toml"
    config = load_schedule(missing)
    assert config.rules == []
    assert config.overlap == "queue"
    assert config.timezone == LOCAL_TIMEZONE


def test_config_to_dict_omits_empty_overrides() -> None:
    config = ScheduleConfig(
        rules=[
            ScheduleRule(
                id="r",
                cron="0 0 * * *",
                repos=["repo"],
                action="verify",
            )
        ]
    )
    dumped = config_to_dict(config)
    rule = dumped["rules"][0]
    assert "target" not in rule
    assert "scanners" not in rule
    assert "severity" not in rule
    assert "workers" not in rule


def test_pidfile_single_instance(tmp_path: Path) -> None:
    pid = tmp_path / "scheduler.pid"
    lock = tmp_path / "scheduler.lock"
    first = PidLock(pid_path=pid, lock_path=lock)
    first.acquire()
    assert running_pid(pid) is not None
    second = PidLock(pid_path=pid, lock_path=lock)
    with pytest.raises(PidfileError, match="already running"):
        second.acquire()
    first.release()
    assert running_pid(pid) is None


def test_state_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "scheduler-state.json"
    state = SchedulerState(started_at="t0", pid=123, busy=True, current_rule="r1")
    state.next_fires["r1"] = "2026-01-01T00:00:00+00:00"
    state.current_repo = "maven-hosted"
    state.progress_pct = 0.42
    state.progress_stage = "scan"
    state.progress_asset = "a.jar"
    state.progress_message = "scan: a.jar"
    state.progress_updated_at = "t1"
    save_state(path, state)
    loaded = load_state(path)
    assert loaded.pid == 123
    assert loaded.busy is True
    assert loaded.next_fires["r1"].startswith("2026")
    assert loaded.current_repo == "maven-hosted"
    assert loaded.progress_pct == 0.42
    assert loaded.progress_stage == "scan"
    assert loaded.progress_asset == "a.jar"
    loaded.clear_progress()
    assert loaded.progress_pct is None
    assert loaded.current_repo is None


def test_state_progress_sink_throttled(tmp_path: Path) -> None:
    from nexus_control.scheduler.progress import StateProgressSink

    path = tmp_path / "scheduler-state.json"
    state = SchedulerState(busy=True, current_rule="r1")
    save_state(path, state)
    sink = StateProgressSink(path, state, min_interval=10.0)
    sink("pkg.jar", 0.1, "download")
    first = load_state(path)
    assert first.progress_pct == 0.1
    assert first.progress_stage == "download"
    # throttled — second call within interval should not overwrite
    sink("other.jar", 0.2, "download")
    second = load_state(path)
    assert second.progress_asset == "pkg.jar"
    # completion always writes
    sink("other.jar", 1.0, "scan")
    done = load_state(path)
    assert done.progress_pct == 1.0
    assert done.progress_asset.endswith("other.jar")
    sink.status("Selecting assets…")
    # status may be throttled after completion write; force via final
    sink.status("Selecting done", final=True)
    assert load_state(path).progress_message == "Selecting done"


def test_due_rules_marks_recent_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    tz = ZoneInfo("UTC")
    # Freeze "now" just after 03:00 UTC on a weekday.
    frozen = datetime(2026, 8, 10, 3, 0, 30, tzinfo=tz)

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN001
            if tz is None:
                return frozen.replace(tzinfo=None)
            return frozen.astimezone(tz)

    monkeypatch.setattr("nexus_control.scheduler.daemon.datetime", _FrozenDateTime)

    config = ScheduleConfig(
        timezone="UTC",
        rules=[
            ScheduleRule(
                id="nightly",
                cron="0 3 * * *",
                repos=["maven-hosted"],
                enabled=True,
            ),
            ScheduleRule(
                id="later",
                cron="0 15 * * *",
                repos=["npm-hosted"],
                enabled=True,
            ),
        ],
    )
    # Baseline like daemon seed: only the just-fired nightly slot is open.
    baseline = {"later": "202608091500"}
    due = _due_rules(config, last_fires=baseline)
    assert [r.id for r, _, _ in due] == ["nightly"]
    due2 = _due_rules(
        config,
        last_fires={**baseline, "nightly": "202608100300"},
    )
    assert due2 == []


def test_due_rules_queues_missed_slot_after_long_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """02:05 still due at 02:20 if the 02:00 job ran long (catch-up queue)."""
    tz = ZoneInfo("UTC")
    frozen = datetime(2026, 8, 10, 2, 20, 0, tzinfo=tz)

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN001
            if tz is None:
                return frozen.replace(tzinfo=None)
            return frozen.astimezone(tz)

    monkeypatch.setattr("nexus_control.scheduler.daemon.datetime", _FrozenDateTime)

    config = ScheduleConfig(
        timezone="UTC",
        rules=[
            ScheduleRule(
                id="early",
                cron="0 2 * * *",
                repos=["maven-hosted"],
                enabled=True,
            ),
            ScheduleRule(
                id="five-past",
                cron="5 2 * * *",
                repos=["npm-hosted"],
                enabled=True,
            ),
        ],
    )
    # early already finished its 02:00 slot; five-past was blocked during that run.
    last_fires = {"early": "202608100200"}
    due = _due_rules(config, last_fires=last_fires)
    assert [r.id for r, _, _ in due] == ["five-past"]
    assert due[0][1].hour == 2 and due[0][1].minute == 5


def test_seed_past_fires_skips_stale_but_keeps_fresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nexus_control.scheduler.daemon import _seed_past_fires

    tz = ZoneInfo("UTC")
    frozen = datetime(2026, 8, 10, 10, 0, 0, tzinfo=tz)

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN001
            if tz is None:
                return frozen.replace(tzinfo=None)
            return frozen.astimezone(tz)

    monkeypatch.setattr("nexus_control.scheduler.daemon.datetime", _FrozenDateTime)

    config = ScheduleConfig(
        timezone="UTC",
        rules=[
            ScheduleRule(id="morning", cron="0 3 * * *", repos=["r"], enabled=True),
        ],
    )
    state = SchedulerState()
    _seed_past_fires(config, state, grace_seconds=90)
    assert state.last_fires["morning"] == "202608100300"
    assert _due_rules(config, state.last_fires) == []

    # Already-tracked rules must not be re-seeded (catch-up after downtime).
    state2 = SchedulerState(last_fires={"morning": "202608090300"})
    _seed_past_fires(config, state2, grace_seconds=90)
    assert state2.last_fires["morning"] == "202608090300"
    due = _due_rules(config, state2.last_fires)
    assert [r.id for r, _, _ in due] == ["morning"]


def test_run_rule_calls_verify_per_repo() -> None:
    rule = ScheduleRule(
        id="multi",
        cron="0 0 * * *",
        repos=["a", "b"],
        action="verify_upload",
        scanners="grype",
        targets={"a": "a-clean", "b": "b-clean"},
    )
    with patch("nexus_control.scheduler.jobs.run_verify", return_value=0) as verify:
        code = run_rule(rule)
    assert code == 0
    assert verify.call_count == 2
    first = verify.call_args_list[0].args[0]
    assert first.repo == "a"
    assert first.upload is True
    assert first.scanners == "grype"
    assert first.target == "a-clean"
    assert first.scan_mode == "incremental"
    assert verify.call_args_list[1].args[0].target == "b-clean"


def test_run_rule_passes_full_scan_mode() -> None:
    rule = ScheduleRule(
        id="weekly",
        cron="0 0 * * 6",
        repos=["a"],
        action="verify_upload",
        scan_mode="full",
    )
    with patch("nexus_control.scheduler.jobs.run_verify", return_value=0) as verify:
        assert run_rule(rule) == 0
    assert verify.call_args.args[0].scan_mode == "full"
    assert verify.call_args.args[0].upload is True


def test_parse_scan_mode_full() -> None:
    parsed = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "weekly",
                    "cron": "0 0 * * 6",
                    "repos": ["maven-hosted"],
                    "action": "verify_upload",
                    "scan_mode": "full",
                }
            ]
        }
    )
    assert parsed.rules[0].scan_mode == "full"

    with pytest.raises(ScheduleStoreError, match="scan_mode"):
        parse_schedule_dict(
            {
                "rules": [
                    {
                        "id": "bad",
                        "cron": "0 0 * * *",
                        "repos": ["maven-hosted"],
                        "scan_mode": "weekly",
                    }
                ]
            }
        )


def test_target_for_defaults_and_rejects_shared_comma_target() -> None:
    rule = ScheduleRule(
        id="r",
        cron="0 0 * * *",
        repos=["test-raw", "test-pypi"],
        targets={"test-raw": "test-raw-verified"},
    )
    assert rule.target_for("test-raw") == "test-raw-verified"
    assert rule.target_for("test-pypi") is None  # → <repo>-verified

    with pytest.raises(ScheduleStoreError, match="single 'target'"):
        parse_schedule_dict(
            {
                "rules": [
                    {
                        "id": "bad",
                        "cron": "0 0 * * *",
                        "repos": ["test-raw", "test-pypi"],
                        "target": "only-one-target",
                        "action": "verify_upload",
                    }
                ]
            }
        )

    migrated = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "legacy",
                    "cron": "0 0 * * *",
                    "repos": ["test-raw", "test-pypi"],
                    "target": "test-raw-verified,pypi-verified",
                    "action": "verify_upload",
                }
            ]
        }
    )
    assert migrated.rules[0].targets == {
        "test-raw": "test-raw-verified",
        "test-pypi": "pypi-verified",
    }
    assert migrated.rules[0].target is None

    ok = parse_schedule_dict(
        {
            "rules": [
                {
                    "id": "ok",
                    "cron": "0 0 * * *",
                    "repos": ["test-raw", "test-pypi"],
                    "action": "verify_upload",
                    "targets": {
                        "test-raw": "test-raw-verified",
                        "test-pypi": "pypi-verified",
                    },
                }
            ]
        }
    )
    assert ok.rules[0].target_for("test-pypi") == "pypi-verified"


def test_run_rule_upload_only() -> None:
    rule = ScheduleRule(
        id="up",
        cron="0 0 * * *",
        repos=["a"],
        action="upload",
    )
    with patch("nexus_control.scheduler.jobs.run_upload", return_value=0) as upload:
        with patch("nexus_control.scheduler.jobs.run_verify") as verify:
            assert run_rule(rule) == 0
    upload.assert_called_once()
    verify.assert_not_called()


def test_overlap_skip_records_skipped(tmp_path: Path) -> None:
    """Simulate busy+skip path used by daemon."""
    from nexus_control.scheduler.daemon import _execute_rule
    from nexus_control.scheduler.state import RuleRunRecord, iso_now

    state_file = tmp_path / "state.json"
    state = SchedulerState(busy=True, current_rule="other")
    # Directly exercise the skip record shape expected by daemon loop.
    state.last_runs["nightly"] = RuleRunRecord(
        rule_id="nightly",
        started_at=iso_now(),
        finished_at=iso_now(),
        exit_code=0,
        message="skipped: busy with other",
        skipped=True,
    )
    save_state(state_file, state)
    loaded = load_state(state_file)
    assert loaded.last_runs["nightly"].skipped is True

    # _execute_rule still runs when called (overlap check is in loop)
    rule = ScheduleRule(id="x", cron="0 0 * * *", repos=["r"])
    settings = MagicMock()
    settings.vk_teams_token = ""
    settings.vk_teams_chat_id = ""
    settings.vk_teams_notify = "off"
    with patch("nexus_control.scheduler.daemon.run_rule", return_value=0):
        with patch(
            "nexus_control.scheduler.daemon.notify_rule_finished"
        ):
            st = SchedulerState()
            _execute_rule(
                settings,
                rule,
                datetime(2026, 1, 1, tzinfo=ZoneInfo("UTC")),
                "x:202601010000",
                st,
                state_file,
            )
    assert st.last_fires["x"] == "202601010000"


def test_run_rule_now_records_last_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Menu / schedule run пишет last_runs, но не last_fires."""
    from nexus_control.scheduler.daemon import run_rule_now
    from nexus_control.scheduler.models import ScheduleConfig, ScheduleRule

    schedule_path = tmp_path / "schedule.toml"
    save_schedule(
        ScheduleConfig(
            timezone="UTC",
            rules=[
                ScheduleRule(
                    id="nightly",
                    cron="0 3 * * *",
                    repos=["maven-hosted"],
                )
            ],
        ),
        schedule_path,
    )
    cache = tmp_path / "cache"
    cache.mkdir()
    state_file = cache / "scheduler-state.json"
    save_state(
        state_file,
        SchedulerState(last_fires={"nightly": "202608100300"}),
    )

    fake_settings = MagicMock()
    fake_settings.nexus_cache_dir = cache
    fake_settings.log_file = tmp_path / "logs" / "app.log"
    fake_settings.log_level = "INFO"
    fake_settings.nexus_password = None
    fake_settings.vk_teams_token = ""
    fake_settings.vk_teams_chat_id = ""
    fake_settings.vk_teams_notify = "off"

    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.load_cli_settings",
        lambda allow_prompt=False: fake_settings,
    )
    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.running_pid",
        lambda _path: None,
    )
    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.setup_logging",
        lambda *_args, **_kwargs: None,
    )

    with patch("nexus_control.scheduler.daemon.run_rule", return_value=0) as run:
        code = run_rule_now("nightly", schedule_file=schedule_path, foreground=True)

    assert code == 0
    run.assert_called_once()
    loaded = load_state(state_file)
    assert loaded.last_runs["nightly"].exit_code == 0
    assert loaded.last_runs["nightly"].message.startswith("manual exit=")
    assert loaded.last_fires["nightly"] == "202608100300"
    assert loaded.busy is False
    assert loaded.current_rule is None


def test_menu_status_smoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from argparse import Namespace

    from nexus_control.cli.cmd_schedule import run_schedule
    from nexus_control.scheduler.models import ScheduleConfig, ScheduleRule

    path = tmp_path / "schedule.toml"
    save_schedule(
        ScheduleConfig(
            timezone="UTC",
            rules=[
                ScheduleRule(
                    id="nightly",
                    cron="0 3 * * *",
                    repos=["maven-hosted"],
                )
            ],
        ),
        path,
    )

    fake_settings = MagicMock()
    fake_settings.nexus_cache_dir = tmp_path / "cache"
    fake_settings.log_file = tmp_path / "logs" / "app.log"
    fake_settings.nexus_cache_dir.mkdir()

    monkeypatch.setattr(
        "nexus_control.scheduler.daemon._settings_no_prompt",
        lambda: fake_settings,
    )
    code = run_schedule(
        Namespace(
            schedule_action="status",
            schedule_file=str(path),
            rule_id=None,
        )
    )
    assert code == 0


def test_status_settings_skip_cli_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    from nexus_control.scheduler.daemon import _settings_no_prompt

    sentinel = object()
    monkeypatch.setattr(
        "nexus_control.config.load_settings",
        lambda **_kwargs: sentinel,
    )

    def _boom(**_kwargs: object) -> None:
        raise AssertionError("status must not resolve Nexus credentials")

    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.load_cli_settings",
        _boom,
    )
    monkeypatch.setattr(
        "nexus_control.cli.bootstrap.load_cli_settings",
        _boom,
    )
    assert _settings_no_prompt() is sentinel


def _manual_run_settings(tmp_path: Path) -> MagicMock:
    fake_settings = MagicMock()
    fake_settings.nexus_cache_dir = tmp_path / "cache"
    fake_settings.nexus_cache_dir.mkdir()
    fake_settings.log_file = tmp_path / "logs" / "nexus-control.log"
    fake_settings.log_level = "INFO"
    fake_settings.nexus_password = None
    fake_settings.vk_teams_token = ""
    fake_settings.vk_teams_chat_id = ""
    fake_settings.vk_teams_notify = "off"
    return fake_settings


def test_run_rule_now_foreground_uses_scheduler_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nexus_control.scheduler.daemon import run_rule_now
    from nexus_control.scheduler.models import ScheduleConfig, ScheduleRule
    from nexus_control.scheduler.paths import scheduler_log_path

    schedule_path = tmp_path / "schedule.toml"
    save_schedule(
        ScheduleConfig(
            timezone="UTC",
            rules=[
                ScheduleRule(
                    id="nightly",
                    cron="0 3 * * *",
                    repos=["maven-hosted"],
                )
            ],
        ),
        schedule_path,
    )
    fake_settings = _manual_run_settings(tmp_path)
    called: dict[str, object] = {}

    def fake_setup(level: str, log_file: Path, password: str | None = None) -> None:
        called["level"] = level
        called["log_file"] = Path(log_file)
        called["password"] = password

    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.load_cli_settings",
        lambda allow_prompt=False: fake_settings,
    )
    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.running_pid",
        lambda _path: None,
    )
    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.setup_logging",
        fake_setup,
    )

    with patch("nexus_control.scheduler.daemon.run_rule", return_value=0):
        with patch("nexus_control.scheduler.daemon.notify_rule_finished"):
            code = run_rule_now(
                "nightly", schedule_file=schedule_path, foreground=True
            )

    assert code == 0
    assert called["log_file"] == scheduler_log_path(fake_settings.log_file)
    assert called["log_file"].name == "scheduler.log"
    assert called["level"] == "INFO"


def test_spawn_rule_run_redirects_stdio_to_scheduler_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from nexus_control.scheduler.daemon import _spawn_rule_run
    from nexus_control.scheduler.paths import scheduler_log_path

    fake_settings = _manual_run_settings(tmp_path)
    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.running_pid",
        lambda _path: None,
    )
    monkeypatch.setattr("time.sleep", lambda _s: None)

    captured: dict[str, object] = {}

    class FakeProc:
        pid = 4242

        def poll(self) -> None:
            return None

    def fake_popen(cmd: list[str], **kwargs: object) -> FakeProc:
        captured["cmd"] = cmd
        captured["stdout"] = kwargs["stdout"]
        captured["stderr"] = kwargs["stderr"]
        captured["env"] = kwargs["env"]
        return FakeProc()

    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.subprocess.Popen",
        fake_popen,
    )

    code = _spawn_rule_run(
        "nightly",
        schedule_path=tmp_path / "schedule.toml",
        settings=fake_settings,
        scan_limit=None,
    )
    assert code == 0

    expected = scheduler_log_path(fake_settings.log_file)
    stdout = captured["stdout"]
    stderr = captured["stderr"]
    assert getattr(stdout, "name") == str(expected)
    assert stderr is stdout
    env = captured["env"]
    assert isinstance(env, dict)
    assert env.get("PYTHONUNBUFFERED") == "1"

    err = capsys.readouterr().err
    assert str(expected) in err
    assert "Log:" in err
    assert "nexus-control.log" not in err


def test_spawn_rule_run_failed_start_points_to_scheduler_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from nexus_control.scheduler.daemon import _spawn_rule_run
    from nexus_control.scheduler.paths import scheduler_log_path

    fake_settings = _manual_run_settings(tmp_path)
    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.running_pid",
        lambda _path: None,
    )
    monkeypatch.setattr("time.sleep", lambda _s: None)

    class DeadProc:
        pid = 7
        returncode = 1

        def poll(self) -> int:
            return 1

    monkeypatch.setattr(
        "nexus_control.scheduler.daemon.subprocess.Popen",
        lambda *_args, **_kwargs: DeadProc(),
    )

    code = _spawn_rule_run(
        "nightly",
        schedule_path=tmp_path / "schedule.toml",
        settings=fake_settings,
        scan_limit=None,
    )
    assert code == 1
    err = capsys.readouterr().err
    expected = scheduler_log_path(fake_settings.log_file)
    assert "Background run failed to start" in err
    assert str(expected) in err
    assert "nexus-control.log" not in err
