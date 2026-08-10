"""Long-running scheduler daemon (pidfile + cron loop)."""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from nexus_control.cli.bootstrap import load_cli_settings
from nexus_control.config import ConfigError, Settings
from nexus_control.logging_setup import setup_logging
from nexus_control.scheduler.cronutil import CronError, next_fire
from nexus_control.scheduler.jobs import run_rule
from nexus_control.scheduler.models import ScheduleConfig, ScheduleRule
from nexus_control.scheduler.paths import (
    lock_path,
    pid_path,
    resolve_schedule_path,
    scheduler_log_path,
    state_path,
)
from nexus_control.scheduler.pidfile import (
    PidLock,
    PidfileError,
    process_is_alive,
    running_pid,
)
from nexus_control.scheduler.state import (
    RuleRunRecord,
    SchedulerState,
    iso_now,
    load_state,
    save_state,
)
from nexus_control.scheduler.store import ScheduleStoreError, load_schedule

logger = logging.getLogger(__name__)

# Внутренний флаг для detached child: run foreground loop.
ENV_DAEMON_FOREGROUND = "NEXUS_CONTROL_SCHEDULER_FOREGROUND"


@dataclass(slots=True)
class DaemonStatus:
    running: bool
    pid: int | None
    schedule_path: Path
    state: SchedulerState
    config: ScheduleConfig


def get_status(
    settings: Settings | None = None,
    *,
    schedule_file: Path | None = None,
) -> DaemonStatus:
    cfg = settings or _settings_no_prompt()
    schedule_path = resolve_schedule_path(schedule_file)
    try:
        config = load_schedule(schedule_path)
    except ScheduleStoreError:
        config = ScheduleConfig()
    sp = state_path(cfg.nexus_cache_dir)
    st = load_state(sp)
    pid = running_pid(pid_path(cfg.nexus_cache_dir))
    return DaemonStatus(
        running=pid is not None,
        pid=pid,
        schedule_path=schedule_path,
        state=st,
        config=config,
    )


def start_daemon(
    *,
    foreground: bool = False,
    schedule_file: Path | None = None,
) -> int:
    """Запустить демон. foreground=True — в текущем процессе (для child/tests)."""
    settings = load_cli_settings(allow_prompt=False)
    schedule_path = resolve_schedule_path(schedule_file)
    try:
        load_schedule(schedule_path)
    except ScheduleStoreError as exc:
        logger.error("%s", exc)
        print(f"Invalid schedule config: {exc}", file=sys.stderr)
        return 2

    existing = running_pid(pid_path(settings.nexus_cache_dir))
    if existing is not None:
        print(f"Scheduler already running (pid={existing})", file=sys.stderr)
        return 1

    if foreground or os.environ.get(ENV_DAEMON_FOREGROUND) == "1":
        return _run_loop(settings, schedule_path)

    return _spawn_detached(schedule_path)


def stop_daemon(settings: Settings | None = None, *, timeout: float = 30.0) -> int:
    """Остановить демон: SIGTERM → wait → при необходимости SIGKILL.

    Во время длинного ``_execute_rule`` флаг stop проверяется только после
    окончания job, поэтому graceful stop может затянуться — тогда форсируем.
    """
    cfg = settings or _settings_no_prompt()
    path = pid_path(cfg.nexus_cache_dir)
    sp = state_path(cfg.nexus_cache_dir)
    pid = running_pid(path)
    if pid is None:
        print("Scheduler is not running.", file=sys.stderr)
        _cleanup_stale_scheduler_files(path, sp, expected_pid=None)
        return 0

    st = load_state(sp)
    if st.busy and st.current_rule:
        print(
            f"Scheduler pid={pid} is busy with rule {st.current_rule!r}; "
            f"sending SIGTERM (will SIGKILL after {timeout:.0f}s if needed)…",
            file=sys.stderr,
        )
    else:
        print(f"Stopping scheduler (pid={pid})…", file=sys.stderr)

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _cleanup_stale_scheduler_files(path, sp, expected_pid=pid)
        print("Scheduler is not running.", file=sys.stderr)
        return 0

    if _wait_until_dead(pid, timeout):
        _cleanup_stale_scheduler_files(path, sp, expected_pid=pid)
        print(f"Stopped scheduler (pid={pid})", file=sys.stderr)
        return 0

    print(
        f"Scheduler pid={pid} did not exit within {timeout:.0f}s; sending SIGKILL…",
        file=sys.stderr,
    )
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        _cleanup_stale_scheduler_files(path, sp, expected_pid=pid)
        print(f"Stopped scheduler (pid={pid})", file=sys.stderr)
        return 0

    if _wait_until_dead(pid, 5.0):
        _cleanup_stale_scheduler_files(path, sp, expected_pid=pid)
        print(f"Stopped scheduler (pid={pid}, forced)", file=sys.stderr)
        return 0

    print(
        f"Scheduler pid={pid} still alive after SIGKILL; check process manually.",
        file=sys.stderr,
    )
    return 1


def _wait_until_dead(pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_is_alive(pid):
            return True
        time.sleep(0.2)
    return not process_is_alive(pid)


def _cleanup_stale_scheduler_files(
    pid_file: Path,
    state_file: Path,
    *,
    expected_pid: int | None,
) -> None:
    """Убрать pidfile и сбросить busy в state после остановки."""
    try:
        if pid_file.is_file():
            if expected_pid is None:
                pid_file.unlink(missing_ok=True)
            else:
                try:
                    current = int(pid_file.read_text(encoding="utf-8").strip())
                except (OSError, ValueError):
                    current = None
                if current in {None, expected_pid}:
                    pid_file.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        st = load_state(state_file)
        if expected_pid is not None and st.pid not in {None, expected_pid}:
            return
        if st.busy or st.current_rule or st.pid is not None:
            st.busy = False
            st.current_rule = None
            st.pid = None
            st.clear_progress()
            save_state(state_file, st)
    except OSError:
        pass


def run_rule_now(rule_id: str, *, schedule_file: Path | None = None) -> int:
    """Синхронный прогон правила (меню / schedule run).

    Креды только из env / scheduler vault — без интерактивного prompt.
    """
    load_cli_settings(allow_prompt=False)
    schedule_path = resolve_schedule_path(schedule_file)
    config = load_schedule(schedule_path)
    rule = config.get_rule(rule_id)
    if rule is None:
        print(f"Unknown rule id: {rule_id}", file=sys.stderr)
        return 2
    if not rule.enabled:
        print(f"Rule {rule_id!r} is disabled; running anyway.", file=sys.stderr)
    print(f"Running rule {rule.id} for repos={rule.repos}", file=sys.stderr)
    return run_rule(rule)


def _settings_no_prompt() -> Settings:
    try:
        return load_cli_settings(allow_prompt=False)
    except ConfigError:
        # Status без credentials: минимальные settings из load_settings.
        from nexus_control.config import load_settings

        return load_settings()


def _spawn_detached(schedule_path: Path) -> int:
    env = os.environ.copy()
    env[ENV_DAEMON_FOREGROUND] = "1"
    cmd = [
        sys.executable,
        "-m",
        "nexus_control.cli",
        "schedule",
        "_daemon",
        "--schedule-file",
        str(schedule_path),
    ]
    # Detach: start_new_session + redirect stdio to /dev/null
    # (логи идут в scheduler.log через setup_logging).
    with open(os.devnull, "rb") as devnull_in, open(os.devnull, "ab") as devnull_out:
        proc = __import__("subprocess").Popen(
            cmd,
            stdin=devnull_in,
            stdout=devnull_out,
            stderr=devnull_out,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
    # Дать child время захватить pidfile.
    time.sleep(0.4)
    if proc.poll() is not None:
        print(
            f"Scheduler failed to start (exit={proc.returncode}). "
            "Check scheduler.log",
            file=sys.stderr,
        )
        return 1
    # pid child'а — из pidfile (после fork внутри child это тот же процесс)
    # Здесь Popen pid и есть daemon pid.
    print(f"Scheduler started (pid={proc.pid})", file=sys.stderr)
    return 0


def _run_loop(settings: Settings, schedule_path: Path) -> int:
    log_path = scheduler_log_path(settings.log_file)
    setup_logging(settings.log_level, log_path, password=settings.nexus_password)
    logger.info("Scheduler daemon starting schedule=%s", schedule_path)

    lock = PidLock(
        pid_path=pid_path(settings.nexus_cache_dir),
        lock_path=lock_path(settings.nexus_cache_dir),
    )
    try:
        lock.acquire()
    except PidfileError as exc:
        logger.error("%s", exc)
        print(str(exc), file=sys.stderr)
        return 1

    stop_flag = False
    reload_flag = False

    def _on_term(signum: int, _frame: object) -> None:
        nonlocal stop_flag
        logger.info("Received signal %s; shutting down", signum)
        stop_flag = True

    def _on_hup(signum: int, _frame: object) -> None:
        nonlocal reload_flag
        logger.info("Received SIGHUP; will reload schedule")
        reload_flag = True

    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    signal.signal(signal.SIGHUP, _on_hup)

    state_file = state_path(settings.nexus_cache_dir)
    state = SchedulerState(started_at=iso_now(), pid=os.getpid())
    save_state(state_file, state)

    try:
        config = load_schedule(schedule_path)
    except ScheduleStoreError as exc:
        logger.error("Invalid schedule at start: %s", exc)
        lock.release()
        return 2

    last_fire_keys: set[str] = set()
    _refresh_next_fires(config, state, state_file)

    while not stop_flag:
        if reload_flag:
            reload_flag = False
            try:
                config = load_schedule(schedule_path)
                state.last_reload_at = iso_now()
                last_fire_keys.clear()
                _refresh_next_fires(config, state, state_file)
                logger.info(
                    "Reloaded schedule (%d rules, tz=%s→%s, overlap=%s)",
                    len(config.rules),
                    config.timezone,
                    config.resolved_timezone(),
                    config.overlap,
                )
            except ScheduleStoreError as exc:
                logger.error("Reload failed: %s", exc)

        due = _due_rules(config, last_fire_keys)
        if due:
            for rule, fire_at, fire_key in due:
                if stop_flag:
                    break
                if state.busy and config.overlap == "skip":
                    logger.warning(
                        "Skipping rule %s (overlap=skip, busy with %s)",
                        rule.id,
                        state.current_rule,
                    )
                    state.last_runs[rule.id] = RuleRunRecord(
                        rule_id=rule.id,
                        started_at=iso_now(),
                        finished_at=iso_now(),
                        exit_code=0,
                        message=f"skipped: busy with {state.current_rule}",
                        skipped=True,
                    )
                    last_fire_keys.add(fire_key)
                    save_state(state_file, state)
                    continue
                # queue/overlap: v1 трактует queue как последовательный wait
                # (мы и так последовательны); overlap — тоже sequential в одном
                # процессе (честный parallel overlap отложен).
                _execute_rule(rule, fire_at, fire_key, state, state_file, last_fire_keys)
            _refresh_next_fires(config, state, state_file)
            continue

        # Sleep until next fire (max 30s so signals/reload are responsive).
        sleep_for = _seconds_until_next(config)
        time.sleep(min(max(sleep_for, 0.2), 30.0))

    state.busy = False
    state.current_rule = None
    save_state(state_file, state)
    lock.release()
    logger.info("Scheduler daemon stopped")
    return 0


def _execute_rule(
    rule: ScheduleRule,
    fire_at: datetime,
    fire_key: str,
    state: SchedulerState,
    state_file: Path,
    last_fire_keys: set[str],
) -> None:
    from nexus_control.scheduler.progress import StateProgressSink

    logger.info(
        "Firing rule %s at %s repos=%s",
        rule.id,
        fire_at.isoformat(),
        rule.repos,
    )
    state.busy = True
    state.current_rule = rule.id
    state.clear_progress()
    started = iso_now()
    save_state(state_file, state)
    sink = StateProgressSink(state_file, state)

    def _on_repo_start(repo: str) -> None:
        state.current_repo = repo
        state.progress_message = f"Starting repo {repo}"
        state.progress_updated_at = iso_now()
        save_state(state_file, state)

    code = 1
    message = ""
    try:
        code = run_rule(rule, on_progress=sink, on_repo_start=_on_repo_start)
        message = f"exit={code}"
    except Exception as exc:  # noqa: BLE001
        logger.exception("Rule %s failed: %s", rule.id, exc)
        code = 1
        message = str(exc)
    finally:
        state.busy = False
        state.current_rule = None
        state.clear_progress()
        state.last_runs[rule.id] = RuleRunRecord(
            rule_id=rule.id,
            started_at=started,
            finished_at=iso_now(),
            exit_code=code,
            message=message,
            skipped=False,
        )
        last_fire_keys.add(fire_key)
        save_state(state_file, state)


def _due_rules(
    config: ScheduleConfig,
    last_fire_keys: set[str],
) -> list[tuple[ScheduleRule, datetime, str]]:
    """Правила, у которых next_fire <= now (и ещё не отмечены в этом слоте)."""
    now = datetime.now(timezone.utc)
    due: list[tuple[ScheduleRule, datetime, str]] = []
    for rule in config.rules:
        if not rule.enabled:
            continue
        try:
            # next_fire after (now - 60s) then check if <= now
            # Better: get previous fire? croniter get_prev
            from croniter import croniter
            from nexus_control.scheduler.cronutil import resolve_tz, validate_cron

            tz = resolve_tz(config.timezone)
            local_now = now.astimezone(tz)
            expr = validate_cron(rule.cron)
            itr = croniter(expr, local_now)
            prev = itr.get_prev(datetime)
            if prev.tzinfo is None:
                prev = prev.replace(tzinfo=tz)
            else:
                prev = prev.astimezone(tz)
            # Fire if previous slot is within the last 90 seconds (catch window)
            # or if we're past it and haven't recorded this minute key yet.
            fire_key = f"{rule.id}:{prev.strftime('%Y%m%d%H%M')}"
            if fire_key in last_fire_keys:
                continue
            age = (local_now - prev).total_seconds()
            if 0 <= age < 90:
                due.append((rule, prev, fire_key))
        except (CronError, ValueError, KeyError) as exc:
            logger.error("Cannot evaluate rule %s: %s", rule.id, exc)
    due.sort(key=lambda item: item[1])
    return due


def _seconds_until_next(config: ScheduleConfig) -> float:
    now = datetime.now(timezone.utc)
    soonest: float | None = None
    for rule in config.rules:
        if not rule.enabled:
            continue
        try:
            nxt = next_fire(rule.cron, timezone=config.timezone, after=now)
            delta = (nxt.astimezone(timezone.utc) - now).total_seconds()
            if soonest is None or delta < soonest:
                soonest = delta
        except CronError:
            continue
    if soonest is None:
        return 30.0
    return max(soonest, 0.5)


def _refresh_next_fires(
    config: ScheduleConfig,
    state: SchedulerState,
    state_file: Path,
) -> None:
    now = datetime.now(timezone.utc)
    next_map: dict[str, str] = {}
    for rule in config.rules:
        if not rule.enabled:
            continue
        try:
            nxt = next_fire(rule.cron, timezone=config.timezone, after=now)
            next_map[rule.id] = nxt.isoformat()
        except CronError as exc:
            next_map[rule.id] = f"error: {exc}"
    state.next_fires = next_map
    state.pid = os.getpid()
    save_state(state_file, state)
