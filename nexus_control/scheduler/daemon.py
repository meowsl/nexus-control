"""Long-running scheduler daemon (pidfile + cron loop)."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from nexus_control.cli.bootstrap import load_cli_settings
from nexus_control.config import Settings
from nexus_control.integrations.vk_notify import (
    notify_rule_finished,
    poll_and_handle_events,
    vk_teams_should_poll,
)
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
from nexus_control.utils.fs import ensure_parent_dir

logger = logging.getLogger(__name__)

# Внутренний флаг для detached child: run foreground loop.
ENV_DAEMON_FOREGROUND = "NEXUS_CONTROL_SCHEDULER_FOREGROUND"
# Child of ``schedule run`` (already detached): execute the rule in-process.
ENV_RUN_FOREGROUND = "NEXUS_CONTROL_SCHEDULER_RUN_FOREGROUND"

# При старте/reload слоты старше grace помечаются handled без запуска
# (чтобы не гонять вчерашние cron). Слоты внутри grace — в очередь.
_STARTUP_GRACE_SECONDS = 90.0
# Short long-poll while a rule is running so Upload still works.
VK_BUSY_POLL_TIME = 2


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


def run_rule_now(
    rule_id: str,
    *,
    schedule_file: Path | None = None,
    scan_limit: int | None = None,
    foreground: bool = False,
) -> int:
    """Прогон правила: по умолчанию в фоне, прогресс через ``schedule status -m``.

    ``foreground=True`` / env ``NEXUS_CONTROL_SCHEDULER_RUN_FOREGROUND`` —
    в текущем процессе (меню-тест, detached child).
    Cron-слоты (``last_fires``) не трогает.
    """
    if os.environ.get(ENV_RUN_FOREGROUND) == "1":
        foreground = True

    settings = load_cli_settings(allow_prompt=False)
    if foreground:
        # load_cli_settings пишет в nexus-control.log; manual run — в scheduler.log.
        _setup_scheduler_file_logging(settings)
    schedule_path = resolve_schedule_path(schedule_file)
    config = load_schedule(schedule_path)
    rule = config.get_rule(rule_id)
    if rule is None:
        print(f"Unknown rule id: {rule_id}", file=sys.stderr)
        return 2
    if not rule.enabled:
        print(f"Rule {rule_id!r} is disabled; running anyway.", file=sys.stderr)
    if scan_limit is not None and scan_limit < 1:
        print("--scan-limit must be >= 1", file=sys.stderr)
        return 2

    if not foreground:
        return _spawn_rule_run(
            rule.id,
            schedule_path=schedule_path,
            settings=settings,
            scan_limit=scan_limit,
        )
    return _run_rule_foreground(
        rule,
        settings=settings,
        scan_limit=scan_limit,
    )


def _setup_scheduler_file_logging(settings: Settings) -> Path:
    """Писать логи демона и manual run в scheduler.log (не в nexus-control.log)."""
    log_path = scheduler_log_path(settings.log_file)
    setup_logging(settings.log_level, log_path, password=settings.nexus_password)
    return log_path


def _active_manual_pid(state: SchedulerState) -> int | None:
    pid = state.run_pid
    if pid is None:
        return None
    if process_is_alive(pid):
        return pid
    return None


def _spawn_rule_run(
    rule_id: str,
    *,
    schedule_path: Path,
    settings: Settings,
    scan_limit: int | None,
) -> int:
    state_file = state_path(settings.nexus_cache_dir)
    state = load_state(state_file)
    daemon_pid = running_pid(pid_path(settings.nexus_cache_dir))
    manual_pid = _active_manual_pid(state)

    if manual_pid is not None:
        print(
            f"A manual run is already active (pid={manual_pid}, "
            f"rule={state.current_rule!r}). "
            "Watch: nexus-control-cli schedule status -m",
            file=sys.stderr,
        )
        return 1
    if daemon_pid is not None and state.busy:
        print(
            f"Scheduler daemon is busy with {state.current_rule!r} "
            f"(pid={daemon_pid}). "
            "Watch: nexus-control-cli schedule status -m",
            file=sys.stderr,
        )
        return 1
    if state.busy:
        state.busy = False
        state.current_rule = None
        state.run_pid = None
        state.clear_progress()
        save_state(state_file, state)

    env = os.environ.copy()
    env[ENV_RUN_FOREGROUND] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    cmd = [
        sys.executable,
        "-m",
        "nexus_control.cli",
        "schedule",
        "_run",
        rule_id,
        "--schedule-file",
        str(schedule_path),
    ]
    if scan_limit is not None:
        cmd.extend(["--scan-limit", str(scan_limit)])
    log_path = scheduler_log_path(settings.log_file)
    ensure_parent_dir(log_path)
    # stdin → /dev/null; stdout/stderr → scheduler.log (ошибки до setup_logging
    # и Rich-прогресс не теряются). Child FileHandler пишет в тот же файл.
    with open(os.devnull, "rb") as devnull_in, open(log_path, "ab") as log_out:
        proc = subprocess.Popen(
            cmd,
            stdin=devnull_in,
            stdout=log_out,
            stderr=log_out,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
    time.sleep(0.4)
    if proc.poll() is not None:
        print(
            f"Background run failed to start (exit={proc.returncode}). "
            f"Check {log_path}",
            file=sys.stderr,
        )
        return 1
    print(
        f"Started rule {rule_id!r} in background (pid={proc.pid}).\n"
        f"Progress: nexus-control-cli schedule status -m\n"
        f"Log: {log_path}",
        file=sys.stderr,
    )
    return 0


def _run_rule_foreground(
    rule: ScheduleRule,
    *,
    settings: Settings,
    scan_limit: int | None,
) -> int:
    effective = scan_limit if scan_limit is not None else rule.scan_limit
    print(
        f"Running rule {rule.id} for repos={rule.repos}"
        + (f" scan_limit={effective}" if effective is not None else ""),
        file=sys.stderr,
    )

    state_file = state_path(settings.nexus_cache_dir)
    state = load_state(state_file)
    daemon_pid = running_pid(pid_path(settings.nexus_cache_dir))
    claim_busy = not (daemon_pid is not None and state.busy)

    from nexus_control.scheduler.progress import StateProgressSink

    started = iso_now()
    sink = None
    on_repo_start = None
    if claim_busy:
        state.busy = True
        state.current_rule = rule.id
        state.run_pid = os.getpid()
        state.clear_progress()
        save_state(state_file, state)
        sink = StateProgressSink(state_file, state)

        def _on_repo_start(repo: str) -> None:
            state.current_repo = repo
            state.progress_message = f"Starting repo {repo}"
            state.progress_updated_at = iso_now()
            save_state(state_file, state)

        on_repo_start = _on_repo_start
    else:
        logger.info(
            "Manual run of %s while daemon busy with %s; "
            "last_runs will still be recorded",
            rule.id,
            state.current_rule,
        )

    code = 1
    message = ""
    try:
        code = run_rule(
            rule,
            on_progress=sink,
            on_repo_start=on_repo_start,
            scan_limit=scan_limit,
        )
        message = f"manual exit={code}"
    except KeyboardInterrupt:
        logger.warning("Manual rule %s interrupted", rule.id)
        code = 130
        message = "manual interrupted"
    except Exception as exc:  # noqa: BLE001
        logger.exception("Manual rule %s failed: %s", rule.id, exc)
        code = 1
        message = f"manual error: {exc}"
    finally:
        latest = load_state(state_file)
        latest.last_runs[rule.id] = RuleRunRecord(
            rule_id=rule.id,
            started_at=started,
            finished_at=iso_now(),
            exit_code=code,
            message=message,
            skipped=False,
        )
        if claim_busy and latest.current_rule == rule.id:
            latest.busy = False
            latest.current_rule = None
            latest.run_pid = None
            latest.clear_progress()
        save_state(state_file, latest)
    try:
        notify_rule_finished(settings, rule, code, manual=True)
    except Exception:  # noqa: BLE001
        logger.exception("VK Teams notify_rule_finished failed")
    return code


def _settings_no_prompt() -> Settings:
    """Settings для status/monitor: без vault и без SSL-warning.

    ``schedule status -m`` опрашивает state раз в секунду — нельзя
    каждый тик резолвить credentials (это спамило ``Restored credentials``).
    """
    from nexus_control.config import load_settings

    return load_settings(run_wizard=False)


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
    _setup_scheduler_file_logging(settings)
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

    # Persist handled cron slots across restarts so catch-up queue works
    # after a long job without replaying ancient fires on cold start.
    _seed_past_fires(config, state, grace_seconds=_STARTUP_GRACE_SECONDS)
    save_state(state_file, state)
    _refresh_next_fires(config, state, state_file)

    while not stop_flag:
        if reload_flag:
            reload_flag = False
            try:
                config = load_schedule(schedule_path)
                state.last_reload_at = iso_now()
                # Не сбрасываем last_fires — иначе сегодняшние слоты уйдут
                # в очередь повторно. Только досеиваем «старые» для новых rules.
                _seed_past_fires(config, state, grace_seconds=_STARTUP_GRACE_SECONDS)
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

        due = _due_rules(config, state.last_fires)
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
                    _mark_fire_handled(state, rule.id, fire_key)
                    save_state(state_file, state)
                    continue
                # queue (default) / overlap: последовательная очередь.
                # Слот, чьё время уже наступило, ждёт окончания текущего job
                # и стартует следом (catch-up без окна 90с).
                # Честный parallel overlap отложен.
                _execute_rule(
                    settings, rule, fire_at, fire_key, state, state_file
                )
            _refresh_next_fires(config, state, state_file)
            continue

        # Sleep until next fire (max 30s so signals/reload are responsive).
        # When VK Teams Upload buttons are enabled, long-poll events instead.
        sleep_for = _seconds_until_next(config)
        wait = min(max(sleep_for, 0.2), 30.0)
        if vk_teams_should_poll(settings):
            poll_time = max(1, min(int(wait), 25))
            try:
                poll_and_handle_events(settings, poll_time=poll_time)
            except Exception:  # noqa: BLE001
                logger.exception("VK Teams event poll failed")
                time.sleep(min(wait, 5.0))
        else:
            time.sleep(wait)

    state.busy = False
    state.current_rule = None
    save_state(state_file, state)
    lock.release()
    logger.info("Scheduler daemon stopped")
    return 0


@contextmanager
def _vk_poll_during_job(settings: Settings) -> Iterator[None]:
    """Short-poll VK Teams while a rule runs so Upload stays responsive."""
    if not vk_teams_should_poll(settings):
        yield
        return
    stop = threading.Event()

    def _run() -> None:
        while not stop.is_set():
            try:
                poll_and_handle_events(settings, poll_time=VK_BUSY_POLL_TIME)
            except Exception:  # noqa: BLE001
                logger.exception("VK Teams event poll failed (busy)")
                if stop.wait(1.0):
                    return
            if stop.wait(0.05):
                return

    thread = threading.Thread(
        target=_run,
        name="vk-teams-poll",
        daemon=True,
    )
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=float(VK_BUSY_POLL_TIME + 3))


def _execute_rule(
    settings: Settings,
    rule: ScheduleRule,
    fire_at: datetime,
    fire_key: str,
    state: SchedulerState,
    state_file: Path,
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
        with _vk_poll_during_job(settings):
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
        _mark_fire_handled(state, rule.id, fire_key)
        save_state(state_file, state)
        try:
            notify_rule_finished(settings, rule, code)
        except Exception:  # noqa: BLE001
            logger.exception("VK Teams notify_rule_finished failed")


def _fire_stamp(fire_at: datetime) -> str:
    return fire_at.strftime("%Y%m%d%H%M")


def _fire_key(rule_id: str, fire_at: datetime) -> str:
    return f"{rule_id}:{_fire_stamp(fire_at)}"


def _mark_fire_handled(state: SchedulerState, rule_id: str, fire_key: str) -> None:
    stamp = fire_key.split(":", 1)[-1]
    prev = state.last_fires.get(rule_id)
    if prev is None or stamp > prev:
        state.last_fires[rule_id] = stamp


def _is_fire_handled(last_fires: dict[str, str], rule_id: str, fire_at: datetime) -> bool:
    last = last_fires.get(rule_id)
    if last is None:
        return False
    return last >= _fire_stamp(fire_at)


def _previous_slot(
    rule: ScheduleRule,
    config: ScheduleConfig,
    *,
    now: datetime | None = None,
) -> tuple[datetime, str] | None:
    """Последний cron-слот правила ≤ now и его fire_key."""
    from croniter import croniter
    from nexus_control.scheduler.cronutil import resolve_tz, validate_cron

    when = now or datetime.now(timezone.utc)
    tz = resolve_tz(config.timezone)
    local_now = when.astimezone(tz)
    expr = validate_cron(rule.cron)
    itr = croniter(expr, local_now)
    prev = itr.get_prev(datetime)
    if prev.tzinfo is None:
        prev = prev.replace(tzinfo=tz)
    else:
        prev = prev.astimezone(tz)
    return prev, _fire_key(rule.id, prev)


def _seed_past_fires(
    config: ScheduleConfig,
    state: SchedulerState,
    *,
    grace_seconds: float = _STARTUP_GRACE_SECONDS,
) -> None:
    """Baseline для правил без истории в ``last_fires``.

    Если правило уже отслеживалось — не трогаем: пропущенные слоты
    (демон был занят или перезапущен) подхватит очередь ``_due_rules``.
    Для нового правила помечаем устаревший prev как handled, чтобы не
    гонять «вчерашний» cron; свежий слот (age < grace) оставляем в очереди.
    """
    now = datetime.now(timezone.utc)
    for rule in config.rules:
        if not rule.enabled:
            continue
        if rule.id in state.last_fires:
            continue
        try:
            slot = _previous_slot(rule, config, now=now)
            if slot is None:
                continue
            prev, fire_key = slot
            age = (now.astimezone(prev.tzinfo) - prev).total_seconds()
            if age >= grace_seconds:
                logger.info(
                    "Seeding baseline slot as handled (new rule): %s age=%.0fs",
                    fire_key,
                    age,
                )
                _mark_fire_handled(state, rule.id, fire_key)
        except (CronError, ValueError, KeyError) as exc:
            logger.error("Cannot seed rule %s: %s", rule.id, exc)


def _due_rules(
    config: ScheduleConfig,
    last_fires: dict[str, str],
) -> list[tuple[ScheduleRule, datetime, str]]:
    """Правила с наступившим и ещё не обработанным cron-слотом.

    Берётся только последний слот каждого правила (get_prev). Если демон был
    занят долгим job, слот остаётся в очереди до выполнения — без окна 90с.
    """
    now = datetime.now(timezone.utc)
    due: list[tuple[ScheduleRule, datetime, str]] = []
    for rule in config.rules:
        if not rule.enabled:
            continue
        try:
            slot = _previous_slot(rule, config, now=now)
            if slot is None:
                continue
            prev, fire_key = slot
            if _is_fire_handled(last_fires, rule.id, prev):
                continue
            age = (now.astimezone(prev.tzinfo) - prev).total_seconds()
            if age >= 0:
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
