"""CLI command: interactive scheduler menu + daemon control."""

from __future__ import annotations

import getpass
import sys
import time
from argparse import Namespace
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from nexus_control.cli.bootstrap import open_cli_client
from nexus_control.config import ConfigError, load_settings
from nexus_control.nexus.client import NexusClient
from nexus_control.nexus.credentials import (
    NON_INTERACTIVE_CREDS_HINT,
    SCHEDULER_VAULT_FILENAME,
    clear_scheduler_credentials,
    save_scheduler_credentials,
)
from nexus_control.scheduler.cronutil import (
    CRON_HELP,
    CRON_PRESETS,
    CronError,
    find_preset,
    format_iso_in_timezone,
    preview_next_fires,
    resolve_tz,
    validate_cron,
)
from nexus_control.scheduler.daemon import (
    get_status,
    run_rule_now,
    start_daemon,
    stop_daemon,
)
from nexus_control.scheduler.models import ScheduleConfig, ScheduleRule
from nexus_control.scheduler.paths import resolve_schedule_path
from nexus_control.scheduler.store import (
    ScheduleStoreError,
    load_schedule,
    save_schedule,
)

console = Console(stderr=True)


def run_schedule(args: Namespace) -> int:
    schedule_file = (
        Path(args.schedule_file).expanduser()
        if getattr(args, "schedule_file", None)
        else None
    )
    action = getattr(args, "schedule_action", None) or "menu"

    if action == "_daemon":
        return start_daemon(foreground=True, schedule_file=schedule_file)
    if action == "start":
        return start_daemon(foreground=False, schedule_file=schedule_file)
    if action == "stop":
        return stop_daemon()
    if action == "status":
        return _cmd_status(
            schedule_file,
            monitor=bool(getattr(args, "monitor", False)),
            interval=float(getattr(args, "monitor_interval", 1.0) or 1.0),
        )
    if action in {"run", "_run"}:
        rule_id = getattr(args, "rule_id", None)
        if not rule_id:
            console.print("[red]rule id required for run[/red]")
            return 2
        return run_rule_now(
            rule_id,
            schedule_file=schedule_file,
            scan_limit=getattr(args, "scan_limit", None),
            foreground=bool(
                action == "_run" or getattr(args, "foreground", False)
            ),
        )
    if action == "login":
        return _cmd_login()
    if action == "logout":
        return _cmd_logout()
    if action == "menu":
        return _run_menu(schedule_file)
    console.print(f"[red]Unknown schedule action: {action}[/red]")
    return 2


def _run_menu(schedule_file: Path | None) -> int:
    path = resolve_schedule_path(schedule_file)
    console.print(
        f"[bold]Nexus Control Scheduler[/bold]\n"
        f"Config: {path}"
    )
    while True:
        console.print()
        console.print(
            "  [cyan]1[/cyan]) List rules\n"
            "  [cyan]2[/cyan]) Add rule\n"
            "  [cyan]3[/cyan]) Edit rule\n"
            "  [cyan]4[/cyan]) Remove rule\n"
            "  [cyan]5[/cyan]) Start daemon\n"
            "  [cyan]6[/cyan]) Stop daemon\n"
            "  [cyan]7[/cyan]) Status / next runs\n"
            "  [cyan]8[/cyan]) Run rule now (background; watch with 7 / status -m)\n"
            "  [cyan]9[/cyan]) Login (save encrypted creds for daemon)\n"
            "  [cyan]L[/cyan]) Logout (clear saved scheduler creds)\n"
            "  [cyan]0[/cyan]) Quit"
        )
        choice = Prompt.ask(
            "Select",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "L", "l"],
            default="0",
        )
        if choice == "0":
            return 0
        if choice == "1":
            _menu_list(path)
        elif choice == "2":
            _menu_add(path)
        elif choice == "3":
            _menu_edit(path)
        elif choice == "4":
            _menu_remove(path)
        elif choice == "5":
            code = start_daemon(foreground=False, schedule_file=path)
            if code != 0:
                console.print(f"[red]Start failed (exit={code})[/red]")
        elif choice == "6":
            stop_daemon()
        elif choice == "7":
            _cmd_status(path)
        elif choice == "8":
            _menu_run(path)
        elif choice == "9":
            _cmd_login()
        elif choice.lower() == "l":
            _cmd_logout()


def _load(path: Path) -> ScheduleConfig:
    try:
        config = load_schedule(path)
    except ScheduleStoreError as exc:
        console.print(f"[red]Cannot load schedule: {exc}[/red]")
        console.print(
            f"[yellow]Файл на месте:[/yellow] {path}\n"
            "Исправьте TOML вручную — меню не затирает битое правило само."
        )
        return ScheduleConfig()

    # Persist auto-migration of legacy comma-separated ``target``.
    if path.is_file():
        try:
            from nexus_control.config_io import read_toml

            raw = read_toml(path)
            needs_rewrite = any(
                isinstance(item, dict) and "," in str(item.get("target") or "")
                for item in (raw.get("rules") or [])
            )
            if needs_rewrite:
                save_schedule(config, path)
                console.print(
                    "[green]Migrated[/green] legacy comma-separated "
                    "target → per-repo targets table"
                )
        except Exception:  # noqa: BLE001
            pass
    return config


def _save(config: ScheduleConfig, path: Path) -> None:
    try:
        save_schedule(config, path)
        console.print(f"[green]Saved[/green] {path}")
    except ScheduleStoreError as exc:
        console.print(f"[red]Save failed: {exc}[/red]")


def _menu_list(path: Path) -> None:
    config = _load(path)
    if not config.rules:
        console.print("[yellow]No rules yet. Use Add rule.[/yellow]")
        return
    table = Table(
        title=(
            f"Rules ({len(config.rules)})  "
            f"tz={config.resolved_timezone()}  overlap={config.overlap}"
        )
    )
    table.add_column("ID")
    table.add_column("On")
    table.add_column("Cron")
    table.add_column("Repos")
    table.add_column("Action")
    table.add_column("Description")
    for rule in config.rules:
        table.add_row(
            rule.id,
            "yes" if rule.enabled else "no",
            rule.cron,
            ", ".join(rule.repos),
            f"{rule.action}" + ("+upload" if rule.upload and rule.action == "verify" else ""),
            rule.description or "",
        )
    console.print(table)


def _menu_add(path: Path) -> None:
    config = _load(path)
    rule_id = Prompt.ask("Rule id").strip()
    if not rule_id:
        console.print("[red]id required[/red]")
        return
    if config.get_rule(rule_id):
        console.print(f"[red]Rule {rule_id!r} already exists[/red]")
        return
    rule = _prompt_rule(config, existing=None, rule_id=rule_id)
    if rule is None:
        return
    config.upsert_rule(rule)
    _maybe_prompt_scheduler_meta(config)
    _save(config, path)


def _menu_edit(path: Path) -> None:
    config = _load(path)
    if not config.rules:
        console.print("[yellow]No rules.[/yellow]")
        return
    rule_id = Prompt.ask(
        "Rule id to edit",
        choices=[r.id for r in config.rules],
    )
    existing = config.get_rule(rule_id)
    if existing is None:
        return
    rule = _prompt_rule(config, existing=existing, rule_id=existing.id)
    if rule is None:
        return
    config.upsert_rule(rule)
    _maybe_prompt_scheduler_meta(config)
    _save(config, path)


def _menu_remove(path: Path) -> None:
    config = _load(path)
    if not config.rules:
        console.print("[yellow]No rules.[/yellow]")
        return
    rule_id = Prompt.ask(
        "Rule id to remove",
        choices=[r.id for r in config.rules],
    )
    if not Confirm.ask(f"Remove rule {rule_id!r}?", default=False):
        return
    config.remove_rule(rule_id)
    _save(config, path)


def _menu_run(path: Path) -> None:
    config = _load(path)
    if not config.rules:
        console.print("[yellow]No rules.[/yellow]")
        return
    rule_id = Prompt.ask(
        "Rule id to run now",
        choices=[r.id for r in config.rules],
    )
    code = run_rule_now(rule_id, schedule_file=path)
    if code == 0:
        console.print("[dim]Watch progress: nexus-control-cli schedule status -m[/dim]")
    else:
        console.print(f"Finished with exit code {code}")


def _cmd_status(
    schedule_file: Path | None,
    *,
    monitor: bool = False,
    interval: float = 1.0,
) -> int:
    try:
        settings = _status_settings()
    except ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    if not monitor:
        console.print(_status_renderable(schedule_file, settings=settings))
        return 0

    poll = max(0.2, float(interval))
    console.print(
        f"[dim]Monitoring scheduler (Ctrl+C to stop), refresh={poll:.1f}s[/dim]"
    )
    try:
        with Live(
            _status_renderable(schedule_file, settings=settings),
            console=console,
            refresh_per_second=max(1, int(1.0 / poll)),
            transient=False,
        ) as live:
            while True:
                time.sleep(poll)
                live.update(_status_renderable(schedule_file, settings=settings))
    except ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    except KeyboardInterrupt:
        console.print("\n[dim]Monitor stopped.[/dim]")
        return 0


def _status_settings():
    """Один раз за процесс status/monitor — без Nexus vault."""
    from nexus_control.scheduler.daemon import _settings_no_prompt

    return _settings_no_prompt()


def _status_renderable(schedule_file: Path | None, *, settings=None):
    """Собрать Rich-renderable для одноразового status / Live monitor."""
    from rich.console import Group

    status = get_status(settings, schedule_file=schedule_file)
    sched_tz = status.config.resolved_timezone()

    def _fmt(value: str | None) -> str:
        return format_iso_in_timezone(value, sched_tz)

    lines: list[str | Text] = []
    if status.running:
        lines.append(
            Text(f"Daemon running pid={status.pid}", style="green")
        )
    else:
        lines.append(Text("Daemon not running", style="yellow"))
    run_pid = status.state.run_pid
    if run_pid:
        from nexus_control.scheduler.pidfile import process_is_alive

        if process_is_alive(run_pid):
            lines.append(Text(f"Manual run pid={run_pid}", style="green"))
    lines.append(f"Schedule file: {status.schedule_path}")
    lines.append(
        f"Timezone={status.config.resolved_timezone()} "
        f"(config={status.config.timezone})  "
        f"overlap={status.config.overlap}  "
        f"rules={len(status.config.rules)}"
    )
    if status.state.started_at:
        lines.append(f"Started at: {_fmt(status.state.started_at)}")
    lines.append(
        f"Updated: {datetime.now(resolve_tz(sched_tz)).isoformat(timespec='seconds')}"
    )

    if status.state.busy:
        rule = status.state.current_rule or "?"
        repo = status.state.current_repo
        busy = f"Busy: {rule}"
        if repo:
            busy += f"  repo={repo}"
        lines.append(Text(busy, style="cyan bold"))
        pct = status.state.progress_pct
        if pct is not None:
            bar = int(max(0.0, min(1.0, pct)) * 20)
            gauge = "█" * bar + "░" * (20 - bar)
            lines.append(
                Text(
                    f"Progress: [{gauge}] {int(pct * 100):3d}%  "
                    f"{status.state.progress_stage}",
                    style="cyan",
                )
            )
        if status.state.progress_message:
            lines.append(f"  {status.state.progress_message}")
        if status.state.progress_updated_at:
            lines.append(
                Text(
                    f"  progress@ {_fmt(status.state.progress_updated_at)}",
                    style="dim",
                )
            )
    else:
        lines.append(Text("Idle (waiting for next cron fire)", style="dim"))

    parts: list[object] = list(lines)
    if status.config.rules:
        table = Table(title=f"Next fires / last runs ({sched_tz})")
        table.add_column("ID")
        table.add_column("Next")
        table.add_column("Last Start")
        table.add_column("Last End")
        table.add_column("Exit")
        for rule in status.config.rules:
            nxt = status.state.next_fires.get(rule.id, "")
            if not nxt and rule.enabled:
                try:
                    fires = preview_next_fires(
                        rule.cron,
                        timezone=status.config.resolved_timezone(),
                        count=1,
                    )
                    nxt = fires[0].isoformat(timespec="seconds") if fires else ""
                except CronError as exc:
                    nxt = f"error: {exc}"
            if nxt and not nxt.startswith("error:"):
                nxt = _fmt(nxt)
            last = status.state.last_runs.get(rule.id)
            last_start = ""
            last_end = ""
            exit_s = ""
            if last:
                last_start = _fmt(last.started_at or "")
                last_end = _fmt(last.finished_at or "")
                if last.skipped:
                    exit_s = "skipped"
                elif last.exit_code is not None:
                    exit_s = str(last.exit_code)
            table.add_row(
                rule.id + ("" if rule.enabled else " (off)"),
                nxt,
                last_start,
                last_end,
                exit_s,
            )
        parts.append(table)
    return Group(*parts)


def _print_cron_presets() -> None:
    console.print("[bold]Быстрый выбор[/bold] (введите номер):")
    for preset in CRON_PRESETS:
        console.print(
            f"  [cyan]{preset.key}[/cyan]) {preset.title}  "
            f"[dim]{preset.cron}[/dim]"
        )
    console.print(
        "  [cyan]c[/cyan]) свой cron  ·  [cyan]help[/cyan] / [cyan]?[/cyan] — шпаргалка"
    )


def _prompt_cron(config: ScheduleConfig, *, default_cron: str) -> str:
    """Спросить расписание: пресет или свой cron + preview next runs."""
    console.print()
    console.print(CRON_HELP)
    console.print(
        f"Timezone: [bold]{config.resolved_timezone()}[/bold] "
        f"[dim](config={config.timezone})[/dim]"
    )
    _print_cron_presets()

    while True:
        raw = Prompt.ask(
            "Расписание (номер пресета, cron или help)",
            default=default_cron,
        ).strip()
        lowered = raw.lower()
        if lowered in {"help", "?", "h"}:
            console.print()
            console.print(CRON_HELP)
            _print_cron_presets()
            continue
        if lowered in {"c", "custom"}:
            raw = Prompt.ask(
                "Свой cron (5 полей: мин час день месяц день_недели)",
                default=default_cron,
            ).strip()
            if raw.lower() in {"help", "?", "h"}:
                console.print()
                console.print(CRON_HELP)
                continue

        preset = find_preset(raw)
        if preset is not None:
            cron_expr = preset.cron
            console.print(
                f"Выбрано: [green]{preset.title}[/green] → [dim]{cron_expr}[/dim]"
            )
        else:
            cron_expr = raw

        try:
            cron_expr = validate_cron(cron_expr)
            fires = preview_next_fires(
                cron_expr, timezone=config.resolved_timezone(), count=3
            )
            console.print("Ближайшие запуски:")
            for fire in fires:
                console.print(f"  • {fire.isoformat()}")
            if Confirm.ask("Оставить это расписание?", default=True):
                return cron_expr
        except CronError as exc:
            console.print(f"[red]{exc}[/red]")
            console.print(
                "Подсказка: введите [cyan]1[/cyan]–[cyan]6[/cyan], "
                "[cyan]help[/cyan] или выражение вроде [dim]0 3 * * 1-5[/dim]"
            )


def _prompt_rule(
    config: ScheduleConfig,
    *,
    existing: ScheduleRule | None,
    rule_id: str,
) -> ScheduleRule | None:
    default_cron = existing.cron if existing else "0 3 * * *"
    cron = _prompt_cron(config, default_cron=default_cron)

    description = Prompt.ask(
        "Description",
        default=existing.description if existing else "",
    ).strip()

    repos = _prompt_repos(existing.repos if existing else None)
    if not repos:
        console.print("[red]At least one repository required[/red]")
        return None

    action = Prompt.ask(
        "Action",
        choices=["verify", "upload", "verify_upload"],
        default=existing.action if existing else "verify",
    )
    upload = False
    if action == "verify":
        upload = Confirm.ask(
            "Upload after verify?",
            default=bool(existing.upload) if existing else False,
        )

    enabled = Confirm.ask(
        "Enabled?",
        default=bool(existing.enabled) if existing else True,
    )

    prefixes_default = ""
    if existing and existing.path_prefixes:
        prefixes_default = ",".join(existing.path_prefixes)
    prefixes_raw = Prompt.ask(
        "path_prefixes (comma-separated, empty=none)",
        default=prefixes_default,
    ).strip()
    path_prefixes = [
        part.strip() for part in prefixes_raw.split(",") if part.strip()
    ] if prefixes_raw else []
    from nexus_control.utils.path_prefixes import normalize_path_prefixes

    path_prefixes = normalize_path_prefixes(path_prefixes)

    excludes_default = ""
    if existing and existing.excluded_prefixes:
        excludes_default = ",".join(existing.excluded_prefixes)
    excludes_raw = Prompt.ask(
        "excluded_prefixes (comma-separated, empty=none)",
        default=excludes_default,
    ).strip()
    excluded_prefixes = [
        part.strip() for part in excludes_raw.split(",") if part.strip()
    ] if excludes_raw else []
    excluded_prefixes = normalize_path_prefixes(excluded_prefixes)

    scanners = Prompt.ask(
        "scanners (empty=config default)",
        default=(existing.scanners or "") if existing else "",
    ).strip() or None

    from nexus_control.services.scan_common import parse_severity_threshold

    severity: str | None = None
    while True:
        severity_raw = Prompt.ask(
            "severity (critical|high|medium|low|negligible, empty=config default)",
            default=(existing.severity or "") if existing else "",
        ).strip()
        if not severity_raw:
            break
        try:
            severity = parse_severity_threshold(severity_raw)
            break
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")

    workers_s = Prompt.ask(
        "workers (empty=config default)",
        default=str(existing.workers) if existing and existing.workers else "",
    ).strip()
    workers = int(workers_s) if workers_s else None

    limit_s = Prompt.ask(
        "limit / download-limit (empty=none)",
        default=str(existing.limit) if existing and existing.limit else "",
    ).strip()
    limit = int(limit_s) if limit_s else None

    scan_limit_s = Prompt.ask(
        "scan_limit / max mains to verify (empty=none, debug)",
        default=(
            str(existing.scan_limit) if existing and existing.scan_limit else ""
        ),
    ).strip()
    scan_limit = int(scan_limit_s) if scan_limit_s else None

    wants_upload = action in {"upload", "verify_upload"} or upload
    targets: dict[str, str] = {}
    legacy_target: str | None = None
    if wants_upload:
        targets = _prompt_targets(repos, existing)
    else:
        console.print(
            "[dim]Upload targets skipped (action does not upload).[/dim]"
        )

    refresh = Confirm.ask(
        "Always refresh asset list?",
        default=bool(existing.refresh) if existing else False,
    )

    return ScheduleRule(
        id=rule_id,
        cron=cron,
        repos=repos,
        enabled=enabled,
        description=description,
        action=action,  # type: ignore[arg-type]
        upload=upload,
        targets=targets,
        target=legacy_target,
        scanners=scanners,
        severity=severity,
        path_prefixes=path_prefixes,
        excluded_prefixes=excluded_prefixes,
        workers=workers,
        limit=limit,
        scan_limit=scan_limit,
        refresh=refresh,
    )


def _prompt_targets(
    repos: list[str],
    existing: ScheduleRule | None,
) -> dict[str, str]:
    """Спросить upload-target для каждого source-repo (пусто = <repo>-verified)."""
    console.print(
        "Upload target [bold]per source repository[/bold] "
        "(empty = [cyan]<repo>-verified[/cyan]). "
        "Do [red]not[/red] put several names in one field."
    )
    out: dict[str, str] = {}
    for repo in repos:
        default = ""
        if existing is not None:
            default = existing.targets.get(repo) or ""
            if (
                not default
                and existing.target
                and len(existing.repos) == 1
                and existing.repos[0] == repo
            ):
                default = existing.target
        while True:
            raw = Prompt.ask(
                f"  target for [cyan]{repo}[/cyan]",
                default=default,
            ).strip()
            if not raw:
                break
            if "," in raw:
                console.print(
                    "[red]One repository name only[/red] "
                    f"(got {raw!r}). Example: {repo}-verified"
                )
                continue
            out[repo] = raw
            break
    if out:
        console.print("Targets:")
        for repo in repos:
            console.print(
                f"  {repo} → {out.get(repo) or f'{repo}-verified'}"
            )
    else:
        console.print(
            "[dim]All targets default to <repo>-verified[/dim]"
        )
    return out


def _prompt_repos(default: list[str] | None) -> list[str]:
    default_s = ",".join(default or [])
    console.print(
        "Repositories: comma-separated names, or [cyan]list[/cyan] to fetch from Nexus."
    )
    while True:
        raw = Prompt.ask("Repos", default=default_s or "")
        if raw.strip().lower() == "list":
            names = _fetch_repo_names()
            if not names:
                continue
            console.print("Available: " + ", ".join(names))
            continue
        repos = [p.strip() for p in raw.split(",") if p.strip()]
        if repos:
            return repos
        console.print("[red]Enter at least one repository[/red]")


def _fetch_repo_names() -> list[str]:
    try:
        with open_cli_client(allow_prompt=False) as ctx:
            repos = ctx.client.list_repositories()
            return [r.name for r in repos if not r.is_docker]
    except (ConfigError, Exception) as exc:  # noqa: BLE001
        console.print(f"[red]Cannot list repos: {exc}[/red]")
        console.print(
            "[yellow]Hint:[/yellow] set NEXUS_USERNAME/NEXUS_PASSWORD in .env "
            "or run [cyan]nexus-control-cli schedule login[/cyan]"
        )
        return []


def _cmd_login() -> int:
    """Один раз спросить креды, проверить против Nexus, сохранить scheduler vault."""
    settings = load_settings()
    env_user = (settings.nexus_username or "").strip()
    env_password = settings.nexus_password or ""

    if env_user and env_password:
        username, password = env_user, env_password
        console.print(
            f"Using NEXUS_USERNAME from env/config ([bold]{username}[/bold]); "
            "validating against Nexus…"
        )
    else:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            console.print(f"[red]{NON_INTERACTIVE_CREDS_HINT}[/red]")
            return 2
        console.print("Nexus authentication for scheduler")
        console.print(
            f"Credentials are stored encrypted in {SCHEDULER_VAULT_FILENAME} "
            "(not tied to NEXUS_SESSION_TTL; clear with schedule logout)."
        )
        hint = f" [{env_user}]" if env_user else ""
        username = input(f"Username{hint}: ").strip() or env_user
        if not username:
            console.print("[red]Username is required[/red]")
            return 2
        password = getpass.getpass("Password: ")
        if not password:
            console.print("[red]Password is required[/red]")
            return 2

    probe = settings.model_copy(
        update={"nexus_username": username, "nexus_password": password}
    )
    client = NexusClient(probe)
    try:
        client.open()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Nexus authentication failed:[/red] {exc}")
        return 2
    finally:
        client.close()

    path = save_scheduler_credentials(probe, username=username, password=password)
    console.print(
        f"[green]Saved encrypted scheduler credentials[/green] "
        f"(user=[bold]{username}[/bold])\n"
        f"Vault: {path}\n"
        "Daemon/start/run will reuse them without prompting. "
        "Clear with [cyan]schedule logout[/cyan]."
    )
    return 0


def _cmd_logout() -> int:
    settings = load_settings()
    existed = clear_scheduler_credentials(settings)
    if existed:
        console.print("[green]Scheduler credentials cleared.[/green]")
    else:
        console.print("No scheduler credentials were stored.")
    return 0


def _maybe_prompt_scheduler_meta(config: ScheduleConfig) -> None:
    host_tz = config.resolved_timezone()
    if Confirm.ask(
        f"Edit scheduler timezone/overlap? "
        f"(now {host_tz}, config={config.timezone}, overlap={config.overlap})",
        default=False,
    ):
        tz = Prompt.ask(
            "Timezone (local = machine TZ, or IANA e.g. Europe/Moscow)",
            default=config.timezone or "local",
        ).strip() or "local"
        overlap = Prompt.ask(
            "Overlap policy",
            choices=["skip", "queue", "overlap"],
            default=config.overlap,
        )
        config.timezone = tz
        config.overlap = overlap  # type: ignore[assignment]
        console.print(
            f"Effective timezone: [bold]{config.resolved_timezone()}[/bold]"
        )
