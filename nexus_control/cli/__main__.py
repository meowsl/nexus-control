"""Точка входа ``nexus-control-cli``."""

from __future__ import annotations

import argparse
import sys

from nexus_control import __version__
from nexus_control.config import ConfigError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexus-control-cli",
        description=(
            "Headless Nexus verify/upload automation (same engine as nexus-control TUI)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_repos = sub.add_parser("repos", help="List Nexus repositories")
    p_repos.add_argument(
        "--json",
        action="store_true",
        help="Print JSON to stdout",
    )
    p_repos.set_defaults(_handler="repos")

    p_verify = sub.add_parser(
        "verify",
        help="Download + scan + copy PASS to local *-verified (+ optional upload)",
    )
    p_verify.add_argument("--repo", required=True, help="Source repository name")
    p_verify.add_argument(
        "--scanners",
        default=None,
        help="Comma-separated scanners (default: from config)",
    )
    p_verify.add_argument(
        "--upload",
        action="store_true",
        help="Upload PASS assets to remote *-verified after verify",
    )
    p_verify.add_argument(
        "--target",
        default=None,
        help="Remote verified repository name (default: <repo>-verified)",
    )
    p_verify.add_argument(
        "--path-prefix",
        default=None,
        help="Only assets whose path starts with this prefix",
    )
    p_verify.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Max main assets requiring download/re-download; unchanged local "
            "assets and sidecars do not consume the limit; Nexus listing stops "
            "when the limit is reached"
        ),
    )
    p_verify.add_argument(
        "--workers",
        type=int,
        default=None,
        help=(
            "Parallel asset workers for download/scan/verify "
            "(default: config pipeline_workers, usually 4)"
        ),
    )
    p_verify.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore asset-list cache; list from Nexus",
    )
    p_verify.add_argument(
        "--json",
        action="store_true",
        help="Print JSON summary to stdout",
    )
    p_verify.set_defaults(_handler="verify")

    p_upload = sub.add_parser(
        "upload",
        help="Upload local *-verified tree to Nexus",
    )
    p_upload.add_argument("--repo", required=True, help="Source repository name")
    p_upload.add_argument(
        "--target",
        default=None,
        help="Remote verified repository name (default: <repo>-verified)",
    )
    p_upload.add_argument(
        "--json",
        action="store_true",
        help="Print JSON summary to stdout",
    )
    p_upload.set_defaults(_handler="upload")

    p_schedule = sub.add_parser(
        "schedule",
        help="Interactive scheduler (rules in schedule.toml + local daemon)",
    )
    p_schedule.add_argument(
        "schedule_action",
        nargs="?",
        default="menu",
        choices=["menu", "start", "stop", "status", "run", "_daemon"],
        help="menu (default) | start | stop | status | run",
    )
    p_schedule.add_argument(
        "rule_id",
        nargs="?",
        default=None,
        help="Rule id for 'run'",
    )
    p_schedule.add_argument(
        "--schedule-file",
        default=None,
        help="Path to schedule.toml (default: XDG config schedule.toml)",
    )
    p_schedule.set_defaults(_handler="schedule")

    p_history = sub.add_parser(
        "history",
        help="List or show saved verify runs (scan history)",
    )
    p_history.add_argument(
        "history_action",
        nargs="?",
        default="list",
        choices=["list", "show"],
        help="list (default) or show <run_id>",
    )
    p_history.add_argument(
        "run_id",
        nargs="?",
        default=None,
        help="Run id for 'show'",
    )
    p_history.add_argument(
        "--repo",
        default=None,
        help="Filter list by repository name",
    )
    p_history.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max runs to list (default: 20)",
    )
    p_history.add_argument(
        "--json",
        action="store_true",
        help="Print JSON to stdout",
    )
    p_history.set_defaults(_handler="history")

    p_vk = sub.add_parser(
        "vk-teams",
        help="VK Teams / VK Workspace bot notifications (scheduler)",
    )
    p_vk.add_argument(
        "vk_action",
        choices=["configure", "status", "test", "disable"],
        help="configure | status | test | disable",
    )
    p_vk.add_argument(
        "--json",
        action="store_true",
        help="JSON output (status)",
    )
    p_vk.add_argument(
        "--clear-vault",
        action="store_true",
        help="With disable: delete encrypted vk-teams.vault",
    )
    p_vk.set_defaults(_handler="vk_teams")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args._handler == "repos":
            from nexus_control.cli.cmd_repos import run_repos

            code = run_repos(args)
        elif args._handler == "verify":
            from nexus_control.cli.cmd_verify import run_verify

            code = run_verify(args)
        elif args._handler == "upload":
            from nexus_control.cli.cmd_upload import run_upload

            code = run_upload(args)
        elif args._handler == "schedule":
            from nexus_control.cli.cmd_schedule import run_schedule

            code = run_schedule(args)
        elif args._handler == "history":
            from nexus_control.cli.cmd_history import run_history

            code = run_history(args)
        elif args._handler == "vk_teams":
            from nexus_control.cli.cmd_vk_teams import run_vk_teams

            code = run_vk_teams(args)
        else:
            parser.error(f"Unknown command: {args.command}")
            return
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130) from None
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"Fatal error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    raise SystemExit(code)


if __name__ == "__main__":
    main()
