"""Валидация cron и next-fire (croniter + zoneinfo)."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter

logger = logging.getLogger(__name__)

# Sentinel в schedule.toml: брать timezone с машины.
LOCAL_TIMEZONE = "local"


class CronError(ValueError):
    """Невалидное cron-выражение или timezone."""


@dataclass(frozen=True, slots=True)
class CronPreset:
    key: str
    cron: str
    title: str


# Пресеты для интерактивного меню (ключ = номер).
CRON_PRESETS: tuple[CronPreset, ...] = (
    CronPreset("1", "0 3 * * *", "каждый день в 03:00"),
    CronPreset("2", "0 3 * * 1-5", "пн–пт в 03:00"),
    CronPreset("3", "30 4 * * 6", "суббота в 04:30"),
    CronPreset("4", "0 0 * * 0", "воскресенье в 00:00"),
    CronPreset("5", "0 */6 * * *", "каждые 6 часов"),
    CronPreset("6", "0 * * * *", "каждый час"),
)

CRON_HELP = """\
[bold]Расписание (cron, 5 полей)[/bold]
  [cyan]минута[/cyan]  [cyan]час[/cyan]  \
[cyan]день_месяца[/cyan]  [cyan]месяц[/cyan]  [cyan]день_недели[/cyan]

  минута       0–59
  час          0–23
  день_месяца  1–31   или [green]*[/green] = любой
  месяц        1–12   или [green]*[/green]
  день_недели  0–7    ([green]0[/green] и [green]7[/green] = вс, \
[green]1[/green] = пн … [green]6[/green] = сб)

  [green]*[/green]     любое значение
  [green],[/green]     список: [dim]1,3,5[/dim]
  [green]-[/green]     диапазон: [dim]1-5[/dim]
  [green]/N[/green]   шаг: [dim]*/6[/dim] (каждые 6 единиц)

[bold]Примеры[/bold]
  [dim]0 3 * * *[/dim]      каждый день в 03:00
  [dim]0 3 * * 1-5[/dim]    будни в 03:00
  [dim]30 4 * * 6[/dim]     суббота в 04:30
  [dim]0 */6 * * *[/dim]    каждые 6 часов
  [dim]0 9 1 * *[/dim]      1-го числа каждого месяца в 09:00
"""


def _zoneinfo_ok(name: str) -> bool:
    try:
        ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return False
    return True


@lru_cache(maxsize=1)
def system_timezone_name() -> str:
    """IANA timezone хоста: ``$TZ``, ``/etc/timezone``, ``/etc/localtime``.

    Fallback: ``UTC``, если определить не удалось.
    """
    env = os.environ.get("TZ", "").strip()
    if env:
        name = env[1:] if env.startswith(":") else env
        if name and not name.startswith("/") and _zoneinfo_ok(name):
            return name

    try:
        text = Path("/etc/timezone").read_text(encoding="utf-8").strip()
    except OSError:
        text = ""
    if text and _zoneinfo_ok(text):
        return text

    localtime = Path("/etc/localtime")
    try:
        target = localtime.resolve(strict=True)
    except OSError:
        target = None
    if target is not None:
        parts = target.parts
        if "zoneinfo" in parts:
            idx = parts.index("zoneinfo")
            name = "/".join(parts[idx + 1:])

            if name and _zoneinfo_ok(name):
                return name

    info = datetime.now().astimezone().tzinfo
    key = getattr(info, "key", None)
    if isinstance(key, str) and _zoneinfo_ok(key):
        return key

    logger.warning(
        "Could not detect system timezone; falling back to UTC. "
        "Set TZ or /etc/timezone, or put timezone=… in schedule.toml"
    )
    return "UTC"


def effective_timezone(name: str | None) -> str:
    """Разрешить timezone из конфига: ``local``/пусто → timezone машины."""
    text = (name or "").strip()
    if not text or text.lower() in {LOCAL_TIMEZONE, "system", "host"}:
        return system_timezone_name()
    return text


def resolve_tz(name: str) -> ZoneInfo:
    resolved = effective_timezone(name)
    try:
        return ZoneInfo(resolved)
    except ZoneInfoNotFoundError as exc:
        raise CronError(f"Unknown timezone: {resolved}") from exc


def find_preset(token: str) -> CronPreset | None:
    """Найти пресет по номеру (1…6) или по cron-строке пресета."""
    text = token.strip().lower()
    if not text:
        return None
    for preset in CRON_PRESETS:
        if text == preset.key or text == preset.cron:
            return preset
    return None


def validate_cron(expr: str) -> str:
    """Проверить 5-field cron; вернуть нормализованную строку."""
    text = " ".join(expr.strip().split())
    if not text:
        raise CronError("Cron expression is empty")
    parts = text.split()
    if len(parts) != 5:
        raise CronError(
            f"Expected 5-field cron (min hour dom month dow), got {len(parts)} fields. "
            "Type 'help' for a cheat sheet, or pick a preset 1–6."
        )
    try:
        croniter(text)
    except (ValueError, KeyError, TypeError) as exc:
        raise CronError(f"Invalid cron expression {text!r}: {exc}") from exc
    return text


def next_fire(
    cron_expr: str,
    *,
    timezone: str,
    after: datetime | None = None,
) -> datetime:
    """Следующий момент срабатывания в заданной timezone (aware datetime)."""
    expr = validate_cron(cron_expr)
    tz = resolve_tz(timezone)
    base = after.astimezone(tz) if after is not None else datetime.now(tz)
    itr = croniter(expr, base)
    nxt = itr.get_next(datetime)
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=tz)
    else:
        nxt = nxt.astimezone(tz)
    return nxt


def preview_next_fires(
    cron_expr: str,
    *,
    timezone: str,
    count: int = 3,
    after: datetime | None = None,
) -> list[datetime]:
    expr = validate_cron(cron_expr)
    tz = resolve_tz(timezone)
    cursor = after.astimezone(tz) if after is not None else datetime.now(tz)
    out: list[datetime] = []
    for _ in range(max(0, count)):
        cursor = next_fire(expr, timezone=timezone, after=cursor)
        out.append(cursor)
    return out


def format_iso_in_timezone(value: str | None, timezone: str) -> str:
    """Parse ISO timestamp and render in schedule timezone (``isoformat`` seconds)."""
    if not value:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    tz = resolve_tz(timezone)
    return dt.astimezone(tz).isoformat(timespec="seconds")
