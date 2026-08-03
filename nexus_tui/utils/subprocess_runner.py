"""Безопасное выполнение subprocess (argv списком, без shell)."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    argv: list[str]

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandError(RuntimeError):
    def __init__(self, message: str, result: CommandResult | None = None) -> None:
        super().__init__(message)
        self.result = result


def which(binary: str) -> str | None:
    """Вернуть абсолютный путь к бинарнику, если он найден в PATH."""
    return shutil.which(binary)


def run_command(
    argv: list[str],
    *,
    timeout: float | None = None,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    check: bool = False,
) -> CommandResult:
    """Запустить команду с ``shell=False``.

    Никогда не передавать секреты через argv, когда есть альтернатива env/stdin.
    """
    if not argv:
        raise ValueError("argv must not be empty")
    # Защита от случайных shell-строк.
    if len(argv) == 1 and any(ch in argv[0] for ch in ("|", ";", "&&", "||", ">")):
        raise ValueError("Refusing shell-like single-string argv; pass a list of args")

    logger.debug("Running command: %s", _redact_argv(argv))
    try:
        completed = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(
            f"Command timed out after {timeout}s: {_redact_argv(argv)}"
        ) from exc
    except FileNotFoundError as exc:
        raise CommandError(f"Executable not found: {argv[0]}") from exc
    except OSError as exc:
        raise CommandError(f"Failed to run {_redact_argv(argv)}: {exc}") from exc

    result = CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        argv=list(argv),
    )
    if check and not result.ok:
        raise CommandError(
            f"Command failed ({result.returncode}): {_redact_argv(argv)}\n"
            f"{result.stderr.strip()}",
            result=result,
        )
    return result


def _redact_argv(argv: list[str]) -> list[str]:
    """По возможности скрыть password-подобные токены argv в логах."""
    redacted: list[str] = []
    hide_next = False
    for item in argv:
        if hide_next:
            redacted.append("***")
            hide_next = False
            continue
        lower = item.lower()
        if lower in {"--password", "-p", "--passwd", "--src-creds", "--dest-creds"}:
            redacted.append(item)
            hide_next = True
            continue
        if "://" in item and "@" in item:
            # Форма user:pass@host
            try:
                scheme, rest = item.split("://", 1)
                if "@" in rest and ":" in rest.split("@", 1)[0]:
                    creds, host = rest.split("@", 1)
                    user = creds.split(":", 1)[0]
                    redacted.append(f"{scheme}://{user}:***@{host}")
                    continue
            except ValueError:
                pass
        redacted.append(item)
    return redacted
