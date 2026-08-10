"""Single-instance pidfile + flock для scheduler daemon."""

from __future__ import annotations

import atexit
import errno
import fcntl
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from nexus_control.utils.fs import ensure_dir, ensure_parent_dir

logger = logging.getLogger(__name__)


class PidfileError(RuntimeError):
    """Не удалось захватить pidfile (уже запущен другой экземпляр)."""


@dataclass(slots=True)
class PidLock:
    pid_path: Path
    lock_path: Path
    _lock_fd: int | None = None

    def acquire(self) -> None:
        ensure_dir(self.lock_path.parent, mode=0o700)
        ensure_parent_dir(self.pid_path)
        fd = os.open(str(self.lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                other = read_pid(self.pid_path)
                raise PidfileError(
                    f"Scheduler already running (pid={other or '?'})"
                ) from exc
            raise
        self._lock_fd = fd
        self.pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
        os.chmod(self.pid_path, 0o600)
        atexit.register(self.release)

    def release(self) -> None:
        fd = self._lock_fd
        self._lock_fd = None
        if fd is None:
            return
        try:
            if self.pid_path.is_file():
                try:
                    current = int(self.pid_path.read_text(encoding="utf-8").strip())
                except ValueError:
                    current = None
                if current == os.getpid():
                    self.pid_path.unlink(missing_ok=True)
        except OSError as exc:
            logger.debug("pidfile cleanup failed: %s", exc)
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def read_pid(pid_path: Path) -> int | None:
    if not pid_path.is_file():
        return None
    try:
        text = pid_path.read_text(encoding="utf-8").strip()
        return int(text) if text else None
    except (OSError, ValueError):
        return None


def process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def running_pid(pid_path: Path) -> int | None:
    pid = read_pid(pid_path)
    if pid is None:
        return None
    if process_is_alive(pid):
        return pid
    return None
