"""Потокобезопасные колбэки в UI-поток Textual."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from nexus_tui.app import NexusTuiApp


def schedule_on_app(app: NexusTuiApp, callback: Callable[..., Any], *args: Any) -> None:
    """Вызвать UI-колбэк из worker-потока без блокировки.

    Не использует ``Screen.app`` (ContextVar) и не ждёт ``call_from_thread().result()``,
    чтобы не дедлочиться с TuiLogHandler.
    """
    loop = getattr(app, "_loop", None)
    if loop is None:
        return

    async def _run() -> None:
        with app._context():
            callback(*args)

    asyncio.run_coroutine_threadsafe(_run(), loop)
