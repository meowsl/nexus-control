"""ConfirmModal: Cancel не должен запускать операцию."""

from __future__ import annotations

import asyncio

from textual.app import App, ComposeResult
from textual.widgets import Label

from nexus_control.ui.widgets import ConfirmModal


class _Harness(App[None]):
    def __init__(self) -> None:
        super().__init__()
        self.result: bool | None = None

    def compose(self) -> ComposeResult:
        yield Label("root")

    def on_mount(self) -> None:
        self.push_screen(ConfirmModal("Confirm verify ALL", "body"), self._after)

    def _after(self, confirmed: bool | None) -> None:
        self.result = confirmed


async def _click_cancel() -> bool | None:
    app = _Harness()
    async with app.run_test() as pilot:
        assert isinstance(app.screen, ConfirmModal)
        await pilot.click("#cancel")
        return app.result


async def _enter_on_focused_confirm() -> bool | None:
    app = _Harness()
    async with app.run_test() as pilot:
        assert isinstance(app.screen, ConfirmModal)
        assert app.screen.focused is not None
        assert app.screen.focused.id == "ok"
        await pilot.press("enter")
        return app.result


async def _enter_on_focused_cancel() -> bool | None:
    """Enter при фокусе на Cancel — отмена, а не Confirm (старый баг)."""
    app = _Harness()
    async with app.run_test() as pilot:
        assert isinstance(app.screen, ConfirmModal)
        app.screen.query_one("#cancel").focus()
        await pilot.pause()
        assert app.screen.focused is not None
        assert app.screen.focused.id == "cancel"
        await pilot.press("enter")
        return app.result


async def _press_escape() -> bool | None:
    app = _Harness()
    async with app.run_test() as pilot:
        await pilot.press("escape")
        return app.result


async def _click_ok() -> bool | None:
    app = _Harness()
    async with app.run_test() as pilot:
        await pilot.click("#ok")
        return app.result


def test_confirm_modal_cancel_button_returns_false() -> None:
    assert asyncio.run(_click_cancel()) is False


def test_confirm_modal_enter_on_confirm_returns_true() -> None:
    assert asyncio.run(_enter_on_focused_confirm()) is True


def test_confirm_modal_enter_on_cancel_returns_false() -> None:
    """Enter при фокусе на Cancel — отмена, а не Confirm (старый баг)."""
    assert asyncio.run(_enter_on_focused_cancel()) is False


def test_confirm_modal_escape_returns_false() -> None:
    assert asyncio.run(_press_escape()) is False


def test_confirm_modal_ok_button_returns_true() -> None:
    assert asyncio.run(_click_ok()) is True
