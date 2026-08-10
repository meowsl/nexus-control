"""Горячие клавиши: фабрики Binding + справка (локализуемые)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from textual.binding import Binding, BindingsMap

from nexus_control.i18n import _


def app_bindings() -> list[Binding]:
    return [
        Binding("ctrl+c", "quit", _("Quit"), show=False),
        Binding("f", "toggle_locale", _("Language"), show=False),
    ]


def _focus_nav_bindings() -> list[Binding]:
    """Tab / Shift+Tab — иначе Screen.BINDINGS теряются при своей BINDINGS-фабрике."""
    return [
        Binding("tab", "app.focus_next", _("Next"), show=False),
        Binding("shift+tab", "app.focus_previous", _("Previous"), show=False),
    ]


def repo_bindings() -> list[Binding]:
    return [
        *_focus_nav_bindings(),
        Binding("q", "app.quit", _("Quit")),
        Binding("r", "refresh", _("Refresh")),
        Binding("slash", "search", _("Filter"), priority=True, show=False),
        Binding("w", "search", _("Filter")),
        Binding("down", "focus_results", _("To list"), show=False),
        Binding("enter", "open_repo", _("Open"), show=True),
        Binding("L", "logout", _("Logout")),
        Binding("f", "app.toggle_locale", _("Language")),
        Binding("h", "open_history", _("History")),
        Binding("question_mark", "help", _("Help")),
        Binding("escape", "close_search", _("Close filter"), show=False, priority=True),
    ]


def asset_bindings() -> list[Binding]:
    return [
        *_focus_nav_bindings(),
        Binding("escape", "escape", _("Back"), priority=True),
        Binding("q", "back", _("Back")),
        Binding("r", "refresh", _("Refresh")),
        Binding("slash", "search", _("Filter"), priority=True),
        Binding("down", "focus_results", _("To list"), show=False),
        Binding("enter", "toggle_node", _("Expand")),
        Binding("space", "toggle_mark", _("Mark"), show=False),
        Binding("u", "clear_marks", _("Unmark")),
        Binding("d", "download_selected", _("Download")),
        Binding("v", "verify_selected", _("Verify")),
        Binding("D", "download_all", _("Download all")),
        Binding("V", "verify_all", _("Verify all")),
        Binding("o", "open_report", _("Report")),
        Binding("h", "open_history", _("History")),
        Binding("s", "scanner_settings", _("Scanners")),
        Binding("f", "app.toggle_locale", _("Language")),
        Binding("question_mark", "help", _("Help")),
        Binding("c", "cancel_job", _("Cancel"), show=False),
    ]


def asset_tree_extra_bindings() -> list[Binding]:
    """Доп. binding поверх Tree.BINDINGS (Space = mark)."""
    return [
        Binding("space", "toggle_mark", _("Mark"), show=False),
    ]


def help_text() -> str:
    return "\n".join(
        [
            f"[b]{_('Repositories')}[/b]",
            f"  q           {_('Quit the application')}",
            f"  r           {_('Refresh repository list')}",
            f"  / , w       {_('Filter by name')}",
            f"  Tab / ↓     {_('From filter to repository list')}",
            f"  Enter       {_('Open assets')}",
            f"  L           {_('Logout (clear Nexus session and encrypted credentials)')}",
            f"  f           {_('Toggle UI language (en/ru)')}",
            f"  h           {_('Open scan history')}",
            f"  ?           {_('Show this help')}",
            "",
            f"[b]{_('Assets')}[/b]",
            f"  Esc / q     {_('Back to repositories')}",
            f"  r           {_('Refresh assets')}",
            f"  /           {_('Filter tree')}",
            f"  Tab / ↓     {_('From filter to asset tree')}",
            f"  Enter       {_('Expand / collapse')}",
            f"  Space       {_('Mark / unmark (● marked, ○ not)')}",
            f"  u           {_('Clear all marks')}",
            f"  d           {_('Download marked (or node under cursor)')}",
            f"  v           {_('Verify marked (download + scanners + copy PASS)')}",
            f"  D           {_('Download entire repository')}",
            f"  V           {_('Verify entire repository')}",
            f"  o           {_('Open last report')}",
            f"  h           {_('Open scan history')}",
            f"  s           {_('Scanners (grype / trivy / both)')}",
            f"  f           {_('Toggle UI language (en/ru)')}",
            f"  ?           {_('Show this help')}",
            "",
            f"[b]{_('Selection rules')}[/b]",
            f"  • {_('Space on file/image marks one asset')}",
            f"  • {_('Space on folder marks the whole branch (recursive on download/verify)')}",
            f"  • {_('Mark several nodes, then press d or v')}",
            f"  • {_('Without marks, d / v use the node under the cursor')}",
            f"  • {_('D / V always mean the entire repository')}",
            f"  • {_('s enables/disables Grype and/or Trivy; PASS only if all enabled PASS')}",
        ]
    )


def apply_bindings(node: Any, factory: Callable[[], Sequence[Binding]]) -> None:
    """Пересобрать ``_bindings`` инстанса и обновить Footer."""
    node._bindings = BindingsMap(list(factory()))
    refresh = getattr(node, "refresh_bindings", None)
    if callable(refresh):
        refresh()


def refresh_class_bindings(cls: type, factory: Callable[[], Sequence[Binding]]) -> None:
    """Обновить ClassVar bindings, чтобы новые инстансы получили актуальные подписи."""
    bindings = list(factory())
    cls.BINDINGS = bindings  # type: ignore[attr-defined]
    cls._merged_bindings = BindingsMap(bindings)
