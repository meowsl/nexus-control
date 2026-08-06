"""Keyboard focus bindings for filter ↔ list navigation."""

from __future__ import annotations

from nexus_control.ui.keybindings import asset_bindings, repo_bindings


def test_repo_bindings_include_tab_navigation() -> None:
    by_key = {b.key: b.action for b in repo_bindings()}
    assert by_key["tab"] == "app.focus_next"
    assert by_key["shift+tab"] == "app.focus_previous"
    assert by_key["down"] == "focus_results"
    assert by_key["w"] == "search"


def test_asset_bindings_include_tab_navigation() -> None:
    by_key = {b.key: b.action for b in asset_bindings()}
    assert by_key["tab"] == "app.focus_next"
    assert by_key["shift+tab"] == "app.focus_previous"
    assert by_key["down"] == "focus_results"
