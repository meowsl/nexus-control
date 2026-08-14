"""Тесты минимального i18n (en/ru)."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_control.config import clear_settings_cache, load_settings
from nexus_control.config_io import read_toml, write_toml_atomic
from nexus_control.config_paths import resolve_config_path
from nexus_control.config_wizard import run_first_run_wizard
from nexus_control.i18n import (
    _,
    get_locale,
    normalize_locale,
    set_locale,
    toggle_locale,
)


@pytest.fixture(autouse=True)
def _reset_locale() -> None:
    set_locale("ru")
    yield
    set_locale("ru")


def test_normalize_locale() -> None:
    assert normalize_locale("EN") == "en"
    assert normalize_locale("ru_RU") == "ru"
    assert normalize_locale("weird") == "ru"


def test_translate_ru_and_en() -> None:
    set_locale("ru")
    assert _("Quit") == "Выход"
    assert _("Refresh") == "Обновить"
    set_locale("en")
    assert _("Quit") == "Quit"
    assert _("Refresh") == "Refresh"


def test_unknown_msgid_passthrough() -> None:
    set_locale("ru")
    assert _("___no_such_key___") == "___no_such_key___"


def test_format_kwargs() -> None:
    set_locale("en")
    assert _("Language: {locale}", locale="en") == "Language: en"
    set_locale("ru")
    assert _("Language: {locale}", locale="ru") == "Язык: ru"


def test_toggle_locale() -> None:
    set_locale("ru")
    assert toggle_locale() == "en"
    assert get_locale() == "en"
    assert toggle_locale() == "ru"


def test_settings_locale_validator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clear_settings_cache()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("NEXUS_CONTROL_CONFIG", raising=False)
    monkeypatch.delenv("NEXUS_URL", raising=False)
    monkeypatch.delenv("NEXUS_CONTROL_LOCALE", raising=False)
    path = resolve_config_path()
    write_toml_atomic(
        path,
        {
            "nexus_url": "http://localhost:8081",
            "locale": "en",
        },
    )
    settings = load_settings(env_file=None, run_wizard=False)
    assert settings.locale == "en"


def test_wizard_writes_locale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clear_settings_cache()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    path = resolve_config_path()

    answers = iter(["en", "http://nexus.test:8081", "n", "grype", "n", "n"])

    def fake_input(prompt: str = "") -> str:
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)

    run_first_run_wizard(config_path=path)
    data = read_toml(path)
    assert data["locale"] == "en"
    assert data["nexus_url"] == "http://nexus.test:8081"
    assert get_locale() == "en"
