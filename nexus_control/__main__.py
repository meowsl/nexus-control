"""Точка входа: ``python -m nexus_control``."""

from __future__ import annotations

import sys


def main() -> None:
    """Загрузить конфигурацию, настроить логирование и запустить Textual-приложение."""
    from nexus_control.app import run_app

    try:
        run_app()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130) from None
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — верхний уровень для UX CLI
        print(f"Fatal error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
