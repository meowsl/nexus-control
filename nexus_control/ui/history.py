"""TUI: история сканирований."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label

from nexus_control.i18n import _
from nexus_control.services.scan_history import (
    ScanRunMeta,
    format_history_when,
    latest_run_for_repo,
    list_runs,
    load_run,
)
from nexus_control.ui.widgets import MessageModal, ReportModal
from nexus_control.utils.text import truncate

if TYPE_CHECKING:
    from nexus_control.app import NexusControlApp


class HistoryModal(ModalScreen[None]):
    """Список сохранённых verify-прогонов → drill-down в ReportModal."""

    BINDINGS = [
        Binding("escape", "close", _("Close"), show=False),
        Binding("enter", "open_selected", _("Open"), show=False),
    ]

    DEFAULT_CSS = """
    HistoryModal {
        align: center middle;
    }
    HistoryModal > Vertical {
        width: 92%;
        height: 80%;
        border: heavy $accent;
        background: $surface;
        padding: 1 1;
    }
    HistoryModal #history-header {
        height: auto;
        margin-bottom: 1;
    }
    HistoryModal #history-table {
        height: 1fr;
    }
    HistoryModal .buttons {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        *,
        repository: str | None = None,
        title: str | None = None,
    ) -> None:
        super().__init__()
        self._repository = repository
        self._title = title or _("Scan history")
        self._rows: list[ScanRunMeta] = []

    def compose(self) -> ComposeResult:
        repo_bit = (
            f" — {self._repository}" if self._repository else f" — {_('all repositories')}"
        )
        with Vertical():
            yield Label(f"[b]{self._title}{repo_bit}[/b]", id="history-header")
            yield DataTable(id="history-table", zebra_stripes=True)
            with Horizontal(classes="buttons"):
                yield Button(_("Open"), variant="primary", id="open")
                yield Button(_("Close"), variant="default", id="close")

    def on_mount(self) -> None:
        app: NexusControlApp = self.app  # type: ignore[assignment]
        self._rows = list_runs(
            app.settings,
            repository=self._repository,
            limit=app.settings.scan_history_keep or 50,
        )
        table = self.query_one("#history-table", DataTable)
        table.add_columns(
            _("When"),
            _("Repo"),
            _("Source"),
            _("Total"),
            _("PASS"),
            _("FAIL"),
            _("ERROR"),
            _("Copied"),
            _("Skipped"),
            _("Scanners"),
            _("Run id"),
        )
        table.cursor_type = "row"
        if not self._rows:
            self.query_one("#history-header", Label).update(
                f"[b]{self._title}[/b]\n[yellow]{_('No scan history yet.')}[/yellow]"
            )
            self.query_one("#open", Button).disabled = True
            return
        for meta in self._rows:
            when = format_history_when(meta.finished_at, meta.started_at)
            table.add_row(
                when,
                truncate(meta.repository, 24),
                meta.source + (f"/{meta.rule_id}" if meta.rule_id else ""),
                str(meta.totals.total),
                str(meta.totals.passed),
                str(meta.totals.failed),
                str(meta.totals.errors),
                str(meta.totals.copied),
                str(meta.totals.checkpoint_skipped),
                "+".join(meta.scanners) if meta.scanners else "-",
                truncate(meta.run_id, 28),
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss(None)
        elif event.button.id == "open":
            self.action_open_selected()

    def action_close(self) -> None:
        self.dismiss(None)

    def action_open_selected(self) -> None:
        if not self._rows:
            return
        table = self.query_one("#history-table", DataTable)
        idx = table.cursor_row
        if idx is None or idx < 0 or idx >= len(self._rows):
            return
        meta = self._rows[idx]
        app: NexusControlApp = self.app  # type: ignore[assignment]
        summary = load_run(app.settings, meta.run_id)
        if summary is None:
            self.app.push_screen(
                MessageModal(
                    _("History"),
                    _("Could not load run {run_id}.", run_id=meta.run_id),
                )
            )
            return
        self.app.push_screen(ReportModal(summary))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_open_selected()


def open_latest_report_or_message(
    app: NexusControlApp,
    *,
    repository: str | None,
    last_summary,
) -> None:
    """Открыть in-memory report или последний disk run для repo."""
    if last_summary is not None:
        app.push_screen(ReportModal(last_summary))
        return
    if repository:
        meta = latest_run_for_repo(app.settings, repository)
        if meta is not None:
            summary = load_run(app.settings, meta.run_id)
            if summary is not None:
                app.push_screen(ReportModal(summary))
                return
    app.push_screen(
        MessageModal(_("Report"), _("No report yet. Run verify first."))
    )
