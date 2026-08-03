"""Переиспользуемые Textual-виджеты и модальные диалоги."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, RichLog, Static

from nexus_tui.models import AssetPipelineResult, PipelineSummary, Verdict
from nexus_tui.utils.text import human_size, truncate


class ConfirmModal(ModalScreen[bool]):
    """Запросить у пользователя подтверждение массовой операции."""

    DEFAULT_CSS = """
    ConfirmModal {
        align: center middle;
    }
    ConfirmModal > Vertical {
        width: 72;
        height: auto;
        max-height: 80%;
        border: heavy $accent;
        background: $surface;
        padding: 1 2;
    }
    ConfirmModal .buttons {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        title: str,
        body: str,
        *,
        confirm_label: str = "Confirm",
    ) -> None:
        super().__init__()
        self._title = title
        self._body = body
        self._confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"[b]{self._title}[/b]")
            yield Static(self._body, id="confirm-body")
            with Horizontal(classes="buttons"):
                yield Button(self._confirm_label, variant="primary", id="ok")
                yield Button("Cancel", variant="default", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "ok")

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key == "escape":
            self.dismiss(False)
        elif event.key == "enter":
            self.dismiss(True)


class MessageModal(ModalScreen[None]):
    DEFAULT_CSS = """
    MessageModal {
        align: center middle;
    }
    MessageModal > Vertical {
        width: 70;
        height: auto;
        max-height: 80%;
        border: heavy $warning;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self._title = title
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"[b]{self._title}[/b]")
            yield Static(self._message)
            yield Button("OK", variant="primary", id="ok")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.dismiss(None)

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key in {"escape", "enter"}:
            self.dismiss(None)


class HelpModal(ModalScreen[None]):
    DEFAULT_CSS = """
    HelpModal {
        align: center middle;
    }
    HelpModal > Vertical {
        width: 78;
        height: auto;
        max-height: 90%;
        border: heavy $accent;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("[b]Keyboard shortcuts[/b]")
            with VerticalScroll():
                yield Static(self._text)
            yield Button("Close", id="ok")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key in {"escape", "enter", "question_mark"}:
            self.dismiss(None)


class ReportModal(ModalScreen[None]):
    """Показать сводную таблицу pipeline с опциональными деталями строк."""

    DEFAULT_CSS = """
    ReportModal {
        align: center middle;
    }
    ReportModal > Vertical {
        width: 96%;
        height: 90%;
        border: heavy $accent;
        background: $surface;
        padding: 1 1;
    }
    ReportModal #details {
        height: 12;
        border: solid $primary;
        margin-top: 1;
    }
    """

    def __init__(self, summary: PipelineSummary) -> None:
        super().__init__()
        self.summary = summary
        self._rows: list[AssetPipelineResult] = list(summary.results)

    def compose(self) -> ComposeResult:
        s = self.summary
        header = (
            f"[b]Results — {s.repository}[/b]  "
            f"scanned={s.total_scanned}  PASS={s.total_passed}  "
            f"FAIL={s.total_failed}  ERROR={s.total_errors}  "
            f"copied={s.total_copied}"
        )
        with Vertical():
            yield Label(header)
            yield DataTable(id="report-table", zebra_stripes=True)
            yield RichLog(id="details", highlight=True, markup=True)
            yield Button("Close", variant="primary", id="ok")

    def on_mount(self) -> None:
        table = self.query_one("#report-table", DataTable)
        table.add_columns(
            "Asset",
            "Type",
            "Download",
            "Scan",
            "Vulns",
            "Crit",
            "High",
            "Med",
            "Low",
            "Verdict",
            "Verified",
        )
        table.cursor_type = "row"
        for result in self._rows:
            table.add_row(
                truncate(result.asset_path, 40),
                result.kind.value,
                result.download.status.value,
                result.scan.status.value,
                str(result.scan.vulnerability_count),
                str(result.scan.counts.critical),
                str(result.scan.counts.high),
                str(result.scan.counts.medium),
                str(result.scan.counts.low),
                _verdict_style(result.verdict),
                truncate(str(result.verify.verified_path or "-"), 28),
            )
        if self._rows:
            self._show_details(0)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if idx is not None and 0 <= idx < len(self._rows):
            self._show_details(idx)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        idx = event.cursor_row
        if idx is not None and 0 <= idx < len(self._rows):
            self._show_details(idx)

    def _show_details(self, index: int) -> None:
        result = self._rows[index]
        log = self.query_one("#details", RichLog)
        log.clear()
        log.write(f"[b]{result.asset_path}[/b]")
        log.write(f"Local: {result.download.local_path or '-'}")
        log.write(f"JSON report: {result.scan.json_report_path or '-'}")
        log.write(f"Verdict: {result.verdict.value}")
        if result.download.error:
            log.write(f"[red]Download error:[/red] {result.download.error}")
        if result.scan.error:
            log.write(f"[red]Scan error:[/red] {result.scan.error}")
        if result.verify.error:
            log.write(f"[red]Verify error:[/red] {result.verify.error}")
        vulns = result.scan.vulnerabilities[:20]
        if vulns:
            log.write("[b]Top vulnerabilities[/b]")
            for v in vulns:
                log.write(
                    f"  [{v.severity.value}] {v.id} "
                    f"{v.package_name}@{v.package_version}"
                )
        elif result.verdict == Verdict.PASS:
            log.write("[green]No vulnerabilities found.[/green]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.dismiss(None)

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key in {"escape", "q"}:
            self.dismiss(None)


def _verdict_style(verdict: Verdict) -> str:
    if verdict == Verdict.PASS:
        return "PASS"
    if verdict == Verdict.FAIL:
        return "FAIL"
    if verdict == Verdict.ERROR:
        return "ERROR"
    return verdict.value


def format_confirm_body(
    *,
    action: str,
    count: int,
    total_size: int | None,
    download_root: str,
    verified_root: str,
) -> str:
    size_txt = human_size(total_size) if total_size is not None else "unknown"
    return (
        f"Action: [b]{action}[/b]\n"
        f"Items: [b]{count}[/b]\n"
        f"Approx. size: {size_txt}\n"
        f"Download path: {download_root}\n"
        f"Verified path: {verified_root}\n\n"
        "Proceed?"
    )
