"""Переиспользуемые Textual-виджеты и модальные диалоги."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Label, RichLog, Static

from nexus_control.i18n import _
from nexus_control.models import AssetPipelineResult, PipelineSummary, Verdict
from nexus_control.services.verified_uploader import (
    UploadSummary,
    VerifiedUploader,
    verified_repo_name,
)
from nexus_control.ui.thread_ui import schedule_on_app
from nexus_control.utils.text import human_size, truncate

if TYPE_CHECKING:
    from nexus_control.app import NexusControlApp

logger = logging.getLogger(__name__)


class ConfirmModal(ModalScreen[bool]):
    """Запросить у пользователя подтверждение массовой операции."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

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
        confirm_label: str | None = None,
        cancel_label: str | None = None,
    ) -> None:
        super().__init__()
        self._title = title
        self._body = body
        self._confirm_label = confirm_label if confirm_label is not None else _("Confirm")
        self._cancel_label = cancel_label if cancel_label is not None else _("Cancel")

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"[b]{self._title}[/b]")
            yield Static(self._body, id="confirm-body")
            with Horizontal(classes="buttons"):
                yield Button(self._confirm_label, variant="primary", id="ok")
                yield Button(self._cancel_label, variant="default", id="cancel")

    def on_mount(self) -> None:
        # По умолчанию фокус на Confirm; Enter активирует только focused-кнопку
        # (не форсирует Confirm при фокусе на Cancel — см. отсутствие on_key Enter).
        self.query_one("#ok", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(event.button.id == "ok")

    def action_cancel(self) -> None:
        self.dismiss(False)


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
            yield Button(_("OK"), variant="primary", id="ok")

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
            yield Label(f"[b]{_('Keyboard shortcuts')}[/b]")
            with VerticalScroll():
                yield Static(self._text)
            yield Button(_("Close"), id="ok")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key in {"escape", "enter", "question_mark"}:
            self.dismiss(None)


class ScannerSettingsModal(ModalScreen[list[str] | None]):
    """Выбор сканеров для verify: grype / trivy / оба."""

    DEFAULT_CSS = """
    ScannerSettingsModal {
        align: center middle;
    }
    ScannerSettingsModal > Vertical {
        width: 64;
        height: auto;
        border: heavy $accent;
        background: $surface;
        padding: 1 2;
    }
    ScannerSettingsModal .hint {
        color: $text-muted;
        margin: 1 0;
    }
    ScannerSettingsModal .error {
        color: $error;
        height: 1;
    }
    ScannerSettingsModal .buttons {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    """

    def __init__(self, selected: list[str]) -> None:
        super().__init__()
        self._selected = {s.lower() for s in selected}

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"[b]{_('Vulnerability scanners')}[/b]")
            yield Static(
                _(
                    "Enable one or both. Verify copies to *-verified only if all "
                    "enabled scanners PASS."
                ),
                classes="hint",
            )
            yield Checkbox(
                "Grype",
                value="grype" in self._selected,
                id="scan-grype",
            )
            yield Checkbox(
                "Trivy",
                value="trivy" in self._selected,
                id="scan-trivy",
            )
            yield Static("", id="scan-error", classes="error")
            with Horizontal(classes="buttons"):
                yield Button(_("Save"), variant="primary", id="ok")
                yield Button(_("Cancel"), variant="default", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        if event.button.id == "ok":
            chosen: list[str] = []
            if self.query_one("#scan-grype", Checkbox).value:
                chosen.append("grype")
            if self.query_one("#scan-trivy", Checkbox).value:
                chosen.append("trivy")
            if not chosen:
                self.query_one("#scan-error", Static).update(
                    _("Select at least one scanner.")
                )
                return
            self.dismiss(chosen)

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key == "escape":
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
        layout: vertical;
    }
    ReportModal #report-header {
        height: auto;
        max-height: 3;
        margin-bottom: 0;
    }
    ReportModal #report-table {
        height: 1fr;
        min-height: 5;
    }
    ReportModal #report-footer {
        height: auto;
        dock: bottom;
        margin-top: 1;
    }
    ReportModal #details {
        height: 10;
        min-height: 8;
        max-height: 12;
        border: solid $primary;
    }
    ReportModal .buttons {
        height: 3;
        min-height: 3;
        align: center middle;
        margin-top: 1;
    }
    """

    def __init__(self, summary: PipelineSummary) -> None:
        super().__init__()
        self.summary = summary
        self._rows: list[AssetPipelineResult] = list(summary.results)
        self._ui_app: NexusControlApp | None = None
        self._uploading = False
        self._uploadable = [
            r
            for r in self._rows
            if r.verdict == Verdict.PASS
            and r.verify.verified_path is not None
            and (r.verify.copied or r.verify.skipped_existing)
        ]

    def compose(self) -> ComposeResult:
        s = self.summary
        target = verified_repo_name(s.repository)
        scanners = "+".join(s.scanners) if s.scanners else "-"
        header = (
            f"[b]Results — {s.repository}[/b]  "
            f"scanners={scanners}  "
            f"scanned={s.total_scanned}  PASS={s.total_passed}  "
            f"FAIL={s.total_failed}  ERROR={s.total_errors}  "
            f"copied={s.total_copied}  "
            f"uploadable={len(self._uploadable)} → {target}"
        )
        with Vertical():
            yield Label(header, id="report-header")
            yield DataTable(id="report-table", zebra_stripes=True)
            with Vertical(id="report-footer"):
                yield RichLog(id="details", highlight=True, markup=True)
                with Horizontal(classes="buttons"):
                    yield Button(
                        _("Upload verified"),
                        variant="success",
                        id="upload",
                        disabled=not self._uploadable,
                    )
                    yield Button(_("Close"), variant="primary", id="ok")

    def on_mount(self) -> None:
        self._ui_app = self.app  # type: ignore[assignment]
        table = self.query_one("#report-table", DataTable)
        table.add_columns(
            _("Asset"),
            _("Type"),
            _("Download"),
            _("Scan"),
            _("Vulns"),
            _("Crit"),
            _("High"),
            _("Med"),
            _("Low"),
            _("Verdict"),
            _("Verified"),
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
        if self._uploading:
            return
        result = self._rows[index]
        log = self.query_one("#details", RichLog)
        log.clear()
        log.write(f"[b]{result.asset_path}[/b]")
        log.write(f"Local: {result.download.local_path or '-'}")
        log.write(f"Verdict (all scanners): {result.verdict.value}")
        if result.download.error:
            log.write(f"[red]Download error:[/red] {result.download.error}")
        if result.verify.error:
            log.write(f"[red]Verify error:[/red] {result.verify.error}")

        if result.scans:
            for name, sc in result.scans.items():
                log.write(
                    f"[b]{name}[/b]: {sc.verdict.value}  "
                    f"vulns={sc.vulnerability_count}  "
                    f"json={sc.json_report_path or '-'}"
                )
                if sc.error:
                    log.write(f"  [red]error:[/red] {sc.error}")
                for v in sc.vulnerabilities[:10]:
                    log.write(
                        f"  [{v.severity.value}] {v.id} "
                        f"{v.package_name}@{v.package_version}"
                    )
        elif result.verdict == Verdict.PASS:
            log.write("[green]No vulnerabilities found.[/green]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            if self._uploading:
                return
            self.dismiss(None)
        elif event.button.id == "upload":
            self._start_upload()

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key in {"escape", "q"}:
            if self._uploading:
                return
            self.dismiss(None)

    def _start_upload(self) -> None:
        if self._uploading or not self._uploadable:
            return
        self._uploading = True
        upload_btn = self.query_one("#upload", Button)
        close_btn = self.query_one("#ok", Button)
        upload_btn.disabled = True
        close_btn.disabled = True
        target = verified_repo_name(self.summary.repository)
        log = self.query_one("#details", RichLog)
        log.clear()
        log.write(
            f"[b]Uploading {len(self._uploadable)} verified asset(s) "
            f"→ [cyan]{target}[/cyan][/b]"
        )
        log.write(
            _("Creating repository if missing…")
        )
        self._run_upload()

    @work(thread=True, exclusive=True, group="upload-verified")
    def _run_upload(self) -> None:
        app = self._ui_app
        if app is None:
            return

        def on_progress(asset_path: str, progress: float, stage: str) -> None:
            schedule_on_app(app, self._on_upload_progress, asset_path, progress, stage)

        try:
            app.ensure_client()
            uploader = VerifiedUploader(app.client)
            summary = uploader.upload(self.summary, on_progress=on_progress)
            schedule_on_app(app, self._on_upload_done, summary)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Verified upload failed")
            schedule_on_app(app, self._on_upload_failed, str(exc))

    def _on_upload_progress(self, asset_path: str, progress: float, stage: str) -> None:
        log = self.query_one("#details", RichLog)
        pct = int(progress * 100)
        log.write(f"[{stage} {pct}%] {truncate(asset_path, 72)}")

    def _on_upload_done(self, summary: UploadSummary) -> None:
        self._uploading = False
        self.query_one("#ok", Button).disabled = False
        # Keep upload disabled after success to avoid duplicate pushes;
        # re-enable only if there were failures (retry remaining).
        upload_btn = self.query_one("#upload", Button)
        upload_btn.disabled = summary.failed == 0 or not self._uploadable

        log = self.query_one("#details", RichLog)
        created = _("created") if summary.created_repository else _("existing")
        log.write(
            "[green]"
            + _(
                "Upload finished ({created}): uploaded={uploaded} "
                "skipped={skipped} failed={failed}",
                created=created,
                uploaded=summary.uploaded,
                skipped=summary.skipped,
                failed=summary.failed,
            )
            + f"[/green] → [cyan]{summary.target_repository}[/cyan]"
        )
        for item in summary.results:
            if item.skipped:
                log.write(
                    f"  [yellow]SKIP[/yellow] {truncate(item.asset_path, 50)}: "
                    f"{item.error or 'skipped'}"
                )
            elif item.ok:
                log.write(f"  [green]OK[/green] {truncate(item.asset_path, 70)}")
            else:
                log.write(
                    f"  [red]FAIL[/red] {truncate(item.asset_path, 50)}: "
                    f"{item.error or 'unknown error'}"
                )

    def _on_upload_failed(self, message: str) -> None:
        self._uploading = False
        self.query_one("#ok", Button).disabled = False
        self.query_one("#upload", Button).disabled = not self._uploadable
        log = self.query_one("#details", RichLog)
        log.write(f"[red]{_('Upload failed:')}[/red] {message}")


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
    scanners: list[str] | None = None,
) -> str:
    size_txt = human_size(total_size) if total_size is not None else _("unknown")
    scanners_txt = "+".join(scanners) if scanners else _("none")
    return (
        f"{_('Action: {action}', action=f'[b]{action}[/b]')}\n"
        f"{_('Items: {count}', count=f'[b]{count}[/b]')}\n"
        f"{_('Scanners: {scanners}', scanners=f'[b]{scanners_txt}[/b]')}\n"
        f"{_('Approx. size: {size}', size=size_txt)}\n"
        f"{_('Download path: {path}', path=download_root)}\n"
        f"{_('Verified path: {path}', path=verified_root)}\n\n"
        f"{_('Proceed?')}"
    )
