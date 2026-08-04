"""Textual-экраны: список репозиториев и дерево артефактов."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    RichLog,
    Static,
    Tree,
)
from textual.widgets.tree import TreeNode as TuiTreeNode

from nexus_tui.models import (
    DockerTag,
    NexusAsset,
    PipelineSummary,
    Repository,
    TreeNode,
)
from nexus_tui.nexus.client import NexusAPIError, NexusAuthError, NexusNetworkError
from nexus_tui.services.pipeline import PipelineService
from nexus_tui.ui.keybindings import HELP_TEXT
from nexus_tui.ui.widgets import (
    ConfirmModal,
    HelpModal,
    MessageModal,
    ReportModal,
    format_confirm_body,
)
from nexus_tui.utils.text import format_attrs, human_size, truncate
from nexus_tui.utils.tree_builder import (
    build_asset_tree,
    build_docker_tag_tree,
    collect_leaf_assets,
    empty_tree,
    filter_tree,
)

if TYPE_CHECKING:
    from nexus_tui.app import NexusTuiApp

logger = logging.getLogger(__name__)


def _schedule_on_app(app: NexusTuiApp, callback: Callable[..., Any], *args: Any) -> None:
    """Потокобезопасно вызвать UI-колбэк, не используя Screen.app из worker-потока.

    Важно: не блокируем worker через ``call_from_thread().result()`` — иначе возможен
    deadlock с TuiLogHandler, который тоже ходит в main loop из того же потока.
    """
    loop = getattr(app, "_loop", None)
    if loop is None:
        return

    async def _run() -> None:
        with app._context():
            callback(*args)

    asyncio.run_coroutine_threadsafe(_run(), loop)


class RepositoriesScreen(Screen[None]):
    """Первый экран: просмотр репозиториев Nexus."""

    BINDINGS = [
        Binding("q", "app.quit", "Выход"),
        Binding("r", "refresh", "Обновить"),
        Binding("slash", "search", "Фильтр", priority=True),
        Binding("enter", "open_repo", "Открыть", show=True),
        Binding("question_mark", "help", "Справка"),
        Binding("escape", "close_search", "Закрыть фильтр", show=False, priority=True),
    ]

    CSS = """
    RepositoriesScreen #status {
        dock: top;
        height: 1;
        background: $boost;
        color: $text;
        padding: 0 1;
    }
    RepositoriesScreen #filter-row {
        height: 3;
        display: none;
        padding: 0 1;
    }
    RepositoriesScreen #filter-row.visible {
        display: block;
    }
    RepositoriesScreen #repo-table {
        height: 1fr;
    }
    RepositoriesScreen #log {
        height: 8;
        border: solid $primary;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._repos: list[Repository] = []
        self._filter = ""
        self._ui_app: NexusTuiApp | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Connecting…", id="status")
        with Vertical(id="filter-row"):
            yield Input(placeholder="Filter repositories…", id="repo-filter")
        yield DataTable(id="repo-table", zebra_stripes=True)
        yield RichLog(id="log", highlight=True, markup=True, max_lines=500)
        yield Footer()

    def on_mount(self) -> None:
        self._ui_app = self.app
        table = self.query_one("#repo-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "Format", "Type", "Support", "URL", "Attributes")
        # Скрытый Input иначе перехватывает фокус и «съедает» клавиши экрана.
        self.query_one("#repo-filter", Input).can_focus = False
        self.query_one("#log", RichLog).can_focus = False
        table.focus()
        self.action_refresh()

    @property
    def app(self) -> NexusTuiApp:  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def action_help(self) -> None:
        self.app.push_screen(HelpModal(HELP_TEXT))

    def action_search(self) -> None:
        row = self.query_one("#filter-row")
        row.toggle_class("visible")
        filt = self.query_one("#repo-filter", Input)
        if row.has_class("visible"):
            filt.can_focus = True
            filt.focus()
        else:
            self._close_filter(filt)

    def action_close_search(self) -> None:
        row = self.query_one("#filter-row")
        if not row.has_class("visible"):
            return
        row.remove_class("visible")
        self._close_filter(self.query_one("#repo-filter", Input))

    def _close_filter(self, filt: Input) -> None:
        filt.value = ""
        filt.can_focus = False
        self._filter = ""
        self._render_rows()
        self.query_one("#repo-table", DataTable).focus()

    @on(Input.Submitted, "#repo-filter")
    def _on_filter_submitted(self, event: Input.Submitted) -> None:
        self._filter = event.value.strip().lower()
        self._render_rows()
        self.action_close_search()

    @on(Input.Changed, "#repo-filter")
    def _on_filter(self, event: Input.Changed) -> None:
        self._filter = event.value.strip().lower()
        self._render_rows()

    def action_refresh(self) -> None:
        self._ui_app = self.app
        self.query_one("#status", Static).update("Loading repositories…")
        self._load_repos()

    @work(thread=True, exclusive=True)
    def _load_repos(self) -> None:
        app = self._ui_app
        if app is None:
            return
        try:
            app.ensure_client()
            repos = app.client.list_repositories()
        except NexusAuthError as exc:
            _schedule_on_app(app, self._on_error, "Authentication error", str(exc))
            return
        except NexusNetworkError as exc:
            _schedule_on_app(app, self._on_error, "Network error", str(exc))
            return
        except NexusAPIError as exc:
            _schedule_on_app(app, self._on_error, "Nexus API error", str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error listing repositories")
            _schedule_on_app(app, self._on_error, "Unexpected error", str(exc))
            return
        _schedule_on_app(app, self._on_repos_loaded, repos)

    def _on_repos_loaded(self, repos: list[Repository]) -> None:
        self._repos = repos
        session = self.app.client.session
        status = (
            f"Connected to {self.app.settings.nexus_url} as "
            f"{self.app.settings.nexus_username} — {len(repos)} repositories"
        )
        if session:
            status += f" | session until {session.expires_at}"
        self.query_one("#status", Static).update(status)
        self._render_rows()
        self._log(f"Loaded {len(repos)} repositories")

    def _render_rows(self) -> None:
        table = self.query_one("#repo-table", DataTable)
        table.clear()
        query = self._filter
        for repo in self._repos:
            if query and query not in repo.name.lower():
                continue
            table.add_row(
                repo.name,
                repo.format,
                repo.type,
                repo.support_level,
                truncate(repo.url or "-", 40),
                truncate(format_attrs(repo.attributes), 40),
                key=repo.name,
            )

    def action_open_repo(self) -> None:
        table = self.query_one("#repo-table", DataTable)
        if table.row_count == 0:
            return
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        name = str(row_key.value) if row_key else None
        if not name:
            # Запасной вариант: имя из строки под курсором
            try:
                name = str(table.get_row_at(table.cursor_row)[0])
            except Exception:  # noqa: BLE001
                return
        self._open_repo_by_name(name)

    @on(DataTable.RowSelected, "#repo-table")
    def _on_repo_selected(self, event: DataTable.RowSelected) -> None:
        name = str(event.row_key.value) if event.row_key else None
        if name:
            self._open_repo_by_name(name)

    def _open_repo_by_name(self, name: str) -> None:
        repo = next((r for r in self._repos if r.name == name), None)
        if repo is None:
            return
        self.app.push_screen(AssetsScreen(repo))

    def _on_error(self, title: str, message: str) -> None:
        self.query_one("#status", Static).update(f"[red]{title}[/red]")
        self._log(f"[red]{title}:[/red] {message}")
        self.app.push_screen(MessageModal(title, message))

    def _log(self, message: str) -> None:
        self.query_one("#log", RichLog).write(message)


class AssetsScreen(Screen[None]):
    """Просмотр артефактов репозитория в виде дерева; действия загрузки/сканирования/проверки."""

    BINDINGS = [
        Binding("escape", "escape", "Назад", priority=True),
        Binding("q", "back", "Назад"),
        Binding("r", "refresh", "Обновить"),
        Binding("slash", "search", "Фильтр", priority=True),
        Binding("enter", "toggle_node", "Раскрыть"),
        Binding("d", "download_selected", "Скачать"),
        Binding("s", "scan_selected", "Скан"),
        Binding("v", "verify_selected", "Verify"),
        Binding("D", "download_all", "Скачать всё"),
        Binding("S", "scan_all", "Скан всё"),
        Binding("V", "verify_all", "Verify всё"),
        Binding("o", "open_report", "Отчёт"),
        Binding("question_mark", "help", "Справка"),
        Binding("c", "cancel_job", "Отмена", show=False),
    ]

    CSS = """
    AssetsScreen #status {
        dock: top;
        height: 3;
        background: $boost;
        padding: 0 1;
    }
    AssetsScreen #filter-row {
        height: 3;
        display: none;
        padding: 0 1;
    }
    AssetsScreen #filter-row.visible {
        display: block;
    }
    AssetsScreen #main {
        height: 1fr;
    }
    AssetsScreen #asset-tree {
        width: 3fr;
        height: 1fr;
    }
    AssetsScreen #side {
        width: 2fr;
        height: 1fr;
    }
    AssetsScreen #progress {
        height: 3;
        padding: 0 1;
    }
    AssetsScreen #log {
        height: 1fr;
        border: solid $primary;
    }
    """

    def __init__(self, repository: Repository) -> None:
        super().__init__()
        self.repository = repository
        self._root_tree: TreeNode = empty_tree()
        self._flat_assets: list[NexusAsset] = []
        self._docker_tags: list[DockerTag] = []
        self._filter = ""
        self._last_summary: PipelineSummary | None = None
        self._cancel = False
        self._busy = False
        self._ui_app: NexusTuiApp | None = None
        # Соответствие id узла textual tree -> доменный TreeNode
        self._node_map: dict[int, TreeNode] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="status")
        with Vertical(id="filter-row"):
            yield Input(placeholder="Filter assets…", id="asset-filter")
        with Horizontal(id="main"):
            yield Tree(self.repository.name, id="asset-tree")
            with Vertical(id="side"):
                with Vertical(id="progress"):
                    yield Label("Idle", id="job-label")
                    yield ProgressBar(total=100, id="job-progress", show_eta=False)
                yield RichLog(id="log", highlight=True, markup=True, max_lines=1000)
        yield Footer()

    def on_mount(self) -> None:
        self._ui_app = self.app
        support = self.repository.support_level
        self.query_one("#status", Static).update(
            f"[b]{self.repository.name}[/b]  format={self.repository.format}  "
            f"type={self.repository.type}  support={support}"
        )
        self.query_one("#asset-filter", Input).can_focus = False
        self.query_one("#log", RichLog).can_focus = False
        self.query_one("#asset-tree", Tree).focus()
        self.action_refresh()

    @property
    def app(self) -> NexusTuiApp:  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_escape(self) -> None:
        """Esc: сначала закрыть фильтр, иначе вернуться к репозиториям."""
        row = self.query_one("#filter-row")
        if row.has_class("visible"):
            row.remove_class("visible")
            self._close_asset_filter(self.query_one("#asset-filter", Input))
            return
        self.action_back()

    def action_help(self) -> None:
        self.app.push_screen(HelpModal(HELP_TEXT))

    def action_search(self) -> None:
        row = self.query_one("#filter-row")
        row.toggle_class("visible")
        filt = self.query_one("#asset-filter", Input)
        if row.has_class("visible"):
            filt.can_focus = True
            filt.focus()
        else:
            self._close_asset_filter(filt)

    def _close_asset_filter(self, filt: Input) -> None:
        filt.value = ""
        filt.can_focus = False
        self._filter = ""
        self._populate_tree(self._root_tree)
        self.query_one("#asset-tree", Tree).focus()

    @on(Input.Changed, "#asset-filter")
    def _on_filter_changed(self, event: Input.Changed) -> None:
        self._filter = event.value.strip()
        view = filter_tree(self._root_tree, self._filter) if self._filter else self._root_tree
        self._populate_tree(view)

    @on(Input.Submitted, "#asset-filter")
    def _on_filter_submitted(self, event: Input.Submitted) -> None:
        self._filter = event.value.strip()
        view = filter_tree(self._root_tree, self._filter) if self._filter else self._root_tree
        self._populate_tree(view)
        row = self.query_one("#filter-row")
        row.remove_class("visible")
        filt = self.query_one("#asset-filter", Input)
        filt.can_focus = False
        self.query_one("#asset-tree", Tree).focus()

    def action_toggle_node(self) -> None:
        """Раскрыть/свернуть узел (Space / Enter через Tree.auto_expand)."""
        tree = self.query_one("#asset-tree", Tree)
        if tree.cursor_node is not None:
            tree.cursor_node.toggle()

    def action_cancel_job(self) -> None:
        if self._busy:
            self._cancel = True
            self._log("[yellow]Cancel requested…[/yellow]")

    def action_refresh(self) -> None:
        if self._busy:
            self._log("[yellow]Busy; wait for the current job.[/yellow]")
            return
        self._ui_app = self.app
        self._log(f"Loading assets for {self.repository.name}…")
        self._load_assets()

    @work(thread=True, exclusive=True)
    def _load_assets(self) -> None:
        app = self._ui_app
        if app is None:
            return
        try:
            app.ensure_client()
            if self.repository.is_docker:
                tags = app.client.list_docker_tags(self.repository)
                tree = build_docker_tag_tree(tags, root_name=self.repository.name)
                _schedule_on_app(app, self._on_docker_loaded, tags, tree)
            else:
                assets = app.client.list_assets(self.repository.name)
                tree = build_asset_tree(assets, root_name=self.repository.name)
                _schedule_on_app(app, self._on_assets_loaded, assets, tree)
        except NexusAPIError as exc:
            _schedule_on_app(app, self._show_error, "Failed to load assets", str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Asset load failed")
            _schedule_on_app(app, self._show_error, "Unexpected error", str(exc))

    def _on_assets_loaded(self, assets: list[NexusAsset], tree: TreeNode) -> None:
        self._flat_assets = assets
        self._docker_tags = []
        self._root_tree = tree
        if not assets:
            self._log("[yellow]Repository is empty (no assets).[/yellow]")
        else:
            self._log(f"Loaded {len(assets)} assets")
        if self.repository.support_level == "partially_supported":
            self._log(
                "[yellow]Repository format is only partially supported; "
                "tree is built from asset paths best-effort.[/yellow]"
            )
        view = filter_tree(tree, self._filter) if self._filter else tree
        self._populate_tree(view)

    def _on_docker_loaded(self, tags: list[DockerTag], tree: TreeNode) -> None:
        self._docker_tags = tags
        self._flat_assets = []
        self._root_tree = tree
        if not tags:
            self._log(
                "[yellow]No docker tags found. If the docker connector port is "
                "not exposed, set NEXUS_DOCKER_REGISTRY=host:port in .env.[/yellow]"
            )
        else:
            self._log(f"Loaded {len(tags)} docker tags (adapter view)")
        view = filter_tree(tree, self._filter) if self._filter else tree
        self._populate_tree(view)

    def _populate_tree(self, root: TreeNode) -> None:
        tree = self.query_one("#asset-tree", Tree)
        tree.clear()
        # Enter уже раскрывает через Tree.auto_expand — не дублируем toggle в handlers.
        tree.auto_expand = True
        self._node_map.clear()
        tree.root.expand()
        self._node_map[id(tree.root)] = root
        for child in sorted(root.children.values(), key=lambda n: (not n.is_dir, n.name.lower())):
            self._add_node(tree.root, child)

    def _add_node(self, parent: TuiTreeNode[Any], node: TreeNode) -> None:
        label = self._label_for(node)
        if node.is_dir:
            tui_node = parent.add(label, data=node, expand=False)
            self._node_map[id(tui_node)] = node
            for child in sorted(
                node.children.values(),
                key=lambda n: (not n.is_dir, n.name.lower()),
            ):
                self._add_node(tui_node, child)
        else:
            tui_node = parent.add_leaf(label, data=node)
            self._node_map[id(tui_node)] = node

    def _label_for(self, node: TreeNode) -> str:
        if node.is_dir:
            return f"[dir] {node.name}/ ({node.child_count})"
        if node.docker_tag is not None:
            return f"[img] {node.name}"
        asset = node.asset
        size = human_size(asset.file_size) if asset else "-"
        ctype = (asset.content_type or "-") if asset else "-"
        modified = (asset.last_modified or "-") if asset else "-"
        return (
            f"[file] {node.name}  [{size}]  "
            f"{truncate(ctype, 24)}  {truncate(str(modified), 20)}"
        )

    # ---- вспомогательные функции выбора -------------------------------------------------
    def _selected_domain_node(self) -> TreeNode | None:
        tree = self.query_one("#asset-tree", Tree)
        cursor = tree.cursor_node
        if cursor is None:
            return self._root_tree
        data = cursor.data
        if isinstance(data, TreeNode):
            return data
        return self._node_map.get(id(cursor), self._root_tree)

    def _items_for_selected(self) -> list[NexusAsset | DockerTag]:
        node = self._selected_domain_node()
        if node is None:
            return []
        # Корень (пустой path) → весь репозиторий
        if node.path == "":
            return self._all_items()
        return collect_leaf_assets(node)

    def _all_items(self) -> list[NexusAsset | DockerTag]:
        if self.repository.is_docker:
            return list(self._docker_tags)
        return list(self._flat_assets)

    def _approx_size(self, items: list[NexusAsset | DockerTag]) -> int | None:
        total = 0
        known = False
        for item in items:
            if isinstance(item, NexusAsset) and item.file_size is not None:
                total += item.file_size
                known = True
        return total if known else None

    # ---- действия -----------------------------------------------------------
    def action_download_selected(self) -> None:
        self._confirm_and_run("download", self._items_for_selected(), download=True, scan=False, verify=False)

    def action_scan_selected(self) -> None:
        # Сканирование подразумевает предварительную загрузку при отсутствии файла — pipeline сначала загружает, затем сканирует.
        self._confirm_and_run("scan", self._items_for_selected(), download=True, scan=True, verify=False)

    def action_verify_selected(self) -> None:
        self._confirm_and_run("verify", self._items_for_selected(), download=True, scan=True, verify=True)

    def action_download_all(self) -> None:
        self._confirm_and_run("download ALL", self._all_items(), download=True, scan=False, verify=False)

    def action_scan_all(self) -> None:
        self._confirm_and_run("scan ALL", self._all_items(), download=True, scan=True, verify=False)

    def action_verify_all(self) -> None:
        self._confirm_and_run("verify ALL", self._all_items(), download=True, scan=True, verify=True)

    def action_open_report(self) -> None:
        if self._last_summary is None:
            self.app.push_screen(MessageModal("Report", "No report yet. Run a scan/verify first."))
            return
        self.app.push_screen(ReportModal(self._last_summary))

    def _confirm_and_run(
        self,
        action: str,
        items: list[NexusAsset | DockerTag],
        *,
        download: bool,
        scan: bool,
        verify: bool,
    ) -> None:
        if self._busy:
            self._log("[yellow]Another job is running.[/yellow]")
            return
        if not items:
            self.app.push_screen(MessageModal("Nothing to do", "No assets selected or repository is empty."))
            return

        settings = self.app.settings
        body = format_confirm_body(
            action=action,
            count=len(items),
            total_size=self._approx_size(items),
            download_root=str(settings.download_root / self.repository.name),
            verified_root=str(settings.verified_repo_dir(self.repository.name)),
        )

        def _after(confirmed: bool | None) -> None:
            if confirmed:
                self._start_pipeline(items, download=download, scan=scan, verify=verify)

        self.app.push_screen(ConfirmModal(f"Confirm {action}", body), _after)

    def _start_pipeline(
        self,
        items: list[NexusAsset | DockerTag],
        *,
        download: bool,
        scan: bool,
        verify: bool,
    ) -> None:
        self._ui_app = self.app
        self._busy = True
        self._cancel = False
        self.query_one("#job-label", Label).update("Starting…")
        self.query_one("#job-progress", ProgressBar).update(progress=0)
        self._run_pipeline(items, download, scan, verify)

    @work(thread=True)
    def _run_pipeline(
        self,
        items: list[NexusAsset | DockerTag],
        download: bool,
        scan: bool,
        verify: bool,
    ) -> None:
        app = self._ui_app
        if app is None:
            return

        def on_progress(asset_path: str, progress: float, stage: str) -> None:
            _schedule_on_app(app, self._update_progress, asset_path, progress, stage)

        try:
            app.ensure_client()
            pipeline = PipelineService(app.settings, app.client)
            summary = pipeline.run(
                repository=self.repository.name,
                items=items,
                download=download,
                scan=scan,
                verify=verify,
                on_progress=on_progress,
                should_cancel=lambda: self._cancel,
            )
            _schedule_on_app(app, self._on_pipeline_done, summary)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Pipeline failed")
            _schedule_on_app(app, self._on_pipeline_failed, str(exc))

    def _update_progress(self, asset_path: str, progress: float, stage: str) -> None:
        self.query_one("#job-label", Label).update(
            f"{stage}: {truncate(asset_path, 60)}"
        )
        self.query_one("#job-progress", ProgressBar).update(progress=progress * 100)
        self._log(f"{stage}: {asset_path}")

    def _on_pipeline_done(self, summary: PipelineSummary) -> None:
        self._busy = False
        self._last_summary = summary
        self.query_one("#job-label", Label).update(
            f"Done — PASS={summary.total_passed} FAIL={summary.total_failed} "
            f"ERROR={summary.total_errors} copied={summary.total_copied}"
        )
        self.query_one("#job-progress", ProgressBar).update(progress=100)
        self._log(
            f"[green]Finished[/green] scanned={summary.total_scanned} "
            f"PASS={summary.total_passed} FAIL={summary.total_failed} "
            f"ERROR={summary.total_errors} copied={summary.total_copied}"
        )
        self.app.push_screen(ReportModal(summary))

    def _on_pipeline_failed(self, message: str) -> None:
        self._busy = False
        self.query_one("#job-label", Label).update("Failed")
        self._show_error("Pipeline failed", message)

    def _show_error(self, title: str, message: str) -> None:
        self._log(f"[red]{title}:[/red] {message}")
        self.app.push_screen(MessageModal(title, message))

    def _log(self, message: str) -> None:
        self.query_one("#log", RichLog).write(message)
