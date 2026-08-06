"""Textual-экраны: список репозиториев и дерево артефактов."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from textual import on, work
from textual.app import ComposeResult
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

from nexus_control.models import (
    DockerTag,
    NexusAsset,
    PipelineSummary,
    Repository,
    TreeNode,
)
from nexus_control.nexus.asset_cache import load_cached_assets, save_cached_assets
from nexus_control.nexus.client import NexusAPIError, NexusAuthError, NexusNetworkError
from nexus_control.nexus.errors import is_ssl_certificate_error
from nexus_control.services.pipeline import PipelineService
from nexus_control.i18n import _
from nexus_control.ui.keybindings import (
    asset_bindings,
    asset_tree_extra_bindings,
    help_text,
    repo_bindings,
)
from nexus_control.ui.thread_ui import schedule_on_app
from nexus_control.ui.widgets import (
    ConfirmModal,
    HelpModal,
    MessageModal,
    ReportModal,
    ScannerSettingsModal,
    format_confirm_body,
)
from nexus_control.utils.text import format_attrs, human_size, truncate
from nexus_control.utils.tree_builder import (
    annotate_counts,
    build_asset_tree,
    build_docker_tag_tree,
    collect_leaf_assets,
    empty_tree,
    filter_tree,
    insert_asset,
)

if TYPE_CHECKING:
    from nexus_control.app import NexusControlApp

logger = logging.getLogger(__name__)


def _node_mark_key(node: TreeNode) -> str:
    """Стабильный ключ для мультивыбора (path у npm metadata может совпадать с dir)."""
    if node.docker_tag is not None:
        return f"docker:{node.docker_tag.repository}:{node.docker_tag.tag}"
    if node.asset is not None:
        return f"asset:{node.asset.id}"
    return f"dir:{node.path}"


def _item_dedupe_key(item: NexusAsset | DockerTag) -> str:
    if isinstance(item, DockerTag):
        return f"docker:{item.repository}:{item.tag}"
    return f"asset:{item.id}"


class AssetTree(Tree[TreeNode]):
    """Tree, где Space отмечает узлы, а Enter раскрывает (через экран)."""

    BINDINGS = [
        *[b for b in Tree.BINDINGS if getattr(b, "key", None) != "space"],
        *asset_tree_extra_bindings(),
    ]

    def action_toggle_mark(self) -> None:
        screen = self.screen
        if isinstance(screen, AssetsScreen):
            screen.action_toggle_mark()


class RepositoriesScreen(Screen[None]):
    """Первый экран: просмотр репозиториев Nexus."""

    BINDINGS = repo_bindings()
    bindings_factory = staticmethod(repo_bindings)

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
        self._repos_loaded = False
        self._filter = ""
        self._ui_app: NexusControlApp | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(_("Connecting…"), id="status")
        with Vertical(id="filter-row"):
            yield Input(placeholder=_("Filter repositories…"), id="repo-filter")
        yield DataTable(id="repo-table", zebra_stripes=True)
        yield RichLog(id="log", highlight=True, markup=True, max_lines=500)
        yield Footer()

    def on_mount(self) -> None:
        self._ui_app = self.app
        table = self.query_one("#repo-table", DataTable)
        table.cursor_type = "row"
        table.add_columns(
            _("Name"),
            _("Format"),
            _("Type"),
            _("Support"),
            _("URL"),
            _("Attributes"),
        )
        # Скрытый Input иначе перехватывает фокус и «съедает» клавиши экрана.
        self.query_one("#repo-filter", Input).can_focus = False
        self.query_one("#log", RichLog).can_focus = False
        table.focus()
        self.action_refresh()

    @property
    def app(self) -> NexusControlApp:  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def action_help(self) -> None:
        self.app.push_screen(HelpModal(help_text()))

    def action_logout(self) -> None:
        """Сбросить Nexus-сессию и encrypted credentials, затем выйти."""
        try:
            self.app.client.logout()
        except Exception:  # noqa: BLE001
            logger.exception("Logout failed")
        logger.info("Logged out: Nexus session and credential vault cleared")
        self.app.exit()

    def action_search(self) -> None:
        row = self.query_one("#filter-row")
        row.toggle_class("visible")
        filt = self.query_one("#repo-filter", Input)
        if row.has_class("visible"):
            filt.can_focus = True
            if self._filter and not filt.value:
                filt.value = self._filter
            filt.focus()
        else:
            self._close_filter(filt)

    def action_close_search(self) -> None:
        row = self.query_one("#filter-row")
        if not row.has_class("visible"):
            return
        row.remove_class("visible")
        self._close_filter(self.query_one("#repo-filter", Input))

    def action_focus_results(self) -> None:
        """Tab/↓ из поля фильтра — в таблицу, фильтр остаётся."""
        row = self.query_one("#filter-row")
        if not row.has_class("visible"):
            return
        focused = self.focused
        if focused is None or focused.id != "repo-filter":
            return
        self._hide_filter_keep_query()

    def _close_filter(self, filt: Input) -> None:
        filt.value = ""
        filt.can_focus = False
        self._filter = ""
        self._render_rows()
        self.query_one("#repo-table", DataTable).focus()

    def _hide_filter_keep_query(self) -> None:
        """Спрятать поле фильтра, оставив применённый запрос и фокус на таблице."""
        row = self.query_one("#filter-row")
        row.remove_class("visible")
        filt = self.query_one("#repo-filter", Input)
        self._filter = filt.value.strip().lower()
        filt.can_focus = False
        self._render_rows()
        self.query_one("#repo-table", DataTable).focus()

    @on(Input.Submitted, "#repo-filter")
    def _on_filter_submitted(self, event: Input.Submitted) -> None:
        self._filter = event.value.strip().lower()
        self._render_rows()
        self._hide_filter_keep_query()

    @on(Input.Changed, "#repo-filter")
    def _on_filter(self, event: Input.Changed) -> None:
        self._filter = event.value.strip().lower()
        self._render_rows()

    def action_refresh(self) -> None:
        self._ui_app = self.app
        self.query_one("#status", Static).update(_("Loading repositories…"))
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
            schedule_on_app(app, self._on_error, _("Authentication error"), str(exc))
            return
        except NexusNetworkError as exc:
            if app.settings.nexus_verify_ssl and is_ssl_certificate_error(exc):
                schedule_on_app(app, self._on_ssl_certificate_error, str(exc))
            else:
                schedule_on_app(app, self._on_error, _("Network error"), str(exc))
            return
        except NexusAPIError as exc:
            schedule_on_app(app, self._on_error, _("Nexus API error"), str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            if app.settings.nexus_verify_ssl and is_ssl_certificate_error(exc):
                schedule_on_app(app, self._on_ssl_certificate_error, str(exc))
                return
            logger.exception("Unexpected error listing repositories")
            schedule_on_app(app, self._on_error, _("Unexpected error"), str(exc))
            return
        schedule_on_app(app, self._on_repos_loaded, repos)

    def _on_repos_loaded(self, repos: list[Repository]) -> None:
        self._repos = repos
        self._repos_loaded = True
        self._update_connection_status()
        self._render_rows()
        self._log(_("Loaded {count} repositories", count=len(repos)))

    def _update_connection_status(self) -> None:
        """Обновить верхнюю статус-строку (с учётом текущей локали)."""
        if not self._repos_loaded:
            self.query_one("#status", Static).update(_("Connecting…"))
            return
        status = _(
            "Connected to {url} as {user} — {count} repositories",
            url=self.app.settings.nexus_url,
            user=self.app.settings.nexus_username,
            count=len(self._repos),
        )
        session = self.app.client.session
        if session:
            status += f" | session until {session.expires_at}"
        self.query_one("#status", Static).update(status)

    def refresh_locale_ui(self) -> None:
        """Перерисовать локализуемые виджеты после смены языка."""
        self.query_one("#repo-filter", Input).placeholder = _("Filter repositories…")
        table = self.query_one("#repo-table", DataTable)
        selected_key = self._selected_row_key(table)
        table.clear(columns=True)
        table.add_columns(
            _("Name"),
            _("Format"),
            _("Type"),
            _("Support"),
            _("URL"),
            _("Attributes"),
        )
        self._render_rows(restore_key=selected_key)
        self._update_connection_status()

    def _on_ssl_certificate_error(self, message: str) -> None:
        """Предложить отключить проверку TLS и повторить загрузку репозиториев."""
        self.query_one("#status", Static).update(
            f"[red]{_('SSL/TLS certificate error')}[/red]"
        )
        self._log(f"[red]{_('SSL certificate error:')}[/red] {message}")
        body = (
            f"{truncate(message, 240)}\n\n"
            f"{_('Do you want to disable SSL/TLS validation?')}"
        )

        def _after(confirmed: bool | None) -> None:
            if confirmed is not True:
                return
            try:
                self.app.disable_ssl_verification(persist=True)
            except Exception as exc:  # noqa: BLE001
                self._on_error(_("Failed to update config"), str(exc))
                return
            self._log(
                "[yellow]"
                + _(
                    "SSL/TLS verification disabled (nexus_verify_ssl=false); retrying…"
                )
                + "[/yellow]"
            )
            self.action_refresh()

        self.app.push_screen(
            ConfirmModal(
                _("Certificate verification error"),
                body,
                confirm_label=_("Yes"),
                cancel_label=_("No"),
            ),
            _after,
        )

    def _selected_row_key(self, table: DataTable) -> object | None:
        if table.row_count <= 0:
            return None
        try:
            return table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:  # noqa: BLE001
            return None

    def _restore_row_key(self, table: DataTable, row_key: object | None) -> None:
        if row_key is None or table.row_count == 0:
            return
        try:
            row_index = table.get_row_index(row_key)
        except Exception:  # noqa: BLE001
            return
        table.move_cursor(row=row_index, animate=False, scroll=True)

    def _render_rows(self, *, restore_key: object | None = None) -> None:
        table = self.query_one("#repo-table", DataTable)
        selected_key = (
            restore_key if restore_key is not None else self._selected_row_key(table)
        )
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
        self._restore_row_key(table, selected_key)

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
    """Просмотр артефактов репозитория в виде дерева; download / verify."""

    BINDINGS = asset_bindings()
    bindings_factory = staticmethod(asset_bindings)

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
        self._loading = False
        self._ui_app: NexusControlApp | None = None
        # Соответствие id узла textual tree -> доменный TreeNode
        self._node_map: dict[int, TreeNode] = {}
        # Узлы TUI, чьи дети уже вставлены (ленивое дерево)
        self._tui_populated: set[int] = set()
        # Мультивыбор: ключи `_node_mark_key`
        self._marked: set[str] = set()
        # Включённые сканеры для verify (инициализируются в on_mount из settings)
        self._enabled_scanners: list[str] = ["grype"]
        self._list_progress_last_ui = 0.0
        self._list_annotate_last = 0.0
        self._load_gen = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="status")
        with Vertical(id="filter-row"):
            yield Input(placeholder=_("Filter assets…"), id="asset-filter")
        with Horizontal(id="main"):
            yield AssetTree(self.repository.name, id="asset-tree")
            with Vertical(id="side"):
                with Vertical(id="progress"):
                    yield Label(_("Idle"), id="job-label")
                    yield ProgressBar(total=100, id="job-progress", show_eta=False)
                yield RichLog(id="log", highlight=True, markup=True, max_lines=1000)
        yield Footer()

    def on_mount(self) -> None:
        self._ui_app = self.app
        try:
            self._enabled_scanners = list(self.app.settings.scanners_list)
        except Exception:  # noqa: BLE001
            self._enabled_scanners = ["grype"]
        self._update_status_bar()
        self.query_one("#asset-filter", Input).can_focus = False
        self.query_one("#log", RichLog).can_focus = False
        self.query_one("#asset-tree", AssetTree).focus()
        self._ui_app = self.app
        self._log(_("Loading assets for {name}…", name=self.repository.name))
        self._begin_list_progress()
        self._load_assets(force=False)

    @property
    def app(self) -> NexusControlApp:  # type: ignore[override]
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
        self.app.push_screen(HelpModal(help_text()))

    def action_search(self) -> None:
        row = self.query_one("#filter-row")
        row.toggle_class("visible")
        filt = self.query_one("#asset-filter", Input)
        if row.has_class("visible"):
            filt.can_focus = True
            if self._filter and not filt.value:
                filt.value = self._filter
            filt.focus()
        else:
            self._close_asset_filter(filt)

    def action_focus_results(self) -> None:
        """↓ из поля фильтра — в дерево, фильтр остаётся."""
        row = self.query_one("#filter-row")
        if not row.has_class("visible"):
            return
        focused = self.focused
        if focused is None or focused.id != "asset-filter":
            return
        self._hide_asset_filter_keep_query()

    def _close_asset_filter(self, filt: Input) -> None:
        filt.value = ""
        filt.can_focus = False
        self._filter = ""
        self._populate_tree(self._root_tree)
        self.query_one("#asset-tree", AssetTree).focus()

    def _hide_asset_filter_keep_query(self) -> None:
        row = self.query_one("#filter-row")
        row.remove_class("visible")
        filt = self.query_one("#asset-filter", Input)
        self._filter = filt.value.strip()
        filt.can_focus = False
        view = filter_tree(self._root_tree, self._filter) if self._filter else self._root_tree
        self._populate_tree(view)
        self.query_one("#asset-tree", AssetTree).focus()

    @on(Input.Changed, "#asset-filter")
    def _on_filter_changed(self, event: Input.Changed) -> None:
        self._filter = event.value.strip()
        view = filter_tree(self._root_tree, self._filter) if self._filter else self._root_tree
        self._populate_tree(view)

    @on(Input.Submitted, "#asset-filter")
    def _on_filter_submitted(self, event: Input.Submitted) -> None:
        self._filter = event.value.strip()
        self._hide_asset_filter_keep_query()

    def action_toggle_node(self) -> None:
        """Раскрыть/свернуть узел под курсором."""
        tree = self.query_one("#asset-tree", AssetTree)
        if tree.cursor_node is not None:
            tree.cursor_node.toggle()

    def action_toggle_mark(self) -> None:
        """Отметить / снять отметку с узла под курсором."""
        node = self._selected_domain_node()
        if node is None:
            return
        key = _node_mark_key(node)
        if key in self._marked:
            self._marked.discard(key)
        else:
            self._marked.add(key)
        self._refresh_tree_labels()
        self._update_status_bar()

    def action_clear_marks(self) -> None:
        if not self._marked:
            return
        self._marked.clear()
        self._refresh_tree_labels()
        self._update_status_bar()
        self._log(f"[dim]{_('Selection cleared')}[/dim]")

    def action_cancel_job(self) -> None:
        if self._busy:
            self._cancel = True
            self._log(f"[yellow]{_('Cancel requested…')}[/yellow]")

    def action_refresh(self) -> None:
        if self._busy or self._loading:
            self._log(f"[yellow]{_('Busy; wait for the current job.')}[/yellow]")
            return
        self._ui_app = self.app
        self._log(_("Loading assets for {name}…", name=self.repository.name))
        self._begin_list_progress()
        self._load_assets(force=True)

    @work(thread=True, exclusive=True)
    def _load_assets(self, force: bool = True) -> None:
        app = self._ui_app
        if app is None:
            return
        gen = self._load_gen

        def on_page(page: int, total: int) -> None:
            schedule_on_app(app, self._update_list_progress, page, total)

        try:
            app.ensure_client()
            settings = app.settings
            if self.repository.is_docker:
                tags = app.client.list_docker_tags(self.repository, on_page=on_page)
                if gen != self._load_gen:
                    return
                schedule_on_app(app, self._set_list_stage, _("Building tree…"))
                tree = build_docker_tag_tree(tags, root_name=self.repository.name)
                schedule_on_app(app, self._on_docker_loaded, gen, tags, tree)
                return

            if not force:
                cached = load_cached_assets(
                    settings.nexus_cache_dir,
                    settings.nexus_url,
                    self.repository.name,
                    ttl_seconds=settings.assets_cache_ttl,
                )
                if cached is not None:
                    assets, cache_age = cached
                    if gen != self._load_gen:
                        return
                    schedule_on_app(app, self._set_list_stage, _("Building tree…"))
                    tree = build_asset_tree(assets, root_name=self.repository.name)
                    schedule_on_app(
                        app,
                        self._on_assets_loaded,
                        gen,
                        assets,
                        tree,
                        True,
                        cache_age,
                    )
                    return

            # Потоковая подгрузка: UI оживает с первой страницы, остальное в фоне.
            schedule_on_app(app, self._on_listing_started, gen)
            assets: list[NexusAsset] = []
            pending: list[NexusAsset] = []
            last_sched = 0.0
            page_number = 0
            for page in app.client.iter_asset_pages(self.repository.name):
                if gen != self._load_gen:
                    return
                page_number += 1
                assets.extend(page)
                pending.extend(page)
                now = time.monotonic()
                if page_number == 1 or now - last_sched >= 0.25:
                    last_sched = now
                    batch = pending
                    pending = []
                    schedule_on_app(
                        app,
                        self._on_assets_page,
                        gen,
                        batch,
                        page_number,
                        len(assets),
                    )
            if gen != self._load_gen:
                return
            if pending:
                schedule_on_app(
                    app,
                    self._on_assets_page,
                    gen,
                    pending,
                    max(page_number, 1),
                    len(assets),
                )
            if settings.assets_cache_ttl > 0:
                save_cached_assets(
                    settings.nexus_cache_dir,
                    settings.nexus_url,
                    self.repository.name,
                    assets,
                )
            schedule_on_app(app, self._on_listing_complete, gen, len(assets))
        except NexusAPIError as exc:
            schedule_on_app(app, self._show_error, _("Failed to load assets"), str(exc))
            schedule_on_app(app, self._end_list_progress, True)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Asset load failed")
            schedule_on_app(app, self._show_error, _("Unexpected error"), str(exc))
            schedule_on_app(app, self._end_list_progress, True)

    def _begin_list_progress(self) -> None:
        self._load_gen += 1
        self._loading = True
        self._list_progress_last_ui = 0.0
        self._list_annotate_last = 0.0
        self.query_one("#job-label", Label).update(_("Listing assets…"))
        self.query_one("#job-progress", ProgressBar).update(total=None, progress=0)

    def _set_list_stage(self, label: str) -> None:
        self.query_one("#job-label", Label).update(label)

    def _update_list_progress(self, page: int, total: int) -> None:
        """Прогресс для docker / кэш-пути (без потокового дерева)."""
        now = time.monotonic()
        if now - self._list_progress_last_ui < 0.15 and page > 1:
            return
        self._list_progress_last_ui = now
        self.query_one("#job-label", Label).update(
            _("Listing assets… {count} (page {page})", count=total, page=page)
        )

    def _end_list_progress(self, error: bool = False) -> None:
        self._loading = False
        bar = self.query_one("#job-progress", ProgressBar)
        if error:
            self.query_one("#job-label", Label).update(_("Failed"))
            bar.update(total=100, progress=0)
        else:
            bar.update(total=100, progress=100)

    def _on_listing_started(self, gen: int) -> None:
        if gen != self._load_gen:
            return
        self._flat_assets = []
        self._docker_tags = []
        self._root_tree = empty_tree(self.repository.name)
        self._marked.clear()
        self._populate_tree(self._root_tree)
        self._update_status_bar()
        self._log(_("Listing in background — browse as folders appear…"))

    def _on_assets_page(
        self,
        gen: int,
        page: list[NexusAsset],
        page_number: int,
        total: int,
    ) -> None:
        if gen != self._load_gen:
            return
        for asset in page:
            insert_asset(self._root_tree, asset)
            self._flat_assets.append(asset)

        now = time.monotonic()
        annotate_counts(self._root_tree)
        self._list_annotate_last = now
        self._list_progress_last_ui = now
        self.query_one("#job-label", Label).update(
            _("Listing assets… {count} (page {page})", count=total, page=page_number)
        )
        self._sync_tree_from_domain()
        self._update_status_bar()

    def _on_listing_complete(self, gen: int, count: int) -> None:
        if gen != self._load_gen:
            return
        annotate_counts(self._root_tree)
        self._sync_tree_from_domain()
        self._update_status_bar()
        if count == 0:
            self._log(f"[yellow]{_('Repository is empty (no assets).')}[/yellow]")
        else:
            self._log(_("Loaded {count} assets", count=count))
        if self.repository.support_level == "partially_supported":
            self._log(
                "[yellow]"
                + _(
                    "Unsupported repository: asset tree is built from paths best-effort."
                )
                + "[/yellow]"
            )
        self._end_list_progress()
        self.query_one("#job-label", Label).update(
            _("Ready — {count} assets", count=count)
        )

    def _on_assets_loaded(
        self,
        gen: int,
        assets: list[NexusAsset],
        tree: TreeNode,
        from_cache: bool = False,
        cache_age: float = 0.0,
    ) -> None:
        if gen != self._load_gen:
            return
        self._flat_assets = assets
        self._docker_tags = []
        self._root_tree = tree
        self._marked.clear()
        if not assets:
            self._log(f"[yellow]{_('Repository is empty (no assets).')}[/yellow]")
        elif from_cache:
            self._log(
                _(
                    "Loaded {count} assets from cache ({age}s old)",
                    count=len(assets),
                    age=int(cache_age),
                )
            )
        else:
            self._log(_("Loaded {count} assets", count=len(assets)))
        if self.repository.support_level == "partially_supported":
            self._log(
                "[yellow]"
                + _(
                    "Unsupported repository: asset tree is built from paths best-effort."
                )
                + "[/yellow]"
            )
        view = filter_tree(tree, self._filter) if self._filter else tree
        self._populate_tree(view)
        self._update_status_bar()
        self._end_list_progress()
        self.query_one("#job-label", Label).update(
            _("Ready — {count} assets", count=len(assets))
        )

    def _on_docker_loaded(
        self, gen: int, tags: list[DockerTag], tree: TreeNode
    ) -> None:
        if gen != self._load_gen:
            return
        self._docker_tags = tags
        self._flat_assets = []
        self._root_tree = tree
        self._marked.clear()
        if not tags:
            self._log(
                "[yellow]"
                + _(
                    "Docker registry not exposed; set NEXUS_DOCKER_REGISTRY=host:port "
                    "in config.toml or env."
                )
                + "[/yellow]"
            )
        else:
            self._log(
                _("Loaded {count} docker tags (adapter view)", count=len(tags))
            )
        view = filter_tree(tree, self._filter) if self._filter else tree
        self._populate_tree(view)
        self._update_status_bar()
        self._end_list_progress()
        self.query_one("#job-label", Label).update(
            _("Ready — {count} tags", count=len(tags))
        )

    def _populate_tree(self, root: TreeNode) -> None:
        tree = self.query_one("#asset-tree", AssetTree)
        tree.clear()
        # Enter раскрывает через auto_expand; Space — отметки (AssetTree).
        tree.auto_expand = True
        self._node_map.clear()
        self._tui_populated.clear()
        tree.root.expand()
        self._node_map[id(tree.root)] = root
        self._tui_populated.add(id(tree.root))
        for child in sorted(
            root.children.values(),
            key=lambda n: (not n.is_dir, n.name.lower()),
        ):
            self._add_child_node(tree.root, child)

    def _add_child_node(self, parent: TuiTreeNode[Any], node: TreeNode) -> None:
        """Вставить один уровень: каталоги без рекурсии (раскрытие по NodeExpanded)."""
        label = self._label_for(node)
        if node.is_dir:
            tui_node = parent.add(label, data=node, expand=False)
            self._node_map[id(tui_node)] = node
            # Пока идёт листинг — пустая папка ещё может наполниться.
            tui_node.allow_expand = bool(node.children) or self._loading
        else:
            tui_node = parent.add_leaf(label, data=node)
            self._node_map[id(tui_node)] = node

    def _sync_tree_from_domain(self) -> None:
        """Подтянуть новые узлы в TUI без сброса раскрытых веток."""
        if self._filter:
            view = filter_tree(self._root_tree, self._filter)
            self._populate_tree(view)
            return
        tree = self.query_one("#asset-tree", AssetTree)
        self._sync_subtree(tree.root, self._root_tree)

    def _sync_subtree(self, tui_parent: TuiTreeNode[Any], domain_parent: TreeNode) -> None:
        existing: dict[str, TuiTreeNode[Any]] = {}
        for child in tui_parent.children:
            data = child.data
            if isinstance(data, TreeNode):
                existing[data.name] = child

        for domain_child in sorted(
            domain_parent.children.values(),
            key=lambda n: (not n.is_dir, n.name.lower()),
        ):
            tui_child = existing.get(domain_child.name)
            if tui_child is None:
                self._add_child_node(tui_parent, domain_child)
                continue
            # data мог устареть по identity — всегда указываем актуальный domain node
            tui_child.data = domain_child
            self._node_map[id(tui_child)] = domain_child
            tui_child.set_label(self._label_for(domain_child))
            if domain_child.is_dir:
                tui_child.allow_expand = bool(domain_child.children) or self._loading
                if id(tui_child) in self._tui_populated:
                    self._sync_subtree(tui_child, domain_child)

    @on(Tree.NodeExpanded)
    def _on_tree_node_expanded(self, event: Tree.NodeExpanded[TreeNode]) -> None:
        tui_node = event.node
        if id(tui_node) in self._tui_populated:
            # Повторное раскрытие во время листинга — дотянуть новых детей.
            data = tui_node.data
            if (
                self._loading
                and isinstance(data, TreeNode)
                and data.is_dir
                and not self._filter
            ):
                self._sync_subtree(tui_node, data)
            return
        data = tui_node.data
        if not isinstance(data, TreeNode) or not data.is_dir:
            return
        self._tui_populated.add(id(tui_node))
        for child in sorted(
            data.children.values(),
            key=lambda n: (not n.is_dir, n.name.lower()),
        ):
            self._add_child_node(tui_node, child)

    def _label_for(self, node: TreeNode) -> str:
        # Не использовать `[x]` / `[dir]` — Rich/Textual съедает это как markup.
        if _node_mark_key(node) in self._marked:
            mark = "[bold green]●[/] "
            name_style_open, name_style_close = "[bold]", "[/]"
        else:
            mark = "[dim]○[/] "
            name_style_open, name_style_close = "", ""

        if node.is_dir:
            return (
                f"{mark}[cyan]dir[/] "
                f"{name_style_open}{node.name}/{name_style_close} "
                f"({node.child_count})"
            )
        if node.docker_tag is not None:
            return (
                f"{mark}[magenta]img[/] "
                f"{name_style_open}{node.name}{name_style_close}"
            )
        asset = node.asset
        size = human_size(asset.file_size) if asset else "-"
        ctype = (asset.content_type or "-") if asset else "-"
        modified = (asset.last_modified or "-") if asset else "-"
        return (
            f"{mark}[yellow]file[/] "
            f"{name_style_open}{node.name}{name_style_close}  "
            f"{size}  {truncate(ctype, 24)}  {truncate(str(modified), 20)}"
        )

    def _refresh_tree_labels(self) -> None:
        tree = self.query_one("#asset-tree", AssetTree)

        def _walk(tui_node: TuiTreeNode[Any]) -> None:
            data = tui_node.data
            if isinstance(data, TreeNode):
                tui_node.set_label(self._label_for(data))
            for child in tui_node.children:
                _walk(child)

        _walk(tree.root)

    def _update_status_bar(self) -> None:
        support = self.repository.support_level
        marked_nodes = len(self._marked)
        marked_assets = len(self._items_from_marks()) if self._marked else 0
        sel = (
            f"  marked={marked_nodes} nodes → {marked_assets} assets"
            if marked_nodes
            else "  marked=0 (Space to select)"
        )
        scanners = "+".join(self._enabled_scanners) or "-"
        listing = ""
        if self._loading and not self.repository.is_docker:
            listing = f"  listing={len(self._flat_assets)}…"
        self.query_one("#status", Static).update(
            f"[b]{self.repository.name}[/b]  format={self.repository.format}  "
            f"type={self.repository.type}  support={support}  "
            f"scanners={scanners}{sel}{listing}"
        )

    def refresh_locale_ui(self) -> None:
        """Перерисовать локализуемые виджеты после смены языка."""
        try:
            self.query_one("#asset-filter", Input).placeholder = _("Filter assets…")
        except Exception:  # noqa: BLE001
            pass
        try:
            label = self.query_one("#job-label", Label)
            # Не затирать активный прогресс pipeline / листинга.
            if not self._busy and not self._loading:
                label.update(_("Idle"))
        except Exception:  # noqa: BLE001
            pass
        self._update_status_bar()

    # ---- вспомогательные функции выбора -------------------------------------------------
    def _selected_domain_node(self) -> TreeNode | None:
        tree = self.query_one("#asset-tree", AssetTree)
        cursor = tree.cursor_node
        if cursor is None:
            return self._root_tree
        data = cursor.data
        if isinstance(data, TreeNode):
            return data
        return self._node_map.get(id(cursor), self._root_tree)

    def _find_node_by_mark_key(self, key: str, root: TreeNode | None = None) -> TreeNode | None:
        node = root if root is not None else self._root_tree
        if _node_mark_key(node) == key:
            return node
        for child in node.children.values():
            found = self._find_node_by_mark_key(key, child)
            if found is not None:
                return found
        return None

    def _items_from_marks(self) -> list[NexusAsset | DockerTag]:
        items: list[NexusAsset | DockerTag] = []
        seen: set[str] = set()
        for key in self._marked:
            node = self._find_node_by_mark_key(key)
            if node is None:
                continue
            if node.path == "":
                batch = self._all_items()
            else:
                batch = collect_leaf_assets(node)
            for item in batch:
                dedupe = _item_dedupe_key(item)
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                items.append(item)
        return items

    def _items_for_action(self) -> list[NexusAsset | DockerTag]:
        """Отмеченные узлы, иначе узел под курсором."""
        if self._marked:
            return self._items_from_marks()
        node = self._selected_domain_node()
        if node is None:
            return []
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
        items = self._items_for_action()
        label = _("download marked") if self._marked else _("download")
        self._confirm_and_run(
            label,
            items,
            download=True,
            scan=False,
            verify=False,
        )

    def action_verify_selected(self) -> None:
        items = self._items_for_action()
        label = _("verify marked") if self._marked else _("verify")
        self._confirm_and_run(
            label,
            items,
            download=True,
            scan=True,
            verify=True,
        )

    def action_download_all(self) -> None:
        self._confirm_and_run(
            _("download ALL"),
            self._all_items(),
            download=True,
            scan=False,
            verify=False,
        )

    def action_verify_all(self) -> None:
        self._confirm_and_run(
            _("verify ALL"),
            self._all_items(),
            download=True,
            scan=True,
            verify=True,
        )

    def action_open_report(self) -> None:
        if self._last_summary is None:
            self.app.push_screen(
                MessageModal(_("Report"), _("No report yet. Run verify first."))
            )
            return
        self.app.push_screen(ReportModal(self._last_summary))

    def action_scanner_settings(self) -> None:
        def _after(chosen: list[str] | None) -> None:
            if chosen:
                self._enabled_scanners = chosen
                self._update_status_bar()
                self._log(_("Scanners: {names}", names="+".join(chosen)))

        self.app.push_screen(
            ScannerSettingsModal(self._enabled_scanners),
            _after,
        )

    def _confirm_and_run(
        self,
        action: str,
        items: list[NexusAsset | DockerTag],
        *,
        download: bool,
        scan: bool,
        verify: bool,
    ) -> None:
        if self._busy or self._loading:
            self._log(f"[yellow]{_('Another job is running.')}[/yellow]")
            return
        if not items:
            self.app.push_screen(
                MessageModal(
                    _("Nothing to do"),
                    _("No assets marked/selected or repository is empty."),
                )
            )
            return

        settings = self.app.settings
        marked_note = ""
        if self._marked:
            marked_note = (
                f"{_('Marked nodes: {count}', count=f'[b]{len(self._marked)}[/b]')}\n"
            )
        body = marked_note + format_confirm_body(
            action=action,
            count=len(items),
            total_size=self._approx_size(items),
            download_root=str(settings.download_root / self.repository.name),
            verified_root=str(settings.verified_repo_dir(self.repository.name)),
            scanners=self._enabled_scanners if scan else None,
        )

        def _after(confirmed: bool | None) -> None:
            if confirmed is True:
                self._start_pipeline(items, download=download, scan=scan, verify=verify)

        self.app.push_screen(
            ConfirmModal(_("Confirm {action}", action=action), body),
            _after,
        )

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
        self.query_one("#job-label", Label).update(_("Starting…"))
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
            schedule_on_app(app, self._update_progress, asset_path, progress, stage)

        try:
            app.ensure_client()
            pipeline = PipelineService(app.settings, app.client)
            summary = pipeline.run(
                repository=self.repository.name,
                items=items,
                download=download,
                scan=scan,
                verify=verify,
                scanners=self._enabled_scanners if scan else None,
                on_progress=on_progress,
                should_cancel=lambda: self._cancel,
            )
            schedule_on_app(app, self._on_pipeline_done, summary)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Pipeline failed")
            schedule_on_app(app, self._on_pipeline_failed, str(exc))

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
            _(
                "Done — PASS={passed} FAIL={failed} ERROR={errors} copied={copied}",
                passed=summary.total_passed,
                failed=summary.total_failed,
                errors=summary.total_errors,
                copied=summary.total_copied,
            )
        )
        self.query_one("#job-progress", ProgressBar).update(progress=100)
        self._log(
            "[green]"
            + _(
                "Finished scanned={scanned} PASS={passed} FAIL={failed} "
                "ERROR={errors} copied={copied}",
                scanned=summary.total_scanned,
                passed=summary.total_passed,
                failed=summary.total_failed,
                errors=summary.total_errors,
                copied=summary.total_copied,
            )
            + "[/green]"
        )
        self.app.push_screen(ReportModal(summary))

    def _on_pipeline_failed(self, message: str) -> None:
        self._busy = False
        self.query_one("#job-label", Label).update(_("Failed"))
        self._show_error(_("Pipeline failed"), message)

    def _show_error(self, title: str, message: str) -> None:
        self._log(f"[red]{title}:[/red] {message}")
        self.app.push_screen(MessageModal(title, message))

    def _log(self, message: str) -> None:
        self.query_one("#log", RichLog).write(message)
