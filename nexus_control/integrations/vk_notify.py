"""Уведомления scheduler → VK Teams + pending Upload callbacks."""

from __future__ import annotations

import html
import logging
import threading
import time
import uuid
from argparse import Namespace
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from nexus_control.config import Settings
from nexus_control.integrations.defectdojo import defectdojo_engagement_url
from nexus_control.integrations.vk_teams import (
    VkTeamsClient,
    VkTeamsError,
    apply_vk_teams_vault,
    merge_inline_keyboards,
    upload_keyboard,
)
from nexus_control.scheduler.models import ScheduleRule
from nexus_control.services.scan_history import ScanRunMeta, latest_run_for_repo
from nexus_control.utils.fs import ensure_dir, read_json, write_json

logger = logging.getLogger(__name__)

VK_MESSAGE_TZ = "Europe/Moscow"

PENDING_TTL_SEC = 24 * 3600
CALLBACK_PREFIX = "up:"
LAST_EVENT_FILENAME = "last_event_id"
PENDING_FILENAME = "pending.json"

_upload_lock = threading.Lock()
_upload_busy = False
_upload_thread: threading.Thread | None = None


@dataclass(slots=True)
class PendingUpload:
    token: str
    rule_id: str
    repos: list[str]
    targets: dict[str, str]
    created_at: float
    chat_id: str
    msg_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "rule_id": self.rule_id,
            "repos": list(self.repos),
            "targets": dict(self.targets),
            "created_at": self.created_at,
            "chat_id": self.chat_id,
            "msg_id": self.msg_id,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PendingUpload | None:
        token = str(raw.get("token") or "").strip()
        rule_id = str(raw.get("rule_id") or "").strip()
        repos_raw = raw.get("repos") or []
        if not token or not rule_id or not isinstance(repos_raw, list):
            return None
        repos = [str(r).strip() for r in repos_raw if str(r).strip()]
        if not repos:
            return None
        targets_raw = raw.get("targets") or {}
        targets: dict[str, str] = {}
        if isinstance(targets_raw, dict):
            targets = {
                str(k): str(v)
                for k, v in targets_raw.items()
                if str(k).strip() and str(v).strip()
            }
        try:
            created_at = float(raw.get("created_at") or 0.0)
        except (TypeError, ValueError):
            created_at = 0.0
        chat_id = str(raw.get("chat_id") or "").strip()
        msg_id = raw.get("msg_id")
        return cls(
            token=token,
            rule_id=rule_id,
            repos=repos,
            targets=targets,
            created_at=created_at,
            chat_id=chat_id,
            msg_id=str(msg_id) if msg_id is not None else None,
        )


@dataclass(slots=True)
class PendingUploadStore:
    path: Path
    _items: dict[str, PendingUpload] = field(default_factory=dict)

    @classmethod
    def load(cls, settings: Settings) -> PendingUploadStore:
        root = _vk_root(settings)
        path = root / PENDING_FILENAME
        store = cls(path=path)
        if not path.is_file():
            return store
        try:
            raw = read_json(path)
        except (OSError, ValueError, TypeError) as exc:
            logger.warning("Failed to read VK pending store: %s", exc)
            return store
        items = raw.get("items") if isinstance(raw, dict) else None
        if not isinstance(items, dict):
            return store
        now = time.time()
        for token, entry in items.items():
            if not isinstance(entry, dict):
                continue
            pending = PendingUpload.from_dict(entry)
            if pending is None:
                continue
            if now - pending.created_at > PENDING_TTL_SEC:
                continue
            store._items[str(token)] = pending
        return store

    def save(self) -> None:
        ensure_dir(self.path.parent, mode=0o700)
        payload = {
            "version": 1,
            "items": {k: v.to_dict() for k, v in self._items.items()},
        }
        write_json(self.path, payload, mode=0o600)

    def put(self, pending: PendingUpload) -> None:
        self._prune()
        self._items[pending.token] = pending
        self.save()

    def pop(self, token: str) -> PendingUpload | None:
        self._prune()
        item = self._items.pop(token, None)
        self.save()
        return item

    def get(self, token: str) -> PendingUpload | None:
        self._prune()
        return self._items.get(token)

    def _prune(self) -> None:
        now = time.time()
        stale = [
            k
            for k, v in self._items.items()
            if now - v.created_at > PENDING_TTL_SEC
        ]
        for key in stale:
            del self._items[key]


def vk_teams_configured(settings: Settings) -> bool:
    cfg = apply_vk_teams_vault(settings)
    token = str(getattr(cfg, "vk_teams_token", "") or "").strip()
    chat_id = str(getattr(cfg, "vk_teams_chat_id", "") or "").strip()
    notify = str(getattr(cfg, "vk_teams_notify", "off") or "off")
    return bool(token and chat_id and notify != "off")


def vk_teams_should_poll(settings: Settings) -> bool:
    """Long-poll events when Upload buttons may be pending."""
    cfg = apply_vk_teams_vault(settings)
    token = str(getattr(cfg, "vk_teams_token", "") or "").strip()
    chat_id = str(getattr(cfg, "vk_teams_chat_id", "") or "").strip()
    upload_button = bool(getattr(cfg, "vk_teams_upload_button", False))
    return bool(token and chat_id and upload_button)


def upload_in_flight() -> bool:
    with _upload_lock:
        return _upload_busy


def wait_upload_idle(timeout: float | None = None) -> bool:
    """Дождаться фонового Upload (для тестов / shutdown)."""
    thread = _upload_thread
    if thread is None:
        return True
    thread.join(timeout=timeout)
    return not thread.is_alive()


def should_notify(
    policy: str,
    exit_code: int,
    metas: list[ScanRunMeta],
) -> bool:
    if policy == "off":
        return False
    if policy == "always":
        return True
    if policy == "failures":
        if exit_code != 0:
            return True
        return any(
            m.totals.failed > 0 or m.totals.errors > 0 for m in metas
        )
    return False


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def format_vk_datetime(value: str | None, *, tz_name: str = VK_MESSAGE_TZ) -> str:
    """``DD.MM.YYYY HH:mm`` в заданной TZ (по умолчанию Europe/Moscow)."""
    dt = _parse_iso_datetime(value)
    if dt is None:
        return "—"
    return dt.astimezone(ZoneInfo(tz_name)).strftime("%d.%m.%Y %H:%M")


def _task_title(repo: str, *, manual: bool, action: str) -> str:
    repo_html = f"<b>{html.escape(repo)}</b>"
    if action == "upload":
        prefix = "Загрузка" if manual else "Плановая загрузка"
    else:
        prefix = "Сканирование" if manual else "Плановое сканирование"
    return f"{prefix} {repo_html}"


def _format_time_range(meta: ScanRunMeta | None) -> str:
    if meta is None:
        return "— - —"
    start = format_vk_datetime(meta.started_at)
    end = format_vk_datetime(meta.finished_at)
    return f"{start} - {end}"


def _defectdojo_url(settings: Settings, meta: ScanRunMeta | None) -> str | None:
    if meta is None:
        return None
    return defectdojo_engagement_url(settings, meta.defectdojo_engagement_id)


def _format_repo_block(
    repo: str,
    meta: ScanRunMeta | None,
    *,
    settings: Settings,
    manual: bool,
    action: str,
) -> str:
    passed = meta.totals.passed if meta is not None else 0
    failed = meta.totals.failed if meta is not None else 0
    lines = [
        _task_title(repo, manual=manual, action=action),
        "",
        _format_time_range(meta),
        "",
        f"📦 <b>{html.escape(repo)}</b>",
        f"✅ Артефакты без уязвимостей: {passed}",
        f"⚠️ Выявлено уязвимостей: {failed}",
    ]
    return "\n".join(lines)


def build_rule_notify_keyboard(
    settings: Settings,
    rule: ScheduleRule,
    metas_by_repo: dict[str, ScanRunMeta | None],
    *,
    upload_callback: str | None = None,
) -> list[list[dict[str, str]]] | None:
    """Inline-кнопки: Upload (callback) + DefectDojo (url) только при FAIL > 0."""
    upload_rows = upload_keyboard(upload_callback) if upload_callback else None

    dd_rows: list[list[dict[str, str]]] = []
    vuln_repos: list[tuple[str, str]] = []
    for repo in rule.repos:
        meta = metas_by_repo.get(repo)
        if meta is None or meta.totals.failed <= 0:
            continue
        url = _defectdojo_url(settings, meta)
        if url:
            vuln_repos.append((repo, url))

    for repo, url in vuln_repos:
        label = "Смотреть в DefectDojo"
        if len(vuln_repos) > 1:
            label = f"{repo} · DefectDojo"
        dd_rows.append([{"text": label, "url": url}])

    return merge_inline_keyboards(upload_rows, dd_rows)


def build_rule_message(
    rule: ScheduleRule,
    metas_by_repo: dict[str, ScanRunMeta | None],
    *,
    settings: Settings,
    manual: bool = False,
) -> str:
    blocks = [
        _format_repo_block(
            repo,
            metas_by_repo.get(repo),
            settings=settings,
            manual=manual,
            action=rule.action,
        )
        for repo in rule.repos
    ]
    return "\n\n".join(blocks)


def notify_rule_finished(
    settings: Settings,
    rule: ScheduleRule,
    exit_code: int,
    *,
    manual: bool = False,
    client: VkTeamsClient | None = None,
) -> None:
    """Best-effort notify after a scheduler rule completes."""
    settings = apply_vk_teams_vault(settings)
    if not vk_teams_configured(settings):
        return

    metas_by_repo: dict[str, ScanRunMeta | None] = {}
    metas: list[ScanRunMeta] = []
    for repo in rule.repos:
        meta = latest_run_for_repo(settings, repo)
        metas_by_repo[repo] = meta
        if meta is not None:
            metas.append(meta)

    if not should_notify(settings.vk_teams_notify, exit_code, metas):
        logger.debug(
            "VK Teams notify skipped (policy=%s exit=%s)",
            settings.vk_teams_notify,
            exit_code,
        )
        return

    text = build_rule_message(
        rule,
        metas_by_repo,
        settings=settings,
        manual=manual,
    )
    bot = client or VkTeamsClient.from_settings(settings)
    chat_id = settings.vk_teams_chat_id.strip()

    keyboard = None
    pending: PendingUpload | None = None
    upload_callback: str | None = None
    show_button = (
        settings.vk_teams_upload_button
        and not rule.wants_upload()
        and rule.wants_verify()
    )
    if show_button:
        token = uuid.uuid4().hex[:12]
        targets: dict[str, str] = {}
        for repo in rule.repos:
            custom = rule.target_for(repo)
            targets[repo] = custom if custom else f"{repo}-verified"
        pending = PendingUpload(
            token=token,
            rule_id=rule.id,
            repos=list(rule.repos),
            targets=targets,
            created_at=time.time(),
            chat_id=chat_id,
        )
        upload_callback = f"{CALLBACK_PREFIX}{token}"

    keyboard = build_rule_notify_keyboard(
        settings,
        rule,
        metas_by_repo,
        upload_callback=upload_callback,
    )

    try:
        response = bot.send_text(
            chat_id,
            text,
            parse_mode="HTML",
            inline_keyboard=keyboard,
        )
    except VkTeamsError as exc:
        logger.error("VK Teams notify failed: %s", exc)
        return

    if pending is not None:
        msg_id = _extract_msg_id(response)
        if msg_id is not None:
            pending.msg_id = msg_id
        PendingUploadStore.load(settings).put(pending)
        logger.info(
            "VK Teams notify sent rule=%s upload_token=%s",
            rule.id,
            pending.token,
        )
    else:
        logger.info("VK Teams notify sent rule=%s", rule.id)


def handle_callback(
    settings: Settings,
    callback_data: str,
    query_id: str,
    *,
    client: VkTeamsClient | None = None,
    run_upload_fn: Any | None = None,
) -> None:
    """Принять callback Upload: сразу ответить и гонять upload в фоне."""
    settings = apply_vk_teams_vault(settings)
    bot = client or VkTeamsClient.from_settings(settings)
    data = (callback_data or "").strip()
    if not data.startswith(CALLBACK_PREFIX):
        try:
            bot.answer_callback_query(query_id, text="Неизвестное действие")
        except VkTeamsError as exc:
            logger.debug("answerCallbackQuery failed: %s", exc)
        return

    token = data[len(CALLBACK_PREFIX):].strip()
    store = PendingUploadStore.load(settings)

    global _upload_busy, _upload_thread
    with _upload_lock:
        already_busy = _upload_busy
        pending: PendingUpload | None = None
        if not already_busy:
            pending = store.pop(token)
            if pending is not None:
                _upload_busy = True

    if already_busy:
        try:
            bot.answer_callback_query(
                query_id,
                text="Загрузка уже выполняется",
                show_alert=True,
            )
        except VkTeamsError as exc:
            logger.debug("answerCallbackQuery failed: %s", exc)
        return

    if pending is None:
        try:
            bot.answer_callback_query(
                query_id,
                text="Кнопка устарела или уже использована",
                show_alert=True,
            )
        except VkTeamsError as exc:
            logger.debug("answerCallbackQuery failed: %s", exc)
        return

    try:
        bot.answer_callback_query(query_id, text="Загружаю…")
    except VkTeamsError as exc:
        logger.warning("answerCallbackQuery failed: %s", exc)

    if run_upload_fn is None:
        from nexus_control.cli.cmd_upload import run_upload as run_upload_fn

    def _job() -> None:
        global _upload_busy
        try:
            _perform_pending_upload(
                settings,
                pending,
                bot,
                run_upload_fn,
            )
        finally:
            with _upload_lock:
                _upload_busy = False

    try:
        _upload_thread = threading.Thread(
            target=_job,
            name="vk-teams-upload",
            daemon=True,
        )
        _upload_thread.start()
    except Exception:
        with _upload_lock:
            _upload_busy = False
        raise


def _perform_pending_upload(
    settings: Settings,
    pending: PendingUpload,
    bot: VkTeamsClient,
    run_upload_fn: Any,
) -> None:
    lines = [
        "⬆️ <b>Загрузка в Nexus</b>",
        f"Правило <code>{html.escape(pending.rule_id)}</code>",
        "",
    ]
    worst = 0
    for repo in pending.repos:
        target = pending.targets.get(repo) or None
        try:
            code = int(
                run_upload_fn(
                    Namespace(
                        repo=repo,
                        target=target,
                        json=False,
                    )
                )
            )
        except SystemExit as exc:
            code = int(exc.code) if isinstance(exc.code, int) else 1
        except Exception as exc:  # noqa: BLE001
            logger.exception("Upload failed for %s: %s", repo, exc)
            code = 1
        if code > worst:
            worst = code
        status = "готово" if code == 0 else f"ошибка (код {code})"
        dest = target or f"{repo}-verified"
        lines.append(
            f"• <code>{html.escape(repo)}</code> → "
            f"<code>{html.escape(dest)}</code> — {status}"
        )

    lines.append("")
    if worst == 0:
        lines.append("Итог: ✅ всё успешно")
    else:
        lines.append(f"Итог: ❌ есть ошибки (код {worst})")
    follow_up = "\n".join(lines)

    try:
        if pending.msg_id:
            bot.edit_text(
                pending.chat_id or settings.vk_teams_chat_id,
                pending.msg_id,
                follow_up,
                parse_mode="HTML",
                inline_keyboard=None,
            )
        else:
            bot.send_text(
                pending.chat_id or settings.vk_teams_chat_id,
                follow_up,
                parse_mode="HTML",
            )
    except VkTeamsError as exc:
        logger.error("VK Teams upload follow-up failed: %s", exc)
        try:
            bot.send_text(
                settings.vk_teams_chat_id,
                follow_up,
                parse_mode="HTML",
            )
        except VkTeamsError as exc2:
            logger.error("VK Teams upload fallback send failed: %s", exc2)


def poll_and_handle_events(
    settings: Settings,
    *,
    poll_time: int = 25,
    client: VkTeamsClient | None = None,
) -> int:
    """Long-poll Bot API events; handle Upload callbacks. Returns lastEventId."""
    settings = apply_vk_teams_vault(settings)
    if not settings.vk_teams_token.strip():
        return _load_last_event_id(settings)

    bot = client or VkTeamsClient.from_settings(settings)
    last_id = _load_last_event_id(settings)
    try:
        events = bot.get_events(last_id, poll_time=poll_time)
    except VkTeamsError as exc:
        logger.warning("VK Teams getEvents failed: %s", exc)
        return last_id

    max_id = last_id
    for event in events:
        if event.event_id > max_id:
            max_id = event.event_id
        etype = event.type
        # Official API uses callbackQuery; some libs use camelCase variants.
        if etype not in {"callbackQuery", "callback_query"}:
            continue
        payload = event.payload
        query_id = str(
            payload.get("queryId")
            or payload.get("query_id")
            or ""
        ).strip()
        callback_data = str(
            payload.get("callbackData")
            or payload.get("callback_data")
            or ""
        ).strip()
        if not query_id or not callback_data:
            continue
        try:
            handle_callback(
                settings,
                callback_data,
                query_id,
                client=bot,
            )
        except Exception:  # noqa: BLE001
            logger.exception("VK Teams callback handler failed")

    if max_id != last_id:
        _save_last_event_id(settings, max_id)
    return max_id


def _vk_root(settings: Settings) -> Path:
    return Path(settings.nexus_cache_dir).expanduser().resolve() / "vk-teams"


def _last_event_path(settings: Settings) -> Path:
    return _vk_root(settings) / LAST_EVENT_FILENAME


def _load_last_event_id(settings: Settings) -> int:
    path = _last_event_path(settings)
    if not path.is_file():
        return 0
    try:
        text = path.read_text(encoding="utf-8").strip()
        return int(text or "0")
    except (OSError, ValueError):
        return 0


def _save_last_event_id(settings: Settings, event_id: int) -> None:
    path = _last_event_path(settings)
    ensure_dir(path.parent, mode=0o700)
    try:
        path.write_text(str(int(event_id)), encoding="utf-8")
        path.chmod(0o600)
    except OSError as exc:
        logger.debug("Failed to persist lastEventId: %s", exc)


def _extract_msg_id(response: dict[str, Any]) -> str | None:
    for key in ("msgId", "messageId", "id"):
        if key in response and response[key] is not None:
            return str(response[key])
    nested = response.get("message")
    if isinstance(nested, dict):
        for key in ("msgId", "messageId", "id"):
            if key in nested and nested[key] is not None:
                return str(nested[key])
    return None
