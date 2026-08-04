"""Хэширование локальных файлов и сверка с checksums Nexus."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nexus_control.models import NexusAsset

logger = logging.getLogger(__name__)

# Предпочтительный порядок алгоритмов (Nexus обычно отдаёт sha1/sha256/md5).
_ALGO_PREFERENCE: tuple[str, ...] = ("sha256", "sha1", "md5")
_SUPPORTED = frozenset(_ALGO_PREFERENCE)

_NPM_BLOB_SUFFIXES = (".tgz", ".tar.gz", ".tar")


def checksum_is_authoritative(asset: NexusAsset) -> bool:
    """Можно ли жёстко доверять checksum ассета относительно HTTP download body.

    Для npm package-root / metadata Nexus часто отдаёт JSON, пересобранный на лету,
    а ``checksum.sha1`` в Assets API относится к другому внутреннему представлению —
    байты ответа не совпадают с заявленным хэшем. Tarball'ы (``/-/*.tgz``) надёжны.
    """
    path = asset.path.replace("\\", "/").lower()
    fmt = (asset.format or "").lower()

    if path.endswith(_NPM_BLOB_SUFFIXES) or "/-/" in path:
        return True
    if fmt == "npm":
        return False
    return True


def normalize_checksums(checksum: dict[str, str] | None) -> dict[str, str]:
    """Нормализовать ключи checksum к lower-case hex-значениям."""
    if not checksum:
        return {}
    out: dict[str, str] = {}
    for key, value in checksum.items():
        algo = str(key).lower().strip()
        if algo not in _SUPPORTED or value is None:
            continue
        hex_value = str(value).strip().lower()
        if hex_value:
            out[algo] = hex_value
    return out


def pick_remote_checksum(checksum: dict[str, str] | None) -> tuple[str, str] | None:
    """Выбрать лучший доступный remote checksum: ``(algo, hex)`` или ``None``."""
    normalized = normalize_checksums(checksum)
    for algo in _ALGO_PREFERENCE:
        if algo in normalized:
            return algo, normalized[algo]
    return None


def hash_file(path: Path, algo: str = "sha256", *, chunk_size: int = 1024 * 1024) -> str:
    """Посчитать hex-digest файла. ``algo``: sha256 / sha1 / md5."""
    name = algo.lower().strip()
    if name not in _SUPPORTED:
        raise ValueError(f"Unsupported hash algorithm: {algo!r}")
    hasher = hashlib.new(name)
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def local_matches_remote(
    path: Path,
    checksum: dict[str, str] | None,
    *,
    file_size: int | None = None,
) -> bool | None:
    """Сверить локальный файл с remote checksum / size.

    Returns:
        ``True`` — совпадает (можно skip),
        ``False`` — отличается (нужна перекачка),
        ``None`` — недостаточно данных для сверки.
    """
    if not path.is_file():
        return False

    picked = pick_remote_checksum(checksum)
    if picked is not None:
        algo, expected = picked
        try:
            actual = hash_file(path, algo)
        except OSError as exc:
            logger.warning("Cannot hash %s: %s", path, exc)
            return False
        if actual.lower() == expected.lower():
            return True
        logger.info(
            "Local/remote checksum mismatch for %s (%s): local=%s remote=%s",
            path,
            algo,
            actual,
            expected,
        )
        return False

    if file_size is not None:
        try:
            local_size = path.stat().st_size
        except OSError:
            return False
        if local_size == file_size:
            return True
        logger.info(
            "Local/remote size mismatch for %s: local=%s remote=%s",
            path,
            local_size,
            file_size,
        )
        return False

    return None


def checksums_mismatch(
    expected: dict[str, str] | None,
    actual: dict[str, str],
    *,
    authoritative: bool = True,
) -> str | None:
    """Сравнить ожидаемые checksums с фактически посчитанными.

    При ``authoritative=False`` жёстко проверяется только sha256 (если есть):
    sha1/md5 mismatch для npm metadata — известный quirk Nexus, не ERROR.

    Возвращает человекочитаемое описание mismatch или ``None``.
    """
    normalized = normalize_checksums(expected)
    if not normalized:
        return None
    algos = ("sha256",) if not authoritative else _ALGO_PREFERENCE
    for algo in algos:
        if algo not in normalized:
            continue
        got = actual.get(algo)
        if got is None:
            continue
        if got.lower() != normalized[algo]:
            return (
                f"{algo.upper()} mismatch: expected {normalized[algo]}, got {got.lower()}"
            )
    return None


def soft_checksum_warning(
    expected: dict[str, str] | None,
    actual: dict[str, str],
) -> str | None:
    """Предупреждение о sha1/md5 mismatch, когда жёсткая проверка отключена."""
    normalized = normalize_checksums(expected)
    for algo in ("sha1", "md5"):
        if algo not in normalized:
            continue
        got = actual.get(algo)
        if got is None:
            continue
        if got.lower() != normalized[algo]:
            return (
                f"{algo.upper()} mismatch (ignored for non-blob asset): "
                f"expected {normalized[algo]}, got {got.lower()}"
            )
    return None


def remote_identity_unchanged(
    remote_checksum: dict[str, str] | None,
    *,
    remote_last_modified: str | None,
    sidecar: dict | None,
) -> bool | None:
    """Сравнить «идентичность» remote-ассета с тем, что было при прошлой загрузке.

    Сравниваем значения общих checksum-ключей (не требуем идентичный набор ключей):
    если remote ``sha1`` тот же, что в sidecar — ассет не обновляли.

    Returns:
        ``True`` — remote не менялся (можно skip),
        ``False`` — remote изменился,
        ``None`` — sidecar нет / недостаточно данных.
    """
    if not sidecar:
        return None

    side_checksum = normalize_checksums(sidecar.get("checksum"))
    remote_norm = normalize_checksums(remote_checksum)
    if side_checksum and remote_norm:
        shared = set(side_checksum) & set(remote_norm)
        if shared:
            return all(side_checksum[k] == remote_norm[k] for k in shared)

    side_lm = sidecar.get("last_modified") or sidecar.get("lastModified")
    if side_lm and remote_last_modified:
        return str(side_lm) == str(remote_last_modified)

    return None


class StreamingMultiHasher:
    """Считать несколько хэшей за один проход по потоку байт."""

    def __init__(self, algos: set[str] | frozenset[str] | None = None) -> None:
        names = {a.lower() for a in (algos or {"sha256"}) if a.lower() in _SUPPORTED}
        if not names:
            names = {"sha256"}
        self._hashers = {name: hashlib.new(name) for name in names}

    def update(self, data: bytes) -> None:
        for hasher in self._hashers.values():
            hasher.update(data)

    def hexdigests(self) -> dict[str, str]:
        return {name: hasher.hexdigest() for name, hasher in self._hashers.items()}


def hashers_for_expected(checksum: dict[str, str] | None) -> StreamingMultiHasher:
    """Создать multi-hasher под ожидаемые checksums (+ всегда sha256)."""
    algos: set[str] = {"sha256"}
    for key in normalize_checksums(checksum):
        algos.add(key)
    return StreamingMultiHasher(algos)
