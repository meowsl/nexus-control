"""Построение раскрываемых деревьев артефактов из плоских путей Nexus."""

from __future__ import annotations

from nexus_control.models import DockerTag, NexusAsset, TreeNode
from nexus_control.utils.safe_path import (
    ASSET_META_LEAF,
    UnsafePathError,
    normalize_asset_path,
)


def insert_asset(root: TreeNode, asset: NexusAsset) -> bool:
    """Вставить один артефакт в существующее дерево.

    Возвращает ``False``, если путь небезопасен / пропущен.
    Дубликаты путей сохраняют последний артефакт.
    Счётчики ``child_count`` не обновляет — вызывайте ``annotate_counts``.
    """
    try:
        posix = normalize_asset_path(asset.path)
    except UnsafePathError:
        return False
    node = root
    parts = list(posix.parts)
    for i, part in enumerate(parts):
        is_last = i == len(parts) - 1
        rel = "/".join(parts[: i + 1])
        if part not in node.children:
            node.children[part] = TreeNode(
                name=part,
                path=rel,
                is_dir=not is_last,
                asset=asset if is_last else None,
            )
        else:
            child = node.children[part]
            if is_last:
                if child.is_dir and child.children:
                    # npm и др.: есть и файл `pkg`, и вложенность `pkg/-/…`.
                    _attach_file_into_dir(child, asset, rel)
                else:
                    child.is_dir = False
                    child.asset = asset
                    child.children.clear()
            elif not child.is_dir:
                _promote_file_to_dir(child)
        node = node.children[part]
    return True


def build_asset_tree(
    assets: list[NexusAsset],
    *,
    root_name: str = "/",
) -> TreeNode:
    """Построить дерево каталогов из полей ``path`` артефактов.

    Дубликаты путей сохраняют последний артефакт. Невалидные пути пропускаются
    (вызывающий при необходимости должен логировать отдельно).
    """
    root = TreeNode(name=root_name, path="", is_dir=True)
    for asset in assets:
        insert_asset(root, asset)
    annotate_counts(root)
    return root


def _attach_file_into_dir(dir_node: TreeNode, asset: NexusAsset, path: str) -> None:
    """Положить asset-файл внутрь существующего каталога без потери детей."""
    name = ASSET_META_LEAF
    if name in dir_node.children:
        # Повторная загрузка того же meta-path — обновить asset.
        leaf = dir_node.children[name]
        leaf.asset = asset
        leaf.path = path
        leaf.is_dir = False
        leaf.children.clear()
        return
    dir_node.children[name] = TreeNode(
        name=name,
        path=path,
        is_dir=False,
        asset=asset,
    )


def _promote_file_to_dir(node: TreeNode) -> None:
    """Превратить листовой файл в каталог, сохранив прежний asset как лист."""
    if node.is_dir:
        return
    file_asset = node.asset
    file_path = node.path
    node.is_dir = True
    node.asset = None
    if file_asset is not None:
        node.children[ASSET_META_LEAF] = TreeNode(
            name=ASSET_META_LEAF,
            path=file_path,
            is_dir=False,
            asset=file_asset,
        )


def build_docker_tag_tree(
    tags: list[DockerTag],
    *,
    root_name: str = "/",
) -> TreeNode:
    """Представить docker-теги под виртуальным каталогом ``images/``."""
    root = TreeNode(name=root_name, path="", is_dir=True)
    images = TreeNode(name="images", path="images", is_dir=True)
    root.children["images"] = images
    for tag in tags:
        safe_name = tag.tag
        images.children[safe_name] = TreeNode(
            name=safe_name,
            path=f"images/{safe_name}",
            is_dir=False,
            docker_tag=tag,
        )
    annotate_counts(root)
    return root


def empty_tree(root_name: str = "/") -> TreeNode:
    return TreeNode(name=root_name, path="", is_dir=True, child_count=0)


def filter_tree(root: TreeNode, query: str) -> TreeNode:
    """Вернуть новое дерево только с ветками, совпадающими с ``query`` (без учёта регистра)."""
    q = query.strip().lower()
    if not q:
        return root

    def _filter(node: TreeNode) -> TreeNode | None:
        if not node.is_dir:
            hay = f"{node.path} {node.name}".lower()
            return node if q in hay else None
        kept: dict[str, TreeNode] = {}
        for name, child in node.children.items():
            filtered = _filter(child)
            if filtered is not None:
                kept[name] = filtered
        self_match = q in node.name.lower() or q in node.path.lower()
        if kept or self_match:
            clone = TreeNode(
                name=node.name,
                path=node.path,
                is_dir=True,
                children=kept,
                asset=node.asset,
                docker_tag=node.docker_tag,
            )
            annotate_counts(clone)
            return clone
        return None

    filtered_root = _filter(root)
    return filtered_root or empty_tree(root.name)


def collect_leaf_assets(node: TreeNode) -> list[NexusAsset | DockerTag]:
    """Собрать все file/image листья под ``node`` (включая сам лист, если это лист)."""
    if not node.is_dir:
        if node.docker_tag is not None:
            return [node.docker_tag]
        if node.asset is not None:
            return [node.asset]
        return []
    items: list[NexusAsset | DockerTag] = []
    for child in node.children.values():
        items.extend(collect_leaf_assets(child))
    return items


def annotate_counts(node: TreeNode) -> int:
    """Пересчитать ``child_count`` (число листьев) для узла и потомков."""
    if not node.is_dir:
        node.child_count = 0
        return 1
    total = 0
    for child in node.children.values():
        total += annotate_counts(child)
    node.child_count = total
    return total
