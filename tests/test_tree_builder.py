"""Модульные тесты построителя дерева путей артефактов."""

from __future__ import annotations

from nexus_tui.models import NexusAsset
from nexus_tui.utils.tree_builder import (
    build_asset_tree,
    collect_leaf_assets,
    empty_tree,
    filter_tree,
)


def _asset(path: str, repo: str = "repo") -> NexusAsset:
    return NexusAsset(id=path, path=path, download_url=None, repository=repo)


def test_build_tree_groups_directories() -> None:
    assets = [
        _asset("com/example/app/1.0/app-1.0.jar"),
        _asset("com/example/app/1.0/app-1.0.pom"),
        _asset("org/company/lib/2.3/lib-2.3.jar"),
    ]
    root = build_asset_tree(assets)
    assert "com" in root.children
    assert "org" in root.children
    com = root.children["com"]
    assert com.is_dir
    jar = (
        root.children["com"]
        .children["example"]
        .children["app"]
        .children["1.0"]
        .children["app-1.0.jar"]
    )
    assert not jar.is_dir
    assert jar.asset is not None
    assert jar.asset.path.endswith("app-1.0.jar")
    assert root.child_count == 3


def test_duplicates_keep_last() -> None:
    a1 = _asset("a/b/file.txt")
    a1.id = "1"
    a2 = _asset("a/b/file.txt")
    a2.id = "2"
    a2.content_type = "text/plain"
    root = build_asset_tree([a1, a2])
    node = root.children["a"].children["b"].children["file.txt"]
    assert node.asset is not None
    assert node.asset.id == "2"
    assert node.asset.content_type == "text/plain"


def test_empty_list() -> None:
    root = build_asset_tree([])
    assert root.children == {}
    assert root.child_count == 0
    assert empty_tree().children == {}


def test_collect_and_filter() -> None:
    assets = [
        _asset("com/example/a.jar"),
        _asset("com/other/b.jar"),
        _asset("org/x/c.jar"),
    ]
    root = build_asset_tree(assets)
    leaves = collect_leaf_assets(root)
    assert len(leaves) == 3
    filtered = filter_tree(root, "example")
    assert "com" in filtered.children
    assert "org" not in filtered.children
    assert len(collect_leaf_assets(filtered)) == 1


def test_skips_traversal_paths() -> None:
    assets = [
        _asset("../etc/passwd"),
        _asset("ok/file.jar"),
    ]
    root = build_asset_tree(assets)
    assert "ok" in root.children
    assert ".." not in root.children
    assert root.child_count == 1
