import type { Asset } from "./types";

/** Same leaf name as TUI when a path is both a file and a directory prefix (npm). */
export const META_LEAF = "(metadata)";

const NUGET_PKG = /\.(nupkg|snupkg)$/i;

export type AssetTreeNode = {
  name: string;
  path: string;
  isDir: boolean;
  asset: Asset | null;
  children: Record<string, AssetTreeNode>;
  childCount: number;
};

export type TreeNodeKind = "folder" | "nuget-version" | "nupkg" | "file";

function node(
  name: string,
  path: string,
  isDir: boolean,
  asset: Asset | null = null,
): AssetTreeNode {
  return { name, path, isDir, asset, children: {}, childCount: 0 };
}

export function normalizeAssetParts(assetPath: string): string[] | null {
  const raw = assetPath.trim().replace(/\\/g, "/");
  if (!raw) return null;
  if (raw.startsWith("/") || /^[A-Za-z]:/.test(raw)) return null;
  if (raw.includes("\0")) return null;
  const parts: string[] = [];
  for (const part of raw.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") return null;
    if (/[<>:"|?*\u0000-\u001f]/.test(part)) return null;
    parts.push(part);
  }
  return parts.length ? parts : null;
}

function isNugetPackagePath(path: string): boolean {
  return NUGET_PKG.test(path.replace(/\\/g, "/").toLowerCase());
}

function looksLikeNugetMetadata(path: string): boolean {
  const p = path.replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase();
  if (isNugetPackagePath(p)) return false;
  if (p.startsWith("v3/registration/") || p.includes("/registration/")) return true;
  if (p.startsWith("v3/") && p.endsWith(".json")) return true;
  if (p.endsWith(".nuspec")) return true;
  return false;
}

/** Hosted NuGet API path ``Package.Id/1.2.3`` without a .nupkg suffix. */
export function isNugetHostedComponentPath(path: string): boolean {
  const p = path.replace(/\\/g, "/").replace(/^\/+/, "");
  if (!p || looksLikeNugetMetadata(p)) return false;
  if (isNugetPackagePath(p)) return true;
  const parts = p.split("/").filter(Boolean);
  if (parts.length !== 2) return false;
  const version = parts[1].toLowerCase();
  if (/\.(json|nuspec|xml|md5|sha1|sha256|sha512)$/.test(version)) return false;
  return true;
}

/** Browse path as in Nexus UI: ``Id/version/Id-version.nupkg``. */
export function nugetBrowsePath(assetPath: string, repoFormat?: string | null): string {
  const path = assetPath.replace(/\\/g, "/").replace(/^\/+/, "");
  const fmt = (repoFormat || "").toLowerCase().trim();
  if (isNugetPackagePath(path)) return path;
  if (fmt === "nuget" || (!fmt && isNugetHostedComponentPath(path))) {
    if (isNugetHostedComponentPath(path) && !isNugetPackagePath(path)) {
      const [packageId, version] = path.split("/");
      return `${packageId}/${version}/${packageId}-${version}.nupkg`;
    }
  }
  return path;
}

export function nodeKind(tree: AssetTreeNode): TreeNodeKind {
  if (!tree.isDir) {
    return NUGET_PKG.test(tree.name) ? "nupkg" : "file";
  }
  const kids = Object.values(tree.children);
  if (
    kids.length > 0 &&
    kids.every((child) => !child.isDir && NUGET_PKG.test(child.name))
  ) {
    return "nuget-version";
  }
  return "folder";
}

function attachFileIntoDir(dirNode: AssetTreeNode, asset: Asset, path: string) {
  const existing = dirNode.children[META_LEAF];
  if (existing) {
    existing.asset = asset;
    existing.path = path;
    existing.isDir = false;
    existing.children = {};
    return;
  }
  dirNode.children[META_LEAF] = node(META_LEAF, path, false, asset);
}

function promoteFileToDir(fileNode: AssetTreeNode) {
  if (fileNode.isDir) return;
  const fileAsset = fileNode.asset;
  const filePath = fileNode.path;
  fileNode.isDir = true;
  fileNode.asset = null;
  if (fileAsset) {
    fileNode.children[META_LEAF] = node(META_LEAF, filePath, false, fileAsset);
  }
}

export function insertAsset(
  root: AssetTreeNode,
  asset: Asset,
  repoFormat?: string | null,
): boolean {
  const parts = normalizeAssetParts(nugetBrowsePath(asset.path, asset.format || repoFormat));
  if (!parts) return false;
  let current = root;
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i];
    const isLast = i === parts.length - 1;
    const rel = parts.slice(0, i + 1).join("/");
    if (!(part in current.children)) {
      current.children[part] = node(part, rel, !isLast, isLast ? asset : null);
    } else {
      const child = current.children[part];
      if (isLast) {
        if (child.isDir && Object.keys(child.children).length > 0) {
          attachFileIntoDir(child, asset, rel);
        } else {
          child.isDir = false;
          child.asset = asset;
          child.children = {};
        }
      } else if (!child.isDir) {
        promoteFileToDir(child);
      }
    }
    current = current.children[part];
  }
  return true;
}

export function annotateCounts(tree: AssetTreeNode): number {
  if (!tree.isDir) {
    tree.childCount = 0;
    return 1;
  }
  let total = 0;
  for (const child of Object.values(tree.children)) {
    total += annotateCounts(child);
  }
  tree.childCount = total;
  return total;
}

export function buildAssetTree(
  assets: Asset[],
  rootName = "/",
  repoFormat?: string | null,
): AssetTreeNode {
  const root = node(rootName, "", true);
  for (const asset of assets) insertAsset(root, asset, repoFormat);
  annotateCounts(root);
  return root;
}

export function filterTree(root: AssetTreeNode, query: string): AssetTreeNode {
  const q = query.trim().toLowerCase();
  if (!q) return root;

  const walk = (tree: AssetTreeNode): AssetTreeNode | null => {
    if (!tree.isDir) {
      const hay = `${tree.path} ${tree.name}`.toLowerCase();
      return hay.includes(q) ? tree : null;
    }
    const kept: Record<string, AssetTreeNode> = {};
    for (const [name, child] of Object.entries(tree.children)) {
      const filtered = walk(child);
      if (filtered) kept[name] = filtered;
    }
    const selfMatch = tree.name.toLowerCase().includes(q) || tree.path.toLowerCase().includes(q);
    if (!Object.keys(kept).length && !selfMatch) return null;
    const clone = node(tree.name, tree.path, true, tree.asset);
    clone.children = kept;
    annotateCounts(clone);
    return clone;
  };

  return walk(root) ?? node(root.name, "", true);
}

export function sortedChildren(tree: AssetTreeNode): AssetTreeNode[] {
  return Object.values(tree.children).sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
  });
}

export type VisibleRow = { node: AssetTreeNode; depth: number; rails: boolean[]; last: boolean };

export function flattenVisible(root: AssetTreeNode, expanded: Set<string>): VisibleRow[] {
  const rows: VisibleRow[] = [];
  const walk = (tree: AssetTreeNode, depth: number, rails: boolean[]) => {
    const kids = sortedChildren(tree);
    kids.forEach((child, i) => {
      const last = i === kids.length - 1;
      rows.push({ node: child, depth, rails, last });
      if (child.isDir && expanded.has(child.path)) {
        walk(child, depth + 1, [...rails, !last]);
      }
    });
  };
  walk(root, 0, []);
  return rows;
}

export function collectDirPaths(tree: AssetTreeNode): string[] {
  const paths: string[] = [];
  const walk = (n: AssetTreeNode) => {
    if (n.isDir && n.path) paths.push(n.path);
    for (const child of Object.values(n.children)) walk(child);
  };
  walk(tree);
  return paths;
}
