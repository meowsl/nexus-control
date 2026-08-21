import { useCallback, useEffect, useMemo, useState } from "react";
import HexLoader from "./HexLoader";
import When from "./When";
import { api, formatBytes } from "./api";
import {
  buildAssetTree,
  collectDirPaths,
  filterTree,
  flattenVisible,
  nodeKind,
  type AssetTreeNode,
} from "./assetTree";
import { readAssetCache, writeAssetCache } from "./assetCache";
import type { Asset } from "./types";

function fileWord(n: number): string {
  const n10 = n % 10;
  const n100 = n % 100;
  if (n10 === 1 && n100 !== 11) return `${n} файл`;
  if (n10 >= 2 && n10 <= 4 && (n100 < 10 || n100 >= 20)) return `${n} файла`;
  return `${n} файлов`;
}

function FolderGlyph() {
  return (
    <svg className="tree-glyph folder" viewBox="0 0 16 16" aria-hidden>
      <path
        fill="#E8B84A"
        d="M1.5 4.25A1.75 1.75 0 0 1 3.25 2.5h3.1c.3 0 .58.15.75.4l.7 1.05h5.95A1.75 1.75 0 0 1 15.5 5.7v6.55A1.75 1.75 0 0 1 13.75 14H3.25A1.75 1.75 0 0 1 1.5 12.25Z"
      />
      <path fill="#F5D07A" d="M1.5 6.4h13v5.85A1.75 1.75 0 0 1 12.75 14H3.25A1.75 1.75 0 0 1 1.5 12.25Z" />
    </svg>
  );
}

function FileGlyph() {
  return (
    <svg className="tree-glyph file" viewBox="0 0 16 16" aria-hidden>
      <path fill="#E4E4E7" d="M4 1.5h5.2L14 6.3V14a1.5 1.5 0 0 1-1.5 1.5h-8A1.5 1.5 0 0 1 3 14V3A1.5 1.5 0 0 1 4 1.5Z" />
      <path fill="#D4D4D8" d="M9.2 1.5V5a1.3 1.3 0 0 0 1.3 1.3H14" />
    </svg>
  );
}

function PackageBoxGlyph() {
  return (
    <svg className="tree-glyph package" viewBox="0 0 16 16" aria-hidden>
      <path fill="#C4A574" d="M8 1.4 14.2 4.6 8 7.8 1.8 4.6Z" />
      <path fill="#8B6914" d="M1.8 4.6 8 7.8v6.8L1.8 11.4Z" />
      <path fill="#A67C3D" d="M14.2 4.6 8 7.8v6.8l6.2-3.2Z" />
    </svg>
  );
}

function NupkgGlyph() {
  return (
    <svg className="tree-glyph nupkg" viewBox="0 0 16 16" aria-hidden>
      <path fill="#F4F4F5" d="M4 1.4h5.1L13.6 6v8.1A1.4 1.4 0 0 1 12.2 15.5H4A1.4 1.4 0 0 1 2.6 14.1V2.8A1.4 1.4 0 0 1 4 1.4Z" />
      <path fill="#E4E4E7" d="M9.1 1.4V5a1.2 1.2 0 0 0 1.2 1.2h3.3" />
      <path fill="#F08C2A" d="M5.6 8.2h4.8v4.8H5.6Z" />
      <path fill="#47D5CF" d="M6.4 9h1.4v1.4H6.4Zm2.2 0h1.4v1.4H8.6Zm-2.2 2.2h1.4v1.4H6.4Z" />
    </svg>
  );
}

function TreeGuides({ depth, rails, last }: { depth: number; rails: boolean[]; last: boolean }) {
  if (depth === 0) return null;
  const cells = [];
  for (let i = 0; i < depth; i += 1) {
    const elbow = i === depth - 1;
    cells.push(
      <span
        key={i}
        className={
          elbow
            ? `tree-guide elbow${last ? " last" : ""}`
            : `tree-guide${rails[i] ? " stem" : ""}`
        }
      />,
    );
  }
  return <span className="tree-guides">{cells}</span>;
}

function NodeGlyph({ kind }: { kind: ReturnType<typeof nodeKind> }) {
  if (kind === "nuget-version") return <PackageBoxGlyph />;
  if (kind === "nupkg") return <NupkgGlyph />;
  if (kind === "folder") return <FolderGlyph />;
  return <FileGlyph />;
}

export default function AssetBrowser({ repo, format }: { repo: string; format?: string }) {
  const [items, setItems] = useState<Asset[]>(() => readAssetCache(repo)?.items ?? []);
  const [loading, setLoading] = useState(() => !readAssetCache(repo));
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const loadAll = useCallback(async (signal: AbortSignal) => {
    const hit = readAssetCache(repo);
    if (hit) {
      setItems(hit.items);
      setLoading(false);
      setError("");
      if (hit.fresh) return;
    } else {
      setLoading(true);
      setItems([]);
      setExpanded(new Set());
      setError("");
    }
    let token: string | null = null;
    const collected: Asset[] = [];
    try {
      do {
        if (signal.aborted) return;
        const qs = token ? `?continuation=${encodeURIComponent(token)}` : "";
        const data = await api<{ items: Asset[]; continuation: string | null }>(
          `/api/repos/${encodeURIComponent(repo)}/assets${qs}`,
        );
        if (signal.aborted) return;
        collected.push(...data.items);
        token = data.continuation;
      } while (token);
      if (signal.aborted) return;
      writeAssetCache(repo, collected);
      setItems(collected);
    } catch (ex) {
      if (signal.aborted) return;
      setError(ex instanceof Error ? ex.message : "Ошибка");
    } finally {
      if (!signal.aborted) setLoading(false);
    }
  }, [repo]);

  useEffect(() => {
    const ac = new AbortController();
    void loadAll(ac.signal);
    return () => ac.abort();
  }, [loadAll]);

  const tree = useMemo(() => buildAssetTree(items, repo, format), [items, repo, format]);
  const visibleTree = useMemo(() => filterTree(tree, query), [tree, query]);
  const filtering = query.trim().length > 0;

  const effectiveExpanded = useMemo(() => {
    if (filtering) return new Set(collectDirPaths(visibleTree));
    return expanded;
  }, [filtering, visibleTree, expanded]);

  const rows = useMemo(
    () => flattenVisible(visibleTree, effectiveExpanded),
    [visibleTree, effectiveExpanded],
  );

  function toggle(dir: AssetTreeNode) {
    if (filtering || !dir.isDir) return;
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(dir.path)) next.delete(dir.path);
      else next.add(dir.path);
      return next;
    });
  }

  function expandAll() {
    setExpanded(new Set(collectDirPaths(tree)));
  }

  function collapseAll() {
    setExpanded(new Set());
  }

  return (
    <>
      {loading ? (
        <div className="table-wrap">
          {error ? <div className="banner error">{error}</div> : null}
          <HexLoader label="Собираем каталог" />
        </div>
      ) : (
        <>
      <div className="filters">
        <label>
          Фильтр
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="путь или имя файла"
          />
        </label>
        <button type="button" className="btn" onClick={expandAll} disabled={filtering}>
          Развернуть всё
        </button>
        <button type="button" className="btn" onClick={collapseAll} disabled={filtering}>
          Свернуть
        </button>
        <span className="muted tree-status">
          {`${fileWord(tree.childCount)}${filtering ? ` · показано ${visibleTree.childCount}` : ""}`}
        </span>
      </div>
      <div className="table-wrap">
        {error ? <div className="banner error">{error}</div> : null}
        <table className="tree-table">
          <colgroup>
            <col />
            <col className="col-size" />
            <col className="col-when" />
          </colgroup>
          <thead>
            <tr>
              <th>Имя</th>
              <th>Размер</th>
              <th>Изменён</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ node, depth, rails, last }) => {
              const open = node.isDir && effectiveExpanded.has(node.path);
              const kind = nodeKind(node);
              return (
                <tr
                  key={`${node.isDir ? "d" : "f"}:${node.path}`}
                  className={`tree-row${node.isDir ? " dir" : ""}`}
                  data-depth={depth}
                  onClick={node.isDir ? () => toggle(node) : undefined}
                >
                  <td>
                    <div className="tree-name">
                      <TreeGuides depth={depth} rails={rails} last={last} />
                      <span className="tree-leaf">
                        <span
                          className={`tree-twist${node.isDir ? "" : " empty"}${open ? " open" : ""}`}
                          aria-hidden
                        >
                          {node.isDir ? (open ? "−" : "+") : null}
                        </span>
                        <NodeGlyph kind={kind} />
                        <span
                          className={kind === "file" || kind === "nupkg" ? "tree-label mono" : "tree-label"}
                          title={node.path}
                        >
                          {node.name}
                        </span>
                      </span>
                    </div>
                  </td>
                  <td className="num">
                    {node.isDir ? fileWord(node.childCount) : formatBytes(node.asset?.file_size)}
                  </td>
                  <td>
                    <When value={node.isDir ? null : node.asset?.last_modified} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {items.length === 0 && !loading ? (
          <p className="empty">В репозитории нет ассетов (или нет прав на просмотр).</p>
        ) : null}
        {filtering && rows.length === 0 && items.length > 0 ? (
          <p className="empty">Ничего не совпало с фильтром.</p>
        ) : null}
      </div>
        </>
      )}
    </>
  );
}
