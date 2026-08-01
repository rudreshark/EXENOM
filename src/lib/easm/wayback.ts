/**
 * Wayback Machine Module
 *
 * Queries the Internet Archive's Wayback Machine CDX API for historical
 * snapshots of the target domain. Extracts:
 *   - urls:           archived URLs with capture timestamp + status code
 *                     (capped at 2000 entries)
 *   - archivedPaths:  unique URL paths ever archived (path discovery for
 *                     hidden / legacy endpoints) — capped at 100
 *   - deletedPages:   URLs whose archived snapshot returned 404 or "999"
 *                     (live-but-now-removed content) — useful for finding
 *                     sensitive endpoints that were taken offline — capped
 *                     at 50
 *   - fileTypes:      file-extension histogram (.pdf, .env, .sql, .bak,
 *                     .json, .xml, .php, ...) sorted by count desc
 *
 * Uses only Node / Bun built-in `fetch` (no external deps). 15s timeout on
 * the CDX query because the API can be slow for large domains.
 */
import type { WaybackResult } from "./types";

/** CDX search endpoint — all archived URLs under `${domain}/*`. */
function cdxUrl(domain: string): string {
  return (
    `https://web.archive.org/cdx/search/cdx` +
    `?url=${domain}/*` +
    `&output=json` +
    `&limit=5000` +
    `&collapse=urlkey` +
    `&fl=original,timestamp,statuscode`
  );
}

/** Fetch + JSON-parse the CDX response with a hard timeout.
 *  Returns the parsed rows array, OR `null` if the API responded with an empty body
 *  (i.e. no archived URLs for this domain).
 *  Throws an Error on hard failures: network error, timeout, non-2xx status,
 *  or unparseable body — the caller is expected to log the message. */
async function fetchCdxRows(domain: string, timeoutMs = 15000): Promise<unknown[][] | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(cdxUrl(domain), {
      signal: ctrl.signal,
      headers: {
        "User-Agent": "easm-scanner/1.0",
        Accept: "application/json",
      },
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`CDX request failed: ${msg}`);
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    throw new Error(`CDX returned HTTP ${res.status} ${res.statusText}`.trim());
  }

  // CDX normally returns application/json, but some proxies rewrite the
  // content-type to text/plain — parse the body as JSON regardless.
  const text = await res.text();
  if (!text || !text.trim()) return null; // empty body = no archived URLs

  try {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) {
      throw new Error("CDX returned non-array JSON");
    }
    return parsed as unknown[][];
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`CDX JSON parse failed: ${msg}`);
  }
}

/** Extract the URL pathname (without origin). Returns null for `/` or unparseable URLs. */
function extractPath(rawUrl: string): string | null {
  try {
    const u = new URL(rawUrl);
    const p = u.pathname;
    if (!p || p === "/") return null;
    return p;
  } catch {
    return null;
  }
}

/** Extract a lowercased file extension (e.g. ".pdf") from the URL's last path segment.
 *  Also handles dotfiles like `.env` / `.htaccess` (segment starts with a dot). */
function extractExt(rawUrl: string): string | null {
  try {
    const u = new URL(rawUrl);
    const seg = u.pathname.split("/").pop() || "";
    const dot = seg.lastIndexOf(".");
    // Reject: no dot at all, or a trailing dot with nothing after it.
    // dot === 0 is allowed (dotfiles like `.env`).
    if (dot < 0 || dot === seg.length - 1) return null;
    const ext = seg.slice(dot).toLowerCase();
    // Reject implausible extensions (too long, or containing non alphanumerics).
    if (ext.length > 10) return null;
    if (!/^\.[a-z0-9]+$/.test(ext)) return null;
    return ext;
  } catch {
    return null;
  }
}

export async function runWayback(
  domain: string,
  log: (msg: string) => void
): Promise<WaybackResult> {
  const empty: WaybackResult = {
    totalUrls: 0,
    urls: [],
    archivedPaths: [],
    deletedPages: [],
    fileTypes: [],
  };

  log(`  Querying Wayback CDX for ${domain}/* ...`);

  let rows: unknown[][] | null;
  try {
    rows = await fetchCdxRows(domain, 15000);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log(`  [-] Wayback CDX query failed: ${msg}`);
    return empty;
  }

  if (!rows || rows.length < 2) {
    // `length < 2` means either no body at all or only the header row —
    // either way there are no archived URLs for this domain.
    log(`  [-] Wayback CDX returned no archived URLs for ${domain}`);
    return empty;
  }

  // First row is the header: ["original","timestamp","statuscode"].
  // Resolve column indices from the header so we survive column reordering.
  const header = rows[0] as unknown[];
  const safeHeader = Array.isArray(header) ? header.map((h) => String(h)) : [];
  let idxOriginal = safeHeader.indexOf("original");
  let idxTimestamp = safeHeader.indexOf("timestamp");
  let idxStatus = safeHeader.indexOf("statuscode");
  if (idxOriginal < 0) idxOriginal = 0;
  if (idxTimestamp < 0) idxTimestamp = 1;
  if (idxStatus < 0) idxStatus = 2;

  const dataRows = rows.slice(1);

  const urls: WaybackResult["urls"] = [];
  const pathSet = new Set<string>();
  const deleted: WaybackResult["deletedPages"] = [];
  const extCount = new Map<string, number>();

  for (const row of dataRows) {
    if (!Array.isArray(row) || row.length < 3) continue;
    const original = String(row[idxOriginal] ?? "");
    const timestamp = String(row[idxTimestamp] ?? "");
    const statusRaw = String(row[idxStatus] ?? "");
    if (!original) continue;

    const status = parseInt(statusRaw, 10) || 0;

    // urls[] — cap at 2000.
    if (urls.length < 2000) {
      urls.push({ url: original, timestamp, status });
    }

    // archivedPaths — unique paths, cap at 100.
    const path = extractPath(original);
    if (path && pathSet.size < 100) {
      pathSet.add(path);
    }

    // deletedPages — statuscode 404 or "999", cap at 50.
    if ((statusRaw === "404" || statusRaw === "999") && deleted.length < 50) {
      deleted.push({ url: original, lastSeen: timestamp });
    }

    // fileTypes — histogram over ALL archived URLs (no cap on the map).
    const ext = extractExt(original);
    if (ext) {
      extCount.set(ext, (extCount.get(ext) || 0) + 1);
    }
  }

  const archivedPaths = Array.from(pathSet).slice(0, 100);

  const fileTypes = Array.from(extCount.entries())
    .map(([ext, count]) => ({ ext, count }))
    .sort((a, b) => b.count - a.count);

  const top5 = fileTypes
    .slice(0, 5)
    .map((f) => `${f.ext}:${f.count}`)
    .join(", ");

  log(`  [+] ${urls.length} archived URLs found`);
  log(`  [+] ${archivedPaths.length} unique paths`);
  log(`  [+] ${deleted.length} deleted/404 pages`);
  log(`  [+] ${fileTypes.length} file types: ${top5}`);

  return {
    totalUrls: urls.length,
    urls,
    archivedPaths,
    deletedPages: deleted,
    fileTypes,
  };
}
