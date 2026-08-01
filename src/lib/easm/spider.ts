/**
 * Advanced Spider Module
 *
 * More thorough than crawl.ts. In addition to BFS link discovery, extracts:
 *   - Forms (action, method, inputs)            → injection candidates
 *   - Hidden inputs                             → CSRF tokens, state, IDs
 *   - Interesting HTML comments                 → TODO/FIXME/secrets leak
 *   - Meta tags (name + content)                → CSRF, generator, author
 *   - JSON-LD structured data                   → org / site metadata
 *   - JS file URLs                              → for later static analysis
 *   - Inline script count                       → SPA / widget heuristic
 *   - sitemap.xml discovery                     → broader URL coverage
 *
 * Same-origin only. BFS frontier. Bounded by maxDepth / maxPages.
 * Uses only Node/Bun built-in fetch — no external packages.
 */
import type { SpiderResult, SpiderForm } from "./types";

// ---- tunables ---------------------------------------------------------

const DEFAULT_MAX_DEPTH = 3;
const DEFAULT_MAX_PAGES = 30;
const FETCH_TIMEOUT_MS = 8000;
const USER_AGENT = "easm-scanner/1.0";
const MAX_JS_PER_PAGE = 15;
const MAX_COMMENTS_PER_PAGE = 10;
const MAX_META_PER_PAGE = 10;
const MAX_BODY_BYTES = 500_000;
const MAX_LINKS_ENQUEUE_PER_PAGE = 20;
const FETCH_BATCH_SIZE = 5;

/** Static-asset extensions we never need to crawl (saves fetch budget). */
const SKIP_EXTENSIONS = [
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp", ".avif",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
  ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
  ".mp4", ".mp3", ".avi", ".mov", ".wav", ".ogg", ".flv", ".webm", ".m4a",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".css", ".map",
];

/** Keywords that make an HTML comment "interesting" (potential info leak). */
const INTERESTING_COMMENT_RE =
  /\b(?:TODO|FIXME|HACK|password|passwd|secret|key|token|admin|debug|temp)\b/i;

// ---- extraction helpers ----------------------------------------------

function extractTitle(html: string): string {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, " ").trim().slice(0, 120) : "";
}

/**
 * Parse all <form> tags that declare an action attribute.
 * Captures action + innerHTML, then extracts method from the opening tag
 * and parses inputs from the inner HTML using two attribute-order-tolerant
 * regexes (name-first and type-first).
 */
function extractForms(html: string, baseUrl: string): SpiderForm[] {
  const forms: SpiderForm[] = [];
  const formRe = /<form[^>]*action=["']([^"']*)["'][^>]*>([\s\S]*?)<\/form>/gi;
  let m: RegExpExecArray | null;
  while ((m = formRe.exec(html)) !== null) {
    const actionRaw = m[1] || "";
    const inner = m[2] || "";
    const fullMatch = m[0];
    const tagEnd = fullMatch.indexOf(">");
    const openTag = tagEnd >= 0 ? fullMatch.slice(0, tagEnd) : fullMatch;
    const methodMatch = openTag.match(/method=["']([^"']+)["']/i);
    const method = methodMatch ? methodMatch[1].toUpperCase() : "GET";

    let action = actionRaw;
    try {
      action = new URL(actionRaw || "", baseUrl).href;
    } catch {
      /* keep raw action on malformed URL */
    }

    forms.push({ action, method, inputs: parseInputs(inner) });
  }
  return forms;
}

/**
 * Pull a single quoted attribute value out of an HTML tag string.
 * Returns "" if the attribute is absent.
 */
function attrValue(tag: string, attr: string): string {
  const re = new RegExp(`\\b${attr}\\s*=\\s*["']([^"']*)["']`, "i");
  const m = tag.match(re);
  return m ? m[1] : "";
}

/**
 * Parse <input> fields from a fragment of HTML.
 *
 * The spec suggests two ordering-tolerant regexes (name-first and
 * type-first). In practice those regexes lose the `value` capture
 * whenever `value` is the final attribute before `>` (greedy `[^>]*`
 * consumes it and the optional value group matches empty). To reliably
 * capture name + type + value across ALL attribute orderings we instead
 * match each full `<input ...>` tag and then pull the attributes out
 * individually. This honours the spec's intent (capture name/type/value,
 * handle any ordering) while actually returning the values. Dedupes by
 * input name (first match wins). Only inputs that declare a `name` are
 * returned (inputs without a name can't be submitted and aren't useful
 * injection candidates).
 */
function parseInputs(
  html: string
): { name: string; type: string; value: string }[] {
  const inputs: { name: string; type: string; value: string }[] = [];
  const seen = new Set<string>();
  const tagRe = /<input\b[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(html)) !== null) {
    const tag = m[0];
    const name = attrValue(tag, "name");
    if (!name) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    const type = (attrValue(tag, "type") || "text").toLowerCase();
    const value = attrValue(tag, "value");
    inputs.push({ name, type, value });
  }
  return inputs;
}

/**
 * Page-wide scan for hidden inputs (inside or outside <form>).
 * Captures name + value — these often carry CSRF tokens, entity IDs,
 * session state, etc. Uses the same robust tag-match approach as
 * parseInputs so values are captured regardless of attribute order.
 */
function extractHiddenInputs(
  html: string
): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  const seen = new Set<string>();
  const tagRe = /<input\b[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(html)) !== null) {
    const tag = m[0];
    const type = attrValue(tag, "type").toLowerCase();
    if (type !== "hidden") continue;
    const name = attrValue(tag, "name");
    if (!name) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    out.push({ name, value: attrValue(tag, "value") });
  }
  return out;
}

/**
 * HTML comments filtered for "interesting" keywords
 * (TODO/FIXME/HACK/password/secret/key/token/admin/debug/temp).
 * Capped at MAX_COMMENTS_PER_PAGE.
 */
function extractComments(html: string): string[] {
  const out: string[] = [];
  const re = /<!--([\s\S]*?)-->/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const c = m[1].trim();
    if (!c) continue;
    if (!INTERESTING_COMMENT_RE.test(c)) continue;
    out.push(c.slice(0, 200));
    if (out.length >= MAX_COMMENTS_PER_PAGE) break;
  }
  return out;
}

/**
 * <meta name|property="..." content="..."> tags.
 * Captures name + content (CSRF tokens, generator, author, keywords, OG tags).
 * Capped at MAX_META_PER_PAGE.
 */
function extractMetaTags(
  html: string
): { name: string; content: string }[] {
  const out: { name: string; content: string }[] = [];
  const re =
    /<meta[^>]+(?:name|property)=["']([^"']+)["'][^>]+content=["']([^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    out.push({ name: m[1], content: m[2] });
    if (out.length >= MAX_META_PER_PAGE) break;
  }
  return out;
}

/**
 * JSON-LD structured data blocks:
 *   <script type="application/ld+json">...</script>
 *   <script type="application/json">...</script>
 */
function extractStructuredData(html: string): string[] {
  const out: string[] = [];
  const re =
    /<script[^>]*type=["']application\/(?:ld\+json|json)["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const body = m[1].trim();
    if (body) out.push(body);
  }
  return out;
}

/**
 * External JS file URLs from <script src="...">.
 * Resolved against the page URL. Capped at MAX_JS_PER_PAGE.
 */
function extractJsFiles(html: string, baseUrl: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const raw = m[1];
    try {
      const abs = new URL(raw, baseUrl).href;
      if (seen.has(abs)) continue;
      seen.add(abs);
      out.push(abs);
      if (out.length >= MAX_JS_PER_PAGE) break;
    } catch {
      /* ignore malformed src */
    }
  }
  return out;
}

/** Count <script> tags that do NOT declare a src attribute (inline scripts). */
function countInlineScripts(html: string): number {
  const all = html.match(/<script\b[^>]*>/gi) || [];
  const withSrc =
    html.match(/<script\b[^>]*\bsrc=["'][^"']+["'][^>]*>/gi) || [];
  return Math.max(0, all.length - withSrc.length);
}

/**
 * Same-origin anchor hrefs, resolved to absolute URLs.
 * Skips fragments, javascript:, mailto:, tel:, data: URIs and static assets.
 */
function extractInternalLinks(html: string, baseUrl: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }
  const re = /<a[^>]+href=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const raw = m[1];
    if (!raw) continue;
    if (
      raw.startsWith("#") ||
      raw.toLowerCase().startsWith("javascript:") ||
      raw.toLowerCase().startsWith("mailto:") ||
      raw.toLowerCase().startsWith("tel:") ||
      raw.toLowerCase().startsWith("data:")
    ) {
      continue;
    }
    try {
      const abs = new URL(raw, baseUrl);
      if (abs.origin !== base.origin) continue;
      if (abs.protocol !== "http:" && abs.protocol !== "https:") continue;
      const cleaned = abs.href.split("#")[0];
      if (seen.has(cleaned)) continue;
      if (isStaticAsset(cleaned)) continue;
      seen.add(cleaned);
      out.push(cleaned);
    } catch {
      /* ignore malformed href */
    }
  }
  return out;
}

/** Extract query-string parameter names from a URL. */
function extractUrlParams(url: string): string[] {
  try {
    const u = new URL(url);
    return Array.from(u.searchParams.keys());
  } catch {
    return [];
  }
}

/** True if the URL path ends with a known static-asset extension. */
function isStaticAsset(url: string): boolean {
  try {
    const u = new URL(url);
    const path = u.pathname.toLowerCase();
    return SKIP_EXTENSIONS.some((ext) => path.endsWith(ext));
  } catch {
    return false;
  }
}

// ---- network helpers --------------------------------------------------

async function fetchPage(
  url: string
): Promise<{ status: number; body: string; contentType: string } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": USER_AGENT },
    });
    const ct = res.headers.get("content-type") || "";
    let body = "";
    if (
      ct.includes("text") ||
      ct.includes("xml") ||
      ct.includes("json") ||
      ct === ""
    ) {
      try {
        body = await res.text();
      } catch {
        body = "";
      }
    }
    return {
      status: res.status,
      body: body.slice(0, MAX_BODY_BYTES),
      contentType: ct,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** Fetch /sitemap.xml from the given origin and parse <loc> URLs. */
async function fetchSitemap(origin: string): Promise<string[]> {
  const sitemapUrl = `${origin}/sitemap.xml`;
  const page = await fetchPage(sitemapUrl);
  if (!page || page.status !== 200) return [];
  const urls: string[] = [];
  const re = /<loc>([^<]+)<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(page.body)) !== null) {
    const u = m[1].trim();
    if (u) urls.push(u);
  }
  return urls;
}

// ---- main entry point -------------------------------------------------

export async function runSpider(
  startUrl: string,
  maxDepth: number,
  maxPages: number,
  log: (msg: string) => void
): Promise<SpiderResult> {
  if (!maxDepth || maxDepth <= 0) maxDepth = DEFAULT_MAX_DEPTH;
  if (!maxPages || maxPages <= 0) maxPages = DEFAULT_MAX_PAGES;

  log(
    `Spidering ${startUrl} (max depth ${maxDepth}, max ${maxPages} pages) ...`
  );

  const pages: SpiderResult["pages"] = [];
  const allForms: SpiderForm[] = [];
  const allParams = new Set<string>();
  const sitemapUrls: string[] = [];

  // Normalize start URL
  let start: URL;
  try {
    start = new URL(startUrl);
  } catch {
    log(`Invalid start URL: ${startUrl}`);
    return { pages, allForms, allParams: [], sitemapUrls };
  }
  const origin = start.origin;
  const startNormalized = start.href.split("#")[0];

  const visited = new Set<string>();
  let queue: { url: string; depth: number }[] = [
    { url: startNormalized, depth: 0 },
  ];

  while (queue.length > 0 && pages.length < maxPages) {
    const batch = queue.splice(0, Math.min(FETCH_BATCH_SIZE, queue.length));
    for (const item of batch) {
      if (pages.length >= maxPages) break;
      if (visited.has(item.url)) continue;
      visited.add(item.url);

      // Aggregate URL query-string params for every URL we attempt, even
      // ones that 4xx/5xx — the params themselves are still injection
      // candidates surfaced by the crawl frontier.
      extractUrlParams(item.url).forEach((p) => allParams.add(p));

      const page = await fetchPage(item.url);
      if (!page) {
        log(`  [${item.depth}] ${item.url.slice(0, 70)} (fetch failed)`);
        continue;
      }
      if (page.status >= 400) {
        log(
          `  [${item.depth}] ${item.url.slice(0, 70)} (status ${page.status})`
        );
        continue;
      }

      const body = page.body;
      const title = extractTitle(body);
      const forms = extractForms(body, item.url);
      const hiddenInputs = extractHiddenInputs(body);
      const comments = extractComments(body);
      const metaTags = extractMetaTags(body);
      const structuredData = extractStructuredData(body);
      const jsFiles = extractJsFiles(body, item.url);
      const inlineScripts = countInlineScripts(body);
      const internalLinks = extractInternalLinks(body, item.url);

      // Aggregate forms + their input names
      for (const f of forms) {
        allForms.push(f);
        for (const inp of f.inputs) allParams.add(inp.name);
      }

      pages.push({
        url: item.url,
        status: page.status,
        title,
        depth: item.depth,
        forms,
        hiddenInputs,
        comments,
        metaTags,
        structuredData,
        jsFiles,
        inlineScripts,
      });

      log(
        `  [${item.depth}] ${item.url.slice(0, 70)} (${forms.length} forms, ${hiddenInputs.length} hidden, ${comments.length} comments)`
      );
      for (const f of forms) {
        log(
          `  [+] form: ${f.action} (${f.method}, ${f.inputs.length} inputs)`
        );
      }

      // Enqueue deeper same-origin links
      if (item.depth < maxDepth) {
        for (const l of internalLinks.slice(0, MAX_LINKS_ENQUEUE_PER_PAGE)) {
          if (!visited.has(l)) queue.push({ url: l, depth: item.depth + 1 });
        }
      }
    }
  }

  // Sitemap discovery (best-effort, after the crawl)
  try {
    const sm = await fetchSitemap(origin);
    if (sm.length > 0) {
      sm.forEach((u) => sitemapUrls.push(u));
      log(`  [+] sitemap.xml: ${sm.length} URL(s) discovered`);
    }
  } catch {
    /* ignore sitemap failures */
  }

  log(
    `Spider complete: ${pages.length} page(s), ${allForms.length} form(s), ${allParams.size} unique param(s), ${sitemapUrls.length} sitemap URL(s).`
  );

  return {
    pages,
    allForms,
    allParams: Array.from(allParams),
    sitemapUrls,
  };
}
