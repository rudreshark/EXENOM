/**
 * JavaScript Analysis Module
 *
 * Downloads JavaScript files referenced by a target web page, then analyzes
 * them for:
 *   - Secrets (AWS / GCP / Slack / GitHub / Stripe / JWT / Bearer / private keys / ...)
 *   - API endpoints (fetch/axios/get/post/put/delete/patch/request calls + /api/... + /vN/...)
 *   - Cloud keys (provider-classified secrets: AWS / GCP / GitHub / Slack / Stripe)
 *   - Internal URLs (localhost, RFC1918 ranges, internal/intranet/staging/dev/admin hostnames)
 *   - Interesting comments (TODO/FIXME/HACK/XXX/password/secret/key/token/admin/debug/temp/test)
 *
 * Pure Node built-ins only (fetch). No external packages.
 */
import type { JsAnalyzeResult } from "./types";

const UA = "easm-scanner/1.0";

const MAX_HOSTS = 5;
const MAX_JS_PER_HOST = 10;
const MAX_JS_TOTAL = 30;

const HTML_TIMEOUT = 8000;
const JS_TIMEOUT = 10000;
const HTML_BODY_LIMIT = 2 * 1024 * 1024; // 2 MB safety cap (spec doesn't specify an HTML cap)
const JS_BODY_LIMIT = 500 * 1024; // 500 KB per spec

const MAX_ENDPOINTS_PER_FILE = 30;
const MAX_COMMENTS_PER_FILE = 10;

// ----------------------------------------------------------------------------
// Secret patterns — type label + regex source + optional capture group + provider
// ----------------------------------------------------------------------------

interface SecretPattern {
  type: string;
  regex: string;
  /** If set, use this capture group as the value; otherwise use the full match. */
  captureGroup?: number;
  /** If set, this secret also counts as a cloud key for the given provider. */
  provider?: "AWS" | "GCP" | "Azure" | "GitHub" | "Slack" | "Stripe";
}

const SECRET_PATTERNS: SecretPattern[] = [
  { type: "AWS Access Key", regex: "AKIA[0-9A-Z]{16}", provider: "AWS" },
  { type: "AWS Secret Key", regex: "aws_secret_access_key\\s*[:=]\\s*['\"]([A-Za-z0-9/+=]{40})['\"]", captureGroup: 1, provider: "AWS" },
  { type: "Google API Key", regex: "AIza[0-9A-Za-z_\\-]{35}", provider: "GCP" },
  { type: "Google OAuth ID", regex: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com", provider: "GCP" },
  { type: "Slack token", regex: "xox[baprs]-[0-9A-Za-z-]{10,48}", provider: "Slack" },
  { type: "Slack webhook", regex: "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", provider: "Slack" },
  { type: "GitHub token", regex: "gh[pousr]_[A-Za-z0-9]{36}", provider: "GitHub" },
  { type: "Stripe key", regex: "(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}", provider: "Stripe" },
  { type: "Generic API key", regex: "api[_-]?key\\s*[:=]\\s*['\"]([A-Za-z0-9_\\-]{20,})['\"]", captureGroup: 1 },
  { type: "Private key", regex: "-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----" },
  { type: "JWT", regex: "eyJ[A-Za-z0-9_\\-]+\\.eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+" },
  { type: "Bearer token", regex: "Bearer\\s+[A-Za-z0-9_\\-\\.]{20,}" },
  { type: "Generic password", regex: "(?:password|passwd|pwd)\\s*[:=]\\s*['\"]([^'\"]{4,})['\"]", captureGroup: 1 },
  { type: "Connection string", regex: "(?:mongodb|postgres|mysql|redis)://[^\\s'\"]+" },
];

// ----------------------------------------------------------------------------
// Network helper
// ----------------------------------------------------------------------------

/**
 * Fetch a URL with an AbortController-based timeout, returning up to `limit`
 * bytes of body decoded as UTF-8 text. Returns "" on any error / non-2xx /
 * timeout so callers can simply skip.
 */
async function fetchText(
  url: string,
  timeoutMs: number,
  limit: number,
  accept: string
): Promise<string> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": UA, Accept: accept },
    });
    if (!res.ok) return "";
    const ab = await res.arrayBuffer();
    const view = ab.byteLength > limit ? ab.slice(0, limit) : ab;
    return new TextDecoder().decode(new Uint8Array(view));
  } catch {
    return "";
  } finally {
    clearTimeout(t);
  }
}

// ----------------------------------------------------------------------------
// Line-number resolver (1-based, binary search over precomputed offsets)
// ----------------------------------------------------------------------------

/** Returns a function mapping a string index to its 1-based line number. */
function makeLineResolver(body: string): (index: number) => number {
  const lineStarts: number[] = [0];
  for (let i = 0; i < body.length; i++) {
    if (body.charCodeAt(i) === 10) lineStarts.push(i + 1); // \n
  }
  return (index: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (lineStarts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

// ----------------------------------------------------------------------------
// Script extraction
// ----------------------------------------------------------------------------

interface ExtractedScripts {
  externalScripts: string[];
  inlineScripts: string[];
}

/**
 * Extract `<script src="...">` URLs (resolved against pageUrl) and inline
 * `<script>` contents from an HTML document. External URLs are deduped and
 * filtered to http(s). Inline scripts with empty content are skipped.
 */
function extractScripts(html: string, pageUrl: string): ExtractedScripts {
  const externalScripts: string[] = [];
  const inlineScripts: string[] = [];
  const seen = new Set<string>();

  const scriptTagRe = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  let m: RegExpExecArray | null;
  while ((m = scriptTagRe.exec(html)) !== null) {
    const attrs = m[1] || "";
    const content = m[2] || "";
    const srcMatch = attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
    if (srcMatch) {
      const src = srcMatch[1];
      try {
        const abs = new URL(src, pageUrl).href;
        // Skip non-http(s) schemes (data:, blob:, javascript:, ...)
        if (!/^https?:/i.test(abs)) continue;
        if (!seen.has(abs)) {
          seen.add(abs);
          externalScripts.push(abs);
        }
      } catch {
        /* malformed URL — skip */
      }
    } else if (content.trim().length > 0) {
      inlineScripts.push(content);
    }
    if (m.index === scriptTagRe.lastIndex) scriptTagRe.lastIndex++;
  }
  return { externalScripts, inlineScripts };
}

// ----------------------------------------------------------------------------
// Per-file analysis
// ----------------------------------------------------------------------------

interface AnalyzedFile {
  url: string;
  size: number;
  secrets: { type: string; value: string; line: number }[];
  endpoints: string[];
  cloudKeys: { provider: string; key: string }[];
  internalUrls: string[];
  comments: string[];
}

function analyzeJs(url: string, body: string): AnalyzedFile {
  const secrets: { type: string; value: string; line: number }[] = [];
  const cloudKeys: { provider: string; key: string }[] = [];
  const endpoints = new Set<string>();
  const internalUrls = new Set<string>();
  const comments: string[] = [];

  const lineOf = makeLineResolver(body);

  // --- Secrets + Cloud keys (single pass per pattern; cloud keys derived
  //     directly from secret matches by provider classification) ---
  for (const sp of SECRET_PATTERNS) {
    const re = new RegExp(sp.regex, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      const value = sp.captureGroup != null ? m[sp.captureGroup] || "" : m[0];
      if (!value) {
        // Guard against zero-length matches looping forever
        if (m.index === re.lastIndex) re.lastIndex++;
        continue;
      }
      const line = lineOf(m.index);
      secrets.push({ type: sp.type, value, line });
      if (sp.provider) {
        cloudKeys.push({ provider: sp.provider, key: value });
      }
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }

  // --- Endpoints (3 patterns, deduped via Set, capped at MAX_ENDPOINTS_PER_FILE) ---
  const tryAddEndpoint = (val: string) => {
    if (endpoints.size < MAX_ENDPOINTS_PER_FILE) endpoints.add(val);
  };

  // Pattern 1: fetch/axios/get/post/put/delete/patch/request calls with a
  // path-string argument that starts with `/`.
  const callRe =
    /(?:fetch|axios|get|post|put|delete|patch|request)\s*\(\s*['"`](\/[A-Za-z0-9_\-\/\{\}\.:]+)['"`]/g;
  let cm: RegExpExecArray | null;
  while (endpoints.size < MAX_ENDPOINTS_PER_FILE && (cm = callRe.exec(body)) !== null) {
    if (cm[1]) tryAddEndpoint(cm[1]);
    if (cm.index === callRe.lastIndex) callRe.lastIndex++;
  }

  // Pattern 2: /api/... literal paths
  if (endpoints.size < MAX_ENDPOINTS_PER_FILE) {
    const apiRe = /\/api\/[A-Za-z0-9_\-\/]+/g;
    while (endpoints.size < MAX_ENDPOINTS_PER_FILE && (cm = apiRe.exec(body)) !== null) {
      tryAddEndpoint(cm[0]);
      if (cm.index === apiRe.lastIndex) apiRe.lastIndex++;
    }
  }

  // Pattern 3: /vN/... versioned API paths
  if (endpoints.size < MAX_ENDPOINTS_PER_FILE) {
    const verRe = /\/v[0-9]+\/[A-Za-z0-9_\-\/]+/g;
    while (endpoints.size < MAX_ENDPOINTS_PER_FILE && (cm = verRe.exec(body)) !== null) {
      tryAddEndpoint(cm[0]);
      if (cm.index === verRe.lastIndex) verRe.lastIndex++;
    }
  }

  // --- Internal URLs (localhost / RFC1918 / internal-staging-dev-admin hostnames) ---
  const intRe =
    /https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+|internal|intranet|staging|dev|admin)[^\s'"]*/g;
  let im: RegExpExecArray | null;
  while ((im = intRe.exec(body)) !== null) {
    internalUrls.add(im[0]);
    if (im.index === intRe.lastIndex) intRe.lastIndex++;
  }

  // --- Comments (block + line) filtered by sensitive keywords ---
  // The `(?<!:)` lookbehind on `//` skips `://` URL fragments so that strings
  // like `"http://example.com"` don't get parsed as `//` line comments.
  const commentRe = /\/\*([\s\S]*?)\*\/|(?<!:)\/\/([^\n]*)/g;
  const keywordRe =
    /\b(?:TODO|FIXME|HACK|XXX|password|secret|key|token|admin|debug|temp|test)/i;
  let com: RegExpExecArray | null;
  while (comments.length < MAX_COMMENTS_PER_FILE && (com = commentRe.exec(body)) !== null) {
    const text = (com[1] != null ? com[1] : com[2] || "").trim();
    if (text && keywordRe.test(text)) {
      comments.push(text.length > 200 ? text.slice(0, 200) + "..." : text);
    }
    if (com.index === commentRe.lastIndex) commentRe.lastIndex++;
  }

  return {
    url,
    size: body.length,
    secrets,
    endpoints: Array.from(endpoints),
    cloudKeys,
    internalUrls: Array.from(internalUrls),
    comments,
  };
}

// ----------------------------------------------------------------------------
// Main entry point
// ----------------------------------------------------------------------------

export async function runJsAnalyze(
  urls: string[],
  log: (msg: string) => void
): Promise<JsAnalyzeResult> {
  const result: JsAnalyzeResult = { files: [] };
  const hosts = urls.slice(0, MAX_HOSTS);
  let totalFiles = 0;

  for (let i = 0; i < hosts.length; i++) {
    if (totalFiles >= MAX_JS_TOTAL) break;

    const url = hosts[i];
    log(`  analyzing ${i + 1}/${urls.length}: ${url}`);

    // 1. Fetch the HTML page (8s timeout, UA "easm-scanner/1.0")
    const html = await fetchText(
      url,
      HTML_TIMEOUT,
      HTML_BODY_LIMIT,
      "text/html,application/xhtml+xml,*/*"
    );
    if (!html) {
      log(`  [-] ${url}: no response or empty body`);
      continue;
    }

    // 2. Extract <script src> URLs + inline <script> contents
    const { externalScripts, inlineScripts } = extractScripts(html, url);

    // Build per-host work queue, capped at MAX_JS_PER_HOST (external first,
    // then inline). Inline scripts carry their body with them so we don't
    // need to fetch them.
    const queue: { url: string; body: string | null }[] = [];
    for (const ext of externalScripts) {
      if (queue.length >= MAX_JS_PER_HOST) break;
      queue.push({ url: ext, body: null });
    }
    for (let j = 0; j < inlineScripts.length; j++) {
      if (queue.length >= MAX_JS_PER_HOST) break;
      queue.push({ url: `${url}#inline-${j + 1}`, body: inlineScripts[j] });
    }

    if (queue.length === 0) {
      log(`  [-] ${url}: no scripts found`);
      continue;
    }

    // 3. Process each candidate (respecting the global cap of 30)
    for (const c of queue) {
      if (totalFiles >= MAX_JS_TOTAL) break;

      // Fetch external JS (10s timeout, 500KB cap); inline scripts already
      // have their body.
      let body = c.body;
      if (body === null) {
        body = await fetchText(
          c.url,
          JS_TIMEOUT,
          JS_BODY_LIMIT,
          "application/javascript,text/javascript,*/*"
        );
      }
      if (!body) {
        // fetch failed / non-2xx / empty — skip silently
        continue;
      }
      totalFiles++;

      const analyzed = analyzeJs(c.url, body);
      result.files.push(analyzed);

      // Per-file summary
      log(
        `  [+] ${c.url}: ${analyzed.secrets.length} secrets, ${analyzed.endpoints.length} endpoints, ${analyzed.cloudKeys.length} cloud keys`
      );

      // Per-secret details
      for (const s of analyzed.secrets) {
        log(`  [!] ${s.type}: ${s.value.slice(0, 50)}...`);
      }
    }
  }

  return result;
}
