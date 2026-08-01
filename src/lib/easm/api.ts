/**
 * API Discovery Module
 *
 * Discovers API endpoints (from HTML / inline JS), GraphQL endpoints,
 * Swagger/OpenAPI documentation, and versioned API base paths for a
 * list of target URLs.
 *
 * Self-contained: uses only the built-in `fetch`. Imports only the
 * `ApiResult` type from "./types".
 */
import type { ApiResult } from "./types";

// ---- Probe target lists --------------------------------------------------

const SWAGGER_PATHS = [
  "/swagger.json",
  "/swagger/v1/swagger.json",
  "/api-docs",
  "/api-docs.json",
  "/openapi.json",
  "/api/openapi.json",
  "/v1/api-docs",
  "/v2/api-docs",
  "/v3/api-docs",
  "/swagger-ui/",
  "/swagger-ui/index.html",
  "/redoc",
  "/api.yaml",
  "/openapi.yaml",
];

const GRAPHQL_PATHS = [
  "/graphql",
  "/graphql/console",
  "/graphiql",
  "/api/graphql",
  "/v1/graphql",
  "/query",
  "/playground",
];

const VERSIONED_PATHS = [
  "/v1/",
  "/v2/",
  "/v3/",
  "/api/v1/",
  "/api/v2/",
  "/api/v3/",
];

// ---- Tunables ------------------------------------------------------------

const FETCH_TIMEOUT_MS = 8000; // HTML page fetch
const PROBE_TIMEOUT_MS = 8000; // swagger / versioned probes
const GRAPHQL_TIMEOUT_MS = 6000; // GraphQL introspection POST
const MAX_HOSTS = 5;
const MAX_ENDPOINTS_PER_HOST = 40;
const MAX_TYPES = 20;
const UA = "easm-scanner/1.0";

// ---- Fetch helper --------------------------------------------------------

interface ProbeResult {
  url: string;
  status: number;
  contentType: string;
  body: string;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = PROBE_TIMEOUT_MS
): Promise<ProbeResult | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = { "User-Agent": UA };
    if (options.headers) {
      // Merge caller headers (Content-Type for POSTs etc.)
      const incoming = options.headers as Record<string, string>;
      for (const k of Object.keys(incoming)) headers[k] = incoming[k];
    }
    const res = await fetch(url, {
      ...options,
      signal: ctrl.signal,
      redirect: "manual",
      headers,
    });
    const ct = res.headers.get("content-type") || "";
    let body = "";
    try {
      body = await res.text();
    } catch {
      body = "";
    }
    return { url, status: res.status, contentType: ct, body };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function safeJson(text: string): any | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function normalizeUrl(u: string): string {
  if (!u) return u;
  if (!/^https?:\/\//i.test(u)) return `http://${u}`;
  return u;
}

function normalizePath(p: string): string {
  if (!p) return "/";
  const stripped = p.replace(/\/+$/, "");
  return stripped || "/";
}

function pathOf(url: string): string {
  try {
    return normalizePath(new URL(url).pathname);
  } catch {
    return "";
  }
}

// ---- Endpoint extraction from HTML / inline JS ---------------------------

/**
 * Extract API endpoint references from HTML / inline JS using the four
 * required regex patterns. Resolves relative URLs against the page URL,
 * dedupes by absolute URL, and tags each with a method + source.
 */
function extractEndpoints(
  html: string,
  pageUrl: string
): { url: string; method: string; source: string }[] {
  const found = new Map<string, { url: string; method: string; source: string }>();

  function add(rawUrl: string, method: string, source: string) {
    if (!rawUrl) return;
    // Strip template-literal variables like ${userId}
    if (rawUrl.includes("${")) {
      rawUrl = rawUrl.replace(/\$\{[^}]*\}/g, "");
    }
    rawUrl = rawUrl.trim();
    if (!rawUrl) return;
    if (/^javascript:/i.test(rawUrl)) return;
    // Skip bare identifiers / variable names (no scheme, no leading / or .)
    if (
      !/^https?:/i.test(rawUrl) &&
      !rawUrl.startsWith("/") &&
      !rawUrl.startsWith("./") &&
      !rawUrl.startsWith("../")
    ) {
      return;
    }
    let absolute: string;
    try {
      absolute = new URL(rawUrl, pageUrl).toString();
    } catch {
      return;
    }
    absolute = absolute.split("#")[0];
    if (!/^https?:/i.test(absolute)) return;
    if (!found.has(absolute)) {
      found.set(absolute, { url: absolute, method, source });
    }
  }

  let m: RegExpExecArray | null;

  // /api/[A-Za-z0-9_\-\/]+  (also matches inside JS strings)
  const apiRe = /\/api\/[A-Za-z0-9_\-\/]+/g;
  while ((m = apiRe.exec(html)) !== null) add(m[0], "GET", "html");

  // /v[0-9]+/[A-Za-z0-9_\-\/]+
  const vRe = /\/v[0-9]+\/[A-Za-z0-9_\-\/]+/g;
  while ((m = vRe.exec(html)) !== null) add(m[0], "GET", "html");

  // fetch('...' | "..." | `...`)
  const fetchRe = /fetch\(['"`]([^'"`]+)['"`]/g;
  while ((m = fetchRe.exec(html)) !== null) add(m[1], "GET", "js");

  // axios.get/post/put/delete('...' | "..." | `...`)
  const axiosRe = /axios\.(get|post|put|delete)\(['"`]([^'"`]+)/g;
  while ((m = axiosRe.exec(html)) !== null) {
    add(m[2], m[1].toUpperCase(), "js");
  }

  return Array.from(found.values());
}

/**
 * Build a map of normalized path -> param names by scanning the page for
 * `path?query` patterns and extracting each `?param=` / `&param=` name.
 */
function extractPathParams(html: string): Map<string, string[]> {
  const map = new Map<string, Set<string>>();
  const urlQsRe = /(\/[A-Za-z0-9_\-\/\.]*[A-Za-z0-9_\-])(\?[^"'\s<>`]+)/g;
  let m: RegExpExecArray | null;
  while ((m = urlQsRe.exec(html)) !== null) {
    const path = normalizePath(m[1]);
    const qs = m[2];
    const paramRe = /[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/g;
    let pm: RegExpExecArray | null;
    while ((pm = paramRe.exec(qs)) !== null) {
      if (!map.has(path)) map.set(path, new Set());
      map.get(path)!.add(pm[1]);
    }
  }
  const out = new Map<string, string[]>();
  for (const [k, v] of map) out.set(k, Array.from(v));
  return out;
}

// ---- Main entry point ----------------------------------------------------

export async function runApi(
  urls: string[],
  log: (msg: string) => void
): Promise<ApiResult> {
  const result: ApiResult = {
    endpoints: [],
    graphql: [],
    swagger: [],
    versionedApis: [],
  };

  const hosts = urls.slice(0, MAX_HOSTS).map(normalizeUrl);
  log(`Discovering APIs on ${hosts.length}/${urls.length} host(s) ...`);

  for (let i = 0; i < hosts.length; i++) {
    const url = hosts[i];
    log(`  discovering APIs on ${i + 1}/${urls.length}: ${url}`);

    // ---- 1a. Fetch HTML page ----
    const page = await fetchWithTimeout(url, {}, FETCH_TIMEOUT_MS);
    const html = page?.body || "";

    // ---- 1b/c. Extract endpoints + attach path-shared params ----
    if (html) {
      const endpoints = extractEndpoints(html, url).slice(
        0,
        MAX_ENDPOINTS_PER_HOST
      );
      const pathParams = extractPathParams(html);
      for (const ep of endpoints) {
        const p = pathOf(ep.url);
        const params = (p && pathParams.get(p)) || [];
        result.endpoints.push({
          url: ep.url,
          method: ep.method,
          source: ep.source,
          params,
        });
      }
    }

    // Origin for path probing
    let origin = "";
    try {
      origin = new URL(url).origin;
    } catch {
      origin = url.replace(/\/$/, "");
    }
    if (!origin) continue;

    // ---- 2. Swagger / OpenAPI discovery ----
    for (const path of SWAGGER_PATHS) {
      const target = `${origin}${path}`;
      const res = await fetchWithTimeout(target, {}, PROBE_TIMEOUT_MS);
      if (!res) continue;
      const trimmed = res.body.trimStart();
      const isJson =
        res.contentType.includes("application/json") ||
        trimmed.startsWith("{");
      // YAML detection: require a YAML-looking body prefix OR yaml
      // content-type. Do NOT gate purely on the .yaml extension — SPAs
      // that 200-fallback every path would otherwise false-positive.
      const isYaml =
        res.contentType.includes("yaml") ||
        trimmed.startsWith("openapi:") ||
        trimmed.startsWith("swagger:");

      if (isJson) {
        const parsed = safeJson(res.body);
        if (parsed && (parsed.swagger || parsed.openapi)) {
          const version = String(parsed.openapi || parsed.swagger);
          const title: string = parsed?.info?.title || "";
          const paths: number = parsed?.paths
            ? Object.keys(parsed.paths).length
            : 0;
          result.swagger.push({ url: target, version, title, paths });
          log(`  [+] Swagger: ${target} (${version}, ${paths} paths)`);
        }
      } else if (isYaml) {
        // YAML detection only — no parser (no external deps allowed).
        result.swagger.push({
          url: target,
          version: "yaml",
          title: "",
          paths: 0,
        });
        log(`  [+] Swagger: ${target} (yaml, 0 paths)`);
      }
    }

    // ---- 3. GraphQL discovery ----
    for (const path of GRAPHQL_PATHS) {
      const target = `${origin}${path}`;
      const res = await fetchWithTimeout(target, {}, PROBE_TIMEOUT_MS);
      if (!res) continue;
      // GraphQL endpoints typically return 200 (Playground UI) or 400
      // (GET without query) on initial probe.
      if (res.status !== 200 && res.status !== 400) continue;

      // Test introspection via POST
      const introBody = JSON.stringify({
        query: "{__schema{types{name}queryType{name}mutationType{name}}}",
      });
      const introRes = await fetchWithTimeout(
        target,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: introBody,
        },
        GRAPHQL_TIMEOUT_MS
      );

      let introspection = false;
      let types: string[] = [];
      let queries: string[] = [];

      if (introRes && introRes.status === 200) {
        const parsed = safeJson(introRes.body);
        if (parsed && parsed.data && parsed.data.__schema) {
          introspection = true;
          const schemaTypes = parsed.data.__schema.types || [];
          types = schemaTypes
            .map((t: any) => (t && typeof t.name === "string" ? t.name : null))
            .filter(
              (n: any) => typeof n === "string" && !n.startsWith("__")
            )
            .slice(0, MAX_TYPES);
          if (
            parsed.data.__schema.queryType &&
            parsed.data.__schema.queryType.name
          ) {
            queries = [parsed.data.__schema.queryType.name];
          }
        }
      }

      result.graphql.push({ url: target, introspection, types, queries });
      log(
        `  [+] GraphQL: ${target} (introspection: ${
          introspection ? "ENABLED" : "disabled"
        })`
      );
    }

    // ---- 4. Versioned APIs ----
    for (const path of VERSIONED_PATHS) {
      const target = `${origin}${path}`;
      const res = await fetchWithTimeout(target, {}, PROBE_TIMEOUT_MS);
      if (!res) continue;
      result.versionedApis.push({
        version: path.replace(/^\//, "").replace(/\/$/, ""),
        url: target,
        status: res.status,
      });
      if (res.status === 200) {
        log(`  [+] Versioned API: ${path} -> ${res.status}`);
      }
    }
  }

  log(
    `API discovery complete: ${result.endpoints.length} endpoint(s), ` +
      `${result.graphql.length} GraphQL, ${result.swagger.length} Swagger, ` +
      `${result.versionedApis.length} versioned.`
  );
  return result;
}
