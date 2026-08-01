/**
 * Cache Poisoning & Web Cache Deception Detection Module
 *
 * Three-stage non-destructive probe:
 *
 *  1. Unkeyed-header detection — sends requests with headers that some caches
 *     do NOT include in the cache key (X-Forwarded-Host, X-Forwarded-Scheme,
 *     X-Forwarded-Proto, X-Original-URL, X-Rewrite-URL, X-Forwarded-Port).
 *     If the response body reflects the injected value OR differs from the
 *     baseline (status / body length), the header is "unkeyed" — an attacker
 *     can manipulate the cached response by varying just that header.
 *
 *  2. Cache poisoning confirmation — for every reflected unkeyed header, we
 *     immediately re-request the URL WITHOUT the header. If the cache now
 *     serves the previously-poisoned response (marker still present), the
 *     cache is confirmed poisoned (HIGH).
 *
 *  3. Web cache deception — appends cacheable-asset suffixes (style.css,
 *     nonexistent.js) and an encoded path-traversal token (..%2f) to the URL.
 *     If the cache returns the same HTML page as the baseline for these
 *     asset-looking paths, an attacker can trick an authenticated victim into
 *     visiting the asset URL; the cache stores the victim's private page under
 *     a cacheable-asset key, and the attacker later retrieves it (HIGH).
 *
 * Built-in fetch only. 8s timeout, 5 hosts max, UA "easm-scanner/1.0".
 */
import type { CacheResult } from "./types";

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------

const UA = "easm-scanner/1.0";
const TIMEOUT_MS = 8_000; // 8s per spec
const MAX_HOSTS = 5;
const POISON_SETTLE_MS = 500; // let the cache store the poisoned entry before re-fetch

interface Resp {
  status: number;
  body: string;
  headers: Record<string, string>;
}

// ----------------------------------------------------------------------------
// fetch helper
// ----------------------------------------------------------------------------

async function fetchWith(
  url: string,
  extraHeaders: Record<string, string> = {},
  timeoutMs: number = TIMEOUT_MS
): Promise<Resp | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: ctrl.signal,
      headers: { "User-Agent": UA, ...extraHeaders },
    });
    let b = "";
    try {
      b = await res.text();
    } catch {
      /* ignore body read errors */
    }
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));
    return { status: res.status, body: b.slice(0, 200_000), headers: h };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// ----------------------------------------------------------------------------
// Unkeyed-header test matrix
// ----------------------------------------------------------------------------

interface UnkeyedSpec {
  header: string;
  value: string;
  /** Substring to grep for in the response body as evidence of reflection. */
  marker: string;
}

const UNKEYED_HEADERS: UnkeyedSpec[] = [
  {
    header: "X-Forwarded-Host",
    value: "evil.attacker.com",
    marker: "evil.attacker.com",
  },
  {
    header: "X-Forwarded-Scheme",
    value: "http",
    marker: "http://",
  },
  {
    header: "X-Forwarded-Proto",
    value: "http",
    marker: "http://",
  },
  { header: "X-Original-URL", value: "/admin", marker: "/admin" },
  { header: "X-Rewrite-URL", value: "/admin", marker: "/admin" },
  { header: "X-Forwarded-Port", value: "80", marker: ":80" },
];

// ----------------------------------------------------------------------------
// HTML / page-similarity helpers
// ----------------------------------------------------------------------------

function extractTitle(body: string): string {
  const m = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, " ").trim().slice(0, 120) : "";
}

function looksLikeHtml(
  body: string,
  headers: Record<string, string>
): boolean {
  const ct = (headers["content-type"] || "").toLowerCase();
  if (ct.includes("text/html")) return true;
  if (
    ct.includes("text/css") ||
    ct.includes("javascript") ||
    ct.includes("image/") ||
    ct.includes("application/json")
  ) {
    return false;
  }
  // No usable Content-Type — sniff the body.
  const trimmed = body.trimStart().slice(0, 200).toLowerCase();
  return (
    trimmed.startsWith("<!doctype") ||
    trimmed.startsWith("<html") ||
    trimmed.startsWith("<head") ||
    trimmed.startsWith("<body")
  );
}

/** Heuristic: are two response bodies the "same page"? */
function isSamePage(a: string, b: string): boolean {
  const ta = extractTitle(a);
  const tb = extractTitle(b);
  if (ta && tb && ta === tb) return true;
  if (a.length > 200 && b.length > 200) {
    const ratio = Math.min(a.length, b.length) / Math.max(a.length, b.length);
    return ratio > 0.7;
  }
  return false;
}

/**
 * Append `suffix` to the URL's path WITHOUT letting `new URL()` normalise it.
 * This is critical for the `..%2f` test — `new URL("https://x/account/..%2f")`
 * would decode the traversal and yield `/`, defeating the WCD probe.
 */
function appendPath(url: string, suffix: string): string {
  try {
    const u = new URL(url);
    const base = u.pathname.endsWith("/") ? u.pathname : u.pathname + "/";
    return `${u.origin}${base}${suffix}`;
  } catch {
    return url.endsWith("/") ? `${url}${suffix}` : `${url}/${suffix}`;
  }
}

// ----------------------------------------------------------------------------
// Main entry point
// ----------------------------------------------------------------------------

export async function runCache(
  urls: string[],
  log: (msg: string) => void
): Promise<CacheResult> {
  const hosts: CacheResult["hosts"] = [];
  const targets = urls.slice(0, MAX_HOSTS);
  log(`Testing cache poisoning / deception on ${targets.length} host(s) ...`);

  for (let i = 0; i < targets.length; i++) {
    const url = targets[i];
    log(`  testing ${url} (${i + 1}/${targets.length}) ...`);

    const unkeyedHeaders: CacheResult["hosts"][0]["unkeyedHeaders"] = [];
    const cachePoisoning: CacheResult["hosts"][0]["cachePoisoning"] = [];
    const webCacheDeception: CacheResult["hosts"][0]["webCacheDeception"] = [];
    const findings: CacheResult["hosts"][0]["findings"] = [];

    // ---- Baseline ----
    const baseline = await fetchWith(url);
    if (!baseline) {
      log(`    [-] ${url} - no baseline response; skipping`);
      hosts.push({
        url,
        unkeyedHeaders,
        cachePoisoning,
        webCacheDeception,
        findings,
      });
      continue;
    }
    log(
      `    [+] baseline: status ${baseline.status}, ${baseline.body.length} bytes`
    );

    // ---- 1. Unkeyed header detection ----
    for (const { header, value, marker } of UNKEYED_HEADERS) {
      log(`  testing ${url} for unkeyed header ${header} ...`);
      const r = await fetchWith(url, { [header]: value });
      if (!r) {
        unkeyedHeaders.push({
          header,
          reflected: false,
          evidence: "no response",
        });
        cachePoisoning.push({
          url,
          header,
          value,
          poisoned: false,
          evidence: "header not reflected; no poisoning test performed",
        });
        continue;
      }

      const markerLower = marker.toLowerCase();
      const markerInBaseline = baseline.body.toLowerCase().includes(markerLower);
      const markerInTest = r.body.toLowerCase().includes(markerLower);
      const markerReflected = markerInTest && !markerInBaseline;
      const statusDiff = r.status !== baseline.status;
      const lengthDiff =
        baseline.body.length > 0 &&
        Math.abs(r.body.length - baseline.body.length) >
          Math.max(200, 0.3 * baseline.body.length);
      const reflected = markerReflected || statusDiff || lengthDiff;

      const evidenceParts: string[] = [];
      if (markerReflected)
        evidenceParts.push(`reflected marker "${marker}" in body`);
      if (statusDiff)
        evidenceParts.push(`status ${baseline.status} -> ${r.status}`);
      if (lengthDiff)
        evidenceParts.push(
          `body length ${baseline.body.length} -> ${r.body.length}`
        );

      unkeyedHeaders.push({
        header,
        reflected,
        evidence: reflected
          ? evidenceParts.join("; ")
          : `no reflection (status ${r.status}, ${r.body.length} bytes)`,
      });

      if (!reflected) {
        cachePoisoning.push({
          url,
          header,
          value,
          poisoned: false,
          evidence: "header not reflected; no poisoning test performed",
        });
        continue;
      }

      log(
        `    [!] ${header}: reflected / unkeyed (${evidenceParts.join("; ")})`
      );
      findings.push({
        id: `CACHE-UNKEYED-${header.replace(/[^A-Z]/gi, "")}`,
        severity: "medium",
        title: `Unkeyed header reflection: ${header}`,
        detail:
          `The response to a request with "${header}: ${value}" differed from baseline (${evidenceParts.join(
            "; "
          )}). This indicates the cache may not include "${header}" in its cache key, ` +
          `enabling cache poisoning — an attacker can manipulate the cached response by varying just this header.`,
      });

      // ---- 2. Cache poisoning confirmation ----
      log(`  testing ${url} for cache poisoning via ${header} ...`);
      // Give the cache a moment to store the poisoned entry.
      await new Promise((res) => setTimeout(res, POISON_SETTLE_MS));
      const r2 = await fetchWith(url); // NO extra header — same cache key
      if (!r2) {
        cachePoisoning.push({
          url,
          header,
          value,
          poisoned: false,
          evidence: "second (verification) request failed",
        });
        continue;
      }

      const stillPoisoned =
        r2.body.toLowerCase().includes(markerLower) && !markerInBaseline;
      cachePoisoning.push({
        url,
        header,
        value,
        poisoned: stillPoisoned,
        evidence: stillPoisoned
          ? `Second request WITHOUT ${header} still returned marker "${marker}" — cache served the poisoned response. (verification status ${r2.status}, ${r2.body.length} bytes)`
          : `Second request WITHOUT ${header} did not contain the marker (status ${r2.status}, ${r2.body.length} bytes) — cache not poisoned.`,
      });
      if (stillPoisoned) {
        log(`    [!] HIGH cache poisoning confirmed via ${header}`);
        findings.push({
          id: `CACHE-POISON-${header.replace(/[^A-Z]/gi, "")}`,
          severity: "high",
          title: `Cache poisoning confirmed via ${header}`,
          detail:
            `A request with "${header}: ${value}" was cached and is now served to subsequent requests that do NOT include the header. ` +
            `An attacker can poison the cache for all users by sending a single request with this unkeyed header set to an attacker-controlled value.`,
        });
      }
    }

    // ---- 3. Web cache deception ----
    const wcdSuffixes = ["style.css", "nonexistent.js", "..%2f"];
    for (const suffix of wcdSuffixes) {
      const testUrl = appendPath(url, suffix);
      log(`  testing ${url} for WCD via /${suffix} ...`);
      const r = await fetchWith(testUrl);
      if (!r) {
        webCacheDeception.push({
          url,
          path: suffix,
          cached: false,
          evidence: "no response",
        });
        continue;
      }

      const isHtml = looksLikeHtml(r.body, r.headers);
      const samePage = isHtml && isSamePage(r.body, baseline.body);
      const cached = r.status === 200 && isHtml && samePage;

      webCacheDeception.push({
        url,
        path: suffix,
        cached,
        evidence: cached
          ? `Response for /${suffix} is HTML same as baseline (status ${r.status}, ${r.body.length} bytes, content-type "${r.headers["content-type"] || "?"}"). The cache is storing the private HTML page under an asset-extension cache key.`
          : `Response for /${suffix}: status ${r.status}, ${r.body.length} bytes, html=${isHtml}, sameAsBaseline=${samePage}, content-type "${r.headers["content-type"] || "?"}".`,
      });

      if (cached) {
        log(`    [!] HIGH WCD via /${suffix}: ${testUrl}`);
        findings.push({
          id: `CACHE-WCD-${suffix.replace(/[^a-z0-9]/gi, "")}`,
          severity: "high",
          title: `Web cache deception via /${suffix}`,
          detail:
            `Requesting ${testUrl} returned the same HTML page as the baseline URL. ` +
            `If an authenticated victim is tricked into visiting this URL, the cache will store their private page content under a cacheable-asset cache key, ` +
            `allowing the attacker to later retrieve the victim's private data by requesting the same URL.`,
        });
      }
    }

    hosts.push({
      url,
      unkeyedHeaders,
      cachePoisoning,
      webCacheDeception,
      findings,
    });
    const reflectedCount = unkeyedHeaders.filter((h) => h.reflected).length;
    const poisonedCount = cachePoisoning.filter((p) => p.poisoned).length;
    const wcdCount = webCacheDeception.filter((w) => w.cached).length;
    log(
      `  [+] ${url}: ${reflectedCount} unkeyed, ${poisonedCount} poisoned, ${wcdCount} WCD, ${findings.length} finding(s)`
    );
  }

  const totalFindings = hosts.reduce((a, h) => a + h.findings.length, 0);
  log(
    `Cache scan complete: ${totalFindings} finding(s) across ${hosts.length} host(s).`
  );

  return { hosts };
}
