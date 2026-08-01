/**
 * Host Header Injection / SSRF / CRLF Injection Testing Module
 *
 * Tests:
 *  1. Host header injection — reflection of injected Host / X-Forwarded-Host.
 *  2. Internal-area bypass via Host: localhost, X-Forwarded-For: 127.0.0.1.
 *  3. Routing bypass via X-Original-URL / X-Rewrite-URL headers.
 *  4. SSRF sink parameter identification in URL query strings + form actions.
 *  5. CRLF injection — header splitting + HTTP response splitting → XSS.
 *
 * Uses only the built-in fetch (Bun / Node 18+). Per-request timeout 8s.
 * User-Agent: "easm-scanner/1.0".
 */
import type { HostHeaderResult } from "./types";

const UA = "easm-scanner/1.0";
const TIMEOUT_MS = 8000;
const MAX_HOSTS = 5;

/** Parameter names that frequently accept URLs and are SSRF sink candidates. */
const SSRF_PARAMS = [
  "url", "redirect", "redirect_url", "return", "returnUrl", "next",
  "target", "dest", "destination", "go", "image", "img", "fetch",
  "proxy", "src", "source", "uri", "callback", "webhook", "file",
  "path", "load", "page", "site", "host", "port", "api", "feed",
  "xml", "open",
];

interface Resp {
  status: number;
  body: string;
  headers: Record<string, string>;
}

interface Finding {
  id: string;
  severity: "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  evidence: string;
}

/**
 * Perform a GET request with an optional set of extra headers.
 * Returns null on network error or timeout. Uses redirect:"manual"
 * so we can inspect 3xx responses and arbitrary injected headers.
 */
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
    return { status: res.status, body: b.slice(0, 200000), headers: h };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** Extract the contents of the first <title> tag (trimmed, max 120 chars). */
function extractTitle(body: string): string {
  const m = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!m) return "";
  return m[1].replace(/\s+/g, " ").trim().slice(0, 120);
}

/** Truncate to N chars, appending an ellipsis if truncation occurred. */
function truncate(s: string, n = 100): string {
  return s.length > n ? s.slice(0, n) + "..." : s;
}

/** Parse all query params from a URL string. Returns empty array on failure. */
function parseQueryParams(url: string): { name: string; value: string }[] {
  try {
    const u = new URL(url);
    return Array.from(u.searchParams.entries()).map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

/** Extract all `action="..."` values from <form> tags in the HTML. */
function extractFormActions(body: string): string[] {
  const actions: string[] = [];
  const re = /<form[^>]*\baction\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    actions.push(m[1]);
  }
  return actions;
}

/** Resolve a possibly-relative URL against a base URL. */
function resolveUrl(base: string, href: string): string | null {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

/**
 * Find SSRF sink parameters in the current URL's query string and in any
 * form actions present in the HTML. Returns a deduplicated list of
 * { param, url } entries describing where each sink was observed.
 */
function findSsrfTestPoints(
  url: string,
  body: string
): { param: string; url: string }[] {
  const found = new Map<string, { param: string; url: string }>();
  const ssrfSet = new Set(SSRF_PARAMS.map((p) => p.toLowerCase()));

  // 1. Current URL query params.
  for (const { name } of parseQueryParams(url)) {
    if (ssrfSet.has(name.toLowerCase())) {
      const key = `${name.toLowerCase()}@${url}`;
      if (!found.has(key)) found.set(key, { param: name, url });
    }
  }

  // 2. Params declared in form actions in the HTML.
  for (const action of extractFormActions(body)) {
    const resolved = resolveUrl(url, action);
    if (!resolved) continue;
    for (const { name } of parseQueryParams(resolved)) {
      if (ssrfSet.has(name.toLowerCase())) {
        const key = `${name.toLowerCase()}@${resolved}`;
        if (!found.has(key)) found.set(key, { param: name, url: resolved });
      }
    }
  }

  return Array.from(found.values());
}

/** Heuristic: does the body / title indicate admin/debug/internal content? */
function looksLikeAdmin(body: string): boolean {
  return /\b(admin|debug|internal|console|dashboard|phpinfo|server-info|wp-admin)\b/i.test(body);
}

/**
 * Run host header injection, SSRF sink discovery, and CRLF injection tests
 * against the provided list of URLs.
 */
export async function runHostHeader(
  urls: string[],
  log: (msg: string) => void
): Promise<HostHeaderResult> {
  const hosts: HostHeaderResult["hosts"] = [];
  const ssrfTestPoints: HostHeaderResult["ssrfTestPoints"] = [];
  const crlfTests: HostHeaderResult["crlfTests"] = [];

  log(`Testing host header / SSRF / CRLF on ${urls.length} host(s) ...`);

  const targets = urls.slice(0, MAX_HOSTS);
  for (let i = 0; i < targets.length; i++) {
    const url = targets[i];
    log(`  testing ${i + 1}/${urls.length}: ${url}`);

    // ---- 0. Baseline response ----
    const baseline = await fetchWith(url);
    if (!baseline) {
      log(`    [-] ${url} - no response`);
      continue;
    }
    const baseTitle = extractTitle(baseline.body);
    const findings: Finding[] = [];

    // ---- 1. Host header injection ----

    // a) Host: evil.attacker.com — reflection check (HIGH)
    {
      const r = await fetchWith(url, { Host: "evil.attacker.com" });
      if (r && r.body.toLowerCase().includes("evil.attacker.com")) {
        const idx = r.body.toLowerCase().indexOf("evil.attacker.com");
        const ev = r.body.slice(Math.max(0, idx - 20), idx + 40);
        findings.push({
          id: "HHI-HOST-REFLECT",
          severity: "high",
          title: "Host header injection — Host header reflected in response",
          detail:
            'The server reflected the injected "Host: evil.attacker.com" header into the response body. This can enable cache poisoning, password-reset poisoning, and routing bypasses.',
          evidence: truncate(ev),
        });
        log(`    [!] HIGH Host header reflected: ${url}`);
      }
    }

    // b) Host: localhost — admin / internal exposure (MEDIUM)
    {
      const r = await fetchWith(url, { Host: "localhost" });
      if (r) {
        const t = extractTitle(r.body);
        const statusChanged = r.status !== baseline.status;
        const titleChanged = !!t && t !== baseTitle;
        const adminish = looksLikeAdmin(r.body);
        if (statusChanged || titleChanged || adminish) {
          const parts: string[] = [];
          if (statusChanged) parts.push(`status ${baseline.status} -> ${r.status}`);
          if (titleChanged) parts.push(`title "${baseTitle}" -> "${t}"`);
          if (adminish) parts.push("body contains admin/debug/internal keyword");
          findings.push({
            id: "HHI-HOST-LOCALHOST",
            severity: "medium",
            title: 'Host header injection — "Host: localhost" alters response',
            detail:
              'Sending "Host: localhost" caused the server to behave differently (admin panel, debug endpoint, or internal content). This may expose privileged functionality.',
            evidence: truncate(parts.join("; ")),
          });
          log(`    [!] MED Host:localhost bypass: ${url} — ${parts.join("; ")}`);
        }
      }
    }

    // c) X-Forwarded-Host: evil.attacker.com — reflection check (HIGH)
    {
      const r = await fetchWith(url, { "X-Forwarded-Host": "evil.attacker.com" });
      if (r && r.body.toLowerCase().includes("evil.attacker.com")) {
        const idx = r.body.toLowerCase().indexOf("evil.attacker.com");
        const ev = r.body.slice(Math.max(0, idx - 20), idx + 40);
        findings.push({
          id: "HHI-XFH-REFLECT",
          severity: "high",
          title: "Host header injection — X-Forwarded-Host reflected",
          detail:
            'The server reflected the injected "X-Forwarded-Host: evil.attacker.com" header. Some applications trust XFH over Host for link generation and password-reset links.',
          evidence: truncate(ev),
        });
        log(`    [!] HIGH X-Forwarded-Host reflected: ${url}`);
      }
    }

    // d) X-Forwarded-For: 127.0.0.1 — internal access bypass (MEDIUM)
    {
      const r = await fetchWith(url, { "X-Forwarded-For": "127.0.0.1" });
      if (r) {
        const t = extractTitle(r.body);
        const statusChanged = r.status !== baseline.status;
        const titleChanged = !!t && t !== baseTitle;
        const adminish = looksLikeAdmin(r.body);
        const accessGranted =
          statusChanged && r.status >= 200 && r.status < 300 &&
          (baseline.status < 200 || baseline.status >= 300);
        if (accessGranted || adminish || (titleChanged && /admin|debug|internal/i.test(t))) {
          const parts: string[] = [];
          if (statusChanged) parts.push(`status ${baseline.status} -> ${r.status}`);
          if (titleChanged) parts.push(`title -> "${t}"`);
          if (adminish) parts.push("admin/debug/internal keyword detected");
          findings.push({
            id: "HHI-XFF-SPOOF",
            severity: "medium",
            title: "X-Forwarded-For spoofing — possible internal access",
            detail:
              'Sending "X-Forwarded-For: 127.0.0.1" altered the response, suggesting the server trusts XFF for access control. Internal endpoints, debug panels, or admin routes may be reachable.',
            evidence: truncate(parts.join("; ")),
          });
          log(`    [!] MED X-Forwarded-For spoofing: ${url} — ${parts.join("; ")}`);
        }
      }
    }

    // e) X-Original-URL / X-Rewrite-URL: /admin — routing bypass (HIGH)
    for (const hdr of ["X-Original-URL", "X-Rewrite-URL"]) {
      const r = await fetchWith(url, { [hdr]: "/admin" });
      if (!r) continue;
      const t = extractTitle(r.body);
      const adminish = looksLikeAdmin(r.body) || /admin/i.test(t);
      const statusChanged = r.status !== baseline.status;
      const reachable = statusChanged && r.status >= 200 && r.status < 300;
      if (adminish || reachable) {
        const ev = adminish
          ? `body shows admin content; status=${r.status}`
          : `status ${baseline.status} -> ${r.status}`;
        findings.push({
          id: `HHI-${hdr.toUpperCase().replace(/-/g, "")}-BYPASS`,
          severity: "high",
          title: `${hdr} routing bypass — /admin reachable`,
          detail:
            `The server honoured the "${hdr}: /admin" header and routed the request to an admin path, bypassing front-end routing rules. This is a known IIS / ASP.NET / reverse-proxy bypass.`,
          evidence: truncate(ev),
        });
        log(`    [!] HIGH ${hdr} routing bypass: ${url} -> /admin`);
      }
    }

    // ---- 2. SSRF test point discovery ----
    const points = findSsrfTestPoints(url, baseline.body);
    for (const p of points) {
      ssrfTestPoints.push({
        param: p.param,
        url: p.url,
        note: "Potential SSRF sink — test with http://127.0.0.1, http://localhost, file:///etc/passwd, gopher://...",
      });
      log(`  [+] SSRF test point: param '${p.param}' in ${p.url}`);
    }

    // ---- 3. CRLF injection ----
    const sep = url.includes("?") ? "&" : "?";
    let crlfInjected = false;
    const crlfEvidenceParts: string[] = [];

    // Test A: header injection via %0d%0a in query value
    const crlfHeaderUrl = `${url}${sep}test=easm%0d%0aInjected-Header:%20yes`;
    {
      const r = await fetchWith(crlfHeaderUrl);
      if (r && r.headers["injected-header"]) {
        crlfInjected = true;
        crlfEvidenceParts.push(`Injected-Header: ${r.headers["injected-header"]}`);
      }
    }

    // Test B: body injection via %0d%0a%0d%0a<script> (HTTP response splitting → XSS)
    const crlfBodyUrl = `${url}${sep}test=easm%0d%0a%0d%0a<script>alert(1)</script>`;
    {
      const r = await fetchWith(crlfBodyUrl);
      if (r) {
        const lower = r.body.toLowerCase();
        const idx = lower.indexOf("easm");
        const after = idx >= 0 ? r.body.slice(idx) : "";
        if (after.toLowerCase().includes("<script>alert(1)</script>")) {
          crlfInjected = true;
          crlfEvidenceParts.push("body reflects <script>alert(1)</script> after param");
        }
      }
    }

    crlfTests.push({
      url,
      injected: crlfInjected,
      evidence: crlfInjected
        ? truncate(crlfEvidenceParts.join("; "))
        : "no CRLF injection detected",
    });
    if (crlfInjected) {
      log(`  [+] CRLF injection confirmed: ${url}`);
    }

    hosts.push({ url, findings });
    log(`  [+] ${url}: ${findings.length} finding(s)`);
  }

  const totalFindings = hosts.reduce((a, h) => a + h.findings.length, 0);
  const crlfPositives = crlfTests.filter((c) => c.injected).length;
  log(
    `Host header / SSRF / CRLF complete: ${totalFindings} finding(s), ` +
    `${ssrfTestPoints.length} SSRF point(s), ` +
    `${crlfPositives} CRLF confirmed across ${hosts.length} host(s).`
  );

  return { hosts, ssrfTestPoints, crlfTests };
}
