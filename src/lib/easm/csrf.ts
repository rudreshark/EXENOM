/**
 * CSRF (Cross-Site Request Forgery) Testing Module
 *
 * Tests:
 *  1. Form-based CSRF token detection — parses every <form action method>…</form>
 *     block, then looks for hidden inputs whose name contains (case-insensitive)
 *     csrf / token / anticsrf / __RequestVerificationToken / authenticity_token.
 *  2. Vulnerability classification:
 *     - POST form without CSRF token            → MEDIUM ("POST form without CSRF token")
 *     - GET form whose action contains          → LOW    ("state-changing GET form without token")
 *       delete|remove|update|admin and no token
 *     - Form with a CSRF token                  → not vulnerable
 *  3. Cookie SameSite audit — fetches Set-Cookie headers and flags session
 *     cookies that lack SameSite=Strict|Lax (LOW).
 *
 * Uses only the built-in fetch + AbortController (Bun / Node 18+).
 * Per-request timeout: 8s. User-Agent: "easm-scanner/1.0".
 */
import type { CsrfResult } from "./types";

const UA = "easm-scanner/1.0";
const TIMEOUT_MS = 8000;
const MAX_HOSTS = 5;

/** Token field name patterns (case-insensitive substring match on input name). */
const CSRF_TOKEN_PATTERNS = [
  "csrf",
  "token",
  "anticsrf",
  "__requestverificationtoken",
  "authenticity_token",
];

/** Cookie name fragments that indicate a session/authentication cookie. */
const SESSION_COOKIE_HINTS = [
  "session", "sess", "sid", "auth", "token", "user", "login",
  "phpsessid", "jsessionid", "asp.net_sessionid", "aspnetsession",
  "connect.sid", "_session", "csrf", "xsrf",
];

interface RawForm {
  action: string;
  method: string;
  inner: string;
}

interface Resp {
  status: number;
  body: string;
  headers: Record<string, string>;
  setCookies: string[];
}

/**
 * GET the page (redirect:"follow" so we get the rendered HTML after any
 * 3xx hop). Returns null on network error / timeout. Captures body (capped
 * at 500 KB), lowercased header map, and a parsed Set-Cookie array.
 */
async function fetchPage(
  url: string,
  timeoutMs: number = TIMEOUT_MS
): Promise<Resp | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: ctrl.signal,
      headers: { "User-Agent": UA },
    });
    let b = "";
    try {
      b = await res.text();
    } catch {
      /* ignore body read errors */
    }
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));

    // Set-Cookie: prefer Headers.getSetCookie() (Bun / Node 18+); fall back
    // to the merged set-cookie header if the API is unavailable.
    let setCookies: string[] = [];
    const anyHeaders = res.headers as unknown as {
      getSetCookie?: () => string[];
    };
    if (typeof anyHeaders.getSetCookie === "function") {
      try {
        const sc = anyHeaders.getSetCookie();
        if (Array.isArray(sc)) setCookies = sc;
      } catch {
        /* ignore */
      }
    }
    if (setCookies.length === 0 && h["set-cookie"]) {
      // Browsers/old runtimes sometimes join multiple Set-Cookie lines with ", ";
      // split on the cookie-attribute boundary to recover individual cookies.
      setCookies = h["set-cookie"]
        .split(/,\s*(?=[A-Za-z0-9_\-.]+=)/)
        .filter((s) => s.length > 0);
    }

    return { status: res.status, body: b.slice(0, 500000), headers: h, setCookies };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** Extract all <form>…</form> blocks with their action / method / inner HTML. */
function extractForms(html: string): RawForm[] {
  const forms: RawForm[] = [];
  const re = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const attrs = m[1] || "";
    const inner = m[2] || "";
    let action = "";
    let method = "GET";
    const actionMatch = attrs.match(/\baction\s*=\s*["']([^"']*)["']/i);
    if (actionMatch) action = actionMatch[1];
    const methodMatch = attrs.match(/\bmethod\s*=\s*["']([^"']*)["']/i);
    if (methodMatch && methodMatch[1]) method = methodMatch[1];
    forms.push({
      action,
      method: method.toUpperCase() || "GET",
      inner,
    });
  }
  return forms;
}

/** Pull an attribute value out of an HTML tag (any attribute order, " or '). */
function attrValue(tag: string, attr: string): string | null {
  const re = new RegExp(`\\b${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, "i");
  const m = tag.match(re);
  if (!m) return null;
  return m[1] ?? m[2] ?? "";
}

/**
 * Find a hidden input whose name matches one of CSRF_TOKEN_PATTERNS.
 * Returns the original-case name attribute, or undefined if none found.
 */
function findCsrfToken(formInner: string): string | undefined {
  const inputRe = /<input\b[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = inputRe.exec(formInner)) !== null) {
    const tag = m[0];
    const type = (attrValue(tag, "type") || "").toLowerCase();
    if (type !== "hidden") continue;
    const nameAttr = attrValue(tag, "name");
    if (!nameAttr) continue;
    const lower = nameAttr.toLowerCase();
    if (CSRF_TOKEN_PATTERNS.some((p) => lower.includes(p))) {
      return nameAttr;
    }
  }
  return undefined;
}

/** Resolve a possibly-relative action URL against the page URL. */
function resolveAction(base: string, action: string): string {
  if (!action) return base;
  try {
    return new URL(action, base).toString();
  } catch {
    return action;
  }
}

/** Pull the cookie name out of a Set-Cookie header value. */
function cookieName(setCookie: string): string {
  const m = setCookie.match(/^([^=;]+)/);
  return m ? m[1].trim() : "";
}

/** Does this cookie look like a session/auth cookie? */
function looksLikeSessionCookie(name: string, fullHeader: string): boolean {
  const lower = name.toLowerCase();
  if (SESSION_COOKIE_HINTS.some((h) => lower.includes(h))) return true;
  // Fallback: scan the full header for session-ish keywords too.
  return /session|sess|sid|auth|token/i.test(fullHeader);
}

/**
 * Run CSRF tests against the provided list of URLs (cap 5).
 * Returns a CsrfResult with per-host forms + findings.
 */
export async function runCsrf(
  urls: string[],
  log: (msg: string) => void
): Promise<CsrfResult> {
  const hosts: CsrfResult["hosts"] = [];
  log(`Testing CSRF on ${urls.length} host(s) ...`);

  const targets = urls.slice(0, MAX_HOSTS);
  for (let i = 0; i < targets.length; i++) {
    const url = targets[i];
    log(`  testing ${i + 1}/${targets.length}: ${url}`);

    const page = await fetchPage(url);
    if (!page) {
      log(`    [-] ${url} - no response`);
      hosts.push({ url, forms: [], findings: [] });
      continue;
    }

    const rawForms = extractForms(page.body);
    const forms: CsrfResult["hosts"][0]["forms"] = [];
    const findings: CsrfResult["hosts"][0]["findings"] = [];

    for (const f of rawForms) {
      const actionResolved = resolveAction(url, f.action);
      const tokenField = findCsrfToken(f.inner);
      const hasCsrfToken = !!tokenField;
      let vulnerable = false;
      let reason = "GET form, no state-changing action";

      if (hasCsrfToken) {
        vulnerable = false;
        reason = `CSRF token present (${tokenField})`;
      } else if (f.method === "POST") {
        vulnerable = true;
        reason = "POST form without CSRF token";
        findings.push({
          id: "CSRF-POST-NO-TOKEN",
          severity: "medium",
          title: "POST form without CSRF token",
          detail:
            `Form at ${actionResolved} (method=POST) does not include a CSRF ` +
            `token field. A cross-site request can submit state-changing data on ` +
            `behalf of an authenticated user. Add a hidden token field (e.g. ` +
            `csrf_token / __RequestVerificationToken / authenticity_token) and ` +
            `validate it server-side.`,
        });
      } else if (/delete|remove|update|admin/i.test(f.action)) {
        vulnerable = true;
        reason = "state-changing GET form without CSRF token";
        findings.push({
          id: "CSRF-GET-STATE-CHANGE",
          severity: "low",
          title: "State-changing GET form without CSRF token",
          detail:
            `Form at ${actionResolved} (method=GET, action contains ` +
            `delete/remove/update/admin) has no CSRF token. Even GET forms can ` +
            `be abused via link/img-tag CSRF; prefer POST + a CSRF token for ` +
            `state-changing operations.`,
        });
      }

      forms.push({
        action: actionResolved,
        method: f.method,
        hasCsrfToken,
        tokenField,
        vulnerable,
        reason,
      });
    }

    // ---- Cookie SameSite audit ----
    // Flag the first session cookie lacking SameSite=Strict|Lax.
    for (const sc of page.setCookies) {
      const name = cookieName(sc);
      if (!looksLikeSessionCookie(name, sc)) continue;
      const hasLaxOrStrict = /samesite\s*=\s*(strict|lax)/i.test(sc);
      if (!hasLaxOrStrict) {
        const hasSameSiteNone = /samesite\s*=\s*none/i.test(sc);
        findings.push({
          id: "CSRF-COOKIE-NOSAMESITE",
          severity: "low",
          title: "Cookie missing SameSite attribute",
          detail:
            `Cookie "${name || "<unknown>"}" was set without SameSite=Strict or ` +
            `SameSite=Lax${hasSameSiteNone ? " (SameSite=None)" : ""}. Browsers ` +
            `may transmit this cookie on cross-site requests, enabling CSRF. ` +
            `Set-Cookie: ${sc.slice(0, 160)}.`,
        });
        break; // one SameSite finding per host is enough
      }
    }

    hosts.push({ url, forms, findings });
    const vulnCount = forms.filter((f) => f.vulnerable).length;
    log(`  [+] ${url}: ${forms.length} form(s), ${vulnCount} vulnerable`);
  }

  const totalForms = hosts.reduce((a, h) => a + h.forms.length, 0);
  const totalVuln = hosts.reduce(
    (a, h) => a + h.forms.filter((f) => f.vulnerable).length,
    0
  );
  const totalFindings = hosts.reduce((a, h) => a + h.findings.length, 0);
  log(
    `CSRF testing complete: ${totalForms} form(s), ${totalVuln} vulnerable, ` +
    `${totalFindings} finding(s) across ${hosts.length} host(s).`
  );
  return { hosts };
}
