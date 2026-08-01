/**
 * Vulnerability / Misconfiguration Checks Module
 * Passive checks based on HTTP response headers:
 *  - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
 *  - Information disclosure (Server, X-Powered-By version leakage)
 *  - Insecure cookie flags
 *  - Clickjacking exposure
 *  - Default/title-based exposed panels
 */
import type { VulnResult } from "./types";

type Severity = "high" | "medium" | "low" | "info";

interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
}

async function fetchWithHeaders(
  url: string,
  timeoutMs = 8000
): Promise<{ headers: Record<string, string>; body: string; status: number } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
    let body = "";
    try {
      body = await res.text();
    } catch {
      /* ignore */
    }
    return { headers, body, status: res.status };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function checkHeaders(headers: Record<string, string>, url: string, https: boolean): Finding[] {
  const out: Finding[] = [];
  const h = (k: string) => headers[k.toLowerCase()];

  if (!h("strict-transport-security")) {
    out.push({
      id: "missing-hsts",
      severity: https ? "medium" : "low",
      title: "Missing HSTS Header",
      detail: `${url} does not send Strict-Transport-Security. HTTPS sites are vulnerable to SSL stripping / downgrade attacks.`,
    });
  }
  if (!h("content-security-policy")) {
    out.push({
      id: "missing-csp",
      severity: "medium",
      title: "Missing Content-Security-Policy",
      detail: `${url} has no CSP header, increasing exposure to XSS and data injection.`,
    });
  }
  if (!h("x-frame-options") && !h("content-security-policy")?.includes("frame-ancestors")) {
    out.push({
      id: "clickjacking",
      severity: "medium",
      title: "Clickjacking Protection Missing",
      detail: `${url} lacks X-Frame-Options / CSP frame-ancestors and may be framable (clickjacking).`,
    });
  }
  if (!h("x-content-type-options")) {
    out.push({
      id: "missing-xcto",
      severity: "low",
      title: "Missing X-Content-Type-Options",
      detail: `${url} does not send nosniff, allowing MIME-type sniffing attacks.`,
    });
  }
  if (!h("referrer-policy")) {
    out.push({
      id: "missing-referrer-policy",
      severity: "info",
      title: "Missing Referrer-Policy",
      detail: `${url} does not set a Referrer-Policy; full referrer may leak to third parties.`,
    });
  }
  if (!h("permissions-policy")) {
    out.push({
      id: "missing-permissions-policy",
      severity: "info",
      title: "Missing Permissions-Policy",
      detail: `${url} does not restrict browser features via Permissions-Policy.`,
    });
  }
  const server = h("server");
  if (server && /\d/.test(server)) {
    out.push({
      id: "server-version-leak",
      severity: "low",
      title: "Server Version Disclosure",
      detail: `${url} exposes server version: "${server}". Remove version tokens to slow attackers.`,
    });
  }
  const xpb = h("x-powered-by");
  if (xpb) {
    out.push({
      id: "xpoweredby-leak",
      severity: "low",
      title: "X-Powered-By Disclosure",
      detail: `${url} leaks technology via X-Powered-By: "${xpb}". Remove the header.`,
    });
  }
  // Cookie security
  const sc = h("set-cookie");
  if (sc) {
    const cookies = sc.split(/,(?=\s*[a-zA-Z0-9_-]+=)/);
    for (const c of cookies) {
      if (/sess|auth|token|jwt/i.test(c) && !/secure/i.test(c)) {
        out.push({
          id: "insecure-cookie-secure",
          severity: "medium",
          title: "Cookie Missing Secure Flag",
          detail: `${url} sets a session cookie without the Secure attribute: "${c.split("=")[0]}".`,
        });
      }
      if (/sess|auth|token|jwt/i.test(c) && !/httponly/i.test(c)) {
        out.push({
          id: "insecure-cookie-httponly",
          severity: "medium",
          title: "Cookie Missing HttpOnly Flag",
          detail: `${url} sets a session cookie without HttpOnly: "${c.split("=")[0]}".`,
        });
      }
    }
  }
  return out;
}

const PANEL_SIGNATURES: { path: string; match: RegExp; title: string; severity?: "high" | "medium" }[] = [
  { path: "/admin", match: /admin|dashboard|login/i, title: "Admin panel exposed" },
  { path: "/wp-admin/", match: /wordpress|wp-login/i, title: "WordPress admin exposed" },
  { path: "/phpmyadmin/", match: /phpmyadmin/i, title: "phpMyAdmin exposed" },
  { path: "/.git/config", match: /\[core\]|repositoryformatversion/i, title: "Git repository exposed", severity: "high" },
  { path: "/.env", match: /=|SECRET|KEY|PASSWORD/i, title: ".env file exposed", severity: "high" },
  { path: "/server-status", match: /Apache Server Status|Server Status/i, title: "Apache server-status exposed" },
  { path: "/actuator", match: /"_links"|actuator/i, title: "Spring Boot Actuator exposed" },
  { path: "/actuator/env", match: /propertySources|config\b/i, title: "Spring Boot Actuator env endpoint exposed", severity: "high" },
  { path: "/actuator/heapdump", match: "", title: "Spring Boot heapdump endpoint reachable", severity: "high" },
  { path: "/metrics", match: /# (HELP|TYPE)|process_cpu/i, title: "Prometheus metrics exposed" },
  { path: "/.svn/entries", match: /dir\n|\d+\n/i, title: "SVN repository exposed", severity: "high" },
  { path: "/.svn/wc.db", match: "", title: "SVN wc.db exposed", severity: "high" },
  { path: "/.hg/store", match: "", title: "Mercurial repository exposed", severity: "high" },
  { path: "/.DS_Store", match: /Bud1/, title: ".DS_Store file exposed" },
  { path: "/composer.json", match: /"require"/i, title: "composer.json exposed" },
  { path: "/package.json", match: /"dependencies"|"devDependencies"/i, title: "package.json exposed" },
  { path: "/yarn.lock", match: /# THIS IS AN AUTOGENERATED FILE/i, title: "yarn.lock exposed" },
  { path: "/Dockerfile", match: /FROM\s/i, title: "Dockerfile exposed" },
  { path: "/docker-compose.yml", match: /services:|version:/i, title: "docker-compose.yml exposed" },
  { path: "/backup.zip", match: "", title: "backup.zip reachable", severity: "high" },
  { path: "/backup.tar.gz", match: "", title: "backup.tar.gz reachable", severity: "high" },
  { path: "/backup.sql", match: /CREATE TABLE|INSERT INTO/i, title: "SQL backup exposed", severity: "high" },
  { path: "/db.sql", match: /CREATE TABLE|INSERT INTO/i, title: "SQL dump exposed", severity: "high" },
  { path: "/dump.sql", match: /CREATE TABLE|INSERT INTO/i, title: "SQL dump exposed", severity: "high" },
  { path: "/.aws/credentials", match: /\[default\]|aws_access_key_id/i, title: "AWS credentials exposed", severity: "high" },
  { path: "/id_rsa", match: /-----BEGIN.*PRIVATE KEY-----/i, title: "Private SSH key exposed", severity: "high" },
  { path: "/wp-config.php.bak", match: /DB_PASSWORD|DB_USER/i, title: "WordPress config backup exposed", severity: "high" },
  { path: "/web.config.bak", match: /<configuration/i, title: "IIS web.config backup exposed", severity: "high" },
  { path: "/swagger-ui/", match: /swagger/i, title: "Swagger UI exposed" },
  { path: "/api-docs", match: /swagger|openapi/i, title: "API docs endpoint exposed" },
  { path: "/graphql", match: /__schema|graphql/i, title: "GraphQL endpoint exposed" },
  { path: "/phpinfo.php", match: /PHP Version|phpinfo/i, title: "phpinfo() exposed" },
  { path: "/console", match: /Werkzeug|Console/i, title: "Debug console exposed (Werkzeug)", severity: "high" },
  { path: "/debug", match: /debug|pprof/i, title: "Debug endpoint exposed", severity: "high" },
  { path: "/trace", match: /trace|stack/i, title: "Trace endpoint exposed", severity: "medium" },
];

async function checkPanels(baseUrl: string): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const sig of PANEL_SIGNATURES) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
    try {
      const res = await fetch(baseUrl + sig.path, {
        signal: ctrl.signal,
        redirect: "manual",
        headers: { "User-Agent": "easm-scanner/1.0" },
      });
      if (res.status === 200) {
        let matched = true;
        let body = "";
        if (sig.match && sig.match.source) {
          body = await res.text();
          matched = sig.match.test(body);
        }
        if (matched) {
          out.push({
            id: `exposed-${sig.path}`,
            severity: sig.severity || "medium",
            title: sig.title,
            detail: `${baseUrl}${sig.path} is reachable (HTTP 200).`,
          });
        }
      }
    } catch {
      /* ignore */
    } finally {
      clearTimeout(t);
    }
  }
  return out;
}

// Deep CORS check — tests reflection with an arbitrary origin + null origin.
async function checkCorsDeep(baseUrl: string): Promise<Finding[]> {
  const out: Finding[] = [];
  const origins = ["https://evil.attacker.com", "null"];
  for (const origin of origins) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
    try {
      const res = await fetch(baseUrl, {
        signal: ctrl.signal,
        method: "GET",
        redirect: "manual",
        headers: { "User-Agent": "easm-scanner/1.0", Origin: origin },
      });
      const acao = res.headers.get("access-control-allow-origin") || "";
      const acac = res.headers.get("access-control-allow-credentials") || "";
      const reflects = acao === origin;
      const wildcard = acao === "*";
      const credCreds = /true/i.test(acac);
      if (reflects && credCreds) {
        out.push({
          id: `cors-reflect-credentials-${origin}`,
          severity: "high",
          title: "CORS Reflects Origin with Credentials",
          detail: `${baseUrl} reflects arbitrary Origin (${origin}) AND sets Access-Control-Allow-Credentials: true. Any malicious site can read authenticated responses cross-origin — full CORS bypass.`,
        });
        break; // one high finding is enough
      }
      if (reflects && origin === "null") {
        out.push({
          id: "cors-null-origin",
          severity: "medium",
          title: "CORS Reflects Null Origin",
          detail: `${baseUrl} reflects Origin: null. Sandboxed iframes / local files can issue cross-origin requests with credentials.`,
        });
      }
      if (wildcard && credCreds) {
        out.push({
          id: "cors-wildcard-credentials",
          severity: "medium",
          title: "CORS Wildcard with Credentials Header",
          detail: `${baseUrl} returns ACAO: * with ACAC: true (browsers reject this combo, but indicates misconfiguration).`,
        });
      }
    } catch {
      /* ignore */
    } finally {
      clearTimeout(t);
    }
  }
  return out;
}

// HTTP method abuse — probes risky methods (PUT/DELETE/PATCH/MOVE/COPY)
async function checkMethodAbuse(baseUrl: string): Promise<Finding[]> {
  const out: Finding[] = [];
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 6000);
  try {
    const res = await fetch(baseUrl, {
      signal: ctrl.signal,
      method: "OPTIONS",
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    const allow = (res.headers.get("allow") || "").toUpperCase();
    if (allow) {
      const risky = ["PUT", "DELETE", "PATCH", "MOVE", "COPY", "TRACE", "CONNECT"].filter((m) =>
        allow.includes(m)
      );
      if (risky.includes("PUT")) {
        out.push({
          id: "http-put-allowed",
          severity: "medium",
          title: "HTTP PUT Method Allowed",
          detail: `${baseUrl} advertises PUT via OPTIONS. If upload is unauthenticated, an attacker can write arbitrary files.`,
        });
      }
      if (risky.includes("DELETE")) {
        out.push({
          id: "http-delete-allowed",
          severity: "medium",
          title: "HTTP DELETE Method Allowed",
          detail: `${baseUrl} advertises DELETE via OPTIONS. If unauthenticated, an attacker can delete resources.`,
        });
      }
      if (risky.includes("TRACE")) {
        out.push({
          id: "http-trace-allowed",
          severity: "low",
          title: "HTTP TRACE Method Allowed (XST)",
          detail: `${baseUrl} allows TRACE. Cross-Site Tracing can be combined with XSS to steal HttpOnly cookies.`,
        });
      }
    }
  } catch {
    /* ignore */
  } finally {
    clearTimeout(t);
  }
  return out;
}

// .git repo dump test — if /.git/HEAD exists, try to read refs and objects
async function checkGitDump(baseUrl: string): Promise<Finding[]> {
  const out: Finding[] = [];
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 6000);
  try {
    const res = await fetch(`${baseUrl}/.git/HEAD`, {
      signal: ctrl.signal,
      redirect: "manual",
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    if (res.status === 200) {
      const head = (await res.text()).trim();
      if (/^ref:\s+refs\/heads\//.test(head) || /^[0-9a-f]{40}$/.test(head)) {
        out.push({
          id: "git-dump-readable",
          severity: "high",
          title: "Git Repository Fully Readable (.git/HEAD)",
          detail: `${baseUrl}/.git/HEAD returns a valid ref pointer ("${head.slice(0, 60)}"). The entire .git directory is exposed — source code + history can be reconstructed with git-dumper.`,
        });
      }
    }
  } catch {
    /* ignore */
  } finally {
    clearTimeout(t);
  }
  return out;
}

export async function runVulns(
  urls: string[],
  log: (msg: string) => void
): Promise<VulnResult> {
  const hosts: VulnResult["hosts"] = [];
  log(`Running vulnerability checks on ${urls.length} host(s) ...`);

  for (const url of urls) {
    const data = await fetchWithHeaders(url);
    const findings: Finding[] = [];
    if (!data) {
      log(`  [-] ${url} - no response, skipping`);
      continue;
    }
    findings.push(...checkHeaders(data.headers, url, url.startsWith("https://")));

    log(`  [~] ${url} probing common exposed paths ...`);
    findings.push(...(await checkPanels(url)));

    log(`  [~] ${url} deep CORS + method abuse + .git dump checks ...`);
    findings.push(...(await checkCorsDeep(url)));
    findings.push(...(await checkMethodAbuse(url)));
    findings.push(...(await checkGitDump(url)));

    hosts.push({ url, findings });
    const sevCount: Record<string, number> = {};
    for (const f of findings) sevCount[f.severity] = (sevCount[f.severity] || 0) + 1;
    const summary = ["high", "medium", "low", "info"]
      .filter((s) => sevCount[s])
      .map((s) => `${sevCount[s]} ${s}`)
      .join(", ");
    log(`  [+] ${url}: ${findings.length} finding(s)${summary ? " (" + summary + ")" : ""}`);
  }

  log(`Vulnerability checks complete: ${hosts.length} host(s) checked.`);
  return { hosts };
}
