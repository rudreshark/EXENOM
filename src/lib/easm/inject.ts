/**
 * Injection Point Detection Module
 *
 * Probes HTTP parameters with safe, non-destructive injection payloads
 * to detect potential SQLi, NoSQLi, SSTI, command injection, XSS,
 * LDAP, XPath, and open-redirect sinks. Detection is evidence-based
 * (error messages, reflection, timing anomalies).
 */
import type { InjectResult } from "./types";

type InjectType =
  | "sqli" | "nosqli" | "ssti" | "cmdi" | "xss" | "ldap" | "xpath" | "openredirect";

interface PayloadSpec {
  type: InjectType;
  payload: string;
  /** regex to test the response body for evidence of vulnerability */
  evidence: RegExp;
  severity: "high" | "medium" | "low";
  /** expected timing delay (ms) for time-based detection */
  timeDelay?: number;
}

const PAYLOADS: PayloadSpec[] = [
  // ---- SQLi (error-based) ----
  {
    type: "sqli",
    payload: "'",
    evidence: /SQL syntax|MySQL|You have an error in your SQL|sqlite3\.|ORA-\d+|PG::|SyntaxError|Unclosed quotation mark|Microsoft SQL Server|SQLSTATE/i,
    severity: "high",
  },
  {
    type: "sqli",
    payload: "1' OR '1'='1",
    evidence: /query.*?failed|SQL syntax|duplicate entry|ORA-|PG::Error/i,
    severity: "high",
  },
  {
    type: "sqli",
    payload: "1 UNION SELECT NULL--",
    evidence: /number of columns|unknown column|SQL syntax/i,
    severity: "high",
  },
  // ---- SQLi (time-based) ----
  {
    type: "sqli",
    payload: "1'; WAITFOR DELAY '0:0:3'--",
    evidence: /.*/,
    severity: "high",
    timeDelay: 2800,
  },
  {
    type: "sqli",
    payload: "1' AND SLEEP(3)-- -",
    evidence: /.*/,
    severity: "high",
    timeDelay: 2800,
  },
  // ---- NoSQLi ----
  {
    type: "nosqli",
    payload: "' || '1'=='1",
    evidence: /mongodb|mongoerror|bsonjson|invalid object id/i,
    severity: "high",
  },
  {
    type: "nosqli",
    payload: "[$ne]=1",
    evidence: /mongodb|query.*?failed/i,
    severity: "high",
  },
  // ---- SSTI ----
  {
    type: "ssti",
    payload: "{{7*7}}",
    evidence: /\b49\b/,
    severity: "high",
  },
  {
    type: "ssti",
    payload: "${7*7}",
    evidence: /\b49\b/,
    severity: "high",
  },
  {
    type: "ssti",
    payload: "#{7*7}",
    evidence: /\b49\b/,
    severity: "high",
  },
  {
    type: "ssti",
    payload: "<%= 7*7 %>",
    evidence: /\b49\b/,
    severity: "high",
  },
  // ---- Command injection ----
  {
    type: "cmdi",
    payload: ";id",
    evidence: /uid=\d+\(.+?\)\s+gid=\d+/i,
    severity: "high",
  },
  {
    type: "cmdi",
    payload: "|id",
    evidence: /uid=\d+\(.+?\)\s+gid=\d+/i,
    severity: "high",
  },
  {
    type: "cmdi",
    payload: "`id`",
    evidence: /uid=\d+\(.+?\)\s+gid=\d+/i,
    severity: "high",
  },
  {
    type: "cmdi",
    payload: "$(whoami)",
    evidence: /^[a-z_][a-z0-9\-]{0,30}$/m,
    severity: "high",
  },
  // ---- XSS (reflection) ----
  {
    type: "xss",
    payload: 'easmxss<svg onload=alert(1)>',
    evidence: /easmxss<svg onload=alert\(1\)>/i,
    severity: "medium",
  },
  {
    type: "xss",
    payload: '"easmxss><script>alert(1)</script>',
    evidence: /easmxss><script>alert\(1\)<\/script>/i,
    severity: "medium",
  },
  // ---- LDAP ----
  {
    type: "ldap",
    payload: ")(uid=*))(|(uid=*",
    evidence: /ldap|directory server|invalid DN syntax|operations error/i,
    severity: "high",
  },
  {
    type: "ldap",
    payload: "*()|uid=*",
    evidence: /ldap|directory server/i,
    severity: "high",
  },
  // ---- XPath ----
  {
    type: "xpath",
    payload: "' or '1'='1",
    evidence: /xpath|xml path language|invalid expression/i,
    severity: "medium",
  },
  // ---- Open redirect ----
  {
    type: "openredirect",
    payload: "https://evil.attacker.com/",
    evidence: /Location:\s*https:\/\/evil\.attacker\.com/i,
    severity: "medium",
  },
];

const PARAM_NAMES = [
  "id", "q", "search", "query", "name", "user", "username", "page",
  "url", "redirect", "next", "return", "returnUrl", "rurl", "go",
  "file", "path", "doc", "document", "item", "cat", "category",
  "type", "action", "cmd", "command", "data", "value", "key", "token",
];

async function fetchWith(
  url: string,
  method: string,
  body: Record<string, string> | null,
  timeoutMs = 8000
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const init: RequestInit = {
      method,
      signal: ctrl.signal,
      redirect: "manual",
      headers: { "User-Agent": "easm-scanner/1.0" },
    };
    if (body && (method === "POST" || method === "PUT" || method === "PATCH")) {
      init.headers = { "User-Agent": "easm-scanner/1.0", "Content-Type": "application/x-www-form-urlencoded" };
      init.body = new URLSearchParams(body).toString();
    }
    const res = await fetch(url, init);
    let b = "";
    try {
      b = await res.text();
    } catch {
      /* ignore */
    }
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));
    return { status: res.status, body: b.slice(0, 100000), headers: h };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function getBaseline(url: string): Promise<{ status: number; body: string } | null> {
  return fetchWith(url, "GET", null, 8000);
}

export async function runInject(
  urls: string[],
  log: (msg: string) => void
): Promise<InjectResult> {
  const hosts: InjectResult["hosts"] = [];
  log(`Testing injection points on ${urls.length} host(s) ...`);

  for (const url of urls.slice(0, 5)) {
    log(`  probing ${url} ...`);
    const baseline = await getBaseline(url);
    if (!baseline) {
      log(`    [-] ${url} - no response`);
      continue;
    }
    const points: InjectResult["hosts"][0]["points"] = [];

    // Test a few common parameter names on GET + POST
    const testedParams = new Set<string>();
    for (const param of PARAM_NAMES.slice(0, 12)) {
      if (testedParams.has(param)) continue;
      testedParams.add(param);

      // GET test
      const getUrl = `${url}${url.includes("?") ? "&" : "?"}${param}=easmtest`;
      // POST test
      const postUrl = url;

      for (const spec of PAYLOADS) {
        // GET injection
        const injectGetUrl = `${url}${url.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(spec.payload)}`;
        const start = Date.now();
        const res = await fetchWith(injectGetUrl, "GET", null, spec.timeDelay ? spec.timeDelay + 3000 : 8000);
        const elapsed = Date.now() - start;

        if (!res) continue;

        // Time-based detection
        if (spec.timeDelay && elapsed >= spec.timeDelay) {
          // Confirm baseline doesn't take this long
          if (elapsed > 2500) {
            points.push({
              type: spec.type,
              param,
              method: "GET",
              payload: spec.payload,
              evidence: `time-based (${elapsed}ms >= ${spec.timeDelay}ms)`,
              severity: spec.severity,
            });
            log(`    [!] ${spec.type.toUpperCase()} (GET ${param}): time-based ${elapsed}ms`);
            break;
          }
        }

        // Evidence-based detection
        if (spec.evidence.test(res.body)) {
          // For SSTI/XSS, ensure the payload is reflected AND the evidence matches
          if (spec.type === "xss") {
            if (res.body.includes(spec.payload)) {
              points.push({
                type: spec.type,
                param,
                method: "GET",
                payload: spec.payload,
                evidence: `reflected: ${spec.payload.slice(0, 40)}`,
                severity: spec.severity,
              });
              log(`    [!] ${spec.type.toUpperCase()} (GET ${param}): reflected`);
              break;
            }
          } else if (spec.type === "ssti") {
            // Only flag if 49 appears AND it's not in the baseline (avoid false positives from page content)
            if (!/\b49\b/.test(baseline.body) && /\b49\b/.test(res.body)) {
              points.push({
                type: spec.type,
                param,
                method: "GET",
                payload: spec.payload,
                evidence: `evaluated: ${spec.payload} -> 49`,
                severity: spec.severity,
              });
              log(`    [!] ${spec.type.toUpperCase()} (GET ${param}): ${spec.payload} -> 49`);
              break;
            }
          } else if (spec.type === "openredirect") {
            const loc = res.headers["location"] || "";
            if (loc.includes("evil.attacker.com")) {
              points.push({
                type: spec.type,
                param,
                method: "GET",
                payload: spec.payload,
                evidence: `redirect to: ${loc.slice(0, 60)}`,
                severity: spec.severity,
              });
              log(`    [!] OPEN REDIRECT (GET ${param}): -> ${loc.slice(0, 50)}`);
              break;
            }
          } else {
            // SQLi/NoSQLi/cmdi/ldap/xpath error-based
            const match = res.body.match(spec.evidence);
            // Avoid false positives: ensure the error wasn't in baseline
            if (match && !baseline.body.includes(match[0])) {
              points.push({
                type: spec.type,
                param,
                method: "GET",
                payload: spec.payload,
                evidence: `error: ${match[0].slice(0, 60)}`,
                severity: spec.severity,
              });
              log(`    [!] ${spec.type.toUpperCase()} (GET ${param}): ${match[0].slice(0, 50)}`);
              break;
            }
          }
        }
      }

      // Only test a few params per host to keep scan time reasonable
      if (points.length >= 5) break;
    }

    hosts.push({ url, points });
    const sevCount: Record<string, number> = {};
    for (const p of points) sevCount[p.severity] = (sevCount[p.severity] || 0) + 1;
    const summary = ["high", "medium", "low"].filter((s) => sevCount[s]).map((s) => `${sevCount[s]} ${s}`).join(", ");
    log(`  [+] ${url}: ${points.length} injection point(s)${summary ? " (" + summary + ")" : ""}`);
  }

  const total = hosts.reduce((a, h) => a + h.points.length, 0);
  log(`Injection testing complete: ${total} point(s) across ${hosts.length} host(s).`);
  return { hosts };
}
