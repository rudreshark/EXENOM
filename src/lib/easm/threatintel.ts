/**
 * Threat-Intelligence Module
 *
 * Queries 4 external OSINT / threat-intel APIs in parallel and
 * aggregates their findings into a single attack-surface view:
 *
 *   1. Shodan DNS API        — subdomains + historical DNS records
 *   2. c99 API               — subdomain enumeration (multi-key fallback)
 *   3. VirusTotal v3 API     — domain reputation, categories, resolved IPs
 *   4. SecurityTrails API    — subdomains + A-record history
 *
 * Each source is queried independently; failures (rate limit, bad key,
 * no credits) are captured per-source so partial results still surface.
 */
import { API_KEYS } from "./apikeys";
import type { ThreatIntelResult, ThreatIntelSource } from "./types";

/** HTTP GET -> JSON with timeout + content-type guard. */
async function httpGetJson(
  url: string,
  timeoutMs: number,
  headers: Record<string, string> = {}
): Promise<any | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "User-Agent": "easm-scanner/1.0", ...headers },
    });
    const text = await res.text();
    const trimmed = text.trim();
    // Guard against HTML error pages / empty bodies.
    if (!trimmed) return null;
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
      // Not JSON — capture as an error string if it looks like an error.
      return { __nonJson: trimmed.slice(0, 200) };
    }
    try {
      return JSON.parse(trimmed);
    } catch {
      return null;
    }
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function pickError(obj: any): string | null {
  if (!obj) return null;
  if (typeof obj.error === "string") return obj.error;
  if (obj.error && typeof obj.error === "object") {
    return obj.error.message || obj.error.code || JSON.stringify(obj.error);
  }
  if (typeof obj.message === "string" && !obj.subdomains) return obj.message;
  if (obj.__nonJson) return obj.__nonJson;
  return null;
}

// ---- Shodan DNS (multi-key rotation) -------------------------------------

async function queryShodan(domain: string, keys: string[]): Promise<ThreatIntelSource> {
  let lastErr = "no keys configured";
  for (const key of keys) {
    const url = `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${key}`;
    const res = await httpGetJson(url, 20000);
    if (!res) {
      lastErr = "no response / timeout";
      continue;
    }
    const err = pickError(res);
    if (err) {
      lastErr = err;
      continue; // try next key
    }
    const subdomains: string[] = (res.subdomains || []).map((s: string) =>
      `${s}.${domain}`.toLowerCase()
    );
    const records: { type: string; value: string }[] = (res.data || []).map((d: any) => ({
      type: d.type || "DNS",
      value: d.value || "",
    }));
    const tags: string[] = res.tags || [];
    return { name: "shodan", ok: true, subdomains, records, tags };
  }
  return { name: "shodan", ok: false, error: lastErr };
}

// ---- c99 (multi-key fallback) -------------------------------------------

async function queryC99(domain: string, keys: string[]): Promise<ThreatIntelSource> {
  let lastErr = "no keys configured";
  for (const key of keys) {
    const url = `https://api.c99.nl/cgi-bin/api?key=${key}&subdomain=${encodeURIComponent(
      domain
    )}&json=1`;
    const res = await httpGetJson(url, 25000);
    if (!res) {
      lastErr = "no response / timeout";
      continue;
    }
    // c99 returns an array of subdomain strings on success.
    if (Array.isArray(res)) {
      const subs = res.map((s) => String(s).toLowerCase()).filter(Boolean);
      return { name: "c99", ok: true, subdomains: subs };
    }
    // Object form.
    if (res.success === true && Array.isArray(res.subdomains)) {
      const subs = res.subdomains.map((s: any) => String(s).toLowerCase());
      return { name: "c99", ok: true, subdomains: subs };
    }
    const err = pickError(res);
    // Any error -> try the next key (different keys may have different
    // access tiers / credit pools). Keep the last error for reporting.
    if (err) {
      lastErr = err;
      continue;
    }
    lastErr = "unexpected response shape";
  }
  return { name: "c99", ok: false, error: lastErr };
}

// ---- VirusTotal v3 (multi-key rotation) ----------------------------------

async function queryVirusTotal(domain: string, keys: string[]): Promise<ThreatIntelSource> {
  let lastErr = "no keys configured";
  for (const key of keys) {
    const reportUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`;
    const report = await httpGetJson(reportUrl, 20000, { "x-apikey": key });
    if (!report) {
      lastErr = "no response / timeout";
      continue;
    }
    const err = pickError(report);
    if (err) {
      lastErr = err;
      continue; // try next key (rate limit / quota)
    }
    const attrs = report.data?.attributes || {};
    const reputation: number = attrs.reputation ?? 0;
    const categories: string[] = attrs.categories
      ? Array.from(new Set(Object.values(attrs.categories).filter(Boolean) as string[]))
      : [];
    const analysisStats = attrs.last_analysis_stats || {
      harmless: 0,
      malicious: 0,
      suspicious: 0,
      undetected: 0,
    };

    let resolvedIps: string[] = [];
    const resUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(
      domain
    )}/resolutions?limit=40`;
    const resRes = await httpGetJson(resUrl, 20000, { "x-apikey": key });
    if (resRes && Array.isArray(resRes.data)) {
      resolvedIps = resRes.data
        .map((d: any) => d.attributes?.ip_address)
        .filter(Boolean) as string[];
    }

    return {
      name: "virustotal",
      ok: true,
      reputation,
      categories,
      analysisStats,
      resolvedIps,
    };
  }
  return { name: "virustotal", ok: false, error: lastErr };
}

// ---- SecurityTrails (multi-key rotation) ---------------------------------

async function querySecurityTrails(
  domain: string,
  keys: string[]
): Promise<ThreatIntelSource> {
  let lastErr = "no keys configured";
  for (const key of keys) {
    const subUrl = `https://api.securitytrails.com/v1/domain/${encodeURIComponent(
      domain
    )}/subdomains`;
    const sub = await httpGetJson(subUrl, 20000, { APIKEY: key });
    if (!sub) {
      lastErr = "no response / timeout";
      continue;
    }
    const err = pickError(sub);
    if (err) {
      lastErr = err;
      continue;
    }
    const subdomains: string[] = (sub.subdomains || []).map((s: string) =>
      `${s}.${domain}`.toLowerCase()
    );

    let ipHistory: { ip: string; firstSeen: string; lastSeen: string }[] = [];
    const histUrl = `https://api.securitytrails.com/v1/history/${encodeURIComponent(
      domain
    )}/dns/a`;
    const hist = await httpGetJson(histUrl, 20000, { APIKEY: key });
    if (hist && Array.isArray(hist.records)) {
      ipHistory = hist.records
        .map((r: any) => ({
          ip: r.values?.[0]?.ip || "",
          firstSeen: r.first_seen || "",
          lastSeen: r.last_seen || "",
        }))
        .filter((r) => r.ip);
    }

    return { name: "securitytrails", ok: true, subdomains, ipHistory };
  }
  return { name: "securitytrails", ok: false, error: lastErr };
}

// ---- Orchestrator --------------------------------------------------------

export async function runThreatIntel(
  domain: string,
  log: (msg: string) => void
): Promise<ThreatIntelResult> {
  log(`Querying 4 threat-intel sources for ${domain} (Shodan×${API_KEYS.shodan.length}, c99×${API_KEYS.c99.length}, VT×${API_KEYS.virustotal.length}, ST×${API_KEYS.securitytrails.length} keys) ...`);

  const results = await Promise.all([
    queryShodan(domain, API_KEYS.shodan).catch((e) => ({
      name: "shodan",
      ok: false,
      error: e?.message || String(e),
    })),
    queryC99(domain, API_KEYS.c99).catch((e) => ({
      name: "c99",
      ok: false,
      error: e?.message || String(e),
    })),
    queryVirusTotal(domain, API_KEYS.virustotal).catch((e) => ({
      name: "virustotal",
      ok: false,
      error: e?.message || String(e),
    })),
    querySecurityTrails(domain, API_KEYS.securitytrails).catch((e) => ({
      name: "securitytrails",
      ok: false,
      error: e?.message || String(e),
    })),
  ]);

  const [shodan, c99, virustotal, securitytrails] = results as [
    ThreatIntelSource,
    ThreatIntelSource,
    ThreatIntelSource,
    ThreatIntelSource
  ];

  for (const s of results as ThreatIntelSource[]) {
    if (s.ok) {
      const parts: string[] = [];
      if (s.subdomains) parts.push(`${s.subdomains.length} subdomains`);
      if (s.records) parts.push(`${s.records.length} DNS records`);
      if (s.reputation !== undefined) parts.push(`reputation ${s.reputation}`);
      if (s.resolvedIps?.length) parts.push(`${s.resolvedIps.length} resolved IPs`);
      if (s.ipHistory?.length) parts.push(`${s.ipHistory.length} IP-history entries`);
      const detail = parts.length ? parts.join(", ") : "ok";
      log(`  [+] ${s.name}: ${detail}`);
    } else {
      log(`  [-] ${s.name}: ${s.error || "failed"}`);
    }
  }

  // Aggregate subdomains across Shodan / c99 / SecurityTrails.
  const subdomainSet = new Set<string>();
  for (const s of [shodan, c99, securitytrails]) {
    if (s.subdomains) s.subdomains.forEach((x) => subdomainSet.add(x.toLowerCase()));
  }
  const resolvedIps = new Set<string>();
  if (virustotal.resolvedIps) virustotal.resolvedIps.forEach((x) => resolvedIps.add(x));
  if (securitytrails.ipHistory) securitytrails.ipHistory.forEach((x) => resolvedIps.add(x.ip));
  if (shodan.records) {
    shodan.records
      .filter((r) => r.type === "A" && r.value)
      .forEach((r) => resolvedIps.add(r.value));
  }

  const reputation = virustotal.reputation ?? null;
  const maliciousVotes = virustotal.analysisStats?.malicious ?? null;
  const categories = virustotal.categories || [];
  const totalRecords = (shodan.records?.length || 0) + (securitytrails.ipHistory?.length || 0);

  const okCount = results.filter((r) => (r as ThreatIntelSource).ok).length;
  log(
    `Threat intel complete: ${okCount}/4 sources returned data, ${subdomainSet.size} unique subdomain(s), ${resolvedIps.size} resolved IP(s).`
  );

  return {
    sources: { shodan, c99, virustotal, securitytrails },
    aggregated: {
      subdomains: Array.from(subdomainSet).sort(),
      resolvedIps: Array.from(resolvedIps).sort(),
      reputation,
      maliciousVotes,
      categories,
      totalRecords,
    },
  };
}
