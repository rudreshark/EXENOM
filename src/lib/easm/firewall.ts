/**
 * Firewall / WAF Detection Module
 *
 * Combines four red-teaming capabilities:
 *   1. WAF / firewall fingerprinting (header + cookie + behavioral)
 *   2. WAF-bypass payload suggestions (contextual to detected WAF)
 *   3. Extra attack-surface discovery:
 *        - robots.txt / sitemap.xml parsing for hidden paths
 *        - CORS misconfiguration probing
 *        - HTTP method enumeration (OPTIONS)
 */
import type { FirewallResult } from "./types";
import {
  XSS_PAYLOADS,
  SQLI_PAYLOADS,
  LFI_PAYLOADS,
  CMDI_PAYLOADS,
  OPENDIRS_PAYLOADS,
  CLOUDFLARE_PAYLOADS,
  MODSECURITY_PAYLOADS,
  AWSWAF_PAYLOADS,
  AKAMAI_PAYLOADS,
  IMPERVA_PAYLOADS,
  totalPayloadCount,
  type PayloadSet,
} from "./payloads";

// ---- WAF fingerprints ----------------------------------------------------

interface WafFingerprint {
  name: string;
  test: (headers: Record<string, string>, cookies: string[], body: string, status: number) => string | null;
}

const WAF_FINGERPRINTS: WafFingerprint[] = [
  {
    name: "Cloudflare",
    test: (h, _c, _b) =>
      h["server"]?.toLowerCase().includes("cloudflare") || h["cf-ray"] ? "server/cf-ray header" : null,
  },
  {
    name: "AWS WAF / CloudFront",
    test: (h) =>
      h["x-amzn-waf-action"] || h["x-amz-cf-id"] || h["via"]?.includes("CloudFront")
        ? "x-amz-cf-id / x-amzn-waf-action"
        : null,
  },
  {
    name: "Akamai",
    test: (h, _c, b) =>
      h["server"]?.toLowerCase().includes("akamai") || h["x-akamai-transformed"] || /reference\s*#?\d+\.\w+/.test(b) && b.includes("akamai")
        ? "server / x-akamai-transformed"
        : null,
  },
  {
    name: "Imperva Incapsula",
    test: (h, c) =>
      h["x-iinfo"] || c.some((x) => /incap_ses|visid_incap/i.test(x))
        ? "x-iinfo / incap_ses cookie"
        : null,
  },
  {
    name: "Sucuri",
    test: (h) =>
      h["server"]?.toLowerCase().includes("sucuri") || h["x-sucuri-id"]
        ? "server / x-sucuri-id"
        : null,
  },
  {
    name: "F5 BIG-IP ASM",
    test: (h, c) =>
      h["server"]?.includes("BigIP") || c.some((x) => /tsip/i.test(x)) || h["x-cnection"]?.includes("BigIP")
        ? "BigIP server / tsip cookie"
        : null,
  },
  {
    name: "Citrix NetScaler",
    test: (h) =>
      h["via"]?.includes("NS-CACHE") || h["x-citrix"] || h["set-cookie"]?.includes("ns_af_")
        ? "via NS-CACHE / ns_af cookie"
        : null,
  },
  {
    name: "ModSecurity / OWASP CRS",
    test: (h, _c, b) =>
      h["server"]?.toLowerCase().includes("mod_security") || /mod_security|modsecurity/i.test(b) || h["x-protected-by"]?.includes("Mod")
        ? "server / body signature"
        : null,
  },
  {
    name: "Wordfence",
    test: (h) => (h["x-wf-"] ? "x-wf-* header" : null),
  },
  {
    name: "Barracuda",
    test: (h, c) =>
      h["server"]?.includes("Barracuda") || c.some((x) => /barra_counter/i.test(x))
        ? "Barracuda server / barra cookie"
        : null,
  },
  {
    name: "Fortinet FortiWeb",
    test: (h) => (h["server"]?.includes("Forti") ? "FortiWeb server" : null),
  },
  {
    name: "Azure Front Door",
    test: (h) => (h["x-azure-ref"] || h["x-azure-signalr"] ? "x-azure-ref" : null),
  },
  {
    name: "StackPath",
    test: (h) => (h["x-sp-url"] || h["server"]?.includes("StackPath") ? "x-sp-url / server" : null),
  },
  {
    name: "DDoS-Guard",
    test: (h, c) =>
      h["server"]?.includes("DDoS-Guard") || c.some((x) => /ddos-guard/i.test(x))
        ? "DDoS-Guard server / cookie"
        : null,
  },
  {
    name: "Reblaze",
    test: (h, c) =>
      h["server"]?.includes("Reblaze") || c.some((x) => /rbzid/i.test(x))
        ? "Reblaze server / rbzid cookie"
        : null,
  },
  {
    name: "Edgecast / Verizon",
    test: (h) => (h["x-ec-debug"] || h["server"]?.includes("ECS") ? "x-ec-debug" : null),
  },
];

// ---- WAF bypass payload database (330+ per category) ---------------------
// Uses the advanced encoded payload generators from ./payloads.ts
// Each category has 330+ layered-encoded variants (URL/HTML/Unicode/hex/case/ws).

const BYPASS_PAYLOADS: Record<string, PayloadSet[]> = {
  Cloudflare: [
    { ...SQLI_PAYLOADS, category: "Cloudflare SQLi bypass" },
    { ...XSS_PAYLOADS, category: "Cloudflare XSS bypass" },
    { ...LFI_PAYLOADS, category: "Cloudflare LFI bypass" },
    { ...CMDI_PAYLOADS, category: "Cloudflare CMDi bypass" },
    CLOUDFLARE_PAYLOADS,
  ],
  "ModSecurity / OWASP CRS": [
    { ...SQLI_PAYLOADS, category: "ModSecurity SQLi bypass" },
    { ...XSS_PAYLOADS, category: "ModSecurity XSS bypass" },
    { ...LFI_PAYLOADS, category: "ModSecurity LFI bypass" },
    { ...CMDI_PAYLOADS, category: "ModSecurity CMDi bypass" },
    MODSECURITY_PAYLOADS,
  ],
  "AWS WAF / CloudFront": [
    { ...SQLI_PAYLOADS, category: "AWS WAF SQLi bypass" },
    { ...XSS_PAYLOADS, category: "AWS WAF XSS bypass" },
    { ...LFI_PAYLOADS, category: "AWS WAF LFI bypass" },
    AWSWAF_PAYLOADS,
  ],
  Akamai: [
    { ...SQLI_PAYLOADS, category: "Akamai SQLi bypass" },
    { ...XSS_PAYLOADS, category: "Akamai XSS bypass" },
    { ...LFI_PAYLOADS, category: "Akamai LFI bypass" },
    AKAMAI_PAYLOADS,
  ],
  "Imperva Incapsula": [
    { ...SQLI_PAYLOADS, category: "Imperva SQLi bypass" },
    { ...XSS_PAYLOADS, category: "Imperva XSS bypass" },
    IMPERVA_PAYLOADS,
  ],
  Generic: [
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    LFI_PAYLOADS,
    CMDI_PAYLOADS,
    OPENDIRS_PAYLOADS,
    CLOUDFLARE_PAYLOADS,
    MODSECURITY_PAYLOADS,
    AWSWAF_PAYLOADS,
    AKAMAI_PAYLOADS,
    IMPERVA_PAYLOADS,
  ],
};

// ---- HTTP helpers --------------------------------------------------------

async function fetchProbe(
  url: string,
  method: string = "GET",
  body?: string,
  headers?: Record<string, string>,
  timeoutMs = 8000
): Promise<{
  status: number;
  headers: Record<string, string>;
  cookies: string[];
  body: string;
} | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      signal: ctrl.signal,
      redirect: "manual",
      body,
      headers: { "User-Agent": "easm-scanner/1.0", ...headers },
    });
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));
    const sc = h["set-cookie"] || "";
    const cookies = sc
      .split(/,(?=\s*[a-zA-Z0-9_-]+=)/)
      .map((c) => c.trim())
      .filter(Boolean);
    let b = "";
    try {
      b = await res.text();
    } catch {
      /* ignore */
    }
    return { status: res.status, headers: h, cookies, body: b };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

const BLOCK_SIGNATURES = [
  /access denied/i, /request blocked/i, /blocked by/i, /security rule/i,
  /forbidden by access control/i, /waf/i, /firewall/i, /incapsula incident/i,
  /attention required.*cloudflare/i, /proxy\s*server\s*denied/i, /your request has been blocked/i,
  /not acceptable/i, /the url you requested has been blocked/i, /web application firewall/i,
];

// ---- Attack-surface discovery --------------------------------------------

async function parseRobotsTxt(baseUrl: string): Promise<string[]> {
  const res = await fetchProbe(`${baseUrl}/robots.txt`);
  if (!res || res.status !== 200) return [];
  const paths = new Set<string>();
  for (const line of res.body.split("\n")) {
    const m = line.match(/^(?:allow|disallow|sitemap):\s*(\S+)/i);
    if (m && m[1] !== "/") paths.add(m[1]);
  }
  return Array.from(paths).slice(0, 30);
}

async function parseSitemap(baseUrl: string): Promise<string[]> {
  const res = await fetchProbe(`${baseUrl}/sitemap.xml`);
  if (!res || res.status !== 200 || !res.body.includes("<urlset") && !res.body.includes("<sitemapindex")) return [];
  const urls = new Set<string>();
  const re = /<loc>([^<]+)<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(res.body)) !== null && urls.size < 30) {
    try {
      const u = new URL(m[1]);
      urls.add(u.pathname);
    } catch {
      urls.add(m[1]);
    }
  }
  return Array.from(urls);
}

async function checkCors(baseUrl: string): Promise<{
  enabled: boolean;
  origin: string;
  credentials: boolean;
  wildcard: boolean;
  reflected: boolean;
}> {
  const evil = "https://evil.attacker.com";
  const res = await fetchProbe(baseUrl, "GET", undefined, { Origin: evil });
  if (!res) return { enabled: false, origin: "", credentials: false, wildcard: false, reflected: false };
  const acao = res.headers["access-control-allow-origin"] || "";
  const acac = res.headers["access-control-allow-credentials"] || "";
  return {
    enabled: !!acao,
    origin: acao,
    credentials: /true/i.test(acac),
    wildcard: acao === "*",
    reflected: acao === evil,
  };
}

async function checkMethods(baseUrl: string): Promise<string[]> {
  const res = await fetchProbe(baseUrl, "OPTIONS");
  if (!res) return [];
  const allow = res.headers["allow"] || "";
  if (allow) return allow.split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
  // Fallback: probe common methods.
  const methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"];
  const found: string[] = [];
  for (const m of methods) {
    const r = await fetchProbe(baseUrl, m);
    if (r && r.status !== 405 && r.status !== 501) found.push(m);
  }
  return found;
}

// ---- Main ----------------------------------------------------------------

export async function runFirewall(
  urls: string[],
  log: (msg: string) => void
): Promise<FirewallResult> {
  const hosts: FirewallResult["hosts"] = [];
  const attackSurface: FirewallResult["attackSurface"] = [];
  const detectedWafs = new Set<string>();
  const bypassPayloads: FirewallResult["bypassPayloads"] = [];

  log(`Running firewall/WAF detection on ${urls.length} host(s) ...`);

  for (const url of urls) {
    log(`  Probing ${url} ...`);
    const res = await fetchProbe(url);
    if (!res) {
      log(`    [-] ${url} - no response`);
      continue;
    }

    // 1. WAF fingerprinting
    const detected: FirewallResult["hosts"][0]["detected"] = [];
    for (const fp of WAF_FINGERPRINTS) {
      const evidence = fp.test(res.headers, res.cookies, res.body, res.status);
      if (evidence) {
        const conf = /server|cookie/i.test(evidence) ? "high" : "medium";
        detected.push({ name: fp.name, confidence: conf, evidence: [evidence] });
      }
    }
    if (detected.length) {
      detected.forEach((d) => {
        detectedWafs.add(d.name);
        log(`    [+] WAF: ${d.name} (${d.confidence}) — ${d.evidence.join(", ")}`);
      });
    } else {
      log(`    [-] no WAF signatures detected`);
    }

    // 2. Behavioral WAF test (send an attack payload, observe block status)
    let blockStatus: number | null = null;
    const blockSignatures: string[] = [];
    const attackUrl = `${url}${url.includes("?") ? "&" : "?"}id=1'+UNION+SELECT+--+-`;
    const attackRes = await fetchProbe(attackUrl);
    if (attackRes) {
      if ([403, 406, 429, 501, 418].includes(attackRes.status)) {
        blockStatus = attackRes.status;
        log(`    [+] WAF active: attack payload blocked with HTTP ${blockStatus}`);
      }
      for (const sig of BLOCK_SIGNATURES) {
        if (sig.test(attackRes.body)) {
          blockSignatures.push(sig.source.slice(0, 30));
          break;
        }
      }
    }

    // 3. HTTP methods
    const methods = await checkMethods(url);
    if (methods.length) {
      const risky = methods.filter((m) => ["PUT", "DELETE", "TRACE", "CONNECT"].includes(m));
      log(`    [+] Methods: ${methods.join(", ")}${risky.length ? " (risky: " + risky.join(", ") + ")" : ""}`);
    }

    // 4. CORS
    const cors = await checkCors(url);
    if (cors.enabled) {
      const flags = [
        cors.wildcard ? "wildcard" : null,
        cors.reflected ? "reflects-origin" : null,
        cors.credentials ? "credentials" : null,
      ].filter(Boolean);
      log(`    [+] CORS: ${cors.origin}${flags.length ? " (" + flags.join(", ") + ")" : ""}`);
    }

    hosts.push({
      url,
      detected,
      blockStatus,
      blockSignatures,
      methods,
      cors,
    });
  }

  // 5. Attack-surface discovery (robots.txt + sitemap.xml)
  log(`Discovering attack surface via robots.txt / sitemap.xml ...`);
  for (const url of urls.slice(0, 3)) {
    const robotsPaths = await parseRobotsTxt(url);
    if (robotsPaths.length) {
      attackSurface.push({ source: `robots.txt (${url})`, paths: robotsPaths });
      log(`  [+] robots.txt: ${robotsPaths.length} path(s)${robotsPaths.length > 3 ? " — " + robotsPaths.slice(0, 3).join(", ") + " ..." : ""}`);
    }
    const sitemapPaths = await parseSitemap(url);
    if (sitemapPaths.length) {
      attackSurface.push({ source: `sitemap.xml (${url})`, paths: sitemapPaths });
      log(`  [+] sitemap.xml: ${sitemapPaths.length} URL(s)`);
    }
  }

  // 6. Build bypass payload suggestions (contextual to detected WAFs)
  log(`Generating advanced WAF-bypass payload suggestions (${totalPayloadCount()}+ encoded payloads available) ...`);
  const wafList = detectedWafs.size ? Array.from(detectedWafs) : ["Generic"];
  for (const waf of wafList) {
    const cats = BYPASS_PAYLOADS[waf] || BYPASS_PAYLOADS.Generic;
    for (const cat of cats) {
      bypassPayloads.push({ waf, category: cat.category, payloads: cat.payloads, note: cat.note });
      log(`  [+] ${waf} :: ${cat.category} (${cat.payloads.length} payloads)`);
    }
  }
  if (bypassPayloads.length === 0) {
    // Always emit generic payloads even if no WAF detected.
    for (const cat of BYPASS_PAYLOADS.Generic) {
      bypassPayloads.push({ waf: "Generic", category: cat.category, payloads: cat.payloads, note: cat.note });
      log(`  [+] Generic :: ${cat.category} (${cat.payloads.length} payloads)`);
    }
  }

  const totalPayloads = bypassPayloads.reduce((a, p) => a + p.payloads.length, 0);
  log(
    `Firewall/WAF analysis complete: ${detectedWafs.size} WAF(s) detected, ${bypassPayloads.length} payload set(s), ${totalPayloads} total payloads, ${attackSurface.reduce((a, s) => a + s.paths.length, 0)} attack-surface path(s).`
  );

  return { hosts, bypassPayloads, attackSurface };
}
