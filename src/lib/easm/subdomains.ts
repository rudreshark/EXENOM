/**
 * Subdomain Enumeration Module
 * Sources:
 *   1. Certificate Transparency logs via crt.sh
 *   2. HackerTarget API
 *   3. AlienVault OTX passive DNS
 *   4. Anubis-DB (jldc.me)
 *   5. RapidDNS
 *   6. DNS brute-force using the built-in wordlist
 * Resolves each candidate to an A record.
 */
import * as dns from "dns";
import { promisify } from "util";
import { SUBDOMAIN_WORDLIST } from "./wordlist";
import type { SubdomainResult } from "./types";

const resolve4 = promisify(dns.resolve4);
const lookup = promisify(dns.lookup);

async function fetchJson(url: string, timeoutMs = 8000, headers: Record<string, string> = {}): Promise<any> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "User-Agent": "easm-scanner/1.0", ...headers },
    });
    if (!res.ok) return null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) return await res.json();
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function fetchText(url: string, timeoutMs = 8000): Promise<string | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function fromCrtSh(domain: string): Promise<{ name: string; source: string }[]> {
  const out: { name: string; source: string }[] = [];
  const data = await fetchJson(
    `https://crt.sh/?q=%25.${domain}&output=json`
  );
  if (Array.isArray(data)) {
    const seen = new Set<string>();
    for (const row of data) {
      const names: string = row.name_value || "";
      for (let n of names.split("\n")) {
        n = n.trim().toLowerCase();
        if (!n || n.startsWith("*")) continue;
        if (n.endsWith(domain) && !seen.has(n)) {
          seen.add(n);
          out.push({ name: n, source: "crt.sh" });
        }
      }
    }
  }
  return out;
}

async function fromHackerTarget(domain: string): Promise<{ name: string; source: string }[]> {
  const out: { name: string; source: string }[] = [];
  const data = await fetchText(
    `https://api.hackertarget.com/hostsearch/?q=${domain}`
  );
  if (typeof data === "string" && data && !data.includes("API count exceeded")) {
    for (const line of data.split("\n")) {
      const [host] = line.split(",");
      if (host && host.trim().endsWith(domain)) {
        out.push({ name: host.trim().toLowerCase(), source: "hackertarget" });
      }
    }
  }
  return out;
}

async function fromAlienVaultOtx(domain: string): Promise<{ name: string; source: string }[]> {
  const out: { name: string; source: string }[] = [];
  const data = await fetchJson(
    `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`,
    10000
  );
  if (data && Array.isArray(data.passive_dns)) {
    const seen = new Set<string>();
    for (const row of data.passive_dns) {
      const host: string = (row.hostname || "").toLowerCase().trim();
      if (!host || host.startsWith("*")) continue;
      if (host.endsWith(domain) && !seen.has(host)) {
        seen.add(host);
        out.push({ name: host, source: "otx" });
      }
    }
  }
  return out;
}

async function fromAnubis(domain: string): Promise<{ name: string; source: string }[]> {
  const out: { name: string; source: string }[] = [];
  const data = await fetchJson(`https://jldc.me/anubis/subdomains/${domain}`, 10000);
  if (Array.isArray(data)) {
    const seen = new Set<string>();
    for (const n of data) {
      const host = String(n).toLowerCase().trim();
      if (!host || host.startsWith("*")) continue;
      if (host.endsWith(domain) && !seen.has(host)) {
        seen.add(host);
        out.push({ name: host, source: "anubis" });
      }
    }
  }
  return out;
}

async function fromRapidDNS(domain: string): Promise<{ name: string; source: string }[]> {
  const out: { name: string; source: string }[] = [];
  const data = await fetchText(
    `https://rapiddns.io/subdomain/${domain}?full=1#result`,
    10000
  );
  if (data && data.includes("<table")) {
    const seen = new Set<string>();
    const re = /<td>([a-zA-Z0-9_.-]+\.[a-zA-Z0-9_.-]+)<\/td>/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(data)) !== null) {
      const host = m[1].toLowerCase().trim();
      if (!host || host.startsWith("*")) continue;
      if (host.endsWith(domain) && !seen.has(host)) {
        seen.add(host);
        out.push({ name: host, source: "rapiddns" });
      }
    }
  }
  return out;
}

async function fromBruteForce(
  domain: string,
  concurrency: number,
  onProgress: (current: number, total: number) => void
): Promise<{ name: string; source: string }[]> {
  const out: { name: string; source: string }[] = [];
  const candidates = SUBDOMAIN_WORDLIST.map((w) => `${w}.${domain}`);
  let idx = 0;
  let done = 0;

  async function worker() {
    while (idx < candidates.length) {
      const my = idx++;
      const host = candidates[my];
      try {
        await resolve4(host);
        out.push({ name: host, source: "bruteforce" });
      } catch {
        /* not resolved */
      } finally {
        done++;
        onProgress(done, candidates.length);
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return out;
}

export async function runSubdomains(
  domain: string,
  concurrency: number,
  max: number,
  log: (msg: string) => void
): Promise<SubdomainResult> {
  log("Enumerating subdomains via crt.sh ...");
  const crt = await fromCrtSh(domain);
  log(`  crt.sh: ${crt.length} candidate(s)`);

  log("Querying HackerTarget hostsearch ...");
  const ht = await fromHackerTarget(domain);
  log(`  hackertarget: ${ht.length} candidate(s)`);

  log("Querying AlienVault OTX passive DNS ...");
  const otx = await fromAlienVaultOtx(domain);
  log(`  otx: ${otx.length} candidate(s)`);

  log("Querying Anubis-DB (jldc.me) ...");
  const anubis = await fromAnubis(domain);
  log(`  anubis: ${anubis.length} candidate(s)`);

  log("Querying RapidDNS ...");
  const rapid = await fromRapidDNS(domain);
  log(`  rapiddns: ${rapid.length} candidate(s)`);

  log(`Brute-forcing ${SUBDOMAIN_WORDLIST.length} common names ...`);
  const brute = await fromBruteForce(domain, concurrency, (c, t) => {
    if (c % 25 === 0 || c === t) log(`  bruteforce progress ${c}/${t}`);
  });

  // Merge & dedupe
  const map = new Map<string, { hostname: string; source: string }>();
  for (const c of [...crt, ...ht, ...otx, ...anubis, ...rapid, ...brute]) {
    if (!map.has(c.name)) map.set(c.name, { hostname: c.name, source: c.source });
  }

  const list = Array.from(map.values()).slice(0, max);

  // Resolve each to an IP
  log(`Resolving ${list.length} unique subdomain(s) to IP ...`);
  const subdomains: SubdomainResult["subdomains"] = [];
  for (const s of list) {
    let ip = "-";
    try {
      const addrs = await resolve4(s.hostname);
      ip = addrs[0] || "-";
    } catch {
      try {
        const l = await lookup(s.hostname);
        ip = l.address;
      } catch {
        ip = "-";
      }
    }
    subdomains.push({ hostname: s.hostname, ip, source: s.source });
  }

  log(`Discovered ${subdomains.length} live subdomain(s).`);
  return { subdomains };
}
