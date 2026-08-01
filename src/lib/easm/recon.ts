/**
 * Recon Module — WHOIS / ASN / GeoIP
 *
 * Gathers registration & infrastructure intelligence for the target:
 *   1. WHOIS — domain registration data (via RDAP, the modern REST API)
 *   2. ASN  — Autonomous System + network owner (via ipinfo.io)
 *   3. GeoIP — geolocation of the resolved IP (via ip-api.com, free)
 *   4. Reverse DNS — PTR records for the resolved IP(s)
 */
import * as dns from "dns";
import { promisify } from "util";
import type { ReconResult } from "./types";

const reverse = promisify(dns.reverse);

async function httpGetJson(url: string, timeoutMs = 8000): Promise<any | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "User-Agent": "easm-scanner/1.0", Accept: "application/json" },
    });
    if (!res.ok) return null;
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("json")) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function rdapLookup(domain: string): Promise<ReconResult["whois"]> {
  const data = await httpGetJson(`https://rdap.org/domain/${domain}`, 10000);
  if (!data) return {};
  const whois: ReconResult["whois"] = {};
  // Events
  for (const ev of data.events || []) {
    if (ev.eventAction === "registration") whois.createdDate = ev.eventDate;
    if (ev.eventAction === "last changed") whois.updatedDate = ev.eventDate;
    if (ev.eventAction === "expiration") whois.expiryDate = ev.eventDate;
  }
  // Nameservers
  whois.nameServers = (data.nameservers || []).map((ns: any) => ns.ldhName || "").filter(Boolean);
  // Entities → registrar + registrant
  for (const ent of data.entities || []) {
    const roles = ent.roles || [];
    if (roles.includes("registrar")) {
      const vcard = ent.vcardArray?.[1] || [];
      for (const f of vcard) {
        if (f[0] === "fn") whois.registrar = f[3];
      }
    }
    if (roles.includes("registrant")) {
      const vcard = ent.vcardArray?.[1] || [];
      for (const f of vcard) {
        if (f[0] === "org") whois.registrantOrg = f[3];
        if (f[0] === "country") whois.registrantCountry = f[3];
      }
    }
  }
  return whois;
}

async function ipInfo(ip: string): Promise<ReconResult["geo"] & { asn?: string; asnOrg?: string }> {
  // ip-api.com (free, no key, returns geo + ISP + org + AS)
  const data = await httpGetJson(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,reverse,query`, 8000);
  if (!data || data.status !== "success") {
    // Fallback to ipinfo.io (also has a free tier)
    const data2 = await httpGetJson(`https://ipinfo.io/${ip}/json`, 8000);
    if (!data2) return { ip };
    return {
      ip,
      country: data2.country,
      region: data2.region,
      city: data2.city,
      lat: data2.loc ? parseFloat(data2.loc.split(",")[0]) : undefined,
      lon: data2.loc ? parseFloat(data2.loc.split(",")[1]) : undefined,
      isp: data2.org,
      org: data2.org,
    };
  }
  return {
    ip: data.query || ip,
    country: data.country,
    region: data.regionName,
    city: data.city,
    lat: data.lat,
    lon: data.lon,
    isp: data.isp,
    org: data.org,
    asn: data.as,
    asnOrg: data.org,
  };
}

export async function runRecon(
  domain: string,
  resolvedIp: string | null,
  log: (msg: string) => void
): Promise<ReconResult> {
  log(`Gathering WHOIS / ASN / GeoIP intel for ${domain} ...`);

  // 1. WHOIS via RDAP
  log("  Querying RDAP (WHOIS) ...");
  const whois = await rdapLookup(domain);
  if (whois.registrar) log(`    [+] Registrar: ${whois.registrar}`);
  if (whois.createdDate) log(`    [+] Created: ${whois.createdDate}`);
  if (whois.expiryDate) log(`    [+] Expires: ${whois.expiryDate}`);
  if (whois.registrantOrg) log(`    [+] Registrant: ${whois.registrantOrg} (${whois.registrantCountry || "?"})`);
  if (!whois.registrar && !whois.createdDate) log("    [-] no RDAP data");

  // 2. GeoIP + ASN
  let geo: ReconResult["geo"] = { ip: resolvedIp || "-" };
  let asn: ReconResult["asn"] = {};
  const ip = resolvedIp;
  if (ip) {
    log(`  Geo-locating IP ${ip} ...`);
    const info = await ipInfo(ip);
    geo = { ip: info.ip, country: info.country, region: info.region, city: info.city, lat: info.lat, lon: info.lon, isp: info.isp, org: info.org };
    if (info.asn) {
      asn = { asn: info.asn, org: info.org, network: info.isp };
    }
    if (geo.city) {
      log(`    [+] ${geo.city}, ${geo.country} (${geo.isp || "?"})`);
    } else {
      log("    [-] geo-location unavailable");
    }
  }

  // 3. Reverse DNS
  log("  Reverse DNS lookup ...");
  let reverseDns: string[] = [];
  if (ip) {
    try {
      reverseDns = await reverse(ip);
      if (reverseDns.length) log(`    [+] ${ip} -> ${reverseDns.join(", ")}`);
      else log("    [-] no PTR record");
    } catch {
      log("    [-] reverse DNS failed");
    }
  }

  const recordCount =
    (whois.registrar ? 1 : 0) +
    (whois.createdDate ? 1 : 0) +
    (whois.expiryDate ? 1 : 0) +
    (whois.nameServers?.length || 0) +
    (asn.asn ? 1 : 0) +
    (geo.city ? 1 : 0) +
    reverseDns.length;

  log(`Recon complete: ${recordCount} record(s) gathered.`);
  return { whois, asn, geo, reverseDns };
}
