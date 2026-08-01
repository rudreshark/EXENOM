/**
 * DNS Reconnaissance Module
 * Resolves common record types for the target and optionally
 * performs reverse lookups on resolved A records.
 */
import * as dns from "dns";
import { promisify } from "util";
import type { DnsResult } from "./types";

const resolveAny = promisify(dns.resolveAny);
const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveMx = promisify(dns.resolveMx);
const resolveNs = promisify(dns.resolveNs);
const resolveTxt = promisify(dns.resolveTxt);
const resolveCname = promisify(dns.resolveCname);
const resolveSoa = promisify(dns.resolveSoa);
const reverse = promisify(dns.reverse);
const lookup = promisify(dns.lookup);

export interface DnsLog {
  (msg: string): void;
}

export async function runDns(
  target: string,
  log: (msg: string) => void
): Promise<DnsResult> {
  const records: DnsResult["records"] = [];
  const resolvers: string[] = [];
  log(`Resolving DNS records for ${target} ...`);

  // A
  try {
    const addrs = await resolve4(target);
    for (const a of addrs) records.push({ type: "A", name: target, value: a });
  } catch {
    /* ignore */
  }

  // AAAA
  try {
    const addrs = await resolve6(target);
    for (const a of addrs) records.push({ type: "AAAA", name: target, value: a });
  } catch {
    /* ignore */
  }

  // CNAME
  try {
    const cnames = await resolveCname(target);
    for (const c of cnames) records.push({ type: "CNAME", name: target, value: c });
  } catch {
    /* ignore */
  }

  // MX
  try {
    const mx = await resolveMx(target);
    for (const m of mx)
      records.push({
        type: "MX",
        name: target,
        value: `${m.exchange} (pri ${m.priority})`,
      });
  } catch {
    /* ignore */
  }

  // NS
  try {
    const ns = await resolveNs(target);
    for (const n of ns) records.push({ type: "NS", name: target, value: n });
    resolvers.push(...ns);
  } catch {
    /* ignore */
  }

  // TXT
  try {
    const txt = await resolveTxt(target);
    for (const t of txt) records.push({ type: "TXT", name: target, value: t.join("") });
  } catch {
    /* ignore */
  }

  // SOA
  try {
    const soa = await resolveSoa(target);
    records.push({
      type: "SOA",
      name: target,
      value: `${soa.nsname} hostmaster=${soa.hostmaster} serial=${soa.serial}`,
    });
  } catch {
    /* ignore */
  }

  // Reverse on first A record
  const firstA = records.find((r) => r.type === "A");
  if (firstA) {
    try {
      const hostnames = await reverse(firstA.value);
      for (const h of hostnames)
        records.push({ type: "PTR", name: firstA.value, value: h });
    } catch {
      /* ignore */
    }
  }

  // Resolve NS servers to IPs for extra surface info
  for (const ns of resolvers.slice(0, 4)) {
    try {
      const ip = await lookup(ns);
      records.push({ type: "NS-IP", name: ns, value: ip.address });
    } catch {
      /* ignore */
    }
  }

  log(`Found ${records.length} DNS record(s).`);
  return { records, resolvers };
}

export { resolveAny, resolve4, resolveMx, resolveNs, reverse, lookup };
