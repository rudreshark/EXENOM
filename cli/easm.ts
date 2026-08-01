#!/usr/bin/env bun
/**
 * EASM - External Attack Surface Management CLI
 *
 * Advanced attack-surface reconnaissance that runs entirely in your
 * Linux terminal.  Usage:
 *
 *   bun run easm scan example.com
 *   bun run easm scan example.com --modules dns,subdomains,http,vulns
 *   bun run easm scan example.com --no-subdomains --ports 80,443,8080
 *   bun run easm scan example.com --output json
 *
 * All output is streamed live to the same terminal.
 */
import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import {
  EasmScanner,
  ALL_MODULES,
  DEFAULT_PORTS,
  normalizeTarget,
  defaultConfig,
  type ModuleId,
  type ScanEvent,
  type ScanResults,
} from "../src/lib/easm";

const BANNER = String.raw`
  _______  __   __  _______  _   _    ___    __  __
 |  ____|  \ \ / / |__   __|| \ | |  / _ \  |  \/  |
 | |__      \ V /     | |  |  \| | | | | | | \  / |
 |  __|     / _ \     | |  | . ' | | |_| | | |\/| |
 |_____|   /_/ \_\    |_|  |_| \_|  \___/  |_|  |_|
   EXENOM - External Attack Surface Management  v1.0
   30 modules | 330+ WAF-bypass payloads per category
   Built by Rudresha RK - Cybersecurity Undergraduate
`;

const MODULE_LABEL: Record<ModuleId, string> = {
  dns: "DNS RECON",
  subdomains: "SUBDOMAIN ENUM",
  ports: "PORT SCAN",
  http: "HTTP PROBE",
  tls: "TLS / CERT",
  tech: "TECH FINGERPRINT",
  banners: "BANNER GRAB",
  vulns: "VULN CHECKS",
  threatintel: "THREAT INTEL",
  emailsec: "EMAIL SECURITY",
  opendirs: "OPEN DIRS",
  firewall: "FIREWALL / WAF",
  subtakeover: "SUBDOMAIN TAKEOVER",
  cloudenum: "CLOUD ENUM",
  screenshots: "HTTP FINGERPRINT",
  jsanalyze: "JS ANALYSIS",
  api: "API DISCOVERY",
  inject: "INJECTION TEST",
  webdav: "WEBDAV PROBE",
  ssltests: "SSL / TLS TESTS",
  crawl: "WEB CRAWLER",
  recon: "RECON (WHOIS/ASN/GEO)",
  spider: "ADVANCED SPIDER",
  wayback: "WAYBACK MACHINE",
  hostheader: "HOST HEADER / SSRF",
  auth: "AUTH BYPASS",
  csrf: "CSRF CHECKS",
  deserialization: "DESERIALIZATION",
  smuggling: "HTTP SMUGGLING",
  cache: "CACHE POISONING",
};

const LEVEL_COLOR: Record<string, (s: string) => string> = {
  info: chalk.dim,
  success: chalk.green,
  warn: chalk.yellow,
  error: chalk.red,
  debug: chalk.gray,
};

function parseModules(s: string): ModuleId[] {
  const parts = s.split(",").map((x) => x.trim().toLowerCase()) as ModuleId[];
  const invalid = parts.filter((p) => !ALL_MODULES.includes(p));
  if (invalid.length) {
    console.error(chalk.red(`Unknown module(s): ${invalid.join(", ")}`));
    console.error(chalk.dim(`Available: ${ALL_MODULES.join(", ")}`));
    process.exit(1);
  }
  return parts;
}

function parsePorts(s: string): number[] {
  const out: number[] = [];
  for (const part of s.split(",")) {
    const p = part.trim();
    if (p.includes("-")) {
      const [a, b] = p.split("-").map((n) => parseInt(n.trim(), 10));
      for (let i = a; i <= b; i++) out.push(i);
    } else if (p) {
      out.push(parseInt(p, 10));
    }
  }
  return out.filter((n) => !isNaN(n) && n > 0 && n < 65536);
}

function hr() {
  console.log(chalk.dim("─".repeat(70)));
}

function renderDns(r: NonNullable<ScanResults["dns"]>) {
  const t = new Table({
    head: [chalk.cyan("TYPE"), chalk.cyan("NAME"), chalk.cyan("VALUE")],
    colWidths: [10, 26, 50],
    style: { head: [], border: ["gray"] },
  });
  for (const rec of r.records) t.push([rec.type, rec.name, rec.value]);
  console.log(t.toString());
}

function renderSubdomains(r: NonNullable<ScanResults["subdomains"]>) {
  const t = new Table({
    head: [chalk.cyan("#"), chalk.cyan("HOSTNAME"), chalk.cyan("IP"), chalk.cyan("SOURCE")],
    colWidths: [5, 40, 18, 14],
    style: { head: [], border: ["gray"] },
  });
  r.subdomains.forEach((s, i) => t.push([String(i + 1), s.hostname, s.ip, s.source]));
  console.log(t.toString());
}

function renderPorts(r: NonNullable<ScanResults["ports"]>) {
  if (!r.ports.length) {
    console.log(chalk.dim("  no open ports"));
  } else {
    const t = new Table({
      head: [chalk.cyan("PORT"), chalk.cyan("PROTO"), chalk.cyan("SERVICE"), chalk.cyan("STATE"), chalk.cyan("BANNER")],
      colWidths: [8, 7, 14, 8, 38],
      style: { head: [], border: ["gray"] },
    });
    for (const p of r.ports)
      t.push([
        String(p.port),
        (p.protocol || "tcp").toUpperCase(),
        p.service,
        p.state === "open" ? chalk.green("open") : p.state,
        (p.banner || "").slice(0, 38),
      ]);
    console.log(t.toString());
  }
  if (r.osGuess && r.osGuess.os && !r.osGuess.os.startsWith("unknown")) {
    console.log(`  ${chalk.bold("OS guess:")} ${chalk.cyan(r.osGuess.os)}${chalk.dim(` (ttl~${r.osGuess.ttl ?? "?"}, ${r.osGuess.confidence})`)}`);
  }
}

function renderHttp(r: NonNullable<ScanResults["http"]>) {
  if (!r.hosts.length) {
    console.log(chalk.dim("  no HTTP services responding"));
    return;
  }
  const t = new Table({
    head: [chalk.cyan("URL"), chalk.cyan("STATUS"), chalk.cyan("TITLE"), chalk.cyan("SERVER")],
    colWidths: [38, 9, 28, 20],
    style: { head: [], border: ["gray"] },
  });
  for (const h of r.hosts) {
    const status = h.status === 0 ? chalk.red("down") : h.status >= 400 ? chalk.red(String(h.status)) : h.status >= 300 ? chalk.yellow(String(h.status)) : chalk.green(String(h.status));
    t.push([h.url, status, (h.title || "").slice(0, 28), (h.server || "").slice(0, 20)]);
  }
  console.log(t.toString());
}

function renderTls(r: NonNullable<ScanResults["tls"]>) {
  if (!r.certs.length) {
    console.log(chalk.dim("  no certificates"));
    return;
  }
  for (const c of r.certs) {
    const exp = c.daysRemaining < 0 ? chalk.red(`EXPIRED ${-c.daysRemaining}d ago`) : c.daysRemaining < 30 ? chalk.yellow(`${c.daysRemaining}d left`) : chalk.green(`${c.daysRemaining}d left`);
    console.log(`  ${chalk.bold(c.host)} ${c.selfSigned ? chalk.red("[SELF-SIGNED]") : ""} ${exp}`);
    console.log(chalk.dim(`    Subject : ${c.subject}`));
    console.log(chalk.dim(`    Issuer  : ${c.issuer}`));
    console.log(chalk.dim(`    Valid   : ${c.validFrom}  ->  ${c.validTo}`));
    if (c.san.length) console.log(chalk.dim(`    SAN     : ${c.san.slice(0, 6).join(", ")}${c.san.length > 6 ? " ..." : ""}`));
  }
}

function renderTech(r: NonNullable<ScanResults["tech"]>) {
  for (const h of r.hosts) {
    const list = h.technologies.map((t) => t.confidence === "high" ? chalk.green(t.name) : t.confidence === "medium" ? chalk.yellow(t.name) : chalk.dim(t.name));
    console.log(`  ${h.url}`);
    console.log(`    ${list.length ? list.join(chalk.dim(" | ")) : chalk.dim("no fingerprints")}`);
  }
}

function renderBanners(r: NonNullable<ScanResults["banners"]>) {
  if (!r.banners.length) {
    console.log(chalk.dim("  no banners"));
    return;
  }
  const t = new Table({
    head: [chalk.cyan("HOST:PORT"), chalk.cyan("SERVICE"), chalk.cyan("BANNER")],
    colWidths: [22, 12, 46],
    style: { head: [], border: ["gray"] },
  });
  for (const b of r.banners) t.push([`${b.host}:${b.port}`, b.service, b.banner.slice(0, 46)]);
  console.log(t.toString());
}

function renderVulns(r: NonNullable<ScanResults["vulns"]>) {
  const sevColor: Record<string, (s: string) => string> = {
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.cyan,
    info: chalk.dim,
  };
  for (const h of r.hosts) {
    if (!h.findings.length) {
      console.log(`  ${h.url} ${chalk.green("no findings")}`);
      continue;
    }
    console.log(`  ${chalk.bold(h.url)}`);
    for (const f of h.findings) {
      console.log(`    ${sevColor[f.severity](`[${f.severity.toUpperCase().padEnd(6)}]`)} ${f.title}`);
      console.log(chalk.dim(`           ${f.detail}`));
    }
  }
}

function renderThreatIntel(r: NonNullable<ScanResults["threatintel"]>) {
  const sources = [
    r.sources.shodan,
    r.sources.c99,
    r.sources.virustotal,
    r.sources.securitytrails,
  ];
  const t = new Table({
    head: [chalk.cyan("SOURCE"), chalk.cyan("STATUS"), chalk.cyan("DETAIL")],
    colWidths: [16, 9, 46],
    style: { head: [], border: ["gray"] },
  });
  for (const s of sources) {
    let detail = "-";
    if (s.ok) {
      const parts: string[] = [];
      if (s.subdomains) parts.push(`${s.subdomains.length} subs`);
      if (s.records) parts.push(`${s.records.length} recs`);
      if (s.reputation !== undefined) parts.push(`rep ${s.reputation}`);
      if (s.resolvedIps?.length) parts.push(`${s.resolvedIps.length} IPs`);
      if (s.ipHistory?.length) parts.push(`${s.ipHistory.length} hist`);
      detail = parts.length ? parts.join(", ") : "ok";
    } else {
      detail = (s.error || "failed").slice(0, 44);
    }
    t.push([s.name, s.ok ? chalk.green("ok") : chalk.red("fail"), detail]);
  }
  console.log(t.toString());

  // VirusTotal verdict
  const vt = r.sources.virustotal;
  if (vt.ok && vt.analysisStats) {
    const mal = vt.analysisStats.malicious || 0;
    const susp = vt.analysisStats.suspicious || 0;
    const verdict = mal >= 3 ? chalk.red.bold("MALICIOUS") : mal >= 1 || susp >= 2 ? chalk.yellow("SUSPICIOUS") : chalk.green("CLEAN");
    console.log(`\n  ${chalk.bold("VirusTotal verdict:")} ${verdict}${chalk.dim(`  (malicious=${mal}, suspicious=${susp}, harmless=${vt.analysisStats.harmless || 0}, undetected=${vt.analysisStats.undetected || 0}, reputation=${vt.reputation ?? 0})`)}`);
    if (vt.categories?.length) {
      console.log(chalk.dim("  Categories: ") + chalk.cyan(vt.categories.slice(0, 8).join(", ")));
    }
  }

  // Aggregated subdomains
  if (r.aggregated.subdomains.length) {
    const sample = r.aggregated.subdomains.slice(0, 15);
    console.log(`\n  ${chalk.bold(`Aggregated subdomains (${r.aggregated.subdomains.length}):`)}`);
    console.log(chalk.dim("    " + sample.join(", ") + (r.aggregated.subdomains.length > 15 ? chalk.gray(` ... +${r.aggregated.subdomains.length - 15} more`) : "")));
  }

  // Aggregated resolved IPs
  if (r.aggregated.resolvedIps.length) {
    const sample = r.aggregated.resolvedIps.slice(0, 12);
    console.log(`\n  ${chalk.bold(`Resolved IPs (${r.aggregated.resolvedIps.length}):`)}`);
    console.log(chalk.dim("    " + sample.join(", ") + (r.aggregated.resolvedIps.length > 12 ? chalk.gray(` ... +${r.aggregated.resolvedIps.length - 12} more`) : "")));
  }

  // SecurityTrails IP history
  const st = r.sources.securitytrails;
  if (st.ok && st.ipHistory?.length) {
    const ht = new Table({
      head: [chalk.cyan("IP"), chalk.cyan("FIRST SEEN"), chalk.cyan("LAST SEEN")],
      colWidths: [20, 14, 14],
      style: { head: [], border: ["gray"] },
    });
    for (const h of st.ipHistory.slice(0, 8)) {
      ht.push([h.ip, (h.firstSeen || "").slice(0, 10), (h.lastSeen || "").slice(0, 10)]);
    }
    console.log(`\n  ${chalk.bold("SecurityTrails A-record history:")}`);
    console.log(ht.toString());
  }
}

function renderEmailSec(r: NonNullable<ScanResults["emailsec"]>) {
  const sevColor: Record<string, (s: string) => string> = {
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.cyan,
    info: chalk.dim,
  };
  // SPF
  const spfStatus = r.spf.present
    ? (r.spf.policy === "-all" ? chalk.green("HardFail (-all)")
       : r.spf.policy === "+all" ? chalk.red("PASS-ALL (+all)")
       : r.spf.policy === "~all" ? chalk.yellow("SoftFail (~all)")
       : r.spf.policy === "?all" ? chalk.yellow("Neutral (?all)")
       : chalk.yellow(String(r.spf.policy)))
    : chalk.red("MISSING");
  console.log(`  ${chalk.bold("SPF ")} ${spfStatus}${chalk.dim(`  (${r.spf.dnsLookups ?? 0} DNS lookups)`)}`);
  if (r.spf.record) console.log(chalk.dim("    " + r.spf.record.slice(0, 100) + (r.spf.record.length > 100 ? "..." : "")));
  // DMARC
  const dmarcStatus = r.dmarc.present
    ? (r.dmarc.policy === "reject" ? chalk.green("p=reject")
       : r.dmarc.policy === "quarantine" ? chalk.yellow("p=quarantine")
       : r.dmarc.policy === "none" ? chalk.yellow("p=none")
       : chalk.yellow(String(r.dmarc.policy)))
    : chalk.red("MISSING");
  console.log(`  ${chalk.bold("DMARC")} ${dmarcStatus}${chalk.dim(`  (pct=${r.dmarc.pct ?? 0}${r.dmarc.rua ? ", rua=" + r.dmarc.rua.slice(0, 30) : ""})`)}`);
  if (r.dmarc.record) console.log(chalk.dim("    " + r.dmarc.record.slice(0, 100) + (r.dmarc.record.length > 100 ? "..." : "")));
  // DKIM
  const dkimStatus = r.dkim.found.length
    ? chalk.green(`${r.dkim.found.length} selector(s) found`)
    : chalk.yellow(`none found (${r.dkim.selectorsChecked.length} checked)`);
  console.log(`  ${chalk.bold("DKIM")} ${dkimStatus}`);
  for (const f of r.dkim.found.slice(0, 5)) {
    console.log(chalk.dim(`    ${f.selector}._domainkey -> ${f.record}`));
  }
  // MX
  const mxStatus = r.mx.servers.length
    ? chalk.green(`${r.mx.servers.length} server(s)`) + chalk.dim(r.mx.providers.length ? " (" + r.mx.providers.join(", ") + ")" : "")
    : chalk.dim("no MX records");
  console.log(`  ${chalk.bold("MX  ")} ${mxStatus}`);
  for (const s of r.mx.servers.slice(0, 5)) {
    console.log(chalk.dim(`    ${String(s.priority).padEnd(4)} ${s.exchange}`));
  }
  // Findings
  if (r.findings.length) {
    console.log(`\n  ${chalk.bold("Email security findings:")}`);
    for (const f of r.findings) {
      console.log(`    ${sevColor[f.severity](`[${f.severity.toUpperCase().padEnd(6)}]`)} ${f.title}`);
      console.log(chalk.dim(`           ${f.detail}`));
    }
  } else {
    console.log(`\n  ${chalk.green("No email security issues found.")}`);
  }
}

function renderOpenDirs(r: NonNullable<ScanResults["opendirs"]>) {
  if (r.directories.length) {
    console.log(`  ${chalk.bold("Open directory listings:")}`);
    const t = new Table({
      head: [chalk.cyan("URL"), chalk.cyan("LISTING TYPE"), chalk.cyan("SERVER")],
      colWidths: [44, 22, 16],
      style: { head: [], border: ["gray"] },
    });
    for (const d of r.directories) t.push([d.url, d.listingType, d.server.slice(0, 14)]);
    console.log(t.toString());
    for (const d of r.directories.slice(0, 6)) {
      if (d.sample.length) console.log(chalk.dim("    sample: " + d.sample.slice(0, 6).join(", ")));
    }
  } else {
    console.log(`  ${chalk.dim("No open directory listings found.")}`);
  }
  if (r.exposedFiles.length) {
    console.log(`\n  ${chalk.bold("Exposed sensitive files:")}`);
    const t = new Table({
      head: [chalk.cyan("URL"), chalk.cyan("STATUS"), chalk.cyan("SIZE"), chalk.cyan("TYPE")],
      colWidths: [46, 9, 9, 11],
      style: { head: [], border: ["gray"] },
    });
    for (const f of r.exposedFiles) t.push([f.url, String(f.status), String(f.size) + "b", f.type]);
    console.log(t.toString());
  }
  if (!r.directories.length && !r.exposedFiles.length) {
    console.log(`  ${chalk.green("No open directories or exposed files.")}`);
  }
}

function renderFirewall(r: NonNullable<ScanResults["firewall"]>) {
  for (const h of r.hosts) {
    console.log(`  ${chalk.bold(h.url)}`);
    if (h.detected.length) {
      for (const d of h.detected) {
        const conf = d.confidence === "high" ? chalk.green : chalk.yellow;
        console.log(`    ${conf("[WAF]")} ${d.name} (${d.confidence}) ${chalk.dim(d.evidence.join(", "))}`);
      }
    } else {
      console.log(`    ${chalk.dim("no WAF signatures detected")}`);
    }
    if (h.blockStatus !== null) {
      console.log(`    ${chalk.yellow("[BLOCK]")} attack payload blocked with HTTP ${h.blockStatus}`);
    }
    if (h.methods.length) {
      const risky = h.methods.filter((m) => ["PUT", "DELETE", "TRACE", "CONNECT"].includes(m));
      const mStr = h.methods.map((m) => (risky.includes(m) ? chalk.yellow(m) : m)).join(", ");
      console.log(`    ${chalk.dim("methods:")} ${mStr}`);
    }
    if (h.cors.enabled) {
      const flags = [h.cors.wildcard ? chalk.red("wildcard") : null, h.cors.reflected ? chalk.red("reflects-origin") : null, h.cors.credentials ? chalk.yellow("credentials") : null].filter(Boolean);
      console.log(`    ${chalk.dim("cors:")} ${chalk.cyan(h.cors.origin)}${flags.length ? chalk.dim(" (" + flags.join(", ") + ")") : ""}`);
    }
  }
  if (r.attackSurface.length) {
    console.log(`\n  ${chalk.bold("Attack surface (robots.txt / sitemap.xml):")}`);
    for (const s of r.attackSurface) {
      console.log(`    ${chalk.cyan(s.source)}`);
      console.log(chalk.dim("      " + s.paths.slice(0, 12).join(", ") + (s.paths.length > 12 ? chalk.gray(` ... +${s.paths.length - 12}`) : "")));
    }
  }
  if (r.bypassPayloads.length) {
    const totalPl = r.bypassPayloads.reduce((a, p) => a + p.payloads.length, 0);
    console.log(`\n  ${chalk.bold(`WAF-bypass payload suggestions (${r.bypassPayloads.length} sets, ${totalPl} payloads):`)}`);
    for (const p of r.bypassPayloads) {
      console.log(`    ${chalk.magenta("[" + p.waf + "]")} ${chalk.cyan(p.category)} ${chalk.dim(`(${p.payloads.length} payloads)`)}`);
      const sample = p.payloads.slice(0, 8);
      for (const pl of sample) {
        console.log(`      ${chalk.green(pl.slice(0, 70))}`);
      }
      if (p.payloads.length > 8) {
        console.log(chalk.gray(`      ... +${p.payloads.length - 8} more (use --output json for full list)`));
      }
      console.log(chalk.dim("      note: " + p.note));
    }
  }
}

function renderSubTakeover(r: NonNullable<ScanResults["subtakeover"]>) {
  console.log(chalk.dim(`  Checked ${r.checked} host(s).`));
  if (!r.vulnerable.length) {
    console.log(`  ${chalk.green("No subdomain takeover vulnerabilities detected.")}`);
    return;
  }
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan };
  console.log(`  ${chalk.bold(`Vulnerable: ${r.vulnerable.length}`)}`);
  const t = new Table({
    head: [chalk.cyan("HOSTNAME"), chalk.cyan("CNAME"), chalk.cyan("SERVICE"), chalk.cyan("SEV"), chalk.cyan("FINGERPRINT")],
    colWidths: [30, 28, 14, 8, 26],
    style: { head: [], border: ["gray"] },
  });
  for (const v of r.vulnerable) {
    t.push([v.hostname, v.cname.slice(0, 28), v.service, sevColor[v.severity](v.severity), v.fingerprint.slice(0, 26)]);
  }
  console.log(t.toString());
}

function renderCloudEnum(r: NonNullable<ScanResults["cloudenum"]>) {
  if (r.buckets.length) {
    console.log(`  ${chalk.bold("Storage buckets:")}`);
    const t = new Table({
      head: [chalk.cyan("PROVIDER"), chalk.cyan("NAME"), chalk.cyan("EXISTS"), chalk.cyan("PUBLIC"), chalk.cyan("LISTING")],
      colWidths: [13, 27, 9, 10, 11],
      style: { head: [], border: ["gray"] },
    });
    for (const b of r.buckets) {
      t.push([b.provider, b.name.slice(0, 25), b.exists ? chalk.green("yes") : chalk.dim("no"), b.public ? chalk.red("PUBLIC") : chalk.dim("-"), b.listing ? chalk.red("listing") : chalk.dim("-")]);
    }
    console.log(t.toString());
    for (const b of r.buckets.filter((x) => x.listing && x.sample.length).slice(0, 4)) {
      console.log(chalk.dim(`    ${b.provider}/${b.name}: ${b.sample.slice(0, 4).join(", ")}`));
    }
  } else {
    console.log(`  ${chalk.dim("No cloud storage buckets found.")}`);
  }
  if (r.repos.length) {
    console.log(`\n  ${chalk.bold("Code repositories:")}`);
    const t = new Table({
      head: [chalk.cyan("PROVIDER"), chalk.cyan("NAME"), chalk.cyan("EXISTS"), chalk.cyan("VISIBILITY")],
      colWidths: [13, 27, 9, 13],
      style: { head: [], border: ["gray"] },
    });
    for (const r2 of r.repos) {
      t.push([r2.provider, r2.name.slice(0, 25), r2.exists ? chalk.green("yes") : chalk.dim("no"), r2.exists && !r2.private ? chalk.green("public") : r2.private ? chalk.yellow("private") : chalk.dim("-")]);
    }
    console.log(t.toString());
  }
  if (!r.buckets.length && !r.repos.length) {
    console.log(`  ${chalk.green("No cloud assets discovered.")}`);
  }
}

function renderScreenshots(r: NonNullable<ScanResults["screenshots"]>) {
  for (const h of r.hosts) {
    console.log(`  ${chalk.bold(h.url)}${chalk.dim(` (${h.statusCode})`)}`);
    if (h.title) console.log(`    ${chalk.cyan("title:")} ${h.title}`);
    if (h.server) console.log(chalk.dim(`    server: ${h.server}${h.poweredBy ? " | x-powered-by: " + h.poweredBy : ""}`));
    if (h.faviconHash) console.log(chalk.dim(`    favicon: sha256=${h.faviconHash.slice(0, 16)}... mmh3=${h.faviconMmh || "?"}`));
    if (h.redirectChain.length > 1) {
      console.log(chalk.dim(`    redirects: ${h.redirectChain.length} hop(s)`));
      for (const hop of h.redirectChain.slice(0, 4)) {
        console.log(chalk.dim(`      ${hop.status} -> ${hop.url.slice(0, 60)}`));
      }
    }
    const sh = h.securityHeaders;
    const shFlags = [sh.hsts ? chalk.green("hsts") : chalk.red("hsts"), sh.csp ? chalk.green("csp") : chalk.red("csp"), sh.xfo ? chalk.green("xfo") : chalk.yellow("xfo"), sh.xcto ? chalk.green("xcto") : chalk.yellow("xcto"), sh.referrer ? chalk.green("referrer") : chalk.dim("referrer")];
    console.log(`    ${chalk.dim("headers:")} ${shFlags.join(" ")}`);
    if (h.cookies.length) {
      const insecure = h.cookies.filter((c) => !c.secure || !c.httpOnly).length;
      console.log(chalk.dim(`    cookies: ${h.cookies.length}`) + (insecure ? chalk.red(` (${insecure} insecure)`) : chalk.green(" (all secure)")));
    }
    console.log(chalk.dim(`    forms: ${h.forms} | inputs: ${h.inputs} | js: ${h.jsFiles} | ext-links: ${h.externalLinks}`));
    if (h.tlsIssuer) console.log(chalk.dim(`    TLS issuer: ${h.tlsIssuer}`));
  }
}

function renderJsAnalyze(r: NonNullable<ScanResults["jsanalyze"]>) {
  if (!r.files.length) {
    console.log(chalk.dim("  no JavaScript files analyzed"));
    return;
  }
  for (const f of r.files) {
    console.log(`  ${chalk.bold(f.url)}${chalk.dim(` (${(f.size / 1024).toFixed(1)} KB)`)}`);
    if (f.secrets.length) {
      console.log(`    ${chalk.red.bold(`Secrets (${f.secrets.length}):`)}`);
      for (const s of f.secrets.slice(0, 12)) {
        console.log(`      ${chalk.red(s.type)} ${chalk.cyan(s.value.slice(0, 50))}${chalk.dim(` (line ${s.line})`)}`);
      }
    }
    if (f.cloudKeys.length) {
      console.log(`    ${chalk.magenta.bold(`Cloud keys (${f.cloudKeys.length}):`)}`);
      for (const k of f.cloudKeys.slice(0, 8)) {
        console.log(`      ${chalk.magenta(k.provider)}: ${chalk.cyan(k.key.slice(0, 40))}`);
      }
    }
    if (f.endpoints.length) {
      console.log(`    ${chalk.green(`Endpoints (${f.endpoints.length}):`)} ${f.endpoints.slice(0, 10).join(", ")}`);
    }
    if (f.internalUrls.length) {
      console.log(`    ${chalk.yellow(`Internal URLs (${f.internalUrls.length}):`)}`);
      for (const u of f.internalUrls.slice(0, 6)) console.log(`      ${chalk.yellow(u.slice(0, 70))}`);
    }
  }
}

function renderApi(r: NonNullable<ScanResults["api"]>) {
  if (r.endpoints.length) {
    console.log(`  ${chalk.bold(`Discovered endpoints (${r.endpoints.length}):`)}`);
    const t = new Table({
      head: [chalk.cyan("METHOD"), chalk.cyan("URL"), chalk.cyan("SOURCE"), chalk.cyan("PARAMS")],
      colWidths: [9, 54, 9, 23],
      style: { head: [], border: ["gray"] },
    });
    for (const e of r.endpoints.slice(0, 25)) t.push([e.method, e.url.slice(0, 52), e.source, e.params.slice(0, 3).join(",")]);
    console.log(t.toString());
  } else {
    console.log(`  ${chalk.dim("No API endpoints discovered.")}`);
  }
  if (r.graphql.length) {
    console.log(`\n  ${chalk.bold("GraphQL endpoints:")}`);
    for (const g of r.graphql) {
      const intro = g.introspection ? chalk.red("INTROSPECTION ENABLED") : chalk.green("introspection disabled");
      console.log(`    ${g.url} — ${intro}`);
      if (g.types.length) console.log(chalk.dim(`      types: ${g.types.slice(0, 10).join(", ")}`));
    }
  }
  if (r.swagger.length) {
    console.log(`\n  ${chalk.bold("Swagger/OpenAPI docs:")}`);
    const t = new Table({
      head: [chalk.cyan("URL"), chalk.cyan("VERSION"), chalk.cyan("TITLE"), chalk.cyan("PATHS")],
      colWidths: [46, 11, 21, 7],
      style: { head: [], border: ["gray"] },
    });
    for (const s of r.swagger) t.push([s.url.slice(0, 44), s.version, s.title.slice(0, 19), String(s.paths)]);
    console.log(t.toString());
  }
  if (r.versionedApis.length) {
    console.log(`\n  ${chalk.bold("Versioned APIs:")}`);
    const t = new Table({
      head: [chalk.cyan("VERSION"), chalk.cyan("URL"), chalk.cyan("STATUS")],
      colWidths: [11, 52, 8],
      style: { head: [], border: ["gray"] },
    });
    for (const v of r.versionedApis) t.push([v.version, v.url.slice(0, 50), String(v.status)]);
    console.log(t.toString());
  }
}

function renderInject(r: NonNullable<ScanResults["inject"]>) {
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan };
  if (!r.hosts.length || r.hosts.every((h) => !h.points.length)) {
    console.log(`  ${chalk.green("No injection points detected.")}`);
    return;
  }
  for (const h of r.hosts) {
    if (!h.points.length) continue;
    console.log(`  ${chalk.bold(h.url)}`);
    const t = new Table({
      head: [chalk.cyan("TYPE"), chalk.cyan("METHOD"), chalk.cyan("PARAM"), chalk.cyan("PAYLOAD"), chalk.cyan("EVIDENCE")],
      colWidths: [11, 8, 13, 29, 35],
      style: { head: [], border: ["gray"] },
    });
    for (const p of h.points) t.push([sevColor[p.severity](p.type.toUpperCase()), p.method, p.param, p.payload.slice(0, 28), p.evidence.slice(0, 34)]);
    console.log(t.toString());
  }
}

function renderWebDav(r: NonNullable<ScanResults["webdav"]>) {
  if (!r.hosts.length) {
    console.log(`  ${chalk.green("No WebDAV-enabled hosts detected.")}`);
    return;
  }
  for (const h of r.hosts) {
    console.log(`  ${chalk.bold(h.url)}`);
    console.log(`    ${h.enabled ? chalk.green("WebDAV enabled") : chalk.dim("not enabled")}`);
    if (h.methods.length) console.log(chalk.dim(`    methods: ${h.methods.join(", ")}`));
    if (h.writable) console.log(`    ${chalk.red.bold("WRITABLE — file upload possible (RCE risk)")}`);
    if (h.propfindDepth) console.log(`    ${chalk.yellow("PROPFIND directory listing enabled")}`);
    for (const u of h.uploads) {
      const flag = u.success ? chalk.red("UPLOADED") : chalk.dim("blocked");
      console.log(`    ${flag} ${u.path.slice(0, 60)} (${u.status})`);
    }
  }
}

function renderSslTests(r: NonNullable<ScanResults["ssltests"]>) {
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.dim };
  if (!r.hosts.length) {
    console.log(chalk.dim("  no hosts tested"));
    return;
  }
  for (const h of r.hosts) {
    console.log(`  ${chalk.bold(h.host)}`);
    const protos = h.protocols.filter((p) => p.enabled).map((p) => (p.insecure ? chalk.red(p.name) : chalk.green(p.name)));
    console.log(`    ${chalk.dim("protocols:")} ${protos.length ? protos.join(", ") : chalk.dim("none")}`);
    if (h.ciphers.length) {
      const c = h.ciphers[0];
      console.log(`    ${chalk.dim("cipher:")} ${h.weakCiphers > 0 ? chalk.red(c.name) : chalk.green(c.name)}${chalk.dim(` (${c.strength})`)}`);
    }
    console.log(chalk.dim(`    cert chain: ${h.certChainLength} cert(s) | OCSP: ${h.ocspStapling ? "yes" : "no"} | HSTS: ${h.hsts ? "yes" : "no"}`));
    if (h.issues.length) {
      for (const iss of h.issues) {
        console.log(`    ${sevColor[iss.severity](`[${iss.severity.toUpperCase().padEnd(6)}]`)} ${iss.title}`);
        console.log(chalk.dim(`           ${iss.detail}`));
      }
    } else {
      console.log(`    ${chalk.green("no SSL/TLS issues")}`);
    }
  }
}

function renderCrawl(r: NonNullable<ScanResults["crawl"]>) {
  if (r.pages.length) {
    console.log(`  ${chalk.bold(`Crawled pages (${r.pages.length}):`)}`);
    const t = new Table({
      head: [chalk.cyan("DEPTH"), chalk.cyan("STATUS"), chalk.cyan("TITLE"), chalk.cyan("LINKS"), chalk.cyan("FORMS")],
      colWidths: [7, 8, 32, 7, 7],
      style: { head: [], border: ["gray"] },
    });
    for (const p of r.pages.slice(0, 20)) t.push([String(p.depth), String(p.status), p.title.slice(0, 30), String(p.links), String(p.forms)]);
    console.log(t.toString());
  }
  if (r.internalLinks.length) {
    console.log(`\n  ${chalk.bold(`Internal links (${r.internalLinks.length}):`)}`);
    console.log(chalk.dim("    " + r.internalLinks.slice(0, 12).join(", ") + (r.internalLinks.length > 12 ? chalk.gray(` ... +${r.internalLinks.length - 12}`) : "")));
  }
  if (r.externalLinks.length) {
    console.log(`\n  ${chalk.bold(`External origins (${r.externalLinks.length}):`)}`);
    console.log(chalk.dim("    " + r.externalLinks.slice(0, 12).join(", ")));
  }
  if (r.emails.length) {
    console.log(`\n  ${chalk.red.bold(`Emails found (${r.emails.length}):`)}`);
    console.log("    " + r.emails.slice(0, 15).map((e) => chalk.red(e)).join(", "));
  }
  if (r.phones.length) {
    console.log(`\n  ${chalk.yellow.bold(`Phones found (${r.phones.length}):`)}`);
    console.log("    " + r.phones.slice(0, 10).join(", "));
  }
  if (r.files.length) {
    console.log(`\n  ${chalk.cyan.bold(`Files found (${r.files.length}):`)}`);
    for (const f of r.files.slice(0, 10)) console.log(`    ${chalk.cyan(f.slice(0, 70))}`);
  }
}

function renderRecon(r: NonNullable<ScanResults["recon"]>) {
  console.log(`  ${chalk.bold("WHOIS / RDAP:")}`);
  if (r.whois.registrar) console.log(`    ${chalk.dim("Registrar:")} ${chalk.cyan(r.whois.registrar)}`);
  if (r.whois.createdDate) console.log(`    ${chalk.dim("Created:")}  ${r.whois.createdDate}`);
  if (r.whois.expiryDate) console.log(`    ${chalk.dim("Expires:")}  ${r.whois.expiryDate}`);
  if (r.whois.registrantOrg) console.log(`    ${chalk.dim("Registrant:")} ${r.whois.registrantOrg}${r.whois.registrantCountry ? ` (${r.whois.registrantCountry})` : ""}`);
  if (r.whois.nameServers?.length) console.log(`    ${chalk.dim("NS:")} ${r.whois.nameServers.slice(0, 4).join(", ")}`);
  if (!r.whois.registrar && !r.whois.createdDate) console.log(`    ${chalk.dim("no RDAP data")}`);
  if (r.asn.asn) {
    console.log(`\n  ${chalk.bold("ASN:")}`);
    console.log(`    ${chalk.dim("AS:")} ${chalk.cyan(r.asn.asn)}${chalk.dim(" | Org:")} ${r.asn.org}${chalk.dim(" | Net:")} ${r.asn.network || "?"}`);
  }
  if (r.geo.city) {
    console.log(`\n  ${chalk.bold("GeoIP:")}`);
    console.log(`    ${chalk.dim("IP:")} ${r.geo.ip}`);
    console.log(`    ${chalk.dim("Location:")} ${chalk.cyan(`${r.geo.city}, ${r.geo.region || ""}, ${r.geo.country || ""}`)}`);
    if (r.geo.lat && r.geo.lon) console.log(`    ${chalk.dim("Coords:")} ${r.geo.lat}, ${r.geo.lon}`);
    if (r.geo.isp) console.log(`    ${chalk.dim("ISP:")} ${r.geo.isp}`);
  }
  if (r.reverseDns.length) {
    console.log(`\n  ${chalk.bold("Reverse DNS:")}`);
    for (const h of r.reverseDns.slice(0, 5)) console.log(`    ${chalk.cyan(r.geo.ip)}${chalk.dim(" ->")} ${h}`);
  }
}

function renderSpider(r: NonNullable<ScanResults["spider"]>) {
  if (r.pages.length) {
    console.log(`  ${chalk.bold(`Spidered pages (${r.pages.length}):`)}`);
    const t = new Table({
      head: [chalk.cyan("D"), chalk.cyan("STATUS"), chalk.cyan("TITLE"), chalk.cyan("FORMS"), chalk.cyan("HIDDEN"), chalk.cyan("JS")],
      colWidths: [4, 8, 28, 8, 8, 6],
      style: { head: [], border: ["gray"] },
    });
    for (const p of r.pages.slice(0, 15)) t.push([String(p.depth), String(p.status), p.title.slice(0, 26), String(p.forms.length), String(p.hiddenInputs.length), String(p.jsFiles.length)]);
    console.log(t.toString());
  }
  if (r.allForms.length) {
    console.log(`\n  ${chalk.bold(`Discovered forms (${r.allForms.length}):`)}`);
    for (const f of r.allForms.slice(0, 10)) {
      console.log(`    ${chalk.cyan(f.method)} ${f.action.slice(0, 55)}${chalk.dim(` (${f.inputs.length} inputs)`)}`);
      for (const inp of f.inputs.slice(0, 4)) {
        const hidden = inp.type === "hidden" ? chalk.yellow(" [hidden]") : "";
        console.log(`      ${inp.name}${chalk.dim(` (${inp.type})`)}${hidden}${inp.value ? chalk.dim(` = ${inp.value.slice(0, 30)}`) : ""}`);
      }
    }
  }
  if (r.allParams.length) {
    console.log(`\n  ${chalk.bold(`Discovered parameters (${r.allParams.length}):`)}`);
    console.log(chalk.dim("    " + r.allParams.slice(0, 25).join(", ")));
  }
  if (r.sitemapUrls.length) {
    console.log(`\n  ${chalk.bold(`Sitemap URLs (${r.sitemapUrls.length}):`)}`);
    console.log(chalk.dim("    " + r.sitemapUrls.slice(0, 10).join(", ")));
  }
}

function renderWayback(r: NonNullable<ScanResults["wayback"]>) {
  console.log(`  ${chalk.bold(`Total archived URLs: ${r.totalUrls}`)}`);
  if (r.archivedPaths.length) {
    console.log(`\n  ${chalk.bold(`Unique archived paths (${r.archivedPaths.length}):`)}`);
    const t = new Table({ head: [chalk.cyan("PATH")], colWidths: [70], style: { head: [], border: ["gray"] } });
    for (const p of r.archivedPaths.slice(0, 20)) t.push([p.slice(0, 68)]);
    console.log(t.toString());
  }
  if (r.deletedPages.length) {
    console.log(`\n  ${chalk.red.bold(`Deleted/404 pages in archive (${r.deletedPages.length}):`)}`);
    const t = new Table({ head: [chalk.cyan("URL"), chalk.cyan("LAST SEEN")], colWidths: [56, 14], style: { head: [], border: ["gray"] } });
    for (const d of r.deletedPages.slice(0, 15)) t.push([d.url.slice(0, 54), d.lastSeen]);
    console.log(t.toString());
  }
  if (r.fileTypes.length) {
    console.log(`\n  ${chalk.bold("File types in archive:")}`);
    const t = new Table({ head: [chalk.cyan("EXT"), chalk.cyan("COUNT")], colWidths: [13, 9], style: { head: [], border: ["gray"] } });
    for (const f of r.fileTypes.slice(0, 15)) t.push([f.ext, String(f.count)]);
    console.log(t.toString());
  }
}

function renderHostHeader(r: NonNullable<ScanResults["hostheader"]>) {
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.dim };
  for (const h of r.hosts) {
    if (!h.findings.length) continue;
    console.log(`  ${chalk.bold(h.url)}`);
    for (const f of h.findings) {
      console.log(`    ${sevColor[f.severity](`[${f.severity.toUpperCase().padEnd(6)}]`)} ${f.title}`);
      console.log(chalk.dim(`           ${f.detail}`));
      if (f.evidence) console.log(chalk.gray(`           evidence: ${f.evidence.slice(0, 80)}`));
    }
  }
  if (r.ssrfTestPoints.length) {
    console.log(`\n  ${chalk.bold(`SSRF test points (${r.ssrfTestPoints.length}):`)}`);
    for (const s of r.ssrfTestPoints.slice(0, 15)) {
      console.log(`    ${chalk.magenta(s.param)}${chalk.gray(" @ ")}${s.url.slice(0, 55)}`);
      console.log(chalk.dim(`      ${s.note.slice(0, 80)}`));
    }
  }
  if (r.crlfTests.length) {
    console.log(`\n  ${chalk.bold(`CRLF injection tests (${r.crlfTests.length}):`)}`);
    for (const c of r.crlfTests) {
      const flag = c.injected ? chalk.red("VULNERABLE") : chalk.green("not vulnerable");
      console.log(`    ${flag} ${c.url.slice(0, 50)}`);
      if (c.injected) console.log(chalk.dim(`      ${c.evidence.slice(0, 80)}`));
    }
  }
}

function renderAuth(r: NonNullable<ScanResults["auth"]>) {
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.dim };
  for (const h of r.hosts) {
    if (!h.findings.length) continue;
    console.log(`  ${chalk.bold(h.url)}`);
    for (const f of h.findings) {
      console.log(`    ${sevColor[f.severity](`[${f.severity.toUpperCase().padEnd(6)}]`)} ${f.title}`);
      console.log(chalk.dim(`           ${f.detail}`));
    }
  }
  const success = r.defaultCreds?.filter((d) => d.success) || [];
  if (success.length) {
    console.log(`\n  ${chalk.red.bold("Default credentials found:")}`);
    for (const d of success) console.log(`    ${chalk.red(d.panel)}${chalk.gray(" @ ")}${d.url.slice(0, 50)}`);
  }
  const jwtVuln = r.jwtTests?.filter((j) => j.noneAlgAccepted || j.weakSecret) || [];
  if (jwtVuln.length) {
    console.log(`\n  ${chalk.red.bold("JWT vulnerabilities:")}`);
    for (const j of jwtVuln) {
      console.log(`    ${j.url.slice(0, 50)} — ${j.noneAlgAccepted ? chalk.red("none-alg accepted") : ""} ${j.weakSecret ? chalk.red("weak secret") : ""}`);
      console.log(chalk.dim(`      ${j.detail}`));
    }
  }
}

function renderCsrf(r: NonNullable<ScanResults["csrf"]>) {
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.dim };
  for (const h of r.hosts) {
    console.log(`  ${chalk.bold(h.url)}`);
    const vuln = h.forms.filter((f) => f.vulnerable);
    console.log(`    ${chalk.dim(`Forms: ${h.forms.length} (${vuln.length} vulnerable)`)}`);
    for (const f of vuln.slice(0, 8)) {
      console.log(`      ${chalk.yellow(f.method)} ${f.action.slice(0, 50)} ${chalk.red("— " + f.reason)}`);
    }
    for (const f of h.findings) {
      console.log(`    ${sevColor[f.severity](`[${f.severity.toUpperCase().padEnd(6)}]`)} ${f.title}`);
      console.log(chalk.dim(`           ${f.detail}`));
    }
  }
}

function renderDeser(r: NonNullable<ScanResults["deserialization"]>) {
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.dim };
  for (const h of r.hosts) {
    if (!h.endpoints.length && !h.findings.length) continue;
    console.log(`  ${chalk.bold(h.url)}`);
    const susp = h.endpoints.filter((e) => e.suspicious);
    if (susp.length) {
      console.log(`    ${chalk.red.bold(`Suspicious sinks (${susp.length}):`)}`);
      for (const e of susp.slice(0, 10)) {
        console.log(`      ${chalk.magenta(e.technique)}${chalk.dim(" param=")}${chalk.cyan(e.param)}${chalk.dim(` (${e.method})`)}`);
        console.log(chalk.dim(`        ${e.response.slice(0, 70)}`));
      }
    }
    for (const f of h.findings) {
      console.log(`    ${sevColor[f.severity](`[${f.severity.toUpperCase().padEnd(6)}]`)} ${f.title}`);
      console.log(chalk.dim(`           ${f.detail}`));
    }
  }
}

function renderSmuggling(r: NonNullable<ScanResults["smuggling"]>) {
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.dim };
  for (const h of r.hosts) {
    if (!h.tests.length && !h.findings.length) continue;
    console.log(`  ${chalk.bold(h.url)}`);
    const anom = h.tests.filter((t) => t.timingAnomaly || t.responseDiff);
    if (anom.length) {
      console.log(`    ${chalk.red.bold(`Smuggling anomalies (${anom.length}):`)}`);
      for (const t of anom) {
        console.log(`      ${chalk.magenta(t.technique)}${t.timingAnomaly ? chalk.red(" timing") : ""}${t.responseDiff ? chalk.red(" response-diff") : ""}`);
        console.log(chalk.dim(`        ${t.detail.slice(0, 70)}`));
      }
    }
    for (const f of h.findings) {
      console.log(`    ${sevColor[f.severity](`[${f.severity.toUpperCase().padEnd(6)}]`)} ${f.title}`);
      console.log(chalk.dim(`           ${f.detail}`));
    }
  }
}

function renderCache(r: NonNullable<ScanResults["cache"]>) {
  const sevColor: Record<string, (s: string) => string> = { high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.dim };
  for (const h of r.hosts) {
    if (!h.findings.length) continue;
    console.log(`  ${chalk.bold(h.url)}`);
    const refl = h.unkeyedHeaders?.filter((u) => u.reflected) || [];
    if (refl.length) {
      console.log(`    ${chalk.yellow("Unkeyed headers reflected:")}`);
      for (const u of refl) console.log(`      ${chalk.yellow(u.header)}${chalk.gray(" — ")}${u.evidence.slice(0, 60)}`);
    }
    const pois = h.cachePoisoning?.filter((p) => p.poisoned) || [];
    if (pois.length) {
      console.log(`    ${chalk.red.bold("Cache poisoning confirmed:")}`);
      for (const p of pois) console.log(`      ${chalk.red(p.header)} = ${p.value.slice(0, 40)}`);
    }
    const wcd = h.webCacheDeception?.filter((w) => w.cached) || [];
    if (wcd.length) {
      console.log(`    ${chalk.red.bold("Web cache deception:")}`);
      for (const w of wcd) console.log(`      ${chalk.cyan(w.path)} — cached private content`);
    }
    for (const f of h.findings) {
      console.log(`    ${sevColor[f.severity](`[${f.severity.toUpperCase().padEnd(6)}]`)} ${f.title}`);
      console.log(chalk.dim(`           ${f.detail}`));
    }
  }
}

async function runScan(targetRaw: string, opts: Record<string, any>) {
  const target = normalizeTarget(targetRaw);
  console.log(chalk.hex("#7c3aed")(BANNER));

  const config = defaultConfig(target);
  if (opts.modules) config.modules = parseModules(opts.modules);
  if (opts.ports) config.ports = parsePorts(opts.ports);
  else config.ports = [...DEFAULT_PORTS];
  if (opts.timeout) config.timeout = parseInt(opts.timeout, 10);
  if (opts.concurrency) config.concurrency = parseInt(opts.concurrency, 10);
  if (opts.noSubdomains) config.enumerateSubdomains = false;
  if (opts.maxSubdomains) config.maxSubdomains = parseInt(opts.maxSubdomains, 10);

  const scanner = new EasmScanner(config);
  const results: ScanResults = {};

  let currentModule: ModuleId | null = null;

  scanner.on("event", (ev: ScanEvent) => {
    switch (ev.type) {
      case "banner":
        console.log(chalk.bold.magenta(`[+] Starting EASM scan on ${ev.target}`));
        hr();
        break;
      case "module:start": {
        currentModule = ev.module;
        console.log(chalk.bold.cyan(`\n■ ${MODULE_LABEL[ev.module]}`));
        break;
      }
      case "module:end":
        break;
      case "log":
        if (ev.log.module === currentModule || ev.log.module) {
          const c = LEVEL_COLOR[ev.log.level] || chalk.dim;
          console.log(c(`  ${ev.log.message}`));
        } else {
          const c = LEVEL_COLOR[ev.log.level] || chalk.dim;
          console.log(c(`  ${ev.log.message}`));
        }
        break;
      case "progress":
        if (ev.module === "ports" && ev.current % 10 === 0) {
          process.stdout.write(chalk.dim(`\r  ports: ${ev.current}/${ev.total}    `));
        }
        break;
      case "result": {
        process.stdout.write("\r" + " ".repeat(40) + "\r");
        const data = ev.data as any;
        switch (ev.module) {
          case "dns": results.dns = data; renderDns(data); break;
          case "subdomains": results.subdomains = data; renderSubdomains(data); break;
          case "ports": results.ports = data; renderPorts(data); break;
          case "http": results.http = data; renderHttp(data); break;
          case "tls": results.tls = data; renderTls(data); break;
          case "tech": results.tech = data; renderTech(data); break;
          case "banners": results.banners = data; renderBanners(data); break;
          case "vulns": results.vulns = data; renderVulns(data); break;
          case "threatintel": results.threatintel = data; renderThreatIntel(data); break;
          case "emailsec": results.emailsec = data; renderEmailSec(data); break;
          case "opendirs": results.opendirs = data; renderOpenDirs(data); break;
          case "firewall": results.firewall = data; renderFirewall(data); break;
          case "subtakeover": results.subtakeover = data; renderSubTakeover(data); break;
          case "cloudenum": results.cloudenum = data; renderCloudEnum(data); break;
          case "screenshots": results.screenshots = data; renderScreenshots(data); break;
          case "jsanalyze": results.jsanalyze = data; renderJsAnalyze(data); break;
          case "api": results.api = data; renderApi(data); break;
          case "inject": results.inject = data; renderInject(data); break;
          case "webdav": results.webdav = data; renderWebDav(data); break;
          case "ssltests": results.ssltests = data; renderSslTests(data); break;
          case "crawl": results.crawl = data; renderCrawl(data); break;
          case "recon": results.recon = data; renderRecon(data); break;
          case "spider": results.spider = data; renderSpider(data); break;
          case "wayback": results.wayback = data; renderWayback(data); break;
          case "hostheader": results.hostheader = data; renderHostHeader(data); break;
          case "auth": results.auth = data; renderAuth(data); break;
          case "csrf": results.csrf = data; renderCsrf(data); break;
          case "deserialization": results.deserialization = data; renderDeser(data); break;
          case "smuggling": results.smuggling = data; renderSmuggling(data); break;
          case "cache": results.cache = data; renderCache(data); break;
        }
        break;
      }
      case "done": {
        process.stdout.write("\r" + " ".repeat(40) + "\r");
        hr();
        const s = ev.summary;
        console.log(chalk.bold.magenta(`\n[✓] Scan complete in ${(s.durationMs / 1000).toFixed(2)}s`));
        const t = new Table({
          head: [chalk.cyan("CATEGORY"), chalk.cyan("FINDINGS")],
          colWidths: [28, 14],
          style: { head: [], border: ["gray"] },
        });
        const labels: [string, string][] = [
          ["DNS records", String(s.findings.dnsRecords)],
          ["Subdomains", String(s.findings.subdomains)],
          ["Open ports", String(s.findings.openPorts)],
          ["HTTP services", String(s.findings.httpServices)],
          ["TLS certificates", String(s.findings.tlsCerts)],
          ["Technologies", String(s.findings.technologies)],
          ["Service banners", String(s.findings.banners)],
          ["Vulnerabilities", String(s.findings.vulnerabilities)],
          ["Intel sources OK", `${s.findings.threatIntelSources}/4`],
          ["Intel subdomains", String(s.findings.threatIntelSubdomains)],
          ["Email sec issues", String(s.findings.emailSecIssues)],
          ["Open dirs / files", String(s.findings.openDirs)],
          ["Firewalls detected", String(s.findings.firewallsDetected)],
          ["Bypass payload sets", String(s.findings.bypassPayloads)],
          ["Attack-surface paths", String(s.findings.attackSurfacePaths)],
          ["Takeover vulnerable", String(s.findings.takeoverVulnerable)],
          ["Cloud assets", String(s.findings.cloudAssets)],
          ["HTTP fingerprints", String(s.findings.httpFingerprints)],
          ["JS secrets found", String(s.findings.jsSecrets)],
          ["JS endpoints", String(s.findings.jsEndpoints)],
          ["API endpoints", String(s.findings.apiEndpoints)],
          ["Injection points", String(s.findings.injectPoints)],
          ["WebDAV hosts", String(s.findings.webdavEnabled)],
          ["SSL/TLS issues", String(s.findings.sslIssues)],
          ["Crawled pages", String(s.findings.crawledPages)],
          ["Crawled links", String(s.findings.crawledLinks)],
          ["Recon records", String(s.findings.reconRecords)],
          ["Spider pages", String(s.findings.spiderPages)],
          ["Spider forms", String(s.findings.spiderForms)],
          ["Wayback URLs", String(s.findings.waybackUrls)],
          ["Host header issues", String(s.findings.hostHeaderIssues)],
          ["Auth issues", String(s.findings.authIssues)],
          ["CSRF issues", String(s.findings.csrfIssues)],
          ["Deser issues", String(s.findings.deserIssues)],
          ["Smuggling issues", String(s.findings.smugglingIssues)],
          ["Cache issues", String(s.findings.cacheIssues)],
        ];
        for (const [k, v] of labels) t.push([k, v]);
        console.log(t.toString());
        if (opts.output === "json") {
          console.log(chalk.dim("\n--- JSON REPORT ---"));
          console.log(JSON.stringify({ summary: s, results }, null, 2));
        }
        break;
      }
    }
  });

  await scanner.run();
}

const program = new Command();
program
  .name("easm")
  .description("Advanced External Attack Surface Management - terminal edition")
  .version("1.0.0");

program
  .command("scan <target>")
  .description("Run an attack-surface scan against <target> (domain or host)")
  .option("-m, --modules <list>", `comma-separated modules: ${ALL_MODULES.join(",")}`)
  .option("-p, --ports <list>", "comma-separated ports / ranges, e.g. 80,443,8000-8100")
  .option("-t, --timeout <ms>", "per-host connect timeout in ms", "4000")
  .option("-c, --concurrency <n>", "scan concurrency", "50")
  .option("--no-subdomains", "skip subdomain enumeration")
  .option("--max-subdomains <n>", "cap number of subdomains kept", "40")
  .option("-o, --output <fmt>", "output format: table (default) | json", "table")
  .action(runScan);

// allow `easm example.com` shorthand
program
  .argument("[target]", "target (shorthand for scan)")
  .allowUnknownOption()
  .action((target: string | undefined) => {
    if (!target) {
      program.help();
      return;
    }
    const rest = process.argv.slice(process.argv.indexOf(target) + 1);
    runScan(target, rest.reduce((acc, cur, i, arr) => {
      if (cur.startsWith("--")) {
        const key = cur.replace(/^--/, "").replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        const val = arr[i + 1] && !arr[i + 1].startsWith("--") ? arr[i + 1] : true;
        acc[key] = val;
      }
      return acc;
    }, {} as Record<string, any>));
  });

program.parseAsync(process.argv).catch((e) => {
  console.error(chalk.red(`Fatal: ${e?.message || e}`));
  process.exit(1);
});
