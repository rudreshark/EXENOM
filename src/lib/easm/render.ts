/**
 * ANSI renderer for EASM scan events.
 * Produces colored terminal strings consumable by xterm.js in the browser.
 */
import type {
  ScanEvent,
  ScanResults,
  DnsResult,
  SubdomainResult,
  PortResult,
  HttpResult,
  TlsResult,
  TechResult,
  BannerResult,
  VulnResult,
  ThreatIntelResult,
  ThreatIntelSource,
  EmailSecResult,
  OpenDirResult,
  FirewallResult,
  SubTakeoverResult,
  CloudEnumResult,
  ScreenshotResult,
  JsAnalyzeResult,
  ApiResult,
  InjectResult,
  WebDavResult,
  SslTestsResult,
  CrawlResult,
  ReconResult,
  SpiderResult,
  WaybackResult,
  HostHeaderResult,
  AuthResult,
  CsrfResult,
  DeserializationResult,
  SmugglingResult,
  CacheResult,
} from "./types";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const MAGENTA = "\x1b[35m";
const CYAN = "\x1b[36m";
const GRAY = "\x1b[90m";
const BRED = "\x1b[91m";
const BGREEN = "\x1b[92m";
const BYELLOW = "\x1b[93m";
const BCYAN = "\x1b[96m";
const BMAGENTA = "\x1b[95m";

export const EASM_COLORS = { RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, GRAY, BRED, BGREEN, BYELLOW, BCYAN, BMAGENTA };

const MODULE_LABEL: Record<string, string> = {
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

const LEVEL_COLOR: Record<string, string> = {
  info: GRAY,
  success: GREEN,
  warn: YELLOW,
  error: RED,
  debug: GRAY,
};

export function pad(s: string, n: number): string {
  const str = String(s);
  // account for ANSI codes (strip for width calc)
  const visible = str.replace(/\x1b\[[0-9;]*m/g, "");
  if (visible.length >= n) return str;
  return str + " ".repeat(n - visible.length);
}

export function trunc(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

export function table(headers: string[], rows: string[][], widths: number[]): string {
  const top = "┌" + widths.map((w) => "─".repeat(w + 2)).join("┬") + "┐";
  const mid = "├" + widths.map((w) => "─".repeat(w + 2)).join("┼") + "┤";
  const bot = "└" + widths.map((w) => "─".repeat(w + 2)).join("┴") + "┘";
  const gray = (s: string) => GRAY + s + RESET;
  const head = "│" + headers.map((h, i) => " " + CYAN + pad(trunc(h, widths[i]), widths[i]) + RESET + " ").join("│") + "│";
  const body = rows.map((r) => "│" + r.map((c, i) => " " + pad(trunc(stripAnsi(c), widths[i]), widths[i]) + " ").join("│") + "│").join(gray(mid) + "\n");
  return [gray(top), head, gray(mid), body, gray(bot)].filter(Boolean).join("\n");
}

export function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function renderDns(r: DnsResult): string {
  if (!r.records.length) return GRAY + "  no DNS records" + RESET;
  return table(["TYPE", "NAME", "VALUE"], r.records.map((x) => [x.type, x.name, x.value]), [8, 26, 46]);
}

function renderSubdomains(r: SubdomainResult): string {
  if (!r.subdomains.length) return GRAY + "  no subdomains discovered" + RESET;
  return table(
    ["#", "HOSTNAME", "IP", "SOURCE"],
    r.subdomains.map((s, i) => [String(i + 1), s.hostname, s.ip, s.source]),
    [4, 38, 16, 12]
  );
}

function renderPorts(r: PortResult): string {
  const lines: string[] = [];
  if (!r.ports.length) {
    lines.push(GRAY + "  no open ports" + RESET);
  } else {
    lines.push(table(
      ["PORT", "PROTO", "SERVICE", "STATE", "BANNER"],
      r.ports.map((p) => [
        String(p.port),
        (p.protocol || "tcp").toUpperCase(),
        p.service,
        p.state === "open" ? GREEN + "open" + RESET : p.state,
        (p.banner || "").slice(0, 38),
      ]),
      [7, 6, 13, 8, 38]
    ));
  }
  if (r.osGuess && r.osGuess.os && !r.osGuess.os.startsWith("unknown")) {
    lines.push("\n  " + BOLD + "OS guess: " + RESET + CYAN + r.osGuess.os + RESET + GRAY + ` (ttl~${r.osGuess.ttl ?? "?"}, ${r.osGuess.confidence})` + RESET);
  }
  return lines.join("\n");
}

function renderHttp(r: HttpResult): string {
  if (!r.hosts.length) return GRAY + "  no HTTP services responding" + RESET;
  return table(
    ["URL", "STATUS", "TITLE", "SERVER"],
    r.hosts.map((h) => {
      const st =
        h.status === 0 ? RED + "down" + RESET
        : h.status >= 400 ? RED + h.status + RESET
        : h.status >= 300 ? YELLOW + h.status + RESET
        : GREEN + h.status + RESET;
      return [h.url, st, (h.title || "").slice(0, 26), (h.server || "").slice(0, 18)];
    }),
    [36, 8, 26, 18]
  );
}

function renderTls(r: TlsResult): string {
  if (!r.certs.length) return GRAY + "  no certificates" + RESET;
  return r.certs
    .map((c) => {
      const exp =
        c.daysRemaining < 0
          ? RED + `EXPIRED ${-c.daysRemaining}d ago` + RESET
          : c.daysRemaining < 30
          ? YELLOW + `${c.daysRemaining}d left` + RESET
          : GREEN + `${c.daysRemaining}d left` + RESET;
      return (
        `  ${BOLD}${c.host}${RESET} ${c.selfSigned ? RED + "[SELF-SIGNED]" + RESET : ""} ${exp}\n` +
        DIM + `    Subject : ${c.subject}${RESET}\n` +
        DIM + `    Issuer  : ${c.issuer}${RESET}\n` +
        DIM + `    Valid   : ${c.validFrom}  ->  ${c.validTo}${RESET}` +
        (c.san.length ? "\n" + DIM + `    SAN     : ${c.san.slice(0, 6).join(", ")}${c.san.length > 6 ? " ..." : ""}${RESET}` : "")
      );
    })
    .join("\n");
}

function renderTech(r: TechResult): string {
  if (!r.hosts.length) return GRAY + "  no hosts fingerprinted" + RESET;
  return r.hosts
    .map((h) => {
      const list = h.technologies.map((t) =>
        t.confidence === "high" ? GREEN + t.name + RESET
        : t.confidence === "medium" ? YELLOW + t.name + RESET
        : GRAY + t.name + RESET
      );
      return `  ${h.url}\n    ${list.length ? list.join(GRAY + " | " + RESET) : GRAY + "no fingerprints" + RESET}`;
    })
    .join("\n");
}

function renderBanners(r: BannerResult): string {
  if (!r.banners.length) return GRAY + "  no banners" + RESET;
  return table(
    ["HOST:PORT", "SERVICE", "BANNER"],
    r.banners.map((b) => [`${b.host}:${b.port}`, b.service, b.banner.slice(0, 46)]),
    [20, 10, 46]
  );
}

function renderVulns(r: VulnResult): string {
  const sev: Record<string, string> = {
    high: RED,
    medium: YELLOW,
    low: CYAN,
    info: GRAY,
  };
  if (!r.hosts.length) return GRAY + "  no hosts checked" + RESET;
  return r.hosts
    .map((h) => {
      if (!h.findings.length) return `  ${h.url} ${GREEN}no findings${RESET}`;
      const lines = h.findings.map(
        (f) => `    ${sev[f.severity]}[${f.severity.toUpperCase().padEnd(6)}]${RESET} ${f.title}\n` + DIM + `           ${f.detail}${RESET}`
      );
      return `  ${BOLD}${h.url}${RESET}\n` + lines.join("\n");
    })
    .join("\n");
}

function renderThreatIntel(r: ThreatIntelResult): string {
  const lines: string[] = [];
  const sources: ThreatIntelSource[] = [
    r.sources.shodan,
    r.sources.c99,
    r.sources.virustotal,
    r.sources.securitytrails,
  ];

  // Per-source status table
  const rows: string[][] = sources.map((s) => {
    const status = s.ok ? GREEN + "ok" + RESET : RED + "fail" + RESET;
    let detail = GRAY + "-" + RESET;
    if (s.ok) {
      const parts: string[] = [];
      if (s.subdomains) parts.push(`${s.subdomains.length} subs`);
      if (s.records) parts.push(`${s.records.length} recs`);
      if (s.reputation !== undefined) parts.push(`rep ${s.reputation}`);
      if (s.resolvedIps?.length) parts.push(`${s.resolvedIps.length} IPs`);
      if (s.ipHistory?.length) parts.push(`${s.ipHistory.length} hist`);
      detail = parts.length ? CYAN + parts.join(", ") + RESET : CYAN + "ok" + RESET;
    } else {
      detail = RED + (s.error || "failed").slice(0, 40) + RESET;
    }
    return [s.name, status, detail];
  });
  lines.push(table(["SOURCE", "STATUS", "DETAIL"], rows, [16, 8, 40]));

  // VirusTotal reputation verdict
  const vt = r.sources.virustotal;
  if (vt.ok && vt.analysisStats) {
    const mal = vt.analysisStats.malicious || 0;
    const susp = vt.analysisStats.suspicious || 0;
    const verdict = mal >= 3 ? RED + BOLD + "MALICIOUS" + RESET : mal >= 1 || susp >= 2 ? YELLOW + "SUSPICIOUS" + RESET : GREEN + "CLEAN" + RESET;
    lines.push(
      "\n  " + BOLD + "VirusTotal verdict: " + RESET + verdict +
      GRAY + `  (malicious=${mal}, suspicious=${susp}, harmless=${vt.analysisStats.harmless || 0}, undetected=${vt.analysisStats.undetected || 0}, reputation=${vt.reputation ?? 0})` + RESET
    );
    if (vt.categories?.length) {
      lines.push(DIM + "  Categories: " + RESET + CYAN + vt.categories.slice(0, 8).join(", ") + RESET);
    }
  }

  // Aggregated subdomains (sample)
  if (r.aggregated.subdomains.length) {
    const sample = r.aggregated.subdomains.slice(0, 15);
    lines.push(
      "\n  " + BOLD + `Aggregated subdomains (${r.aggregated.subdomains.length}):` + RESET
    );
    lines.push(DIM + "    " + sample.join(GRAY + ", " + RESET + DIM) + (r.aggregated.subdomains.length > 15 ? GRAY + ` ... +${r.aggregated.subdomains.length - 15} more` + RESET : "") + RESET
    );
  }

  // Aggregated resolved IPs (sample)
  if (r.aggregated.resolvedIps.length) {
    const sample = r.aggregated.resolvedIps.slice(0, 12);
    lines.push(
      "\n  " + BOLD + `Resolved IPs (${r.aggregated.resolvedIps.length}):` + RESET
    );
    lines.push(DIM + "    " + sample.join(GRAY + ", " + RESET + DIM) + (r.aggregated.resolvedIps.length > 12 ? GRAY + ` ... +${r.aggregated.resolvedIps.length - 12} more` + RESET : "") + RESET
    );
  }

  // SecurityTrails IP history (sample)
  const st = r.sources.securitytrails;
  if (st.ok && st.ipHistory?.length) {
    lines.push("\n  " + BOLD + "SecurityTrails A-record history:" + RESET);
    const histRows = st.ipHistory.slice(0, 8).map((h) => [
      h.ip,
      (h.firstSeen || "").slice(0, 10),
      (h.lastSeen || "").slice(0, 10),
    ]);
    lines.push(table(["IP", "FIRST SEEN", "LAST SEEN"], histRows, [18, 12, 12]));
  }

  return lines.join("\n");
}

function renderEmailSec(r: EmailSecResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN, info: GRAY };

  // SPF
  const spfStatus = r.spf.present
    ? (r.spf.policy === "-all" ? GREEN + "HardFail (-all)" + RESET
       : r.spf.policy === "+all" ? RED + "PASS-ALL (+all)" + RESET
       : r.spf.policy === "~all" ? YELLOW + "SoftFail (~all)" + RESET
       : r.spf.policy === "?all" ? YELLOW + "Neutral (?all)" + RESET
       : YELLOW + String(r.spf.policy) + RESET)
    : RED + "MISSING" + RESET;
  lines.push("  " + BOLD + "SPF  " + RESET + spfStatus + GRAY + `  (${r.spf.dnsLookups ?? 0} DNS lookups)` + RESET);
  if (r.spf.record) lines.push(DIM + "    " + r.spf.record.slice(0, 100) + (r.spf.record.length > 100 ? "..." : "") + RESET);

  // DMARC
  const dmarcStatus = r.dmarc.present
    ? (r.dmarc.policy === "reject" ? GREEN + "p=reject" + RESET
       : r.dmarc.policy === "quarantine" ? YELLOW + "p=quarantine" + RESET
       : r.dmarc.policy === "none" ? YELLOW + "p=none" + RESET
       : YELLOW + String(r.dmarc.policy) + RESET)
    : RED + "MISSING" + RESET;
  lines.push("  " + BOLD + "DMARC" + RESET + " " + dmarcStatus + GRAY + `  (pct=${r.dmarc.pct ?? 0}${r.dmarc.rua ? ", rua=" + r.dmarc.rua.slice(0, 30) : ""})` + RESET);
  if (r.dmarc.record) lines.push(DIM + "    " + r.dmarc.record.slice(0, 100) + (r.dmarc.record.length > 100 ? "..." : "") + RESET);

  // DKIM
  const dkimStatus = r.dkim.found.length
    ? GREEN + `${r.dkim.found.length} selector(s) found` + RESET
    : YELLOW + `none found (${r.dkim.selectorsChecked.length} checked)` + RESET;
  lines.push("  " + BOLD + "DKIM " + RESET + dkimStatus);
  for (const f of r.dkim.found.slice(0, 5)) {
    lines.push(DIM + "    " + f.selector + "._domainkey -> " + f.record + RESET);
  }

  // MX
  const mxStatus = r.mx.servers.length
    ? GREEN + `${r.mx.servers.length} server(s)` + RESET + GRAY + (r.mx.providers.length ? " (" + r.mx.providers.join(", ") + ")" : "") + RESET
    : GRAY + "no MX records" + RESET;
  lines.push("  " + BOLD + "MX   " + RESET + " " + mxStatus);
  for (const s of r.mx.servers.slice(0, 5)) {
    lines.push(DIM + "    " + String(s.priority).padEnd(4) + " " + s.exchange + RESET);
  }

  // Findings
  if (r.findings.length) {
    lines.push("\n  " + BOLD + "Email security findings:" + RESET);
    for (const f of r.findings) {
      lines.push("    " + sev[f.severity] + `[${f.severity.toUpperCase().padEnd(6)}]` + RESET + " " + f.title);
      lines.push(DIM + "           " + f.detail + RESET);
    }
  } else {
    lines.push("\n  " + GREEN + "No email security issues found." + RESET);
  }

  return lines.join("\n");
}

function renderOpenDirs(r: OpenDirResult): string {
  const lines: string[] = [];
  if (r.directories.length) {
    lines.push("  " + BOLD + "Open directory listings:" + RESET);
    const rows = r.directories.map((d) => [
      d.url,
      d.listingType,
      d.server.slice(0, 14),
    ]);
    lines.push(table(["URL", "LISTING TYPE", "SERVER"], rows, [42, 20, 14]));
    for (const d of r.directories.slice(0, 6)) {
      if (d.sample.length) {
        lines.push(DIM + "    sample: " + d.sample.slice(0, 6).join(", ") + RESET);
      }
    }
  } else {
    lines.push("  " + GRAY + "No open directory listings found." + RESET);
  }

  if (r.exposedFiles.length) {
    lines.push("\n  " + BOLD + "Exposed sensitive files:" + RESET);
    const rows = r.exposedFiles.map((f) => [
      f.url,
      String(f.status),
      String(f.size) + "b",
      f.type,
    ]);
    lines.push(table(["URL", "STATUS", "SIZE", "TYPE"], rows, [44, 8, 8, 10]));
  }

  if (!r.directories.length && !r.exposedFiles.length) {
    lines.push("  " + GREEN + "No open directories or exposed files." + RESET);
  }

  return lines.join("\n");
}

function renderFirewall(r: FirewallResult): string {
  const lines: string[] = [];

  // Per-host WAF detection
  for (const h of r.hosts) {
    lines.push("  " + BOLD + h.url + RESET);
    if (h.detected.length) {
      for (const d of h.detected) {
        const conf = d.confidence === "high" ? GREEN : YELLOW;
        lines.push("    " + conf + "[WAF]" + RESET + " " + d.name + " (" + d.confidence + ") " + GRAY + d.evidence.join(", ") + RESET);
      }
    } else {
      lines.push("    " + GRAY + "no WAF signatures detected" + RESET);
    }
    if (h.blockStatus !== null) {
      lines.push("    " + YELLOW + "[BLOCK]" + RESET + " attack payload blocked with HTTP " + h.blockStatus);
    }
    if (h.methods.length) {
      const risky = h.methods.filter((m) => ["PUT", "DELETE", "TRACE", "CONNECT"].includes(m));
      const mStr = h.methods.map((m) => (risky.includes(m) ? YELLOW + m + RESET : m)).join(GRAY + ", " + RESET);
      lines.push("    " + GRAY + "methods: " + RESET + mStr);
    }
    if (h.cors.enabled) {
      const flags = [h.cors.wildcard ? RED + "wildcard" + RESET : null, h.cors.reflected ? RED + "reflects-origin" + RESET : null, h.cors.credentials ? YELLOW + "credentials" + RESET : null].filter(Boolean);
      lines.push("    " + GRAY + "cors: " + RESET + CYAN + h.cors.origin + RESET + (flags.length ? GRAY + " (" + flags.join(GRAY + ", " + RESET) + GRAY + ")" + RESET : ""));
    }
  }

  // Attack surface (robots.txt / sitemap.xml)
  if (r.attackSurface.length) {
    lines.push("\n  " + BOLD + "Attack surface (robots.txt / sitemap.xml):" + RESET);
    for (const s of r.attackSurface) {
      lines.push("    " + CYAN + s.source + RESET);
      lines.push(DIM + "      " + s.paths.slice(0, 12).join(GRAY + ", " + RESET + DIM) + (s.paths.length > 12 ? GRAY + " ... +" + (s.paths.length - 12) + RESET : "") + RESET);
    }
  }

  // Bypass payloads
  if (r.bypassPayloads.length) {
    const totalPl = r.bypassPayloads.reduce((a, p) => a + p.payloads.length, 0);
    lines.push("\n  " + BOLD + `WAF-bypass payload suggestions (${r.bypassPayloads.length} sets, ${totalPl} payloads):` + RESET);
    for (const p of r.bypassPayloads) {
      lines.push("    " + MAGENTA + "[" + p.waf + "]" + RESET + " " + CYAN + p.category + RESET + GRAY + " (" + p.payloads.length + " payloads)" + RESET);
      // Show a sample of up to 8 payloads (full list available in JSON output)
      const sample = p.payloads.slice(0, 8);
      for (const pl of sample) {
        lines.push("      " + GREEN + pl.slice(0, 70) + RESET);
      }
      if (p.payloads.length > 8) {
        lines.push(GRAY + "      ... +" + (p.payloads.length - 8) + " more (use --output json for full list)" + RESET);
      }
      lines.push(DIM + "      note: " + p.note + RESET);
    }
  }

  return lines.join("\n");
}

function renderSubTakeover(r: SubTakeoverResult): string {
  const lines: string[] = [];
  lines.push("  " + GRAY + `Checked ${r.checked} host(s).` + RESET);
  if (!r.vulnerable.length) {
    lines.push("  " + GREEN + "No subdomain takeover vulnerabilities detected." + RESET);
    return lines.join("\n");
  }
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN };
  lines.push("  " + BOLD + `Vulnerable: ${r.vulnerable.length}` + RESET);
  const rows = r.vulnerable.map((v) => [
    v.hostname,
    v.cname.slice(0, 30),
    v.service,
    sev[v.severity] + v.severity + RESET,
    v.fingerprint.slice(0, 26),
  ]);
  lines.push(table(["HOSTNAME", "CNAME", "SERVICE", "SEV", "FINGERPRINT"], rows, [30, 28, 14, 8, 26]));
  return lines.join("\n");
}

function renderCloudEnum(r: CloudEnumResult): string {
  const lines: string[] = [];
  if (r.buckets.length) {
    lines.push("  " + BOLD + "Storage buckets:" + RESET);
    const rows = r.buckets.map((b) => [
      b.provider,
      b.name.slice(0, 24),
      b.exists ? GREEN + "yes" + RESET : GRAY + "no" + RESET,
      b.public ? RED + "PUBLIC" + RESET : GRAY + "-" + RESET,
      b.listing ? RED + "listing" + RESET : GRAY + "-" + RESET,
    ]);
    lines.push(table(["PROVIDER", "NAME", "EXISTS", "PUBLIC", "LISTING"], rows, [12, 26, 8, 9, 10]));
    for (const b of r.buckets.filter((x) => x.listing && x.sample.length).slice(0, 4)) {
      lines.push(DIM + "    " + b.provider + "/" + b.name + ": " + b.sample.slice(0, 4).join(", ") + RESET);
    }
  } else {
    lines.push("  " + GRAY + "No cloud storage buckets found." + RESET);
  }
  if (r.repos.length) {
    lines.push("\n  " + BOLD + "Code repositories:" + RESET);
    const rows = r.repos.map((r2) => [
      r2.provider,
      r2.name.slice(0, 24),
      r2.exists ? GREEN + "yes" + RESET : GRAY + "no" + RESET,
      r2.exists && !r2.private ? GREEN + "public" + RESET : r2.private ? YELLOW + "private" + RESET : GRAY + "-" + RESET,
    ]);
    lines.push(table(["PROVIDER", "NAME", "EXISTS", "VISIBILITY"], rows, [12, 26, 8, 12]));
  }
  if (!r.buckets.length && !r.repos.length) {
    lines.push("  " + GREEN + "No cloud assets discovered." + RESET);
  }
  return lines.join("\n");
}

function renderScreenshots(r: ScreenshotResult): string {
  const lines: string[] = [];
  for (const h of r.hosts) {
    lines.push("  " + BOLD + h.url + RESET + GRAY + " (" + h.statusCode + ")" + RESET);
    if (h.title) lines.push("    " + CYAN + "title: " + RESET + h.title);
    if (h.server) lines.push(DIM + "    server: " + h.server + (h.poweredBy ? " | x-powered-by: " + h.poweredBy : "") + RESET);
    if (h.faviconHash) lines.push(DIM + "    favicon: sha256=" + h.faviconHash.slice(0, 16) + "... mmh3=" + (h.faviconMmh || "?") + RESET);
    if (h.redirectChain.length > 1) {
      lines.push(DIM + "    redirects: " + h.redirectChain.length + " hop(s)" + RESET);
      for (const hop of h.redirectChain.slice(0, 4)) {
        lines.push(DIM + "      " + hop.status + " -> " + hop.url.slice(0, 60) + RESET);
      }
    }
    // Security headers summary
    const sh = h.securityHeaders;
    const shFlags = [
      sh.hsts ? GREEN + "hsts" + RESET : RED + "hsts" + RESET,
      sh.csp ? GREEN + "csp" + RESET : RED + "csp" + RESET,
      sh.xfo ? GREEN + "xfo" + RESET : YELLOW + "xfo" + RESET,
      sh.xcto ? GREEN + "xcto" + RESET : YELLOW + "xcto" + RESET,
      sh.referrer ? GREEN + "referrer" + RESET : GRAY + "referrer" + RESET,
    ];
    lines.push("    " + GRAY + "headers: " + RESET + shFlags.join(GRAY + " " + RESET));
    if (h.cookies.length) {
      const insecure = h.cookies.filter((c) => !c.secure || !c.httpOnly).length;
      lines.push(DIM + "    cookies: " + h.cookies.length + (insecure ? RED + " (" + insecure + " insecure)" + RESET : GREEN + " (all secure)" + RESET));
    }
    lines.push(DIM + "    forms: " + h.forms + " | inputs: " + h.inputs + " | js: " + h.jsFiles + " | ext-links: " + h.externalLinks + RESET);
    if (h.tlsIssuer) lines.push(DIM + "    TLS issuer: " + h.tlsIssuer + RESET);
  }
  return lines.join("\n");
}

function renderJsAnalyze(r: JsAnalyzeResult): string {
  const lines: string[] = [];
  if (!r.files.length) {
    return GRAY + "  no JavaScript files analyzed" + RESET;
  }
  for (const f of r.files) {
    lines.push("  " + BOLD + f.url + RESET + GRAY + ` (${(f.size / 1024).toFixed(1)} KB)` + RESET);
    if (f.secrets.length) {
      lines.push("    " + RED + BOLD + `Secrets (${f.secrets.length}):` + RESET);
      for (const s of f.secrets.slice(0, 12)) {
        lines.push("      " + RED + s.type + RESET + " " + CYAN + s.value.slice(0, 50) + RESET + GRAY + ` (line ${s.line})` + RESET);
      }
    }
    if (f.cloudKeys.length) {
      lines.push("    " + MAGENTA + BOLD + `Cloud keys (${f.cloudKeys.length}):` + RESET);
      for (const k of f.cloudKeys.slice(0, 8)) {
        lines.push("      " + MAGENTA + k.provider + RESET + ": " + CYAN + k.key.slice(0, 40) + RESET);
      }
    }
    if (f.endpoints.length) {
      lines.push("    " + GREEN + `Endpoints (${f.endpoints.length}):` + RESET + " " + f.endpoints.slice(0, 10).join(GRAY + ", " + RESET + GREEN));
      if (f.endpoints.length > 10) lines.push(GRAY + `      ... +${f.endpoints.length - 10} more` + RESET);
    }
    if (f.internalUrls.length) {
      lines.push("    " + YELLOW + `Internal URLs (${f.internalUrls.length}):` + RESET);
      for (const u of f.internalUrls.slice(0, 6)) {
        lines.push("      " + YELLOW + u.slice(0, 70) + RESET);
      }
    }
    if (f.comments.length) {
      lines.push("    " + GRAY + `Interesting comments (${f.comments.length}):` + RESET);
      for (const c of f.comments.slice(0, 5)) {
        lines.push("      " + GRAY + c.slice(0, 70) + RESET);
      }
    }
  }
  return lines.join("\n");
}

function renderApi(r: ApiResult): string {
  const lines: string[] = [];
  if (r.endpoints.length) {
    lines.push("  " + BOLD + `Discovered endpoints (${r.endpoints.length}):` + RESET);
    const rows = r.endpoints.slice(0, 25).map((e) => [e.method, e.url.slice(0, 52), e.source, e.params.slice(0, 3).join(",")]);
    lines.push(table(["METHOD", "URL", "SOURCE", "PARAMS"], rows, [7, 52, 8, 22]));
  } else {
    lines.push("  " + GRAY + "No API endpoints discovered." + RESET);
  }
  if (r.graphql.length) {
    lines.push("\n  " + BOLD + "GraphQL endpoints:" + RESET);
    for (const g of r.graphql) {
      const intro = g.introspection ? RED + "INTROSPECTION ENABLED" + RESET : GREEN + "introspection disabled" + RESET;
      lines.push("    " + g.url + " — " + intro);
      if (g.types.length) lines.push(DIM + "      types: " + g.types.slice(0, 10).join(", ") + RESET);
      if (g.queries.length) lines.push(DIM + "      queries: " + g.queries.slice(0, 10).join(", ") + RESET);
    }
  }
  if (r.swagger.length) {
    lines.push("\n  " + BOLD + "Swagger/OpenAPI docs:" + RESET);
    const rows = r.swagger.map((s) => [s.url.slice(0, 44), s.version, s.title.slice(0, 20), String(s.paths)]);
    lines.push(table(["URL", "VERSION", "TITLE", "PATHS"], rows, [44, 10, 20, 6]));
  }
  if (r.versionedApis.length) {
    lines.push("\n  " + BOLD + "Versioned APIs:" + RESET);
    const rows = r.versionedApis.map((v) => [v.version, v.url.slice(0, 50), String(v.status)]);
    lines.push(table(["VERSION", "URL", "STATUS"], rows, [10, 50, 7]));
  }
  return lines.join("\n");
}

function renderInject(r: InjectResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN };
  if (!r.hosts.length || r.hosts.every((h) => !h.points.length)) {
    return GREEN + "  No injection points detected." + RESET;
  }
  for (const h of r.hosts) {
    if (!h.points.length) continue;
    lines.push("  " + BOLD + h.url + RESET);
    const rows = h.points.map((p) => [
      sev[p.severity] + p.type.toUpperCase() + RESET,
      p.method,
      p.param,
      p.payload.slice(0, 28),
      p.evidence.slice(0, 34),
    ]);
    lines.push(table(["TYPE", "METHOD", "PARAM", "PAYLOAD", "EVIDENCE"], rows, [10, 7, 12, 28, 34]));
  }
  return lines.join("\n");
}

function renderWebDav(r: WebDavResult): string {
  const lines: string[] = [];
  if (!r.hosts.length) {
    return GREEN + "  No WebDAV-enabled hosts detected." + RESET;
  }
  for (const h of r.hosts) {
    lines.push("  " + BOLD + h.url + RESET);
    lines.push("    " + (h.enabled ? GREEN + "WebDAV enabled" + RESET : GRAY + "not enabled" + RESET));
    if (h.methods.length) lines.push(DIM + "    methods: " + h.methods.join(", ") + RESET);
    if (h.writable) lines.push("    " + RED + BOLD + "WRITABLE — file upload possible (RCE risk)" + RESET);
    if (h.propfindDepth) lines.push("    " + YELLOW + "PROPFIND directory listing enabled" + RESET);
    if (h.authRequired) lines.push(DIM + "    auth required" + RESET);
    for (const u of h.uploads) {
      const flag = u.success ? RED + "UPLOADED" + RESET : GRAY + "blocked" + RESET;
      lines.push("    " + flag + " " + u.path.slice(0, 60) + " (" + u.status + ")");
    }
  }
  return lines.join("\n");
}

function renderSslTests(r: SslTestsResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN, info: GRAY };
  if (!r.hosts.length) {
    return GRAY + "  no hosts tested" + RESET;
  }
  for (const h of r.hosts) {
    lines.push("  " + BOLD + h.host + RESET);
    // Protocols
    const protos = h.protocols.filter((p) => p.enabled).map((p) => (p.insecure ? RED + p.name + RESET : GREEN + p.name + RESET));
    lines.push("    " + GRAY + "protocols: " + RESET + (protos.length ? protos.join(GRAY + ", " + RESET) : GRAY + "none" + RESET));
    // Ciphers
    if (h.ciphers.length) {
      lines.push("    " + GRAY + "cipher: " + RESET + (h.weakCiphers > 0 ? RED : GREEN) + h.ciphers[0].name + RESET + GRAY + ` (${h.ciphers[0].strength})` + RESET);
    }
    lines.push(DIM + "    cert chain: " + h.certChainLength + " cert(s) | OCSP: " + (h.ocspStapling ? "yes" : "no") + " | HSTS: " + (h.hsts ? "yes" : "no") + RESET);
    // Issues
    if (h.issues.length) {
      for (const iss of h.issues) {
        lines.push("    " + sev[iss.severity] + "[" + iss.severity.toUpperCase().padEnd(6) + "]" + RESET + " " + iss.title);
        lines.push(DIM + "           " + iss.detail + RESET);
      }
    } else {
      lines.push("    " + GREEN + "no SSL/TLS issues" + RESET);
    }
  }
  return lines.join("\n");
}

function renderCrawl(r: CrawlResult): string {
  const lines: string[] = [];
  if (r.pages.length) {
    lines.push("  " + BOLD + `Crawled pages (${r.pages.length}):` + RESET);
    const rows = r.pages.slice(0, 20).map((p) => [
      String(p.depth),
      String(p.status),
      p.title.slice(0, 30),
      String(p.links),
      String(p.forms),
    ]);
    lines.push(table(["DEPTH", "STATUS", "TITLE", "LINKS", "FORMS"], rows, [6, 7, 30, 6, 6]));
  }
  if (r.internalLinks.length) {
    lines.push("\n  " + BOLD + `Internal links (${r.internalLinks.length}):` + RESET);
    lines.push(DIM + "    " + r.internalLinks.slice(0, 12).join(GRAY + ", " + RESET + DIM) + (r.internalLinks.length > 12 ? GRAY + ` ... +${r.internalLinks.length - 12}` + RESET : "") + RESET);
  }
  if (r.externalLinks.length) {
    lines.push("\n  " + BOLD + `External origins (${r.externalLinks.length}):` + RESET);
    lines.push(DIM + "    " + r.externalLinks.slice(0, 12).join(GRAY + ", " + RESET + DIM) + RESET);
  }
  if (r.emails.length) {
    lines.push("\n  " + RED + BOLD + `Emails found (${r.emails.length}):` + RESET);
    lines.push("    " + r.emails.slice(0, 15).map((e) => RED + e + RESET).join(GRAY + ", " + RESET));
  }
  if (r.phones.length) {
    lines.push("\n  " + YELLOW + BOLD + `Phones found (${r.phones.length}):` + RESET);
    lines.push("    " + r.phones.slice(0, 10).join(GRAY + ", " + RESET));
  }
  if (r.files.length) {
    lines.push("\n  " + CYAN + BOLD + `Files found (${r.files.length}):` + RESET);
    for (const f of r.files.slice(0, 10)) lines.push("    " + CYAN + f.slice(0, 70) + RESET);
  }
  return lines.join("\n");
}

function renderRecon(r: ReconResult): string {
  const lines: string[] = [];
  // WHOIS
  lines.push("  " + BOLD + "WHOIS / RDAP:" + RESET);
  if (r.whois.registrar) lines.push("    " + GRAY + "Registrar: " + RESET + CYAN + r.whois.registrar + RESET);
  if (r.whois.createdDate) lines.push("    " + GRAY + "Created:  " + RESET + r.whois.createdDate);
  if (r.whois.expiryDate) lines.push("    " + GRAY + "Expires:  " + RESET + r.whois.expiryDate);
  if (r.whois.registrantOrg) lines.push("    " + GRAY + "Registrant: " + RESET + r.whois.registrantOrg + (r.whois.registrantCountry ? " (" + r.whois.registrantCountry + ")" : ""));
  if (r.whois.nameServers?.length) lines.push("    " + GRAY + "NS: " + RESET + r.whois.nameServers.slice(0, 4).join(", "));
  if (!r.whois.registrar && !r.whois.createdDate) lines.push("    " + GRAY + "no RDAP data" + RESET);
  // ASN
  if (r.asn.asn) {
    lines.push("\n  " + BOLD + "ASN:" + RESET);
    lines.push("    " + GRAY + "AS: " + RESET + CYAN + r.asn.asn + RESET + GRAY + " | Org: " + RESET + r.asn.org + GRAY + " | Net: " + RESET + (r.asn.network || "?"));
  }
  // GeoIP
  if (r.geo.city) {
    lines.push("\n  " + BOLD + "GeoIP:" + RESET);
    lines.push("    " + GRAY + "IP: " + RESET + r.geo.ip);
    lines.push("    " + GRAY + "Location: " + RESET + CYAN + `${r.geo.city}, ${r.geo.region || ""}, ${r.geo.country || ""}` + RESET);
    if (r.geo.lat && r.geo.lon) lines.push("    " + GRAY + "Coords: " + RESET + `${r.geo.lat}, ${r.geo.lon}`);
    if (r.geo.isp) lines.push("    " + GRAY + "ISP: " + RESET + r.geo.isp);
  }
  // Reverse DNS
  if (r.reverseDns.length) {
    lines.push("\n  " + BOLD + "Reverse DNS:" + RESET);
    for (const h of r.reverseDns.slice(0, 5)) lines.push("    " + CYAN + r.geo.ip + RESET + GRAY + " -> " + RESET + h);
  }
  return lines.join("\n");
}

function renderSpider(r: SpiderResult): string {
  const lines: string[] = [];
  if (r.pages.length) {
    lines.push("  " + BOLD + `Spidered pages (${r.pages.length}):` + RESET);
    const rows = r.pages.slice(0, 15).map((p) => [
      String(p.depth),
      String(p.status),
      p.title.slice(0, 26),
      String(p.forms.length),
      String(p.hiddenInputs.length),
      String(p.jsFiles.length),
    ]);
    lines.push(table(["D", "STATUS", "TITLE", "FORMS", "HIDDEN", "JS"], rows, [3, 7, 26, 7, 7, 5]));
  }
  if (r.allForms.length) {
    lines.push("\n  " + BOLD + `Discovered forms (${r.allForms.length}):` + RESET);
    for (const f of r.allForms.slice(0, 10)) {
      lines.push("    " + CYAN + f.method + RESET + " " + f.action.slice(0, 55) + GRAY + ` (${f.inputs.length} inputs)` + RESET);
      for (const inp of f.inputs.slice(0, 4)) {
        const hidden = inp.type === "hidden" ? YELLOW + " [hidden]" + RESET : "";
        lines.push("      " + inp.name + GRAY + " (" + inp.type + ")" + RESET + hidden + (inp.value ? GRAY + " = " + inp.value.slice(0, 30) + RESET : ""));
      }
    }
  }
  if (r.allParams.length) {
    lines.push("\n  " + BOLD + `Discovered parameters (${r.allParams.length}):` + RESET);
    lines.push(DIM + "    " + r.allParams.slice(0, 25).join(GRAY + ", " + RESET + DIM) + RESET);
  }
  if (r.sitemapUrls.length) {
    lines.push("\n  " + BOLD + `Sitemap URLs (${r.sitemapUrls.length}):` + RESET);
    lines.push(DIM + "    " + r.sitemapUrls.slice(0, 10).join(GRAY + ", " + RESET + DIM) + RESET);
  }
  return lines.join("\n");
}

function renderWayback(r: WaybackResult): string {
  const lines: string[] = [];
  lines.push("  " + BOLD + `Total archived URLs: ${r.totalUrls}` + RESET);
  if (r.archivedPaths.length) {
    lines.push("\n  " + BOLD + `Unique archived paths (${r.archivedPaths.length}):` + RESET);
    const rows = r.archivedPaths.slice(0, 20).map((p) => [p.slice(0, 68)]);
    lines.push(table(["PATH"], rows, [68]));
  }
  if (r.deletedPages.length) {
    lines.push("\n  " + RED + BOLD + `Deleted/404 pages in archive (${r.deletedPages.length}):` + RESET);
    const rows = r.deletedPages.slice(0, 15).map((d) => [d.url.slice(0, 54), d.lastSeen]);
    lines.push(table(["URL", "LAST SEEN"], rows, [54, 14]));
  }
  if (r.fileTypes.length) {
    lines.push("\n  " + BOLD + "File types in archive:" + RESET);
    const rows = r.fileTypes.slice(0, 15).map((f) => [f.ext, String(f.count)]);
    lines.push(table(["EXT", "COUNT"], rows, [12, 8]));
  }
  return lines.join("\n");
}

function renderHostHeader(r: HostHeaderResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN, info: GRAY };
  for (const h of r.hosts) {
    if (!h.findings.length) continue;
    lines.push("  " + BOLD + h.url + RESET);
    for (const f of h.findings) {
      lines.push("    " + sev[f.severity] + "[" + f.severity.toUpperCase().padEnd(6) + "]" + RESET + " " + f.title);
      lines.push(DIM + "           " + f.detail + RESET);
      if (f.evidence) lines.push(GRAY + "           evidence: " + f.evidence.slice(0, 80) + RESET);
    }
  }
  if (r.ssrfTestPoints.length) {
    lines.push("\n  " + BOLD + `SSRF test points (${r.ssrfTestPoints.length}):` + RESET);
    for (const s of r.ssrfTestPoints.slice(0, 15)) {
      lines.push("    " + MAGENTA + s.param + RESET + GRAY + " @ " + RESET + s.url.slice(0, 55));
      lines.push(DIM + "      " + s.note.slice(0, 80) + RESET);
    }
  }
  if (r.crlfTests.length) {
    lines.push("\n  " + BOLD + `CRLF injection tests (${r.crlfTests.length}):` + RESET);
    for (const c of r.crlfTests) {
      const flag = c.injected ? RED + "VULNERABLE" + RESET : GREEN + "not vulnerable" + RESET;
      lines.push("    " + flag + " " + c.url.slice(0, 50));
      if (c.injected) lines.push(DIM + "      " + c.evidence.slice(0, 80) + RESET);
    }
  }
  return lines.join("\n");
}

function renderAuth(r: AuthResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN, info: GRAY };
  for (const h of r.hosts) {
    if (!h.findings.length) continue;
    lines.push("  " + BOLD + h.url + RESET);
    for (const f of h.findings) {
      lines.push("    " + sev[f.severity] + "[" + f.severity.toUpperCase().padEnd(6) + "]" + RESET + " " + f.title);
      lines.push(DIM + "           " + f.detail + RESET);
    }
  }
  if (r.defaultCreds?.length) {
    const success = r.defaultCreds.filter((d) => d.success);
    if (success.length) {
      lines.push("\n  " + RED + BOLD + "Default credentials found:" + RESET);
      for (const d of success) lines.push("    " + RED + d.panel + RESET + GRAY + " @ " + RESET + d.url.slice(0, 50));
    }
  }
  if (r.jwtTests?.length) {
    const vuln = r.jwtTests.filter((j) => j.noneAlgAccepted || j.weakSecret);
    if (vuln.length) {
      lines.push("\n  " + RED + BOLD + "JWT vulnerabilities:" + RESET);
      for (const j of vuln) {
        lines.push("    " + j.url.slice(0, 50) + " — " + (j.noneAlgAccepted ? RED + "none-alg accepted" + RESET : "") + (j.weakSecret ? RED + " weak secret" + RESET : ""));
        lines.push(DIM + "      " + j.detail + RESET);
      }
    }
  }
  if (!r.hosts.some((h) => h.findings.length)) lines.push("  " + GREEN + "No auth issues detected." + RESET);
  return lines.join("\n");
}

function renderCsrf(r: CsrfResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN, info: GRAY };
  for (const h of r.hosts) {
    lines.push("  " + BOLD + h.url + RESET);
    if (h.forms.length) {
      const vuln = h.forms.filter((f) => f.vulnerable);
      lines.push("    " + GRAY + `Forms: ${h.forms.length} (${vuln.length} vulnerable)` + RESET);
      for (const f of vuln.slice(0, 8)) {
        lines.push("      " + YELLOW + f.method + RESET + " " + f.action.slice(0, 50) + RED + " — " + f.reason + RESET);
      }
    }
    for (const f of h.findings) {
      lines.push("    " + sev[f.severity] + "[" + f.severity.toUpperCase().padEnd(6) + "]" + RESET + " " + f.title);
      lines.push(DIM + "           " + f.detail + RESET);
    }
  }
  return lines.join("\n");
}

function renderDeser(r: DeserializationResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN, info: GRAY };
  for (const h of r.hosts) {
    if (!h.endpoints.length && !h.findings.length) continue;
    lines.push("  " + BOLD + h.url + RESET);
    const susp = h.endpoints.filter((e) => e.suspicious);
    if (susp.length) {
      lines.push("    " + RED + BOLD + `Suspicious sinks (${susp.length}):` + RESET);
      for (const e of susp.slice(0, 10)) {
        lines.push("      " + MAGENTA + e.technique + RESET + GRAY + " param=" + RESET + CYAN + e.param + RESET + GRAY + " (" + e.method + ")" + RESET);
        lines.push(DIM + "        " + e.response.slice(0, 70) + RESET);
      }
    }
    for (const f of h.findings) {
      lines.push("    " + sev[f.severity] + "[" + f.severity.toUpperCase().padEnd(6) + "]" + RESET + " " + f.title);
      lines.push(DIM + "           " + f.detail + RESET);
    }
  }
  if (!r.hosts.some((h) => h.findings.length)) lines.push("  " + GREEN + "No deserialization issues." + RESET);
  return lines.join("\n");
}

function renderSmuggling(r: SmugglingResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN, info: GRAY };
  for (const h of r.hosts) {
    if (!h.tests.length && !h.findings.length) continue;
    lines.push("  " + BOLD + h.url + RESET);
    const anom = h.tests.filter((t) => t.timingAnomaly || t.responseDiff);
    if (anom.length) {
      lines.push("    " + RED + BOLD + `Smuggling anomalies (${anom.length}):` + RESET);
      for (const t of anom) {
        lines.push("      " + MAGENTA + t.technique + RESET + (t.timingAnomaly ? RED + " timing" + RESET : "") + (t.responseDiff ? RED + " response-diff" + RESET : ""));
        lines.push(DIM + "        " + t.detail.slice(0, 70) + RESET);
      }
    }
    for (const f of h.findings) {
      lines.push("    " + sev[f.severity] + "[" + f.severity.toUpperCase().padEnd(6) + "]" + RESET + " " + f.title);
      lines.push(DIM + "           " + f.detail + RESET);
    }
  }
  if (!r.hosts.some((h) => h.findings.length)) lines.push("  " + GREEN + "No smuggling issues detected." + RESET);
  return lines.join("\n");
}

function renderCache(r: CacheResult): string {
  const lines: string[] = [];
  const sev: Record<string, string> = { high: RED, medium: YELLOW, low: CYAN, info: GRAY };
  for (const h of r.hosts) {
    if (!h.findings.length) continue;
    lines.push("  " + BOLD + h.url + RESET);
    if (h.unkeyedHeaders?.length) {
      const refl = h.unkeyedHeaders.filter((u) => u.reflected);
      if (refl.length) {
        lines.push("    " + YELLOW + "Unkeyed headers reflected:" + RESET);
        for (const u of refl) lines.push("      " + YELLOW + u.header + RESET + GRAY + " — " + u.evidence.slice(0, 60) + RESET);
      }
    }
    if (h.cachePoisoning?.length) {
      const pois = h.cachePoisoning.filter((p) => p.poisoned);
      if (pois.length) {
        lines.push("    " + RED + BOLD + "Cache poisoning confirmed:" + RESET);
        for (const p of pois) lines.push("      " + RED + p.header + RESET + " = " + p.value.slice(0, 40));
      }
    }
    if (h.webCacheDeception?.length) {
      const wcd = h.webCacheDeception.filter((w) => w.cached);
      if (wcd.length) {
        lines.push("    " + RED + BOLD + "Web cache deception:" + RESET);
        for (const w of wcd) lines.push("      " + CYAN + w.path + RESET + " — cached private content");
      }
    }
    for (const f of h.findings) {
      lines.push("    " + sev[f.severity] + "[" + f.severity.toUpperCase().padEnd(6) + "]" + RESET + " " + f.title);
      lines.push(DIM + "           " + f.detail + RESET);
    }
  }
  if (!r.hosts.some((h) => h.findings.length)) lines.push("  " + GREEN + "No cache issues detected." + RESET);
  return lines.join("\n");
}

export function renderResult(module: string, data: any): string {
  switch (module) {
    case "dns": return renderDns(data as DnsResult);
    case "subdomains": return renderSubdomains(data as SubdomainResult);
    case "ports": return renderPorts(data as PortResult);
    case "http": return renderHttp(data as HttpResult);
    case "tls": return renderTls(data as TlsResult);
    case "tech": return renderTech(data as TechResult);
    case "banners": return renderBanners(data as BannerResult);
    case "vulns": return renderVulns(data as VulnResult);
    case "threatintel": return renderThreatIntel(data as ThreatIntelResult);
    case "emailsec": return renderEmailSec(data as EmailSecResult);
    case "opendirs": return renderOpenDirs(data as OpenDirResult);
    case "firewall": return renderFirewall(data as FirewallResult);
    case "subtakeover": return renderSubTakeover(data as SubTakeoverResult);
    case "cloudenum": return renderCloudEnum(data as CloudEnumResult);
    case "screenshots": return renderScreenshots(data as ScreenshotResult);
    case "jsanalyze": return renderJsAnalyze(data as JsAnalyzeResult);
    case "api": return renderApi(data as ApiResult);
    case "inject": return renderInject(data as InjectResult);
    case "webdav": return renderWebDav(data as WebDavResult);
    case "ssltests": return renderSslTests(data as SslTestsResult);
    case "crawl": return renderCrawl(data as CrawlResult);
    case "recon": return renderRecon(data as ReconResult);
    case "spider": return renderSpider(data as SpiderResult);
    case "wayback": return renderWayback(data as WaybackResult);
    case "hostheader": return renderHostHeader(data as HostHeaderResult);
    case "auth": return renderAuth(data as AuthResult);
    case "csrf": return renderCsrf(data as CsrfResult);
    case "deserialization": return renderDeser(data as DeserializationResult);
    case "smuggling": return renderSmuggling(data as SmugglingResult);
    case "cache": return renderCache(data as CacheResult);
    default: return "";
  }
}

export function renderSummary(summary: any): string {
  const labels: [string, string][] = [
    ["DNS records", String(summary.findings.dnsRecords)],
    ["Subdomains", String(summary.findings.subdomains)],
    ["Open ports", String(summary.findings.openPorts)],
    ["HTTP services", String(summary.findings.httpServices)],
    ["TLS certificates", String(summary.findings.tlsCerts)],
    ["Technologies", String(summary.findings.technologies)],
    ["Service banners", String(summary.findings.banners)],
    ["Vulnerabilities", String(summary.findings.vulnerabilities)],
    ["Intel sources OK", String(summary.findings.threatIntelSources) + "/4"],
    ["Intel subdomains", String(summary.findings.threatIntelSubdomains)],
    ["Email sec issues", String(summary.findings.emailSecIssues)],
    ["Open dirs / files", String(summary.findings.openDirs)],
    ["Firewalls detected", String(summary.findings.firewallsDetected)],
    ["Bypass payload sets", String(summary.findings.bypassPayloads)],
    ["Attack-surface paths", String(summary.findings.attackSurfacePaths)],
    ["Takeover vulnerable", String(summary.findings.takeoverVulnerable)],
    ["Cloud assets", String(summary.findings.cloudAssets)],
    ["HTTP fingerprints", String(summary.findings.httpFingerprints)],
    ["JS secrets found", String(summary.findings.jsSecrets)],
    ["JS endpoints", String(summary.findings.jsEndpoints)],
    ["API endpoints", String(summary.findings.apiEndpoints)],
    ["Injection points", String(summary.findings.injectPoints)],
    ["WebDAV hosts", String(summary.findings.webdavEnabled)],
    ["SSL/TLS issues", String(summary.findings.sslIssues)],
    ["Crawled pages", String(summary.findings.crawledPages)],
    ["Crawled links", String(summary.findings.crawledLinks)],
    ["Recon records", String(summary.findings.reconRecords)],
    ["Spider pages", String(summary.findings.spiderPages)],
    ["Spider forms", String(summary.findings.spiderForms)],
    ["Wayback URLs", String(summary.findings.waybackUrls)],
    ["Host header issues", String(summary.findings.hostHeaderIssues)],
    ["Auth issues", String(summary.findings.authIssues)],
    ["CSRF issues", String(summary.findings.csrfIssues)],
    ["Deser issues", String(summary.findings.deserIssues)],
    ["Smuggling issues", String(summary.findings.smugglingIssues)],
    ["Cache issues", String(summary.findings.cacheIssues)],
  ];
  return table(["CATEGORY", "FINDINGS"], labels, [26, 12]);
}

/** Convert a single ScanEvent into terminal text (without trailing newline). */
export function renderEvent(ev: ScanEvent): string | null {
  switch (ev.type) {
    case "banner":
      return (
        BOLD + BMAGENTA + `[+] Starting EASM scan on ${ev.target}` + RESET + "\n" +
        GRAY + "─".repeat(64) + RESET
      );
    case "module:start":
      return BOLD + BCYAN + `\n■ ${MODULE_LABEL[ev.module] || ev.module}` + RESET;
    case "module:end":
      return null;
    case "log": {
      const c = LEVEL_COLOR[ev.log.level] || GRAY;
      return c + `  ${ev.log.message}` + RESET;
    }
    case "progress":
      if (ev.module === "ports")
        return GRAY + `\r  ports: ${ev.current}/${ev.total}` + RESET;
      return null;
    case "result":
      return renderResult(ev.module, ev.data);
    case "done": {
      const s = ev.summary;
      return (
        GRAY + "─".repeat(64) + RESET + "\n" +
        BOLD + BMAGENTA + `\n[✓] Scan complete in ${(s.durationMs / 1000).toFixed(2)}s` + RESET + "\n\n" +
        renderSummary(s)
      );
    }
    default:
      return null;
  }
}

export function welcomeBanner(): string {
  return [
    BMAGENTA + BOLD + "  ███████ ██   ██ ███████ ███   ██  ██████  ███    ███" + RESET,
    BMAGENTA + BOLD + "  ██       ██ ██  ██      ████  ██ ██    ██ ████  ████" + RESET,
    BMAGENTA + BOLD + "  █████    ███   █████   ██ ██ ██ ██    ██ ██ ████ ██" + RESET,
    BMAGENTA + BOLD + "  ██       ██ ██  ██      ██  ████ ██    ██ ██  ██  ██" + RESET,
    BMAGENTA + BOLD + "  ███████ ██   ██ ███████ ██   ███  ██████  ██      ██" + RESET,
    "",
    CYAN + BOLD + "  External Attack Surface Management" + RESET + GRAY + "  v1.0  ·  terminal edition" + RESET,
    "",
    GRAY + "  ─────────────────────────────────────────────────────────" + RESET,
    "",
    GREEN + "  Ready." + RESET + "  Type " + CYAN + "help" + RESET + " to see available commands.",
    "",
  ].join("\n");
}

export { MODULE_LABEL };
