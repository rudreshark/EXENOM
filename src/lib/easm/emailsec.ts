/**
 * Email Security Module
 *
 * Validates SPF, DMARC, DKIM and MX configuration for the target
 * domain and reports weaknesses an attacker could exploit for
 * spoofing / phishing / subdomain takeover of email.
 */
import * as dns from "dns";
import { promisify } from "util";
import type { EmailSecResult } from "./types";

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);

const DKIM_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "k1",
  "s1",
  "s1024",
  "mail",
  "dkim",
  "smtp",
  "azure",
  "microsoft",
  "amazon",
  "ses",
  "sendgrid",
  "mailgun",
  "zoho",
  "protonmail",
  "1e100",
];

const MX_PROVIDERS: { match: RegExp; name: string }[] = [
  { match: /google|gmail|1e100/i, name: "Google Workspace" },
  { match: /outlook|office365|microsoft|protection\.outlook/i, name: "Microsoft 365" },
  { match: /proofpoint/i, name: "Proofpoint" },
  { match: /mimecast/i, name: "Mimecast" },
  { match: /zoho/i, name: "Zoho Mail" },
  { match: /protonmail|proton\.me/i, name: "ProtonMail" },
  { match: /fastmail/i, name: "Fastmail" },
  { match: /amazonaws|amazonses/i, name: "Amazon SES" },
  { match: /sendgrid/i, name: "SendGrid" },
  { match: /mailgun/i, name: "Mailgun" },
  { match: /postmark/i, name: "Postmark" },
  { match: /yahoo/i, name: "Yahoo" },
  { match: /yandex/i, name: "Yandex" },
  { match: /qq\.com/i, name: "Tencent QQ" },
  { match: /163\.com|netease/i, name: "NetEase" },
];

async function getTxt(name: string): Promise<string[]> {
  try {
    const rows = await resolveTxt(name);
    return rows.map((r) => r.join(""));
  } catch {
    return [];
  }
}

function countDnsLookups(spf: string): number {
  // RFC 7208: include, a, mx, exists, redirect, ptr each count as a lookup.
  let n = 0;
  const tokens = spf.split(/\s+/);
  for (const t of tokens) {
    const mech = t.split(":")[0].split("=")[0].toLowerCase();
    if (["include", "a", "mx", "exists", "redirect", "ptr"].includes(mech)) n++;
  }
  return n;
}

export async function runEmailSec(
  domain: string,
  log: (msg: string) => void
): Promise<EmailSecResult> {
  log(`Analyzing email security for ${domain} (SPF, DMARC, DKIM, MX) ...`);
  const findings: EmailSecResult["findings"] = [];

  // ---- SPF ----
  log("  Querying SPF record ...");
  const txtRecords = await getTxt(domain);
  const spfRecord = txtRecords.find((t) => /^v=spf1/i.test(t));
  const spf: EmailSecResult["spf"] = {
    present: !!spfRecord,
    record: spfRecord,
    issues: [],
  };

  if (!spfRecord) {
    spf.issues.push("No SPF record found");
    findings.push({
      id: "spf-missing",
      severity: "high",
      title: "Missing SPF Record",
      detail: `${domain} has no SPF record. Any mail server can send email claiming to be from this domain, enabling spoofing & phishing.`,
    });
  } else {
    const allMatch = spfRecord.match(/\ball\s*(\S*)/i);
    const allMech = allMatch ? `all${allMatch[1] ? " " + allMatch[1] : ""}` : "all";
    spf.policy = (allMatch ? "all" : "none") as any;
    if (/\+all/i.test(spfRecord)) {
      spf.policy = "+all";
      spf.issues.push("SPF uses +all (PASS ALL) — completely permissive");
      findings.push({
        id: "spf-passall",
        severity: "high",
        title: "SPF Uses +all (Permissive)",
        detail: `${domain} SPF ends with +all, which authorizes EVERY mail server to send on behalf of the domain. Effectively no SPF protection.`,
      });
    } else if (/\?all/i.test(spfRecord)) {
      spf.policy = "?all";
      spf.issues.push("SPF uses ?all (neutral) — no enforcement");
      findings.push({
        id: "spf-neutral",
        severity: "medium",
        title: "SPF Uses ?all (Neutral)",
        detail: `${domain} SPF ends with ?all (neutral), providing no enforcement against spoofing.`,
      });
    } else if (/~all/i.test(spfRecord)) {
      spf.policy = "~all";
      spf.issues.push("SPF uses ~all (softfail) — weaker than hardfail");
      findings.push({
        id: "spf-softfail",
        severity: "low",
        title: "SPF Uses ~all (SoftFail)",
        detail: `${domain} SPF uses ~all (SoftFail). Spoofed mail is marked but typically still delivered. Prefer -all (HardFail).`,
      });
    } else if (/-all/i.test(spfRecord)) {
      spf.policy = "-all";
      log("    SPF policy: -all (HardFail) ✓");
    } else {
      spf.policy = "all";
      spf.issues.push("SPF has no 'all' mechanism — no enforcement");
      findings.push({
        id: "spf-no-all",
        severity: "medium",
        title: "SPF Missing 'all' Mechanism",
        detail: `${domain} SPF record has no 'all' qualifier, defaulting to neutral — no enforcement.`,
      });
    }
    spf.dnsLookups = countDnsLookups(spfRecord);
    if (spf.dnsLookups > 10) {
      spf.issues.push(`SPF exceeds 10 DNS lookups (RFC 7208 limit): ${spf.dnsLookups}`);
      findings.push({
        id: "spf-lookups",
        severity: "medium",
        title: "SPF Exceeds 10 DNS Lookup Limit",
        detail: `${domain} SPF requires ${spf.dnsLookups} DNS lookups (>10 RFC limit). Lookups beyond 10 are ignored, causing legitimate mail to fail SPF.`,
      });
    }
    log(`    SPF: ${spf.policy} (${spf.dnsLookups} DNS lookups)`);
  }

  // ---- DMARC ----
  log("  Querying DMARC record (_dmarc.{domain}) ...");
  const dmarcRecords = await getTxt(`_dmarc.${domain}`);
  const dmarcRecord = dmarcRecords.find((t) => /^v=DMARC1/i.test(t));
  const dmarc: EmailSecResult["dmarc"] = {
    present: !!dmarcRecord,
    record: dmarcRecord,
    issues: [],
  };

  if (!dmarcRecord) {
    dmarc.policy = "missing";
    dmarc.issues.push("No DMARC record found");
    findings.push({
      id: "dmarc-missing",
      severity: "high",
      title: "Missing DMARC Record",
      detail: `${domain} has no DMARC record at _dmarc.${domain}. No policy instructs receivers how to handle SPF/DKIM failures — spoofing goes unmitigated.`,
    });
  } else {
    const pMatch = dmarcRecord.match(/p=(\w+)/i);
    const pctMatch = dmarcRecord.match(/pct=(\d+)/i);
    const ruaMatch = dmarcRecord.match(/rua=([^;]+)/i);
    dmarc.policy = (pMatch ? pMatch[1] : "none") as any;
    dmarc.pct = pctMatch ? parseInt(pctMatch[1], 10) : 100;
    dmarc.rua = ruaMatch ? ruaMatch[1] : undefined;

    if (dmarc.policy === "none") {
      dmarc.issues.push("DMARC policy p=none (monitor only, no enforcement)");
      findings.push({
        id: "dmarc-none",
        severity: "medium",
        title: "DMARC Policy p=none (Monitor Only)",
        detail: `${domain} DMARC policy is p=none. Emails failing authentication are still delivered; only reports are generated. Upgrade to p=quarantine or p=reject.`,
      });
    } else if (dmarc.policy === "quarantine") {
      dmarc.issues.push("DMARC policy p=quarantine (partial enforcement)");
      findings.push({
        id: "dmarc-quarantine",
        severity: "low",
        title: "DMARC Policy p=quarantine",
        detail: `${domain} DMARC policy is p=quarantine. Failed auth goes to spam but is not rejected. Consider p=reject for stronger enforcement.`,
      });
    } else if (dmarc.policy === "reject") {
      log("    DMARC policy: p=reject ✓");
    }
    if (dmarc.pct !== undefined && dmarc.pct < 100) {
      dmarc.issues.push(`DMARC pct=${dmarc.pct} (partial rollout)`);
      findings.push({
        id: "dmarc-pct",
        severity: "low",
        title: `DMARC pct=${dmarc.pct} (Partial Rollout)`,
        detail: `${domain} DMARC applies policy to only ${dmarc.pct}% of mail. ${100 - dmarc.pct}% of spoofed mail still reaches inbox.`,
      });
    }
    if (!dmarc.rua) {
      dmarc.issues.push("No DMARC rua (report) address configured");
      findings.push({
        id: "dmarc-no-rua",
        severity: "info",
        title: "DMARC Missing rua Reporting",
        detail: `${domain} DMARC has no rua= address. No aggregate reports are received, reducing visibility into spoofing attempts.`,
      });
    }
    log(`    DMARC: p=${dmarc.policy} pct=${dmarc.pct}`);
  }

  // ---- DKIM ----
  log(`  Checking ${DKIM_SELECTORS.length} common DKIM selectors ...`);
  const dkim: EmailSecResult["dkim"] = {
    selectorsChecked: DKIM_SELECTORS,
    found: [],
    issues: [],
  };
  let checked = 0;
  const rawFound: { selector: string; record: string }[] = [];
  for (const sel of DKIM_SELECTORS) {
    const recs = await getTxt(`${sel}._domainkey.${domain}`);
    checked++;
    const dkimRec = recs.find((t) => /^v=DKIM1/i.test(t) || /k=rsa/i.test(t));
    if (dkimRec) {
      rawFound.push({ selector: sel, record: dkimRec });
      log(`    [+] DKIM found: ${sel}._domainkey.${domain}`);
    }
    if (checked % 6 === 0) log(`    ... checked ${checked}/${DKIM_SELECTORS.length}`);
  }

  // Detect wildcard DKIM: query a random nonexistent selector — if it
  // returns the same record, the domain has a wildcard _domainkey TXT
  // (often an empty `p=` key), which is a misconfiguration.
  const wildcardProbe = `zz-nonexistent-${Date.now().toString(36)}._domainkey.${domain}`;
  const wildcardRecs = await getTxt(wildcardProbe);
  const wildcardDkim = wildcardRecs.find((t) => /^v=DKIM1/i.test(t) || /k=rsa/i.test(t));
  if (wildcardDkim) {
    const wildcardEmpty = /p=\s*(;|$)/i.test(wildcardDkim);
    dkim.issues.push("Wildcard DKIM record detected (all selectors return identical record)");
    findings.push({
      id: "dkim-wildcard",
      severity: wildcardEmpty ? "high" : "medium",
      title: wildcardEmpty ? "Wildcard Empty DKIM Record" : "Wildcard DKIM Record",
      detail: `${domain} returns a DKIM TXT record for EVERY selector (incl. random ones like ${wildcardProbe}). ${wildcardEmpty ? "The record has an empty public key (p=), a misconfiguration that can weaken DKIM signature validation." : "Wildcard DKIM is unusual and may indicate misconfiguration."}`,
    });
    // Keep only the first found (they're all identical) to avoid noise.
    dkim.found = rawFound.slice(0, 1).map((f) => ({ selector: f.selector + " (wildcard)", record: f.record.slice(0, 120) + "..." }));
    log(`    [!] Wildcard DKIM detected — all selectors return identical record`);
  } else {
    dkim.found = rawFound.map((f) => ({ selector: f.selector, record: f.record.slice(0, 120) + "..." }));
  }

  if (dkim.found.length === 0 && !wildcardDkim) {
    dkim.issues.push("No DKIM records found on common selectors");
    findings.push({
      id: "dkim-missing",
      severity: "medium",
      title: "No DKIM Signature Found",
      detail: `${domain} has no DKIM records on ${DKIM_SELECTORS.length} common selectors. Without DKIM, mail cannot be cryptographically verified, weakening DMARC alignment.`,
    });
  } else if (!wildcardDkim) {
    log(`    DKIM: ${dkim.found.length} selector(s) found`);
  }

  // ---- MX ----
  log("  Querying MX records ...");
  const mx: EmailSecResult["mx"] = { servers: [], providers: [], issues: [] };
  try {
    const mxRecords = await resolveMx(domain);
    mx.servers = mxRecords.map((m) => ({ exchange: m.exchange, priority: m.priority }));
    const nullMx = mxRecords.some((m) => !m.exchange || m.exchange === "." || m.exchange === "");
    if (nullMx) {
      mx.issues.push("Null MX record (RFC 7505) — domain explicitly does not accept mail");
      findings.push({
        id: "mx-null",
        severity: "info",
        title: "Null MX Record (No Mail)",
        detail: `${domain} publishes a null MX (RFC 7505), declaring it does not accept email. Legitimate configuration for non-mail domains.`,
      });
      log("    MX: null MX (domain does not accept mail)");
    } else {
      const providerSet = new Set<string>();
      for (const s of mx.servers) {
        for (const p of MX_PROVIDERS) {
          if (p.match.test(s.exchange) && !providerSet.has(p.name)) {
            providerSet.add(p.name);
          }
        }
      }
      mx.providers = Array.from(providerSet);
      if (mx.providers.length === 0 && mx.servers.length > 0) {
        mx.issues.push("MX uses unknown/non-mainstream provider");
        findings.push({
          id: "mx-unknown",
          severity: "info",
          title: "Unknown MX Provider",
          detail: `${domain} uses MX server(s) not matching known providers: ${mx.servers.map((s) => s.exchange).join(", ")}. Verify the provider's security posture.`,
        });
      }
      log(`    MX: ${mx.servers.length} server(s)${mx.providers.length ? " (" + mx.providers.join(", ") + ")" : ""}`);
    }
    if (mx.servers.length === 0 && !nullMx) {
      mx.issues.push("No MX records — domain cannot receive mail");
      findings.push({
        id: "mx-none",
        severity: "info",
        title: "No MX Records",
        detail: `${domain} has no MX records and cannot receive email. If unexpected, this may indicate misconfiguration.`,
      });
      log("    MX: no records");
    }
  } catch {
    mx.issues.push("MX lookup failed");
    log("    MX: lookup failed");
  }

  const highCount = findings.filter((f) => f.severity === "high").length;
  const medCount = findings.filter((f) => f.severity === "medium").length;
  log(
    `Email security analysis complete: ${findings.length} finding(s)${findings.length ? ` (${highCount} high, ${medCount} medium)` : ""}.`
  );

  return { domain, spf, dmarc, dkim, mx, findings };
}
