/**
 * Subdomain Takeover Detection Module
 *
 * Detects potential subdomain takeover vulnerabilities by:
 *  1. Resolving CNAMEs for each host.
 *  2. Matching CNAMEs against a database of takeover-prone external
 *     service domains (S3, GitHub Pages, Heroku, Azure, etc.).
 *  3. Fetching HTTP/HTTPS responses (first 5 KB) and matching the body
 *     and status code against known takeover fingerprints.
 *  4. Flagging dangling CNAMEs — CNAME points to a known takeover-prone
 *     service but the host has no A record or HTTP is unreachable — as
 *     medium-severity "cname-dangling" findings.
 *
 * Uses only Node built-ins (dns, fetch). No external packages.
 */

import * as dns from "dns";
import { promisify } from "util";
import type { SubTakeoverResult } from "./types";

const resolveCname = promisify(dns.resolveCname);
const resolve4 = promisify(dns.resolve4);

const MAX_HOSTS = 80;
const HTTP_TIMEOUT_MS = 8000;
const PROGRESS_INTERVAL = 15;
const BODY_LIMIT = 5000; // first 5 KB of response body

interface Fingerprint {
  service: string;
  /** Patterns matched (case-insensitive) against the CNAME target. */
  cnamePatterns: RegExp[];
  /** Substrings matched (case-insensitive) against the response body. */
  bodySignatures: string[];
  /** Optional HTTP status that on its own is a takeover signal for this service. */
  statusMatch?: number;
  /** Default severity when this service is matched (overridden to "low" for soft matches). */
  severity: "high" | "medium";
}

/**
 * Database of takeover fingerprints. CNAME patterns are matched against
 * the resolved CNAME target; bodySignatures / statusMatch are matched
 * against the HTTP response. The first fingerprint (by array order) whose
 * CNAME pattern matches a host is used as the service of record.
 */
const FINGERPRINTS: Fingerprint[] = [
  {
    service: "AWS S3",
    cnamePatterns: [
      /\.s3\.amazonaws\.com$/i,
      /\.s3-website[-.][a-z0-9.-]*\.amazonaws\.com$/i,
    ],
    bodySignatures: ["The specified bucket does not exist", "NoSuchBucket"],
    statusMatch: 404,
    severity: "high",
  },
  {
    service: "GitHub Pages",
    cnamePatterns: [/\.github\.io$/i],
    bodySignatures: [
      "There isn't a GitHub Pages site here",
      "For root URLs (like http://example.com/)",
    ],
    statusMatch: 404,
    severity: "high",
  },
  {
    service: "GitLab Pages",
    cnamePatterns: [/\.gitlab\.io$/i],
    bodySignatures: [
      "The page you're looking for could not be found",
      "page you're looking for could not be found",
    ],
    severity: "medium",
  },
  {
    service: "Heroku",
    cnamePatterns: [/\.herokuapp\.com$/i, /\.herokussl\.com$/i, /\.herokudns\.com$/i],
    bodySignatures: [
      "No such app",
      "herokucdn.com/error-pages/no-such-app.html",
    ],
    statusMatch: 404,
    severity: "high",
  },
  {
    service: "Fastly",
    cnamePatterns: [/\.fastly\.net$/i],
    bodySignatures: [
      "Fastly error: unknown domain",
      "Please check that this is the correct URL",
    ],
    severity: "medium",
  },
  {
    service: "Tumblr",
    cnamePatterns: [/\.tumblr\.com$/i],
    bodySignatures: [
      "Whatever you were looking for doesn't currently exist at this address",
      "doesn't currently exist at this address",
    ],
    severity: "medium",
  },
  {
    service: "Shopify",
    cnamePatterns: [/\.myshopify\.com$/i, /\.shopify\.com$/i],
    bodySignatures: [
      "Sorry, this shop is currently unavailable",
      "Sorry, this store is currently unavailable",
    ],
    severity: "medium",
  },
  {
    service: "Pantheon",
    cnamePatterns: [/\.pantheonsite\.io$/i, /\.pantheon\.io$/i],
    bodySignatures: [
      "The gods are wise, but do not know of the site which you seek",
      "The gods are wise",
    ],
    severity: "medium",
  },
  {
    service: "Cloudfront",
    cnamePatterns: [/\.cloudfront\.net$/i],
    bodySignatures: [
      "Bad request",
      "ERROR: The request could not be satisfied",
      "ERROR The request could not be satisfied",
    ],
    severity: "medium",
  },
  {
    service: "Bitbucket",
    cnamePatterns: [/\.bitbucket\.io$/i],
    bodySignatures: ["Repository not found", "is not a Bitbucket resource"],
    severity: "medium",
  },
  {
    service: "Surge.sh",
    cnamePatterns: [/\.surge\.sh$/i],
    bodySignatures: ["project not found", "project_not_found"],
    severity: "medium",
  },
  {
    service: "Unbounce",
    cnamePatterns: [/\.unbouncepages\.com$/i],
    bodySignatures: [
      "The requested URL was not found on this server",
      "requested URL was not found on this server",
    ],
    severity: "medium",
  },
  {
    service: "Tilda",
    cnamePatterns: [/\.tilda\.ws$/i],
    bodySignatures: ["Please renew your subscription", "renew your subscription"],
    severity: "medium",
  },
  {
    service: "Strikingly",
    cnamePatterns: [/\.strikinglydns\.com$/i, /\.strikingly\.com$/i],
    bodySignatures: ["page not found", "PAGE NOT FOUND"],
    severity: "medium",
  },
  {
    service: "Webflow",
    cnamePatterns: [/\.webflow\.io$/i],
    bodySignatures: [
      "The page you are looking for doesn't exist or has been moved",
      "page you are looking for doesn't exist",
    ],
    severity: "medium",
  },
  {
    service: "Netlify",
    cnamePatterns: [/\.netlify\.app$/i, /\.netlify\.com$/i],
    bodySignatures: ["Not Found - Request ID:", "Not Found.\nRequest ID"],
    severity: "medium",
  },
  {
    service: "Vercel",
    cnamePatterns: [/\.vercel\.app$/i, /\.now\.sh$/i, /\.zeit\.co$/i],
    bodySignatures: ["The deployment could not be found", "Deployment not found"],
    severity: "medium",
  },
  {
    service: "Azure",
    cnamePatterns: [
      /\.azurewebsites\.net$/i,
      /\.cloudapp\.net$/i,
      /\.trafficmanager\.net$/i,
      /\.azureedge\.net$/i,
      /\.blob\.core\.windows\.net$/i,
      /\.azure-api\.net$/i,
    ],
    bodySignatures: [
      "404 Web Site not found",
      "The web page you are trying to access is currently unavailable",
      "Microsoft Azure Web Site - We couldn't find the page you requested",
    ],
    statusMatch: 404,
    severity: "high",
  },
  {
    service: "Cargo",
    cnamePatterns: [/\.cargocollective\.com$/i],
    bodySignatures: ["404 Not Found", "<title>Cargo - 404 Not Found</title>"],
    severity: "medium",
  },
  {
    service: "Smugmug",
    cnamePatterns: [/\.smugmug\.com$/i, /\.smugmug\.net$/i, /\.smugmug\.dev$/i],
    bodySignatures: ["smugmug | 404 - not found", "404 - not found"],
    severity: "medium",
  },
  {
    service: "Statuspage",
    cnamePatterns: [/\.statuspage\.io$/i],
    bodySignatures: ["You are being redirected", "redirected"],
    severity: "medium",
  },
  {
    service: "Acquia",
    cnamePatterns: [/\.acquia-sites\.com$/i, /\.acsitefactory\.com$/i],
    bodySignatures: ["Web Site Not Found", "site not found"],
    severity: "medium",
  },
  {
    service: "Readme.io",
    cnamePatterns: [/\.readme\.io$/i],
    bodySignatures: [
      "Project doesnt exist... yet!",
      "Project doesn't exist... yet!",
    ],
    severity: "medium",
  },
];

interface HttpProbe {
  status: number;
  body: string; // first BODY_LIMIT chars
  ok: boolean;
}

/**
 * Fetch a host over HTTPS (then HTTP fallback) with an 8s timeout.
 * Returns the HTTP status and the first 5 KB of the response body.
 * On total failure (no scheme responds) returns ok:false.
 */
async function probeHost(host: string): Promise<HttpProbe> {
  for (const scheme of ["https", "http"] as const) {
    const url = `${scheme}://${host}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        signal: ctrl.signal,
        redirect: "manual",
        headers: { "User-Agent": "easm-scanner/1.0 (subtakeover)" },
      });
      const raw = await res.text();
      return { status: res.status, body: raw.slice(0, BODY_LIMIT), ok: true };
    } catch {
      // try next scheme
    } finally {
      clearTimeout(timer);
    }
  }
  return { status: 0, body: "", ok: false };
}

/**
 * Run subdomain-takeover detection against a list of hostnames.
 *
 * Caps the input at 80 hosts. For each host: resolves the CNAME, and if
 * it points to a known takeover-prone service, resolves the A record
 * (dangling check) and probes HTTP/HTTPS to match against fingerprints.
 *
 * Findings are emitted via `log` and returned in the result. Progress is
 * logged every 15 hosts.
 */
export async function runSubTakeover(
  hosts: string[],
  log: (msg: string) => void
): Promise<SubTakeoverResult> {
  const capped = hosts.slice(0, MAX_HOSTS);
  const result: SubTakeoverResult = { checked: 0, vulnerable: [] };

  log(
    `Scanning ${capped.length} host(s) for subdomain takeover (cap ${MAX_HOSTS})...`
  );

  let i = 0;
  for (const host of capped) {
    i++;
    result.checked = i;

    if (i % PROGRESS_INTERVAL === 0) {
      log(`  ... ${i}/${capped.length} checked`);
    }

    // --- Resolve CNAME ---
    let cnames: string[] = [];
    try {
      cnames = await resolveCname(host);
    } catch {
      // No CNAME or DNS resolution failure — cannot be a takeover target.
      continue;
    }
    if (cnames.length === 0) continue;

    const cname = cnames[0];

    // Match CNAME against the fingerprint database.
    const matchedFps = FINGERPRINTS.filter((fp) =>
      fp.cnamePatterns.some((p) => p.test(cname))
    );
    if (matchedFps.length === 0) continue;

    // --- Resolve A record (follows the CNAME chain) ---
    // If the target service has been deleted, this throws ENOTFOUND
    // — a strong dangling signal.
    let hasA = false;
    try {
      const addrs = await resolve4(host);
      if (addrs.length > 0) hasA = true;
    } catch {
      // dangling (CNAME target has no A record)
    }

    // --- Fetch HTTP/HTTPS response ---
    const probe = await probeHost(host);

    let finding:
      | { service: string; fingerprint: string; severity: "high" | "medium" | "low" }
      | null = null;

    if (probe.ok) {
      const bodyLower = probe.body.toLowerCase();
      for (const fp of matchedFps) {
        // 1) Body signature match — strongest signal.
        const sigMatch = fp.bodySignatures.find((s) =>
          bodyLower.includes(s.toLowerCase())
        );
        if (sigMatch) {
          finding = {
            service: fp.service,
            fingerprint: sigMatch,
            severity: fp.severity,
          };
          break;
        }
        // 2) Status match (e.g. S3/GitHub/Azure 404 with no body signature
        //    present in the response).
        if (fp.statusMatch && probe.status === fp.statusMatch) {
          finding = {
            service: fp.service,
            fingerprint: `HTTP ${probe.status}`,
            severity: fp.severity,
          };
          break;
        }
      }

      // 3) Soft match — CNAME to a takeover-prone service + a generic 404,
      //    but no service-specific signature was present. Flag as low.
      if (!finding && probe.status === 404) {
        const fp = matchedFps[0];
        finding = {
          service: fp.service,
          fingerprint: `HTTP 404 (soft match)`,
          severity: "low",
        };
      }
    }

    // 4) Dangling CNAME — CNAME to a known takeover-prone service but
    //    HTTP unreachable OR no A record. Per spec: medium severity,
    //    fingerprint "cname-dangling".
    if (!finding && (!probe.ok || !hasA)) {
      const fp = matchedFps[0];
      finding = {
        service: fp.service,
        fingerprint: "cname-dangling",
        severity: "medium",
      };
    }

    if (finding) {
      result.vulnerable.push({
        hostname: host,
        cname,
        service: finding.service,
        fingerprint: finding.fingerprint,
        severity: finding.severity,
      });
      log(
        `  [+] VULNERABLE: ${host} -> ${finding.service} (${finding.fingerprint})`
      );
    }
  }

  log(
    `Subdomain takeover check complete: ${result.checked} checked, ${result.vulnerable.length} vulnerable.`
  );
  return result;
}
