/**
 * Deep HTTP Fingerprinting ("screenshots") Module
 * Despite its name, this module performs deep HTTP analysis on a list of URLs:
 *   - title, favicon SHA256 + MurmurHash3 (shodan/fofa-style)
 *   - full redirect chain (manual follow, up to 5 hops)
 *   - server / X-Powered-By disclosure
 *   - security-headers presence (HSTS / CSP / XFO / XCTO / Referrer) + HSTS max-age
 *   - Set-Cookie parsing (name, secure, httpOnly, SameSite)
 *   - <form>, <input>, external <script src> and unique external <a href> domain counts
 *   - HTTPS detection + TLS issuer.O extraction
 *
 * Pure Node built-ins only (crypto, tls, fetch). No external packages.
 */
import * as crypto from "crypto";
import * as tls from "tls";
import type { ScreenshotResult } from "./types";

const UA = "easm-scanner/1.0 (+deep-http-fp)";
const MAX_HOSTS = 10;
const MAX_REDIRECTS = 5;
const HTTP_TIMEOUT = 8000;
const FAVICON_TIMEOUT = 8000;
const TLS_TIMEOUT = 6000;
const BODY_LIMIT = 50 * 1024; // 50 KB

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/** Decode common HTML entities (named + numeric) and trim/collapse whitespace. */
function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&nbsp;/gi, " ")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h: string) => {
      try {
        return String.fromCodePoint(parseInt(h, 16));
      } catch {
        return "";
      }
    })
    .replace(/&#(\d+);/g, (_, d: string) => {
      try {
        return String.fromCodePoint(parseInt(d, 10));
      } catch {
        return "";
      }
    });
}

/**
 * MurmurHash3 x86 32-bit, operating on raw bytes.
 * Returns the unsigned 32-bit hash as a numeric string — the standard
 * format shodan/fofa use for favicon lookups.
 *
 * Reference: Gary Court's public-domain JS implementation, adapted for Buffer.
 * A small `mul32` helper replaces the manual 16-bit-split multiplications to
 * keep the arithmetic readable (and provably balanced).
 */

/** 32-bit multiply with wraparound: (a * b) mod 2^32 via 16-bit splits. */
function mul32(a: number, b: number): number {
  const al = a & 0xffff;
  const ah = (a >>> 16) & 0xffff;
  return ((al * b) + (((ah * b) & 0xffff) << 16)) & 0xffffffff;
}

function murmurhash3_32(buf: Buffer, seed = 0): string {
  const len = buf.length;
  const remainder = len & 3;
  const bytes = len - remainder;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let h1 = seed;
  let i = 0;

  while (i < bytes) {
    let k1 =
      buf[i] |
      (buf[i + 1] << 8) |
      (buf[i + 2] << 16) |
      (buf[i + 3] << 24);
    i += 4;

    k1 = mul32(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = mul32(k1, c2);

    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = (mul32(h1, 5) + 0xe6546b64) & 0xffffffff;
  }

  let k1 = 0;
  if (remainder >= 3) k1 = (buf[i + 2] & 0xff) << 16;
  if (remainder >= 2) k1 |= (buf[i + 1] & 0xff) << 8;
  if (remainder >= 1) {
    k1 |= buf[i] & 0xff;
    k1 = mul32(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = mul32(k1, c2);
    h1 ^= k1;
  }

  h1 ^= len;

  h1 ^= h1 >>> 16;
  h1 = mul32(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = mul32(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return (h1 >>> 0).toString();
}

/** Extract <title> from HTML body: regex, entity-decode, collapse whitespace, trim to 120 chars. */
function parseTitle(body: string): string {
  const m = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!m) return "";
  return decodeEntities(m[1]).replace(/\s+/g, " ").trim().slice(0, 120);
}

/** Extract security-header presence + HSTS max-age from a flat header record. */
function parseSecurityHeaders(headers: Record<string, string>): {
  hsts: boolean;
  csp: boolean;
  xfo: boolean;
  xcto: boolean;
  referrer: boolean;
  hstsMaxAge: number | null;
} {
  const hstsHeader = headers["strict-transport-security"] || "";
  let hstsMaxAge: number | null = null;
  if (hstsHeader) {
    const m = hstsHeader.match(/max-age\s*=\s*(\d+)/i);
    if (m) hstsMaxAge = parseInt(m[1], 10);
  }
  return {
    hsts: !!hstsHeader,
    csp: !!headers["content-security-policy"],
    xfo: !!headers["x-frame-options"],
    xcto: !!headers["x-content-type-options"],
    referrer: !!headers["referrer-policy"],
    hstsMaxAge,
  };
}

/** Parse a list of raw Set-Cookie header values into structured records. */
function parseCookies(rawCookies: string[]): {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
}[] {
  const out: { name: string; secure: boolean; httpOnly: boolean; sameSite: string }[] = [];
  for (const raw of rawCookies) {
    if (!raw) continue;
    // A single Set-Cookie header may contain multiple cookies separated by ", "
    // when the server splits them — but that's rare. We split on the canonical
    // boundary (comma followed by a new cookie name=) just in case.
    const parts = raw.split(/,(?=\s*[a-zA-Z0-9_-]+=)/);
    for (const cookie of parts) {
      const segs = cookie.split(";");
      if (segs.length === 0) continue;
      const namePart = segs[0];
      const eq = namePart.indexOf("=");
      if (eq < 0) continue;
      const name = namePart.slice(0, eq).trim();
      if (!name) continue;
      let secure = false;
      let httpOnly = false;
      let sameSite = "";
      for (let i = 1; i < segs.length; i++) {
        const p = segs[i].trim();
        const lower = p.toLowerCase();
        if (lower === "secure") secure = true;
        else if (lower === "httponly") httpOnly = true;
        else if (lower.startsWith("samesite=")) {
          sameSite = p.slice("samesite=".length).trim();
        }
      }
      out.push({ name, secure, httpOnly, sameSite });
    }
  }
  return out;
}

/** Count forms, inputs, external JS files, and unique external link domains from HTML. */
function analyzeBody(body: string, finalUrl: string): {
  forms: number;
  inputs: number;
  jsFiles: number;
  externalLinks: number;
} {
  const forms = (body.match(/<form\b/gi) || []).length;
  const inputs = (body.match(/<input\b/gi) || []).length;

  // External <script src="http...">
  const scriptMatches = body.match(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi) || [];
  let jsFiles = 0;
  for (const sm of scriptMatches) {
    const srcMatch = sm.match(/\bsrc\s*=\s*["']?([^"'\s>]+)/i);
    if (srcMatch && /^https?:\/\//i.test(srcMatch[1])) jsFiles++;
  }

  // Unique external <a href="http..."> domains
  const anchorMatches = body.match(/<a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)/gi) || [];
  const externalDomains = new Set<string>();
  let baseHost = "";
  try {
    baseHost = new URL(finalUrl).hostname.toLowerCase();
  } catch {
    /* ignore */
  }
  for (const am of anchorMatches) {
    const hrefMatch = am.match(/\bhref\s*=\s*["']?([^"'\s>]+)/i);
    if (!hrefMatch) continue;
    const href = hrefMatch[1];
    if (!/^https?:\/\//i.test(href)) continue;
    try {
      const host = new URL(href).hostname.toLowerCase();
      if (host && host !== baseHost) externalDomains.add(host);
    } catch {
      /* ignore */
    }
  }

  return { forms, inputs, jsFiles, externalLinks: externalDomains.size };
}

/**
 * Fetch a URL with manual redirect following, recording every redirect hop.
 * Returns the final URL, status, headers, raw Set-Cookie list, body (<=50KB),
 * and the recorded redirect chain.
 */
async function fetchWithRedirectChain(
  startUrl: string,
  timeoutMs = HTTP_TIMEOUT,
  maxRedirects = MAX_REDIRECTS
): Promise<{
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  redirectChain: { url: string; status: number }[];
}> {
  const chain: { url: string; status: number }[] = [];
  let currentUrl = startUrl;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch(currentUrl, {
        signal: ctrl.signal,
        redirect: "manual",
        headers: { "User-Agent": UA, Accept: "text/html,application/xhtml+xml,*/*" },
      });
    } catch {
      clearTimeout(t);
      return {
        finalUrl: currentUrl,
        status: 0,
        headers: {},
        setCookies: [],
        body: "",
        redirectChain: chain,
      };
    }
    clearTimeout(t);

    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));

    // Extract Set-Cookie list — prefer Headers.getSetCookie() when available,
    // otherwise fall back to splitting the merged header.
    const setCookies: string[] = [];
    try {
      const getter = (res.headers as unknown as {
        getSetCookie?: () => string[];
      }).getSetCookie;
      if (typeof getter === "function") {
        const list = getter.call(res.headers);
        if (Array.isArray(list)) setCookies.push(...list);
      }
    } catch {
      /* ignore */
    }
    if (setCookies.length === 0 && headers["set-cookie"]) {
      setCookies.push(
        ...headers["set-cookie"].split(/,(?=\s*[a-zA-Z0-9_-]+=)/)
      );
    }

    const status = res.status;
    const location = headers["location"] || "";
    const isRedirect = status >= 300 && status < 400 && location;

    if (isRedirect && hop < maxRedirects) {
      // Record this hop and continue
      chain.push({ url: currentUrl, status });
      try {
        currentUrl = new URL(location, currentUrl).href;
      } catch {
        // malformed Location — bail
        return {
          finalUrl: currentUrl,
          status,
          headers,
          setCookies,
          body: "",
          redirectChain: chain,
        };
      }
      continue;
    }

    // Final response — read body (up to BODY_LIMIT bytes)
    let body = "";
    try {
      const ab = await res.arrayBuffer();
      const view = ab.byteLength > BODY_LIMIT ? ab.slice(0, BODY_LIMIT) : ab;
      body = new TextDecoder().decode(new Uint8Array(view));
    } catch {
      /* ignore */
    }

    if (isRedirect) {
      // Hit max-redirects cap on a redirect response — record final hop
      chain.push({ url: currentUrl, status });
    }

    return {
      finalUrl: currentUrl,
      status,
      headers,
      setCookies,
      body,
      redirectChain: chain,
    };
  }

  // Unreachable in practice
  return {
    finalUrl: currentUrl,
    status: 0,
    headers: {},
    setCookies: [],
    body: "",
    redirectChain: chain,
  };
}

/** Fetch /favicon.ico at the FINAL redirect target's origin. Returns SHA256 + MMH3. */
async function fetchFavicon(
  finalUrl: string,
  timeoutMs = FAVICON_TIMEOUT
): Promise<{ hash: string | null; mmh: string | null }> {
  let origin: string;
  try {
    origin = new URL(finalUrl).origin;
  } catch {
    return { hash: null, mmh: null };
  }
  const favUrl = origin + "/favicon.ico";

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(favUrl, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": UA },
    });
    if (!res.ok) return { hash: null, mmh: null };
    const ab = await res.arrayBuffer();
    const buf = Buffer.from(ab);
    if (!buf || buf.length === 0) return { hash: null, mmh: null };
    const hash = crypto.createHash("sha256").update(buf).digest("hex");
    const mmh = murmurhash3_32(buf);
    return { hash, mmh };
  } catch {
    return { hash: null, mmh: null };
  } finally {
    clearTimeout(t);
  }
}

/** Connect to host:443 and read the peer certificate's issuer.O (6s timeout). */
function getTlsIssuer(host: string, timeoutMs = TLS_TIMEOUT): Promise<string> {
  return new Promise<string>((resolve) => {
    let settled = false;
    const finish = (val: string) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(val);
    };
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          if (cert && cert.issuer) {
            finish(cert.issuer.O || cert.issuer.CN || "");
          } else {
            finish("");
          }
        } catch {
          finish("");
        }
      }
    );
    socket.setTimeout(timeoutMs);
    socket.once("timeout", () => finish(""));
    socket.once("error", () => finish(""));
  });
}

// ----------------------------------------------------------------------------
// Public entry point
// ----------------------------------------------------------------------------

export async function runScreenshots(
  urls: string[],
  log: (msg: string) => void
): Promise<ScreenshotResult> {
  const out: ScreenshotResult["hosts"] = [];
  const capped = urls.slice(0, MAX_HOSTS);
  log(`Deep HTTP fingerprinting ${capped.length}/${urls.length} URL(s) ...`);

  for (let i = 0; i < capped.length; i++) {
    const url = capped[i];
    log(`  analyzing ${i + 1}/${urls.length}: ${url}`);

    // 1a. Fetch + manual redirect chain
    const { finalUrl, status, headers, setCookies, body, redirectChain } =
      await fetchWithRedirectChain(url);

    if (status === 0) {
      log(`  [-] ${url} - no response`);
      continue;
    }

    // 1b. Title
    const title = parseTitle(body);

    // 1c. Favicon (computed from the FINAL redirect target's origin)
    const fav = await fetchFavicon(finalUrl);

    // 1d. Server / X-Powered-By
    const server = headers["server"] || "";
    const poweredBy = headers["x-powered-by"] || "";

    // 1e. Security headers + HSTS max-age
    const secHeaders = parseSecurityHeaders(headers);

    // 1f. Cookies
    const cookies = parseCookies(setCookies);

    // 1g. Forms / inputs / external JS / unique external link domains
    const counts = analyzeBody(body, finalUrl);

    // 1h. HTTPS detection
    const https = finalUrl.toLowerCase().startsWith("https://");

    // 1i. TLS issuer (HTTPS only)
    let tlsIssuer = "";
    if (https) {
      let host = "";
      try {
        host = new URL(finalUrl).hostname;
      } catch {
        host = "";
      }
      if (host) {
        try {
          tlsIssuer = await getTlsIssuer(host);
        } catch {
          tlsIssuer = "";
        }
      }
    }

    const faviconHashShort = fav.hash ? fav.hash.slice(0, 12) + "..." : "none";
    log(
      `  [+] ${url} -> ${status} "${title}" | favicon=${faviconHashShort} | ${counts.jsFiles} js, ${counts.forms} forms`
    );

    out.push({
      url,
      title,
      statusCode: status,
      redirectChain,
      faviconHash: fav.hash,
      faviconMmh: fav.mmh,
      server,
      poweredBy,
      securityHeaders: {
        hsts: secHeaders.hsts,
        csp: secHeaders.csp,
        xfo: secHeaders.xfo,
        xcto: secHeaders.xcto,
        referrer: secHeaders.referrer,
      },
      cookies,
      forms: counts.forms,
      inputs: counts.inputs,
      jsFiles: counts.jsFiles,
      externalLinks: counts.externalLinks,
      https,
      hstsMaxAge: secHeaders.hstsMaxAge,
      tlsIssuer,
    });
  }

  log(`Deep HTTP fingerprinting complete: ${out.length} host(s).`);
  return { hosts: out };
}
