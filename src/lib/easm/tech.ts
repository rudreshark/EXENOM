/**
 * Technology Fingerprinting Module
 * Inspects HTTP response headers + HTML to fingerprint the
 * web server, language, framework, CDN and JS libraries.
 */
import type { TechResult } from "./types";

interface Fingerprint {
  name: string;
  /** returns confidence label if matched */
  test: (headers: Record<string, string>, body: string, cookies: string[]) => string | null;
}

const FINGERPRINTS: Fingerprint[] = [
  {
    name: "Nginx",
    test: (h) => (h["server"]?.toLowerCase().includes("nginx") ? "high" : null),
  },
  {
    name: "Apache",
    test: (h) => (h["server"]?.toLowerCase().includes("apache") ? "high" : null),
  },
  {
    name: "Microsoft IIS",
    test: (h) => (h["server"]?.toLowerCase().includes("microsoft-iis") ? "high" : null),
  },
  {
    name: "LiteSpeed",
    test: (h) => (h["server"]?.toLowerCase().includes("litespeed") ? "high" : null),
  },
  {
    name: "Caddy",
    test: (h) => (h["server"]?.toLowerCase().includes("caddy") ? "high" : null),
  },
  {
    name: "Cloudflare",
    test: (h) => (h["server"]?.toLowerCase().includes("cloudflare") || h["cf-ray"] ? "high" : null),
  },
  {
    name: "Cloudfront",
    test: (h) => (h["x-amz-cf-id"] || h["via"]?.includes("CloudFront") ? "high" : null),
  },
  {
    name: "Akamai",
    test: (h) => (h["x-akamai-transformed"] || h["server"]?.toLowerCase().includes("akamai") ? "high" : null),
  },
  {
    name: "PHP",
    test: (h) => (h["x-powered-by"]?.toLowerCase().includes("php") ? "high" : null),
  },
  {
    name: "ASP.NET",
    test: (h, _b, c) =>
      h["x-powered-by"]?.toLowerCase().includes("asp.net") ||
      h["x-aspnet-version"] ||
      c.some((x) => x.toLowerCase().startsWith("aspnetsession"))
        ? "high"
        : null,
  },
  {
    name: "Express",
    test: (h) => (h["x-powered-by"]?.toLowerCase().includes("express") ? "high" : null),
  },
  {
    name: "Next.js",
    test: (h, b) =>
      h["x-powered-by"]?.toLowerCase().includes("next.js") ||
      b.includes("__next") ||
      b.includes("_next/static")
        ? "high"
        : null,
  },
  {
    name: "React",
    test: (_h, b) => (b.includes("react") || b.includes("__NEXT_DATA__") ? "medium" : null),
  },
  {
    name: "Vue.js",
    test: (_h, b) => (b.includes("vue") || b.includes("data-v-") ? "medium" : null),
  },
  {
    name: "Angular",
    test: (_h, b) => (b.includes("ng-app") || b.includes("ng-version") ? "high" : null),
  },
  {
    name: "WordPress",
    test: (_h, b) =>
      b.includes("wp-content") || b.includes("wp-includes") || b.includes('name="generator" content="WordPress')
        ? "high"
        : null,
  },
  {
    name: "Drupal",
    test: (h, b) =>
      h["x-generator"]?.toLowerCase().includes("drupal") ||
      b.includes("Drupal.settings")
        ? "high"
        : null,
  },
  {
    name: "Joomla",
    test: (_h, b) => (b.includes("joomla") || b.includes('name="generator" content="Joomla') ? "high" : null),
  },
  {
    name: "jQuery",
    test: (_h, b) => (b.includes("jquery") ? "medium" : null),
  },
  {
    name: "Bootstrap",
    test: (_h, b) => (b.includes("bootstrap") ? "medium" : null),
  },
  {
    name: "Tailwind CSS",
    test: (_h, b) => (b.includes("tailwind") ? "medium" : null),
  },
  {
    name: "Google Analytics",
    test: (_h, b) => (b.includes("google-analytics.com") || b.includes("gtag") ? "high" : null),
  },
  {
    name: "Varnish",
    test: (h) => (h["via"]?.toLowerCase().includes("varnish") || h["x-varnish"] ? "high" : null),
  },
  {
    name: "OpenResty",
    test: (h) => (h["server"]?.toLowerCase().includes("openresty") ? "high" : null),
  },
];

async function fetchHeaders(
  url: string,
  timeoutMs = 8000
): Promise<{ headers: Record<string, string>; body: string; cookies: string[] } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
    const setCookie = res.headers.get("set-cookie") || "";
    const cookies = setCookie
      .split(/,(?=\s*[a-zA-Z0-9_-]+=)/)
      .map((c) => c.trim())
      .filter(Boolean);
    let body = "";
    try {
      body = await res.text();
    } catch {
      /* ignore */
    }
    return { headers, body, cookies };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

export async function runTech(
  urls: string[],
  log: (msg: string) => void
): Promise<TechResult> {
  const hosts: TechResult["hosts"] = [];
  log(`Fingerprinting technologies for ${urls.length} host(s) ...`);

  for (const url of urls) {
    const data = await fetchHeaders(url);
    if (!data) {
      log(`  [-] ${url} - no response`);
      continue;
    }
    const techs: { name: string; confidence: string }[] = [];
    const seen = new Set<string>();
    for (const fp of FINGERPRINTS) {
      const conf = fp.test(data.headers, data.body, data.cookies);
      if (conf && !seen.has(fp.name)) {
        seen.add(fp.name);
        techs.push({ name: fp.name, confidence: conf });
      }
    }
    hosts.push({ url, technologies: techs });
    log(
      `  [+] ${url}: ${techs.length ? techs.map((t) => t.name).join(", ") : "no fingerprints"}`
    );
  }

  log(`Technology fingerprinting complete: ${hosts.length} host(s) analyzed.`);
  return { hosts };
}
