/**
 * Web Crawler Module
 *
 * Spiders a target website up to a configurable depth, extracting:
 *   - Internal links (same-origin)  → expands crawl frontier
 *   - External links (third-party)  → attack-surface expansion
 *   - Email addresses               → phishing/OSINT targets
 *   - Phone numbers                 → social-engineering intel
 *   - File links (.pdf, .doc, .xls, .zip ...) → document exposure
 *   - Form parameters               → injection candidates
 */
import type { CrawlResult } from "./types";

const FILE_EXT = [
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".zip", ".tar", ".gz", ".rar", ".7z", ".csv", ".txt", ".xml",
  ".sql", ".db", ".bak", ".log", ".json", ".yml", ".yaml", ".env",
];

function extractLinks(html: string, baseUrl: string): { internal: string[]; external: string[] } {
  const internal = new Set<string>();
  const external = new Set<string>();
  const re = /href\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return { internal: [], external: [] };
  }
  while ((m = re.exec(html)) !== null) {
    const raw = m[1];
    if (!raw || raw.startsWith("#") || raw.startsWith("javascript:") || raw.startsWith("mailto:") || raw.startsWith("tel:")) continue;
    try {
      const abs = new URL(raw, baseUrl);
      if (abs.origin === base.origin) {
        internal.add(abs.href.split("#")[0]);
      } else if (abs.protocol === "http:" || abs.protocol === "https:") {
        external.add(abs.origin);
      }
    } catch {
      /* ignore malformed */
    }
  }
  return { internal: Array.from(internal), external: Array.from(external) };
}

function extractTitle(html: string): string {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, " ").trim().slice(0, 100) : "";
}

function countForms(html: string): number {
  return (html.match(/<form[\s>]/gi) || []).length;
}

function extractParams(html: string): string[] {
  const params = new Set<string>();
  // <input name="...">
  const re1 = /<input[^>]+name\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re1.exec(html)) !== null) params.add(m[1]);
  // <a href="?param=value">
  const re2 = /[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/g;
  while ((m = re2.exec(html)) !== null) params.add(m[1]);
  return Array.from(params).slice(0, 20);
}

function extractEmails(html: string): string[] {
  const set = new Set<string>();
  const re = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    if (!m[0].endsWith(".png") && !m[0].endsWith(".jpg") && !m[0].endsWith(".svg")) {
      set.add(m[0]);
    }
  }
  return Array.from(set);
}

function extractPhones(html: string): string[] {
  const set = new Set<string>();
  const re = /(?:\+?\d[\d\s\-().]{8,}\d)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const cleaned = m[0].replace(/\s/g, "");
    if (cleaned.length >= 10 && cleaned.length <= 17) set.add(m[0].trim());
  }
  return Array.from(set).slice(0, 20);
}

function extractFiles(links: string[]): string[] {
  return links.filter((l) => FILE_EXT.some((ext) => l.toLowerCase().includes(ext)));
}

async function fetchPage(url: string, timeoutMs = 8000): Promise<{ status: number; body: string } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    const ct = res.headers.get("content-type") || "";
    let body = "";
    if (ct.includes("text") || ct.includes("xml") || ct === "") {
      try {
        body = await res.text();
      } catch {
        body = "";
      }
    }
    return { status: res.status, body: body.slice(0, 200000) };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

export async function runCrawl(
  startUrl: string,
  maxDepth: number,
  maxPages: number,
  log: (msg: string) => void
): Promise<CrawlResult> {
  log(`Spidering ${startUrl} (max depth ${maxDepth}, max ${maxPages} pages) ...`);
  const visited = new Set<string>();
  const pages: CrawlResult["pages"] = [];
  const allInternal = new Set<string>();
  const allExternal = new Set<string>();
  const allEmails = new Set<string>();
  const allPhones = new Set<string>();
  const allFiles = new Set<string>();
  let queue: { url: string; depth: number }[] = [{ url: startUrl, depth: 0 }];

  while (queue.length > 0 && pages.length < maxPages) {
    const batch = queue.splice(0, Math.min(5, queue.length));
    for (const item of batch) {
      if (visited.has(item.url) || pages.length >= maxPages) continue;
      visited.add(item.url);
      log(`  [${item.depth}] ${item.url.slice(0, 70)}`);
      const page = await fetchPage(item.url);
      if (!page || page.status >= 400) continue;

      const title = extractTitle(page.body);
      const forms = countForms(page.body);
      const params = extractParams(page.body);
      const links = extractLinks(page.body, item.url);

      pages.push({
        url: item.url,
        status: page.status,
        title,
        depth: item.depth,
        links: links.internal.length + links.external.length,
        forms,
        params,
      });

      links.internal.forEach((l) => allInternal.add(l));
      links.external.forEach((l) => allExternal.add(l));
      extractEmails(page.body).forEach((e) => allEmails.add(e));
      extractPhones(page.body).forEach((p) => allPhones.add(p));
      extractFiles(links.internal).forEach((f) => allFiles.add(f));

      // Enqueue deeper links
      if (item.depth < maxDepth) {
        for (const l of links.internal.slice(0, 15)) {
          if (!visited.has(l)) queue.push({ url: l, depth: item.depth + 1 });
        }
      }
    }
  }

  log(
    `Crawl complete: ${pages.length} page(s), ${allInternal.size} internal link(s), ${allExternal.size} external link(s), ${allEmails.size} email(s), ${allFiles.size} file(s).`
  );
  return {
    pages,
    internalLinks: Array.from(allInternal).slice(0, 100),
    externalLinks: Array.from(allExternal).slice(0, 50),
    emails: Array.from(allEmails),
    phones: Array.from(allPhones),
    files: Array.from(allFiles),
  };
}
