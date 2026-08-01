/**
 * WebDAV Probing Module
 *
 * Detects WebDAV-enabled servers and tests for dangerous methods
 * (PUT/MKCOL/DELETE) that allow unauthenticated file upload and
 * potential remote code execution.
 */
import type { WebDavResult } from "./types";

async function request(
  url: string,
  method: string,
  body?: string,
  headers: Record<string, string> = {},
  timeoutMs = 8000
): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const init: RequestInit = {
      method,
      signal: ctrl.signal,
      headers: { "User-Agent": "easm-scanner/1.0", ...headers },
    };
    if (body) init.body = body;
    const res = await fetch(url, init);
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => (h[k.toLowerCase()] = v));
    let b = "";
    try {
      b = await res.text();
    } catch {
      /* ignore */
    }
    return { status: res.status, headers: h, body: b.slice(0, 50000) };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

const WEBDAV_METHODS = ["OPTIONS", "PROPFIND", "MKCOL", "PUT", "DELETE", "COPY", "MOVE", "LOCK", "UNLOCK", "PROPPATCH"];

function parseAllowMethods(allow: string): string[] {
  if (!allow) return [];
  return allow
    .split(",")
    .map((m) => m.trim().toUpperCase())
    .filter(Boolean);
}

function extractResourcesFromPropfind(body: string): number {
  // Count <D:response> or <response> elements
  const matches = body.match(/<(?:D:|d:)?response>/gi);
  return matches ? matches.length : 0;
}

export async function runWebDav(
  urls: string[],
  log: (msg: string) => void
): Promise<WebDavResult> {
  const hosts: WebDavResult["hosts"] = [];
  log(`Probing WebDAV on ${urls.length} host(s) ...`);

  for (const url of urls.slice(0, 6)) {
    log(`  testing ${url} ...`);
    const result: WebDavResult["hosts"][0] = {
      url,
      enabled: false,
      methods: [],
      writable: false,
      propfindDepth: false,
      authRequired: false,
      uploads: [],
    };

    // 1. OPTIONS — discover allowed methods
    const opts = await request(url, "OPTIONS");
    if (opts) {
      if (opts.status === 401 || opts.status === 407) {
        result.authRequired = true;
      }
      const allow = opts.headers["allow"] || opts.headers["dav"] || "";
      const davHeader = opts.headers["dav"] || "";
      const methods = parseAllowMethods(allow);
      result.methods = methods;

      // WebDAV is considered enabled if DAV header present OR WebDAV methods in Allow
      const webdavMethods = methods.filter((m) => WEBDAV_METHODS.includes(m));
      if (davHeader || webdavMethods.length >= 2) {
        result.enabled = true;
        log(`    [+] WebDAV enabled (DAV: ${davHeader || "n/a"}, methods: ${webdavMethods.join(", ") || "none"})`);
      }
    }

    // 2. PROPFIND — test directory listing
    const propfind = await request(
      url,
      "PROPFIND",
      '<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>',
      { Depth: "1", "Content-Type": "application/xml" }
    );
    if (propfind && (propfind.status === 207 || propfind.status === 200)) {
      result.enabled = true;
      result.propfindDepth = true;
      const resCount = extractResourcesFromPropfind(propfind.body);
      log(`    [+] PROPFIND successful (207 Multi-Status, ${resCount} resource(s))`);
    }

    // 3. MKCOL — test directory creation
    const testDir = `${url.replace(/\/$/, "")}/easm-test-${Date.now().toString(36)}`;
    const mkcol = await request(testDir, "MKCOL");
    if (mkcol && (mkcol.status === 201 || mkcol.status === 200)) {
      result.writable = true;
      log(`    [!] MKCOL succeeded — created ${testDir} (HTTP ${mkcol.status})`);
      // Clean up
      await request(testDir, "DELETE");
    }

    // 4. PUT — test file upload
    const testFile = `${url.replace(/\/$/, "")}/easm-test-${Date.now().toString(36)}.txt`;
    const put = await request(
      testFile,
      "PUT",
      "easm-webdav-test-marker",
      { "Content-Type": "text/plain" }
    );
    if (put && (put.status === 201 || put.status === 200 || put.status === 204)) {
      result.writable = true;
      result.uploads.push({ path: testFile, success: true, status: put.status });
      log(`    [!] PUT succeeded — uploaded ${testFile} (HTTP ${put.status}) — potential RCE via webshell upload`);
      // Clean up
      await request(testFile, "DELETE");
    } else if (put) {
      result.uploads.push({ path: testFile, success: false, status: put.status });
    }

    if (result.enabled) {
      hosts.push(result);
    } else {
      log(`    [-] ${url} - WebDAV not enabled`);
    }
  }

  const enabledCount = hosts.length;
  const writableCount = hosts.filter((h) => h.writable).length;
  log(`WebDAV probing complete: ${enabledCount} WebDAV host(s)${writableCount ? `, ${writableCount} writable` : ""}.`);
  return { hosts };
}
