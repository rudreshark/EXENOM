/**
 * HTTP Probing Module
 * Probes a list of hosts over HTTP & HTTPS, capturing status, title,
 * server header, redirects and resolved IP.
 */
import * as dns from "dns";
import { promisify } from "util";
import type { HttpResult } from "./types";

const lookup = promisify(dns.lookup);

async function probeUrl(
  url: string,
  timeoutMs = 8000
): Promise<{
  status: number;
  title: string;
  server: string;
  redirect: string;
}> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "manual",
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    const server = res.headers.get("server") || "";
    const location = res.headers.get("location") || "";
    const ct = res.headers.get("content-type") || "";
    let title = "";
    if (ct.includes("text/html") || ct.includes("xml") || ct === "") {
      try {
        const body = await res.text();
        const m = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
        if (m) title = m[1].replace(/\s+/g, " ").trim().slice(0, 120);
      } catch {
        /* ignore body read errors */
      }
    }
    return { status: res.status, title, server, redirect: location };
  } catch {
    return { status: 0, title: "", server: "", redirect: "" };
  } finally {
    clearTimeout(t);
  }
}

export async function runHttp(
  hosts: string[],
  log: (msg: string) => void
): Promise<HttpResult> {
  const out: HttpResult["hosts"] = [];
  log(`Probing ${hosts.length} host(s) over HTTP/HTTPS ...`);

  for (const host of hosts) {
    let ip = "-";
    try {
      ip = (await lookup(host)).address;
    } catch {
      /* ignore */
    }

    const httpsUrl = `https://${host}`;
    const httpUrl = `http://${host}`;

    const httpsRes = await probeUrl(httpsUrl);
    if (httpsRes.status > 0) {
      out.push({
        url: httpsUrl,
        status: httpsRes.status,
        title: httpsRes.title,
        server: httpsRes.server,
        redirect: httpsRes.redirect,
        https: true,
        ip,
      });
      log(`  [+] ${httpsUrl} ${httpsRes.status} ${httpsRes.title || httpsRes.server || ""}`.trim());
      continue;
    }

    const httpRes = await probeUrl(httpUrl);
    if (httpRes.status > 0) {
      out.push({
        url: httpUrl,
        status: httpRes.status,
        title: httpRes.title,
        server: httpRes.server,
        redirect: httpRes.redirect,
        https: false,
        ip,
      });
      log(`  [+] ${httpUrl} ${httpRes.status} ${httpRes.title || httpRes.server || ""}`.trim());
      continue;
    }

    log(`  [-] ${host} - no HTTP/HTTPS response`);
  }

  log(`HTTP probing complete: ${out.length} service(s) responding.`);
  return { hosts: out };
}
