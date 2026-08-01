/**
 * Banner Grabbing Module
 * Connects to known service ports and reads the greeting/banner.
 */
import * as net from "net";
import type { BannerResult } from "./types";

const PROBES: { port: number; service: string; write?: string }[] = [
  { port: 21, service: "ftp" },
  { port: 22, service: "ssh" },
  { port: 25, service: "smtp" },
  { port: 110, service: "pop3" },
  { port: 143, service: "imap" },
  { port: 80, service: "http", write: "HEAD / HTTP/1.0\r\n\r\n" },
  { port: 443, service: "https" },
  { port: 3306, service: "mysql" },
  { port: 5432, service: "postgresql" },
  { port: 6379, service: "redis", write: "INFO\r\n" },
  { port: 27017, service: "mongodb" },
  { port: 11211, service: "memcached", write: "version\r\n" },
  { port: 9200, service: "elasticsearch", write: "GET / HTTP/1.0\r\n\r\n" },
];

function grab(host: string, port: number, service: string, write: string | undefined, timeout = 6000): Promise<string> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(banner.trim().slice(0, 200));
    };
    socket.setTimeout(timeout);
    socket.once("connect", () => {
      if (write) socket.write(write);
      setTimeout(finish, 1200);
    });
    socket.on("data", (d) => {
      banner += d.toString("utf8");
      if (banner.length > 300) finish();
    });
    socket.once("timeout", finish);
    socket.once("error", finish);
    socket.connect(port, host);
  });
}

export async function runBanners(
  host: string,
  openPorts: number[],
  log: (msg: string) => void
): Promise<BannerResult> {
  const banners: BannerResult["banners"] = [];
  const targets = PROBES.filter((p) => openPorts.includes(p.port));
  if (targets.length === 0) {
    log("No banner-grabbable service ports open; skipping.");
    return { banners };
  }
  log(`Grabbing banners on ${targets.length} port(s) for ${host} ...`);

  for (const p of targets) {
    const banner = await grab(host, p.port, p.service, p.write);
    if (banner) {
      banners.push({ host, port: p.port, service: p.service, banner });
      log(`  [+] ${host}:${p.port} (${p.service}) -> ${banner.split("\n")[0]}`);
    } else {
      log(`  [-] ${host}:${p.port} (${p.service}) -> no banner`);
    }
  }

  log(`Banner grabbing complete: ${banners.length} banner(s).`);
  return { banners };
}
