/**
 * TLS / Certificate Analysis Module
 * Connects to each host:443, retrieves the peer certificate and
 * reports validity, issuer, SAN entries and self-signed status.
 */
import * as tls from "tls";
import * as dns from "dns";
import { promisify } from "util";
import type { TlsResult } from "./types";

const lookup = promisify(dns.lookup);

function getCert(host: string, port = 443, timeout = 8000): Promise<tls.PeerCertificate | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (cert: tls.PeerCertificate | null) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(cert);
    };
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        finish(cert || null);
      }
    );
    socket.setTimeout(timeout);
    socket.once("timeout", () => finish(null));
    socket.once("error", () => finish(null));
  });
}

function parseSubject(cert: tls.PeerCertificate): string {
  const s = cert.subject;
  const parts: string[] = [];
  if (s.CN) parts.push(`CN=${s.CN}`);
  if (s.O) parts.push(`O=${s.O}`);
  if (s.OU) parts.push(`OU=${s.OU}`);
  if (s.C) parts.push(`C=${s.C}`);
  return parts.join(", ") || JSON.stringify(s);
}

function parseIssuer(cert: tls.PeerCertificate): string {
  const i = cert.issuer;
  const parts: string[] = [];
  if (i.CN) parts.push(`CN=${i.CN}`);
  if (i.O) parts.push(`O=${i.O}`);
  return parts.join(", ") || JSON.stringify(i);
}

export async function runTls(
  hosts: string[],
  log: (msg: string) => void
): Promise<TlsResult> {
  const certs: TlsResult["certs"] = [];
  log(`Analyzing TLS certificates for ${hosts.length} host(s) ...`);

  for (const host of hosts) {
    let ip = "-";
    try {
      ip = (await lookup(host)).address;
    } catch {
      /* ignore */
    }
    const cert = await getCert(host);
    if (!cert) {
      log(`  [-] ${host} - no TLS certificate`);
      continue;
    }

    const validFrom = cert.valid_from;
    const validTo = cert.valid_to;
    const daysRemaining = Math.round(
      (new Date(validTo).getTime() - Date.now()) / 86400000
    );
    const subject = parseSubject(cert);
    const issuer = parseIssuer(cert);
    const selfSigned =
      subject === issuer || (cert.subject.CN && cert.issuer.CN === cert.subject.CN);

    const sanRaw: string = (cert.subjectaltname as string) || "";
    const san = sanRaw
      .split(", ")
      .map((s) => s.replace(/^DNS:/, "").trim())
      .filter(Boolean);

    certs.push({
      host: `${host} (${ip})`,
      subject,
      issuer,
      validFrom,
      validTo,
      daysRemaining,
      serialNumber: cert.serialNumber,
      signatureAlgorithm: cert.fingerprint ? "sha256/rsa" : "unknown",
      san,
      selfSigned,
    });

    const expiryFlag =
      daysRemaining < 0 ? "EXPIRED" : daysRemaining < 30 ? `EXPIRES SOON (${daysRemaining}d)` : `${daysRemaining}d left`;
    log(
      `  [+] ${host} ${selfSigned ? "SELF-SIGNED " : ""}${expiryFlag} | ${subject}`
    );
  }

  log(`TLS analysis complete: ${certs.length} certificate(s).`);
  return { certs };
}
