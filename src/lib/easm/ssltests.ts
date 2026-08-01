/**
 * Advanced SSL/TLS Tests Module
 *
 * For each host (port 443) performs:
 *   - Protocol support probing (SSLv2 / SSLv3 / TLSv1.0 / TLSv1.1 / TLSv1.2 / TLSv1.3)
 *     using tls.connect with specific secureProtocol / minVersion+maxVersion options.
 *   - Negotiated-cipher capture on a TLSv1.2 connection (Node only negotiates ONE
 *     cipher per handshake; we record that one + classify its strength).
 *   - Certificate-chain length by walking `getPeerCertificate(true).issuerCertificate`
 *     (with a fingerprint-visited set so the self-signed root terminates cleanly).
 *   - OCSP stapling: `requestOCSP: true` + an `OCSPResponse` listener registered
 *     synchronously after tls.connect() (before the async handshake) — we wait up
 *     to 2s after `secureConnect` for an OCSP response.
 *   - HSTS: HTTPS fetch of `https://${host}/` and check for the
 *     `strict-transport-security` header.
 *   - Ticket rotation: not testable from a client; recorded as `false` (unknown).
 *
 * Severity-tagged issues are produced for: SSLv2/SSLv3 enabled, TLSv1.0/TLSv1.1
 * enabled, weak/insecure negotiated cipher, missing HSTS, no TLSv1.2/1.3 support,
 * and self-signed peer certificate.
 *
 * Pure Node built-ins only (tls, fetch). No external packages.
 */
import * as tls from "tls";
import type { SslTestsResult } from "./types";

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------

const MAX_HOSTS = 8;
const PORT = 443;
const PROTO_TIMEOUT = 6000; // 6s per protocol probe
const TLS12_TIMEOUT = 6000; // 6s for the TLSv1.2 enumeration connection
const OCSP_WAIT = 2000; // wait up to 2s after secureConnect for OCSP response
const HSTS_TIMEOUT = 6000; // 6s for the HTTPS fetch
const UA = "easm-scanner/1.0 (+ssl-tests)";

// ----------------------------------------------------------------------------
// Protocol test definitions
// ----------------------------------------------------------------------------

interface ProtocolTest {
  name: string;
  /** true for SSLv2 / SSLv3 / TLSv1.0 — protocols considered insecure. */
  insecure: boolean;
  /** Extra tls.connect options to force negotiation of just this protocol. */
  options: tls.ConnectionOptions;
  /**
   * Acceptable `socket.getProtocol()` return values that count as "this
   * protocol is enabled". Modern TLS stacks (especially Bun/BoringSSL) often
   * silently ignore `minVersion`/`maxVersion` and `secureProtocol`, so we
   * verify the negotiated version rather than trusting the connect callback
   * alone — otherwise a server that only speaks TLSv1.3 would falsely look
   * like it speaks SSLv2 just because Bun upgraded the handshake.
   *
   * For TLSv1.2 we ALSO accept "TLSv1.3" because in practice every TLSv1.3
   * server also supports TLSv1.2, but Bun will always negotiate the higher
   * version when both are available.
   */
  acceptableProtocols: string[];
}

const PROTOCOL_TESTS: ProtocolTest[] = [
  // SSLv2 / SSLv3 use the legacy `secureProtocol` slot — modern Node/OpenSSL
  // disables these at compile time, so tls.connect will throw or error out,
  // and we record enabled:false. That's the expected behaviour.
  {
    name: "SSLv2",
    insecure: true,
    options: { secureProtocol: "SSLv2_method" } as tls.ConnectionOptions,
    acceptableProtocols: ["SSLv2"],
  },
  {
    name: "SSLv3",
    insecure: true,
    options: { secureProtocol: "SSLv3_method" } as tls.ConnectionOptions,
    acceptableProtocols: ["SSLv3"],
  },
  {
    name: "TLSv1.0",
    insecure: true,
    options: { minVersion: "TLSv1", maxVersion: "TLSv1" },
    acceptableProtocols: ["TLSv1"],
  },
  {
    name: "TLSv1.1",
    insecure: false,
    options: { minVersion: "TLSv1.1", maxVersion: "TLSv1.1" },
    acceptableProtocols: ["TLSv1.1"],
  },
  {
    name: "TLSv1.2",
    insecure: false,
    options: { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" },
    // Accept TLSv1.3 too — see comment above (TLS 1.3 implies 1.2 in practice).
    acceptableProtocols: ["TLSv1.2", "TLSv1.3"],
  },
  {
    name: "TLSv1.3",
    insecure: false,
    options: { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" },
    acceptableProtocols: ["TLSv1.3"],
  },
];

// ----------------------------------------------------------------------------
// Cipher strength classification
// ----------------------------------------------------------------------------

type CipherStrength = "strong" | "weak" | "insecure";

/**
 * Classify a cipher suite name into strong / weak / insecure based on the
 * keywords present in the OpenSSL-style cipher name.
 *
 *  - insecure: RC4, NULL, EXPORT / EXP-, MD5, aNULL / AECDH (anonymous), 40-bit
 *  - strong:   AEAD (GCM / CCM / ChaCha20 / Poly1305) or SHA-2 family (SHA256/384/512)
 *  - weak:     3DES / DES / CBC / SHA1 (non-SHA2), or anything unknown
 */
function classifyCipher(name: string): CipherStrength {
  const upper = name.toUpperCase();

  // Insecure markers — RC4, NULL, EXPORT/EXP-, MD5, anonymous, 40-bit
  if (
    /\bRC4\b/.test(upper) ||
    /\bNULL\b/.test(upper) ||
    /\bMD5\b/.test(upper) ||
    /\bANON\b/.test(upper) ||
    /\bAECDH\b/.test(upper) ||
    /\bEXPORT\b/.test(upper) ||
    /(^|[-_])EXP[-_]/.test(upper) ||
    /40[-_]?BIT/.test(upper)
  ) {
    return "insecure";
  }

  // Strong — AEAD ciphers or SHA-2 family MAC
  // `\bCCM(?:\d+)?\b` matches both "CCM" and "CCM8" (RFC 6605 AES-CCM-8).
  if (
    /\bGCM\b/.test(upper) ||
    /\bCCM(?:\d+)?\b/.test(upper) ||
    /\bCHACHA20\b/.test(upper) ||
    /\bPOLY1305\b/.test(upper) ||
    /SHA[-_]?(?:256|384|512)/.test(upper)
  ) {
    return "strong";
  }

  // Weak — 3DES / DES / CBC / SHA1 (plain "SHA" or "SHA1", not SHA256/384/512)
  if (
    /\b3DES\b/.test(upper) ||
    /\bDES\b/.test(upper) ||
    /\bCBC\b/.test(upper) ||
    /\bSHA1?\b/.test(upper)
  ) {
    return "weak";
  }

  // Unknown — be conservative
  return "weak";
}

// ----------------------------------------------------------------------------
// Protocol probe
// ----------------------------------------------------------------------------

interface ProtocolResult {
  name: string;
  enabled: boolean;
  insecure: boolean;
}

/**
 * Probe a single TLS protocol version. Resolves (never rejects) with
 * { enabled: true } only if the TLS handshake completes successfully; any
 * throw / error event / timeout resolves { enabled: false }.
 */
function testProtocol(host: string, test: ProtocolTest, timeout = PROTO_TIMEOUT): Promise<ProtocolResult> {
  return new Promise((resolve) => {
    let settled = false;
    let socket: tls.TLSSocket | null = null;

    const finish = (enabled: boolean) => {
      if (settled) return;
      settled = true;
      if (socket) {
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
      }
      resolve({ name: test.name, enabled, insecure: test.insecure });
    };

    try {
      socket = tls.connect(
        {
          host,
          port: PORT,
          servername: host,
          rejectUnauthorized: false,
          ...test.options,
        },
        () => {
          // Handshake completed. Verify the negotiated protocol actually
          // matches what we asked for — Bun/BoringSSL and some Node builds
          // silently ignore `secureProtocol`/`minVersion`/`maxVersion` and
          // upgrade the handshake to TLSv1.3, so a successful connect()
          // callback alone is NOT proof that the requested protocol is
          // enabled on the server.
          let negotiated: string | null = null;
          try {
            negotiated = socket?.getProtocol() ?? null;
          } catch {
            /* ignore */
          }
          const enabled =
            !!negotiated && test.acceptableProtocols.includes(negotiated);
          finish(enabled);
        }
      );
    } catch {
      // Synchronous throw (e.g. SSLv2_method rejected by OpenSSL) — protocol unavailable
      if (!settled) {
        settled = true;
        resolve({ name: test.name, enabled: false, insecure: test.insecure });
      }
      return;
    }

    if (!socket) return;

    socket.setTimeout(timeout);
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.once("close", () => finish(false));
  });
}

// ----------------------------------------------------------------------------
// TLSv1.2 deep probe — cipher + cert chain + OCSP stapling
// ----------------------------------------------------------------------------

interface Tls12Info {
  cipher: { name: string; strength: CipherStrength } | null;
  certChainLength: number;
  selfSigned: boolean;
  ocspStapling: boolean;
}

/**
 * Open a TLSv1.2 connection and capture:
 *   - the negotiated cipher (socket.getCipher())
 *   - the peer-cert chain length (walk issuerCertificate with a visited set)
 *   - self-signed detection (subject.CN == issuer.CN or fingerprint matches issuer)
 *   - OCSP stapling (requestOCSP:true + OCSPResponse listener within 2s of secureConnect)
 *
 * Resolves (never rejects) — any failure resolves a zeroed-out Tls12Info.
 */
function probeTls12(host: string, timeout = TLS12_TIMEOUT): Promise<Tls12Info> {
  return new Promise((resolve) => {
    let settled = false;
    let ocspReceived = false;
    let socket: tls.TLSSocket | null = null;
    let ocspTimer: ReturnType<typeof setTimeout> | null = null;
    let connectTimer: ReturnType<typeof setTimeout> | null = null;

    const empty: Tls12Info = {
      cipher: null,
      certChainLength: 0,
      selfSigned: false,
      ocspStapling: false,
    };

    const finalize = (info: Tls12Info) => {
      if (settled) return;
      settled = true;
      if (ocspTimer) clearTimeout(ocspTimer);
      if (connectTimer) clearTimeout(connectTimer);
      if (socket) {
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
      }
      resolve(info);
    };

    try {
      // `requestOCSP` is a valid tls.connect option (Node docs) but isn't
      // present in every @types/node release — cast the options bag to
      // tls.ConnectionOptions so TS accepts it.
      const connectOpts = {
        host,
        port: PORT,
        servername: host,
        rejectUnauthorized: false,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.2",
        requestOCSP: true,
      } as tls.ConnectionOptions;
      socket = tls.connect(connectOpts, () => {
          // Handshake complete — capture cipher + cert chain
          let cipher: { name: string; strength: CipherStrength } | null = null;
          try {
            const c = socket?.getCipher();
            if (c && c.name) {
              cipher = { name: c.name, strength: classifyCipher(c.name) };
            }
          } catch {
            /* ignore */
          }

          let certChainLength = 0;
          let selfSigned = false;
          try {
            // `getPeerCertificate(true)` returns DetailedPeerCertificate (with
            // `issuerCertificate` chain) — TS doesn't always resolve the
            // boolean-overload correctly through `?.`, so cast explicitly.
            const cert = socket?.getPeerCertificate(true) as
              | tls.DetailedPeerCertificate
              | undefined;
            if (cert && cert.fingerprint) {
              // Self-signed detection (works on both Node and Bun):
              //   - subject.CN === issuer.CN
              //   - full subject JSON === full issuer JSON
              //   - leaf's issuerCertificate fingerprint === leaf fingerprint
              const subjCN = cert.subject?.CN;
              const issCN = cert.issuer?.CN;
              const subjStr = JSON.stringify(cert.subject || {});
              const issStr = JSON.stringify(cert.issuer || {});
              const issuerFp = cert.issuerCertificate?.fingerprint;
              if (
                (subjCN && issCN && subjCN === issCN) ||
                subjStr === issStr ||
                (issuerFp && issuerFp === cert.fingerprint)
              ) {
                selfSigned = true;
              }

              // Walk the issuer chain if it's exposed (Node). Bun does NOT
              // expose `issuerCertificate`, so we fall back to a heuristic:
              //   - self-signed → chain length 1
              //   - issued by a CA → chain length 2 (assume leaf + intermediate)
              if (cert.issuerCertificate && cert.issuerCertificate.fingerprint) {
                certChainLength = 1;
                const seen = new Set<string>([cert.fingerprint]);
                let current: tls.DetailedPeerCertificate | undefined =
                  cert.issuerCertificate;
                while (
                  current &&
                  current.fingerprint &&
                  !seen.has(current.fingerprint)
                ) {
                  seen.add(current.fingerprint);
                  certChainLength++;
                  current = current.issuerCertificate;
                }
              } else {
                certChainLength = selfSigned ? 1 : 2;
              }
            }
          } catch {
            /* ignore */
          }

          // Wait up to OCSP_WAIT (2s) for an OCSPResponse event before finalizing
          ocspTimer = setTimeout(() => {
            finalize({
              cipher,
              certChainLength,
              selfSigned,
              ocspStapling: ocspReceived,
            });
          }, OCSP_WAIT);
        }
      );
    } catch {
      resolve(empty);
      return;
    }

    if (!socket) {
      resolve(empty);
      return;
    }

    // Register the OCSPResponse listener synchronously (before the async
    // handshake has a chance to emit it). requestOCSP:true above asks the
    // server to staple an OCSP response; if it does, this event fires.
    socket.on("OCSPResponse", () => {
      ocspReceived = true;
    });

    connectTimer = setTimeout(() => finalize(empty), timeout);
    socket.once("error", () => finalize(empty));
    socket.once("close", () => finalize(empty));
  });
}

// ----------------------------------------------------------------------------
// HSTS check via fetch
// ----------------------------------------------------------------------------

async function checkHsts(host: string, timeout = HSTS_TIMEOUT): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(`https://${host}/`, {
        signal: controller.signal,
        redirect: "manual",
        headers: { "User-Agent": UA },
      });
      // Headers.get with a normalised lowercase header name (fetch API lowercases)
      return res.headers.has("strict-transport-security");
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return false;
  }
}

// ----------------------------------------------------------------------------
// Main entry point
// ----------------------------------------------------------------------------

export async function runSslTests(
  hosts: string[],
  log: (msg: string) => void
): Promise<SslTestsResult> {
  const capped = hosts.slice(0, MAX_HOSTS);
  log(
    `Running advanced SSL/TLS tests on ${capped.length}/${hosts.length} host(s) ...`
  );

  const result: SslTestsResult = { hosts: [] };

  for (let i = 0; i < capped.length; i++) {
    const host = capped[i];
    log(`  testing ${i + 1}/${hosts.length}: ${host}`);

    // --- a) Protocol support ---
    const protocols: ProtocolResult[] = [];
    for (const test of PROTOCOL_TESTS) {
      protocols.push(await testProtocol(host, test));
    }

    // --- b/c/d) TLSv1.2 deep probe (cipher + cert chain + OCSP) ---
    const tls12 = await probeTls12(host);

    // --- e) HSTS ---
    const hsts = await checkHsts(host);

    // --- f) Ticket rotation: unknown / not testable from client ---
    const ticketRotation = false;

    // Aggregate cipher counts
    const ciphers = tls12.cipher ? [tls12.cipher] : [];
    const cipherCount = ciphers.length;
    const weakCiphers = ciphers.filter(
      (c) => c.strength === "weak" || c.strength === "insecure"
    ).length;

    // --- g) Issues / findings ---
    type Issue = SslTestsResult["hosts"][number]["issues"][number];
    const issues: Issue[] = [];

    const enabled = (name: string): boolean =>
      protocols.find((p) => p.name === name)?.enabled ?? false;

    if (enabled("SSLv2")) {
      issues.push({
        id: "sslv2-enabled",
        severity: "high",
        title: "SSLv2 Enabled",
        detail:
          "SSLv2 is fundamentally broken (no integrity for handshakes, weak MAC, DROWN). Disable it immediately.",
      });
    }
    if (enabled("SSLv3")) {
      issues.push({
        id: "sslv3-enabled",
        severity: "high",
        title: "SSLv3 Enabled (POODLE)",
        detail:
          "SSLv3 is vulnerable to the POODLE padding-oracle attack (CVE-2014-3566). Disable it.",
      });
    }
    if (enabled("TLSv1.0")) {
      issues.push({
        id: "tlsv10-enabled",
        severity: "medium",
        title: "TLSv1.0 Enabled (BEAST/CRIME)",
        detail:
          "TLSv1.0 is deprecated (RFC 8996) and exposed to BEAST/CRIME-class attacks. Disable unless strictly required for legacy clients.",
      });
    }
    if (enabled("TLSv1.1")) {
      issues.push({
        id: "tlsv11-enabled",
        severity: "low",
        title: "TLSv1.1 Enabled (weak)",
        detail:
          "TLSv1.1 is deprecated (RFC 8996) and lacks modern AEAD cipher support. Disable in favour of TLSv1.2/1.3.",
      });
    }

    if (tls12.cipher && (tls12.cipher.strength === "weak" || tls12.cipher.strength === "insecure")) {
      issues.push({
        id: "weak-cipher",
        severity: "medium",
        title: "Weak Cipher Negotiated",
        detail: `Negotiated TLSv1.2 cipher "${tls12.cipher.name}" is classified as ${tls12.cipher.strength}. Prefer AEAD ciphers (GCM / ChaCha20-Poly1305) with SHA-2 MACs.`,
      });
    }

    if (!hsts) {
      issues.push({
        id: "missing-hsts",
        severity: "low",
        title: "Missing HSTS on HTTPS",
        detail:
          "The HTTPS endpoint did not return a Strict-Transport-Security header, leaving clients vulnerable to SSL-strip / MITM downgrade.",
      });
    }

    if (!enabled("TLSv1.2") && !enabled("TLSv1.3")) {
      issues.push({
        id: "no-modern-tls",
        severity: "high",
        title: "No Modern TLS (1.2/1.3) Support",
        detail:
          "The server does not support TLSv1.2 or TLSv1.3 — no modern, secure TLS is available. Clients are forced onto deprecated protocol versions.",
      });
    }

    if (tls12.selfSigned) {
      issues.push({
        id: "self-signed-cert",
        severity: "medium",
        title: "Self-signed Certificate",
        detail:
          "The peer certificate's subject matches its issuer — it is self-signed and not chained to a trusted CA. Clients will see trust warnings.",
      });
    }

    result.hosts.push({
      host,
      protocols,
      ciphers,
      cipherCount,
      weakCiphers,
      issues,
      certChainLength: tls12.certChainLength,
      ocspStapling: tls12.ocspStapling,
      hsts,
      ticketRotation,
    });

    // --- h) Per-host summary log ---
    const tls12Flag = enabled("TLSv1.2") ? "yes" : "no";
    const tls13Flag = enabled("TLSv1.3") ? "yes" : "no";
    log(
      `  [+] ${host}: TLSv1.2=${tls12Flag}, TLSv1.3=${tls13Flag}, ${issues.length} issue(s)`
    );
  }

  const totalIssues = result.hosts.reduce((n, h) => n + h.issues.length, 0);
  log(
    `SSL/TLS tests complete: ${result.hosts.length} host(s), ${totalIssues} total issue(s).`
  );

  return result;
}
