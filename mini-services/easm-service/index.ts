/**
 * EASM WebSocket Mini-Service
 *
 * Accepts scan commands from the web terminal and streams ScanEvents
 * back to the connected client in real time. The actual scanning work
 * is performed by the shared EASM engine under src/lib/easm.
 *
 * Protocol (client -> server):
 *   socket.emit("scan:start", { target, options })
 *
 * Protocol (server -> client):
 *   socket.emit("scan:event", ScanEvent)
 *   socket.emit("scan:error", { message })
 *   socket.emit("scan:ready")
 */
import { createServer } from "http";
import { Server } from "socket.io";
import {
  EasmScanner,
  ALL_MODULES,
  DEFAULT_PORTS,
  normalizeTarget,
  defaultConfig,
  type ModuleId,
  type ScanEvent,
} from "../../src/lib/easm";

const httpServer = createServer();
const io = new Server(httpServer, {
  path: "/",
  cors: { origin: "*", methods: ["GET", "POST"] },
  pingTimeout: 120000,
  pingInterval: 25000,
});

interface ScanStartPayload {
  target: string;
  modules?: ModuleId[];
  ports?: number[];
  timeout?: number;
  concurrency?: number;
  enumerateSubdomains?: boolean;
  maxSubdomains?: number;
}

function buildConfig(payload: ScanStartPayload) {
  const config = defaultConfig(payload.target);
  if (payload.modules && payload.modules.length) {
    const valid = payload.modules.filter((m) => ALL_MODULES.includes(m));
    if (valid.length) config.modules = valid;
  } else {
    config.modules = [...ALL_MODULES];
  }
  if (payload.ports && payload.ports.length) config.ports = payload.ports;
  else config.ports = [...DEFAULT_PORTS];
  if (payload.timeout) config.timeout = payload.timeout;
  if (payload.concurrency) config.concurrency = payload.concurrency;
  if (payload.enumerateSubdomains === false) config.enumerateSubdomains = false;
  if (payload.maxSubdomains) config.maxSubdomains = payload.maxSubdomains;
  config.target = normalizeTarget(payload.target);
  return config;
}

io.on("connection", (socket) => {
  console.log(`[easm-service] client connected: ${socket.id}`);
  socket.emit("scan:ready");

  let active: EasmScanner | null = null;
  let cancelled = false;

  socket.on("scan:start", (payload: ScanStartPayload) => {
    if (active) {
      socket.emit("scan:error", { message: "A scan is already running on this connection." });
      return;
    }
    if (!payload?.target || !payload.target.trim()) {
      socket.emit("scan:error", { message: "No target provided." });
      return;
    }

    const config = buildConfig(payload);
    const scanner = new EasmScanner(config);
    active = scanner;
    cancelled = false;

    scanner.on("event", (ev: ScanEvent) => {
      if (!cancelled) socket.emit("scan:event", ev);
    });

    // Run asynchronously so we don't block the event loop / socket.
    scanner
      .run()
      .then((results) => {
        socket.emit("scan:complete", {
          target: config.target,
          results,
        });
      })
      .catch((e: any) => {
        socket.emit("scan:error", { message: e?.message || String(e) });
      })
      .finally(() => {
        active = null;
      });
  });

  socket.on("scan:cancel", () => {
    cancelled = true;
    active = null;
    socket.emit("scan:cancelled");
  });

  socket.on("disconnect", () => {
    cancelled = true;
    active = null;
    console.log(`[easm-service] client disconnected: ${socket.id}`);
  });

  socket.on("error", (err) => {
    console.error(`[easm-service] socket error (${socket.id}):`, err);
  });
});

const PORT = 3004;
httpServer.listen(PORT, () => {
  console.log(`[easm-service] WebSocket server running on port ${PORT}`);
});

process.on("SIGTERM", () => httpServer.close(() => process.exit(0)));
process.on("SIGINT", () => httpServer.close(() => process.exit(0)));
