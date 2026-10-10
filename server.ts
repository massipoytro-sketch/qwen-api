import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { env } from "./src/config/env";
import healthHandler from "./api/health";
import securityCheckHandler from "./api/security-check";
import securityEventHandler from "./api/security-event";
import outboxWorkerHandler from "./api/outbox-worker";
import honeyAlertHandler from "./api/honey-alert";

const MAX_BODY_BYTES = 64 * 1024;
const PORT = Number(process.env.PORT ?? "3000");
const API_HANDLERS = new Map<string, (request: Request) => Promise<Response> | Response>([
  ["/api/health", healthHandler],
  ["/api/security-check", securityCheckHandler],
  ["/api/security-event", securityEventHandler],
  ["/api/outbox-worker", outboxWorkerHandler],
  ["/api/internal/honey-alert", honeyAlertHandler],
]);
const HOP_BY_HOP_HEADERS = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
]);
const DEFAULT_RESPONSE_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
};

class PayloadTooLargeError extends Error {
  constructor() {
    super("PAYLOAD_TOO_LARGE");
    this.name = "PayloadTooLargeError";
  }
}

async function readBoundedBody(request: IncomingMessage): Promise<Buffer> {
  const contentLength = request.headers["content-length"];
  if (typeof contentLength === "string") {
    const declaredLength = Number(contentLength);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
      // Drain without buffering so an oversized upload cannot accumulate in memory.
      request.resume();
      throw new PayloadTooLargeError();
    }
  }

  const chunks: Buffer[] = [];
  let size = 0;
  let oversized = false;

  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > MAX_BODY_BYTES) {
      oversized = true;
      continue;
    }
    if (!oversized) chunks.push(buffer);
  }

  if (oversized) throw new PayloadTooLargeError();
  return Buffer.concat(chunks, size);
}

function getRequestHeaders(request: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (value === undefined || HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
    } else {
      headers.set(name, value);
    }
  }
  return headers;
}

function writeJson(
  response: ServerResponse,
  status: number,
  payload: Record<string, unknown>,
  requestId: string,
): void {
  const body = Buffer.from(JSON.stringify(payload), "utf8");
  response.statusCode = status;
  for (const [name, value] of Object.entries(DEFAULT_RESPONSE_HEADERS)) {
    response.setHeader(name, value);
  }
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("content-length", body.byteLength);
  response.setHeader("x-request-id", requestId);
  response.end(body);
}

async function handleHttpRequest(incoming: IncomingMessage, outgoing: ServerResponse): Promise<void> {
  const candidateId = incoming.headers["x-request-id"];
  const requestId = typeof candidateId === "string" && /^[a-zA-Z0-9._:-]{1,100}$/.test(candidateId)
    ? candidateId
    : randomUUID();

  try {
    const method = (incoming.method ?? "GET").toUpperCase();
    if (!["GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"].includes(method)) {
      writeJson(outgoing, 405, { error: "METHOD_NOT_ALLOWED", requestId }, requestId);
      return;
    }

    const rawUrl = incoming.url ?? "/";
    if (!rawUrl.startsWith("/") || rawUrl.startsWith("//")) {
      writeJson(outgoing, 400, { error: "INVALID_REQUEST_TARGET", requestId }, requestId);
      return;
    }
    const url = new URL(rawUrl, "http://127.0.0.1");
    const handler = API_HANDLERS.get(url.pathname);
    if (!handler) {
      writeJson(outgoing, 404, { error: "NOT_FOUND", requestId }, requestId);
      return;
    }
    if (url.pathname === "/api/health" && method !== "GET") {
      writeJson(outgoing, 405, { error: "METHOD_NOT_ALLOWED", requestId }, requestId);
      return;
    }

    const body = await readBoundedBody(incoming);
    if ((method === "GET" || method === "HEAD") && body.byteLength > 0) {
      writeJson(outgoing, 400, { error: "BODY_NOT_ALLOWED", requestId }, requestId);
      return;
    }

    const requestHeaders = getRequestHeaders(incoming);
    const apiRequest = new Request(url, {
      method,
      headers: requestHeaders,
      ...(method === "GET" || method === "HEAD" ? {} : { body: new Uint8Array(body) }),
    });
    const apiResponse = await handler(apiRequest);

    outgoing.statusCode = apiResponse.status;
    for (const [name, value] of Object.entries(DEFAULT_RESPONSE_HEADERS)) {
      outgoing.setHeader(name, value);
    }
    apiResponse.headers.forEach((value, name) => {
      if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase())) outgoing.setHeader(name, value);
    });
    outgoing.setHeader("x-request-id", apiResponse.headers.get("x-request-id") ?? requestId);

    if (method === "HEAD" || apiResponse.status === 204 || apiResponse.status === 304) {
      outgoing.end();
      return;
    }
    const responseBody = Buffer.from(await apiResponse.arrayBuffer());
    outgoing.setHeader("content-length", responseBody.byteLength);
    outgoing.end(responseBody);
  } catch (error) {
    if (error instanceof PayloadTooLargeError) {
      writeJson(outgoing, 413, { error: "PAYLOAD_TOO_LARGE", requestId }, requestId);
      return;
    }
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      service: "gainiren-security",
      event: "http_adapter_error",
      requestId,
      errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR",
    }));
    if (!outgoing.headersSent) {
      writeJson(outgoing, 500, { error: "INTERNAL_ERROR", requestId }, requestId);
    } else {
      outgoing.destroy();
    }
  }
}

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}

const server = createServer({ maxHeaderSize: 16 * 1024 }, (request, response) => {
  void handleHttpRequest(request, response);
});
server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 64;
server.maxRequestsPerSocket = 1_000;

server.listen(PORT, "0.0.0.0", () => {
  console.info(JSON.stringify({
    timestamp: new Date().toISOString(),
    service: "gainiren-security",
    event: "server_started",
    port: PORT,
    outboxWorkerEnabled: Boolean(env.OUTBOX_WORKER_TOKEN),
    analyticsEnabled: Boolean(env.DUCKDB_ANALYTICS_URL && env.DUCKDB_ANALYTICS_TOKEN),
    aiEnabled: Boolean(env.AI_ANALYZER_ENDPOINT && env.AI_ANALYZER_API_KEY && env.AI_ANALYZER_MODEL),
  }));
});

let workerInFlight = false;
const workerTimer = env.OUTBOX_WORKER_TOKEN ? setInterval(async () => {
  if (workerInFlight || server.listening === false) return;
  workerInFlight = true;
  try {
    const response = await fetch(`http://127.0.0.1:${PORT}/api/outbox-worker`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.OUTBOX_WORKER_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ batchSize: 25 }),
      signal: AbortSignal.timeout(12_000),
    });
    if (!response.ok) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        service: "gainiren-security",
        event: "outbox_tick_failed",
        status: response.status,
      }));
    }
    await response.body?.cancel();
  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      service: "gainiren-security",
      event: "outbox_tick_error",
      errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR",
    }));
  } finally {
    workerInFlight = false;
  }
}, 15_000) : undefined;
workerTimer?.unref();

function shutdown(signal: string) {
  console.info(JSON.stringify({
    timestamp: new Date().toISOString(),
    service: "gainiren-security",
    event: "server_shutdown",
    signal,
  }));
  if (workerTimer) clearInterval(workerTimer);
  server.close(() => process.exit(0));
  const forceExit = setTimeout(() => process.exit(1), 10_000);
  forceExit.unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
