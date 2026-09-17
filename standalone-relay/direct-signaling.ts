import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import { authenticateLocalDevice, RelayError } from "../lib/quantic/relay.ts";

export type DirectSignalType = "offer" | "answer" | "ice" | "cancel" | "receipt";
export type EncryptedDirectSignal = {
  ciphertext: string;
  iv: string;
  ephemeralPublicKey: JsonWebKey;
};
export type DirectSignalRecord = {
  id: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  type: DirectSignalType;
  encrypted: EncryptedDirectSignal;
  createdAt: string;
  expiresAt: string;
};

type AuthenticatedDevice = { canonicalAddress: string; deviceId: string };
type DirectSignalingOptions = {
  authenticate?: (locator: string, token: string | null, deviceId?: string | null) => AuthenticatedDevice;
  now?: () => number;
  ttlMs?: number;
  maxQueue?: number;
  maxPayloadBytes?: number;
};

const MAX_REQUEST_BYTES = 96 * 1024;
const DEFAULT_SIGNAL_TTL_MS = 60_000;
const DEFAULT_MAX_QUEUE = 64;
const DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024;
const SIGNAL_TYPES = new Set<DirectSignalType>(["offer", "answer", "ice", "cancel", "receipt"]);

function bearer(request: IncomingMessage) {
  const header = request.headers.authorization ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1] ?? null;
}

function applyCors(response: ServerResponse) {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.setHeader("Access-Control-Max-Age", "86400");
}

function json(response: ServerResponse, status: number, payload: unknown) {
  applyCors(response);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.end(`${JSON.stringify(payload)}\n`);
}

async function readJson(request: IncomingMessage) {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > MAX_REQUEST_BYTES) throw new RelayError("Signal direct Quantic trop volumineux.", 413);
    chunks.push(buffer);
  }
  if (!bytes) throw new RelayError("Corps JSON direct requis.", 400);
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch {
    throw new RelayError("JSON de signal direct invalide.", 400);
  }
}

function validateEncrypted(value: unknown, maxPayloadBytes: number): EncryptedDirectSignal {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new RelayError("Signal direct chiffré requis.", 400);
  }
  const encrypted = value as Partial<EncryptedDirectSignal>;
  if (
    typeof encrypted.ciphertext !== "string" ||
    encrypted.ciphertext.length < 4 ||
    typeof encrypted.iv !== "string" ||
    encrypted.iv.length < 4 ||
    !encrypted.ephemeralPublicKey ||
    encrypted.ephemeralPublicKey.kty !== "EC" ||
    encrypted.ephemeralPublicKey.crv !== "P-256" ||
    typeof encrypted.ephemeralPublicKey.x !== "string" ||
    typeof encrypted.ephemeralPublicKey.y !== "string"
  ) {
    throw new RelayError("Signal direct chiffré invalide.", 400);
  }
  if (Buffer.byteLength(JSON.stringify(encrypted), "utf8") > maxPayloadBytes) {
    throw new RelayError("Signal direct chiffré trop volumineux.", 413);
  }
  return JSON.parse(JSON.stringify(encrypted)) as EncryptedDirectSignal;
}

export function createDirectSignalingRequestHandler(options: DirectSignalingOptions = {}) {
  const authenticate = options.authenticate ?? authenticateLocalDevice;
  const now = options.now ?? Date.now;
  const ttlMs = options.ttlMs ?? DEFAULT_SIGNAL_TTL_MS;
  const maxQueue = options.maxQueue ?? DEFAULT_MAX_QUEUE;
  const maxPayloadBytes = options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 5_000 || ttlMs > 5 * 60_000) throw new Error("TTL direct invalide.");
  if (!Number.isSafeInteger(maxQueue) || maxQueue < 1 || maxQueue > 256) throw new Error("Capacité de signal direct invalide.");
  if (!Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes < 1_024 || maxPayloadBytes > 128 * 1024) {
    throw new Error("Taille de signal direct invalide.");
  }

  const queues = new Map<string, DirectSignalRecord[]>();
  const presence = new Map<string, number>();
  const deviceKey = (canonicalAddress: string, deviceId: string) => `${canonicalAddress}#${deviceId}`;

  function prune(key: string) {
    const cutoff = now();
    const queue = (queues.get(key) ?? []).filter((signal) => Date.parse(signal.expiresAt) > cutoff);
    if (queue.length) queues.set(key, queue);
    else queues.delete(key);
    const presentUntil = presence.get(key);
    if (presentUntil !== undefined && presentUntil <= cutoff) presence.delete(key);
    return queue;
  }

  function authenticateExact(locator: string, token: string | null, deviceId: string) {
    const authenticated = authenticate(locator, token, deviceId);
    if (authenticated.canonicalAddress !== locator || authenticated.deviceId !== deviceId) {
      throw new RelayError("Authentification de signal direct incohérente.", 401);
    }
    return authenticated;
  }

  return async function directSignalingRequestHandler(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<boolean> {
    const url = new URL(request.url ?? "/", "http://quantic-relay.local");
    if (!url.pathname.startsWith("/api/quantic/direct/")) return false;

    try {
      if (request.method === "OPTIONS") {
        applyCors(response);
        response.statusCode = 204;
        response.end();
        return true;
      }

      if (url.pathname === "/api/quantic/direct/poll") {
        if (request.method !== "GET") throw new RelayError("Méthode directe non autorisée.", 405);
        const handle = (url.searchParams.get("handle") ?? "").trim().toLowerCase();
        const deviceId = (url.searchParams.get("deviceId") ?? "").trim();
        const authenticated = authenticateExact(handle, bearer(request), deviceId);
        const key = deviceKey(authenticated.canonicalAddress, authenticated.deviceId);
        const signals = prune(key);
        queues.delete(key);
        presence.set(key, now() + ttlMs);
        json(response, 200, { signals });
        return true;
      }

      if (request.method !== "POST") throw new RelayError("Méthode directe non autorisée.", 405);
      const body = await readJson(request);

      if (url.pathname === "/api/quantic/direct/announce") {
        const handle = String(body.handle ?? "").trim().toLowerCase();
        const deviceId = String(body.deviceId ?? "").trim();
        const authenticated = authenticateExact(handle, bearer(request), deviceId);
        const expiresAt = now() + ttlMs;
        presence.set(deviceKey(authenticated.canonicalAddress, authenticated.deviceId), expiresAt);
        json(response, 200, { online: true, expiresAt: new Date(expiresAt).toISOString() });
        return true;
      }

      if (url.pathname === "/api/quantic/direct/send") {
        const from = String(body.from ?? "").trim().toLowerCase();
        const fromDeviceId = String(body.fromDeviceId ?? "").trim();
        const to = String(body.to ?? "").trim().toLowerCase();
        const toDeviceId = String(body.toDeviceId ?? "").trim();
        const type = String(body.type ?? "") as DirectSignalType;
        if (!SIGNAL_TYPES.has(type)) throw new RelayError("Type de signal direct invalide.", 400);
        const authenticated = authenticateExact(from, bearer(request), fromDeviceId);
        if (!to || !toDeviceId) throw new RelayError("Destination directe invalide.", 400);
        const encrypted = validateEncrypted(body.encrypted, maxPayloadBytes);
        const targetKey = deviceKey(to, toDeviceId);
        const queue = prune(targetKey);
        if (queue.length >= maxQueue) throw new RelayError("File de signalisation directe saturée.", 429);
        const created = now();
        const signal: DirectSignalRecord = {
          id: randomUUID(),
          from: authenticated.canonicalAddress,
          fromDeviceId: authenticated.deviceId,
          to,
          toDeviceId,
          type,
          encrypted,
          createdAt: new Date(created).toISOString(),
          expiresAt: new Date(created + ttlMs).toISOString(),
        };
        queue.push(signal);
        queues.set(targetKey, queue);
        json(response, 202, { accepted: true, id: signal.id, targetOnline: (presence.get(targetKey) ?? 0) > created });
        return true;
      }

      throw new RelayError("Route directe Quantic inconnue.", 404);
    } catch (error) {
      if (error instanceof RelayError) {
        json(response, error.status, { error: error.message });
      } else {
        json(response, 400, { error: error instanceof Error ? error.message : "Erreur de signal direct." });
      }
      return true;
    }
  };
}
