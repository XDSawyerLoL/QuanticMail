import type { IncomingMessage, ServerResponse } from "node:http";

import { registerIdentityCompat } from "../lib/quantic/register-compat.ts";
import { RelayError } from "../lib/quantic/relay.ts";
import { RelayRuntime } from "./runtime.ts";

const MAX_REGISTER_BYTES = 512 * 1024;

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

async function readBody(request: IncomingMessage) {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > MAX_REGISTER_BYTES) throw new RelayError("Corps de requête Quantic trop volumineux.", 413);
    chunks.push(buffer);
  }
  if (!bytes) throw new RelayError("Corps JSON Quantic requis.", 400);
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new RelayError("Objet JSON Quantic requis.", 400);
    }
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof RelayError) throw error;
    throw new RelayError("JSON Quantic invalide.", 400);
  }
}

/**
 * Intercepts only root registration so the standalone relay gets the same
 * 10/32-hex root-device compatibility migration as the Next bootstrap API.
 * OPTIONS and every other route continue through the normal relay handler.
 */
export function createCompatRegisterRequestHandler(runtime: RelayRuntime) {
  return async function handleCompatRegister(request: IncomingMessage, response: ServerResponse) {
    const url = new URL(request.url ?? "/", "http://quantic-relay.local");
    if (url.pathname !== "/api/quantic/register" || request.method !== "POST") return false;

    try {
      const body = await readBody(request);
      const result = await runtime.mutate(() => registerIdentityCompat({
        handle: String(body.handle ?? ""),
        publicKey: (body.publicKey ?? {}) as JsonWebKey,
        signingPublicKey: (body.signingPublicKey ?? {}) as JsonWebKey,
        authToken: String(body.authToken ?? ""),
        deviceId: typeof body.deviceId === "string" ? body.deviceId : undefined,
        challenge: typeof body.challenge === "string" ? body.challenge : undefined,
        signature: typeof body.signature === "string" ? body.signature : undefined,
      }));
      json(response, 201, result);
    } catch (error) {
      if (error instanceof RelayError) json(response, error.status, { error: error.message });
      else json(response, 400, { error: "Requête Quantic invalide." });
    }
    return true;
  };
}
