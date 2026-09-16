import type { IncomingMessage, ServerResponse } from "node:http";

import {
  acknowledgeEnvelopes,
  acknowledgeReceipts,
  createIdentityChallenge,
  enqueueEnvelope,
  pullEnvelopes,
  pullReceipts,
  registerAuthorizedDevice,
  registerIdentity,
  RelayError,
  resolveIdentity,
  type QuanticPublicKey,
} from "../lib/quantic/relay.ts";
import {
  publishStandaloneManifest,
  readStandaloneManifest,
} from "../lib/quantic/standalone-manifest.ts";
import {
  claimStandalonePreKey,
  publishStandalonePreKeys,
  standalonePreKeyStatus,
} from "../lib/quantic/standalone-prekeys.ts";
import type { QuanticIdentityManifest } from "../lib/quantic/manifest-types.ts";
import type { SignedPreKeyRecord } from "../lib/quantic/prekey-core.mjs";
import { RelayRuntime } from "./runtime.ts";

export const MAX_REQUEST_BYTES = 512 * 1024;

class RelayHttpRequestError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
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

function bearer(request: IncomingMessage) {
  const value = request.headers.authorization;
  return typeof value === "string" && value.startsWith("Bearer ") ? value.slice(7) : null;
}

async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const declaredLength = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) {
    request.resume();
    throw new RelayHttpRequestError("Corps de requête Quantic trop volumineux.", 413);
  }

  const contentType = request.headers["content-type"];
  if (typeof contentType === "string" && !contentType.toLowerCase().startsWith("application/json")) {
    request.resume();
    throw new RelayHttpRequestError("Content-Type JSON requis.", 415);
  }

  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > MAX_REQUEST_BYTES) {
      throw new RelayHttpRequestError("Corps de requête Quantic trop volumineux.", 413);
    }
    chunks.push(buffer);
  }

  if (bytes === 0) throw new RelayHttpRequestError("Corps JSON Quantic requis.", 400);
  try {
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new RelayHttpRequestError("Objet JSON Quantic requis.", 400);
    }
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof RelayHttpRequestError) throw error;
    throw new RelayHttpRequestError("JSON Quantic invalide.", 400);
  }
}

function methodNotAllowed(response: ServerResponse) {
  json(response, 405, { error: "Méthode Quantic non autorisée." });
}

export function createRelayRequestHandler(runtime: RelayRuntime) {
  return async function relayRequestHandler(request: IncomingMessage, response: ServerResponse) {
    applyCors(response);

    try {
      const url = new URL(request.url ?? "/", "http://quantic-relay.local");
      const path = url.pathname;
      const method = request.method ?? "GET";

      if (!path.startsWith("/api/quantic/")) {
        json(response, 404, { error: "Route Quantic introuvable." });
        return;
      }

      if (method === "OPTIONS") {
        response.statusCode = 204;
        response.end();
        return;
      }

      if (path === "/api/quantic/health") {
        if (method !== "GET") return methodNotAllowed(response);
        json(response, 200, {
          ok: true,
          protocol: "quantic-relay/1",
          service: "Quantic Network Relay",
          capabilities: ["durable-state-v2", "signed-manifests", "one-time-prekeys"],
          time: new Date().toISOString(),
        });
        return;
      }

      if (path === "/api/quantic/challenge") {
        if (method !== "POST") return methodNotAllowed(response);
        const body = await readJsonBody(request);
        const result = await runtime.mutate(() =>
          createIdentityChallenge({
            handle: String(body.handle ?? ""),
            publicKey: (body.publicKey ?? {}) as QuanticPublicKey,
            signingPublicKey: (body.signingPublicKey ?? {}) as QuanticPublicKey,
          }),
        );
        json(response, 201, result);
        return;
      }

      if (path === "/api/quantic/register") {
        if (method !== "POST") return methodNotAllowed(response);
        const body = await readJsonBody(request);
        const result = await runtime.mutate(() =>
          registerIdentity({
            handle: String(body.handle ?? ""),
            publicKey: (body.publicKey ?? {}) as QuanticPublicKey,
            signingPublicKey: (body.signingPublicKey ?? {}) as QuanticPublicKey,
            authToken: String(body.authToken ?? ""),
            deviceId: typeof body.deviceId === "string" ? body.deviceId : undefined,
            challenge: typeof body.challenge === "string" ? body.challenge : undefined,
            signature: typeof body.signature === "string" ? body.signature : undefined,
          }),
        );
        json(response, 201, result);
        return;
      }

      if (path === "/api/quantic/resolve") {
        if (method !== "GET") return methodNotAllowed(response);
        const handle = url.searchParams.get("handle") ?? "";
        const resolved = await runtime.read(() => resolveIdentity(handle));
        const manifest = await runtime.read(() => readStandaloneManifest(resolved.canonicalAddress));
        json(response, 200, manifest ? { ...resolved, manifest } : resolved);
        return;
      }

      if (path === "/api/quantic/manifest") {
        if (method === "GET") {
          const canonical = url.searchParams.get("canonical") ?? url.searchParams.get("handle") ?? "";
          if (!canonical) throw new RelayHttpRequestError("Adresse canonique Quantic requise.", 400);
          const manifest = await runtime.read(() => readStandaloneManifest(canonical));
          if (!manifest) throw new RelayHttpRequestError("Manifeste Quantic introuvable.", 404);
          json(response, 200, { manifest });
          return;
        }
        if (method === "POST") {
          const body = await readJsonBody(request);
          if (!body.manifest) throw new RelayHttpRequestError("Manifeste signé requis.", 400);
          const manifest = await runtime.mutate(() =>
            publishStandaloneManifest(body.manifest as QuanticIdentityManifest),
          );
          json(response, 200, { manifest, persisted: true, mode: "standalone" });
          return;
        }
        return methodNotAllowed(response);
      }

      if (path === "/api/quantic/devices/revoke") {
        if (method !== "POST") return methodNotAllowed(response);
        const body = await readJsonBody(request);
        if (!body.manifest) throw new RelayHttpRequestError("Manifeste signé requis.", 400);
        const manifest = await runtime.mutate(() =>
          publishStandaloneManifest(body.manifest as QuanticIdentityManifest),
        );
        json(response, 200, { manifest, persisted: true, mode: "standalone" });
        return;
      }

      if (path === "/api/quantic/devices/register") {
        if (method !== "POST") return methodNotAllowed(response);
        const body = await readJsonBody(request);
        const result = await runtime.mutate(() =>
          registerAuthorizedDevice({
            certificate: body.certificate as Parameters<typeof registerAuthorizedDevice>[0]["certificate"],
            authToken: String(body.authToken ?? ""),
          }),
        );
        json(response, 201, result);
        return;
      }

      if (path === "/api/quantic/prekeys/publish") {
        if (method !== "POST") return methodNotAllowed(response);
        const body = await readJsonBody(request);
        const result = await runtime.mutate(() =>
          publishStandalonePreKeys({
            locator: String(body.handle ?? ""),
            authToken: bearer(request),
            deviceId: String(body.deviceId ?? ""),
            records: Array.isArray(body.records) ? body.records as SignedPreKeyRecord[] : [],
          }),
        );
        json(response, 200, result);
        return;
      }

      if (path === "/api/quantic/prekeys/claim") {
        if (method !== "POST") return methodNotAllowed(response);
        const body = await readJsonBody(request);
        const record = await runtime.mutate(() =>
          claimStandalonePreKey({
            senderLocator: String(body.from ?? ""),
            senderAuthToken: bearer(request),
            senderDeviceId: String(body.fromDeviceId ?? ""),
            recipientCanonicalAddress: String(body.to ?? ""),
            recipientDeviceId: String(body.toDeviceId ?? ""),
          }),
        );
        if (!record) {
          json(response, 404, { prekey: null });
          return;
        }
        json(response, 200, { prekey: record });
        return;
      }

      if (path === "/api/quantic/prekeys/status") {
        if (method !== "GET") return methodNotAllowed(response);
        const handle = url.searchParams.get("handle") ?? "";
        const deviceId = url.searchParams.get("deviceId") ?? "";
        const result = await runtime.mutate(() =>
          standalonePreKeyStatus({
            locator: handle,
            authToken: bearer(request),
            deviceId,
          }),
        );
        json(response, 200, result);
        return;
      }

      if (path === "/api/quantic/send") {
        if (method !== "POST") return methodNotAllowed(response);
        const body = await readJsonBody(request);
        const result = await runtime.mutate(() =>
          enqueueEnvelope({
            clientMessageId: String(body.clientMessageId ?? ""),
            from: String(body.from ?? ""),
            fromDeviceId: typeof body.fromDeviceId === "string" ? body.fromDeviceId : undefined,
            to: String(body.to ?? ""),
            toDeviceId: String(body.toDeviceId ?? ""),
            authToken: bearer(request),
            ciphertext: String(body.ciphertext ?? ""),
            iv: String(body.iv ?? ""),
            ephemeralPublicKey: (body.ephemeralPublicKey ?? {}) as QuanticPublicKey,
          }),
        );
        json(response, 202, result);
        return;
      }

      if (path === "/api/quantic/pull") {
        if (method !== "GET") return methodNotAllowed(response);
        const handle = url.searchParams.get("handle") ?? "";
        const deviceId = url.searchParams.get("deviceId");
        const envelopes = await runtime.read(() => pullEnvelopes(handle, bearer(request), deviceId));
        json(response, 200, { envelopes });
        return;
      }

      if (path === "/api/quantic/ack") {
        if (method !== "POST") return methodNotAllowed(response);
        const body = await readJsonBody(request);
        const result = await runtime.mutate(() =>
          acknowledgeEnvelopes(
            String(body.handle ?? ""),
            bearer(request),
            typeof body.deviceId === "string" ? body.deviceId : undefined,
            Array.isArray(body.ids) ? body.ids : [],
          ),
        );
        json(response, 200, result);
        return;
      }

      if (path === "/api/quantic/receipts") {
        if (method === "GET") {
          const handle = url.searchParams.get("handle") ?? "";
          const deviceId = url.searchParams.get("deviceId");
          const receipts = await runtime.read(() => pullReceipts(handle, bearer(request), deviceId));
          json(response, 200, { receipts });
          return;
        }
        if (method === "POST") {
          const body = await readJsonBody(request);
          const result = await runtime.mutate(() =>
            acknowledgeReceipts(
              String(body.handle ?? ""),
              bearer(request),
              typeof body.deviceId === "string" ? body.deviceId : undefined,
              Array.isArray(body.ids) ? body.ids : [],
            ),
          );
          json(response, 200, result);
          return;
        }
        return methodNotAllowed(response);
      }

      json(response, 404, { error: "Route Quantic introuvable." });
    } catch (error) {
      if (error instanceof RelayError) {
        json(response, error.status, { error: error.message });
        return;
      }
      if (error instanceof RelayHttpRequestError) {
        json(response, error.status, { error: error.message });
        return;
      }
      json(response, 500, { error: "Erreur interne Quantic Relay." });
    }
  };
}
