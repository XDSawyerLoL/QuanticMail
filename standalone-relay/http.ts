import type { IncomingMessage, ServerResponse } from "node:http";

import { enqueueFederatedEnvelope } from "../lib/quantic/federation-delivery.ts";
import type {
  QuanticPortableEnvelope,
  QuanticRouteManifest,
} from "../lib/quantic/federation-types.ts";
import type { QuanticIdentityManifest } from "../lib/quantic/manifest-types.ts";
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
import { acceptRouteManifest } from "../lib/quantic/route-manifest-state.ts";
import { signRelayHello, type RelayIdentity } from "./identity.ts";
import { RelayRuntime } from "./runtime.ts";

export const MAX_REQUEST_BYTES = 512 * 1024;

export type RelayHttpFederationContext = {
  identity: RelayIdentity;
  getPublicEndpoint(): string;
};

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

function sameP256Key(first: JsonWebKey, second: JsonWebKey) {
  return (
    first?.kty === "EC" &&
    second?.kty === "EC" &&
    first.crv === "P-256" &&
    second.crv === "P-256" &&
    first.x === second.x &&
    first.y === second.y
  );
}

function endpointOrigin(value: string) {
  try {
    return new URL(value).origin;
  } catch {
    throw new RelayError("Endpoint de fédération invalide.", 400);
  }
}

function validateForwardPacket(body: Record<string, unknown>, localRelayId: string) {
  if (body.format !== "quantic-federation-forward" || body.version !== 1) {
    throw new RelayError("Paquet de fédération Quantic invalide.", 400);
  }
  if (typeof body.federationId !== "string" || !/^[A-Za-z0-9._:-]{12,128}$/.test(body.federationId)) {
    throw new RelayError("Identifiant de fédération invalide.", 400);
  }
  if (!Number.isSafeInteger(body.hopLimit) || (body.hopLimit as number) <= 0 || (body.hopLimit as number) > 16) {
    throw new RelayError("Limite de sauts de fédération invalide.", 400);
  }
  if (!Array.isArray(body.visitedRelayIds) || body.visitedRelayIds.length > 16) {
    throw new RelayError("Historique de relais invalide.", 400);
  }
  if (
    body.visitedRelayIds.some(
      (relayId) => typeof relayId !== "string" || !/^[0-9a-f]{64}$/.test(relayId),
    )
  ) {
    throw new RelayError("Historique de relais invalide.", 400);
  }
  if (body.visitedRelayIds.includes(localRelayId)) {
    throw new RelayError("Boucle de fédération Quantic détectée.", 409);
  }
  if (typeof body.previousRelayId !== "string" || !/^[0-9a-f]{64}$/.test(body.previousRelayId)) {
    throw new RelayError("Relay ID précédent invalide.", 400);
  }
  if (typeof body.expiresAt !== "string" || Number.isNaN(Date.parse(body.expiresAt))) {
    throw new RelayError("Expiration de fédération invalide.", 400);
  }
  if (Date.parse(body.expiresAt) <= Date.now()) {
    throw new RelayError("Paquet de fédération Quantic expiré.", 410);
  }
  if (typeof body.previousRelayAttestation !== "string" || body.previousRelayAttestation.length < 8) {
    throw new RelayError("Attestation du relais précédent absente.", 400);
  }
}

export function createRelayRequestHandler(
  runtime: RelayRuntime,
  federation?: RelayHttpFederationContext,
) {
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
          ...(federation ? { relayId: federation.identity.relayId, federation: "quantic-federation/1" } : {}),
          time: new Date().toISOString(),
        });
        return;
      }

      if (path === "/api/quantic/federation/hello") {
        if (method !== "POST") return methodNotAllowed(response);
        if (!federation) {
          throw new RelayHttpRequestError("Fédération Quantic indisponible.", 503);
        }
        const body = await readJsonBody(request);
        const nonce = typeof body.nonce === "string" ? body.nonce : "";
        if (!/^[A-Za-z0-9._~-]{16,256}$/.test(nonce)) {
          throw new RelayHttpRequestError("Nonce de fédération invalide.", 400);
        }
        try {
          json(response, 200, signRelayHello(federation.identity, federation.getPublicEndpoint(), nonce));
        } catch (error) {
          throw new RelayHttpRequestError(
            error instanceof Error ? error.message : "Preuve de relais invalide.",
            400,
          );
        }
        return;
      }

      if (path === "/api/quantic/federation/forward") {
        if (method !== "POST") return methodNotAllowed(response);
        if (!federation) throw new RelayError("Fédération Quantic indisponible.", 503);
        const body = await readJsonBody(request);
        validateForwardPacket(body, federation.identity.relayId);

        const result = await runtime.mutate(() => {
          let route: QuanticRouteManifest;
          try {
            route = acceptRouteManifest(
              body.recipientRouteManifest as QuanticRouteManifest,
              body.recipientIdentityManifest as QuanticIdentityManifest,
            );
          } catch (error) {
            throw new RelayError(
              error instanceof Error ? error.message : "Route Manifest Quantic invalide.",
              400,
            );
          }

          const localRoute = route.payload.relays.find(
            (entry) => entry.relayId === federation.identity.relayId,
          );
          if (!localRoute) {
            throw new RelayError("Ce relais n’est pas autorisé par le Route Manifest destinataire.", 403);
          }
          if (!sameP256Key(localRoute.classicalSigningPublicKey, federation.identity.publicKeyJwk)) {
            throw new RelayError("La clé du relais ne correspond pas au Route Manifest destinataire.", 403);
          }
          if (endpointOrigin(localRoute.endpoint) !== endpointOrigin(federation.getPublicEndpoint())) {
            throw new RelayError("L’endpoint du relais ne correspond pas au Route Manifest destinataire.", 403);
          }

          return enqueueFederatedEnvelope({
            envelope: body.envelope as QuanticPortableEnvelope,
            senderIdentityManifest: body.senderIdentityManifest as QuanticIdentityManifest,
            recipientIdentityManifest: body.recipientIdentityManifest as QuanticIdentityManifest,
            senderCryptoProfile: body.senderCryptoProfile,
          });
        });
        json(response, 202, result);
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
        json(response, 200, await runtime.read(() => resolveIdentity(handle)));
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
