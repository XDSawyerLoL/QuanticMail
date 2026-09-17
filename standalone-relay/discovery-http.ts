import type { IncomingMessage, ServerResponse } from "node:http";

import { discoveryKey, validateDiscoveryBundle } from "../lib/quantic/discovery-core.mjs";
import type { QuanticRouteManifest } from "../lib/quantic/federation-types.ts";
import type { QuanticIdentityManifest } from "../lib/quantic/manifest-types.ts";
import { getRouteManifest, acceptRouteManifest } from "../lib/quantic/route-manifest-state.ts";
import { publishStandaloneManifest } from "../lib/quantic/standalone-manifest.ts";
import {
  getStandaloneManifest,
  getStandaloneManifestStore,
} from "../lib/quantic/standalone-v11-state.ts";
import { createDiscoveryService, type DiscoveryBundle } from "./discovery-service.ts";
import { discoveryPeerEntries, type DiscoveryPeer } from "./discovery-state.ts";
import { xorDistance } from "./kademlia.ts";
import { RelayRuntime } from "./runtime.ts";

const DISCOVERY_KEY = /^[0-9a-f]{64}$/;
const MAX_DISCOVERY_PEERS = 20;
const MAX_REQUEST_BYTES = 512 * 1024;
const DISCOVERY_FETCH_TIMEOUT_MS = 5_000;

class DiscoveryHttpError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

function json(response: ServerResponse, status: number, payload: unknown) {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.end(`${JSON.stringify(payload)}\n`);
}

async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const declaredLength = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) {
    request.resume();
    throw new DiscoveryHttpError("Corps Discovery trop volumineux.", 413);
  }
  const contentType = request.headers["content-type"];
  if (typeof contentType === "string" && !contentType.toLowerCase().startsWith("application/json")) {
    request.resume();
    throw new DiscoveryHttpError("Content-Type JSON requis.", 415);
  }

  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > MAX_REQUEST_BYTES) throw new DiscoveryHttpError("Corps Discovery trop volumineux.", 413);
    chunks.push(buffer);
  }
  if (bytes === 0) throw new DiscoveryHttpError("Corps JSON Discovery requis.", 400);
  try {
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new DiscoveryHttpError("Objet JSON Discovery requis.", 400);
    }
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof DiscoveryHttpError) throw error;
    throw new DiscoveryHttpError("JSON Discovery invalide.", 400);
  }
}

function requireKey(value: unknown) {
  if (typeof value !== "string" || !DISCOVERY_KEY.test(value)) {
    throw new DiscoveryHttpError("Clé Discovery invalide.", 400);
  }
  return value;
}

function requireCanonicalAddress(value: unknown) {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) {
    throw new DiscoveryHttpError("Adresse canonique Discovery invalide.", 400);
  }
  try {
    discoveryKey("identity", value);
  } catch {
    throw new DiscoveryHttpError("Adresse canonique Discovery invalide.", 400);
  }
  return value;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function findLocalBundle(key: string): DiscoveryBundle | null {
  for (const [canonicalAddress, identityManifest] of getStandaloneManifestStore()) {
    const routeManifest = getRouteManifest(canonicalAddress);
    if (!routeManifest) continue;
    if (
      discoveryKey("identity", canonicalAddress) === key ||
      discoveryKey("route", canonicalAddress) === key
    ) {
      return clone({ identityManifest, routeManifest });
    }
  }
  return null;
}

function localBundle(canonicalAddress: string): DiscoveryBundle | null {
  const identityManifest = getStandaloneManifest(canonicalAddress);
  const routeManifest = getRouteManifest(canonicalAddress);
  if (!identityManifest || !routeManifest) return null;
  return clone({ identityManifest, routeManifest });
}

function nearestPeers(key: string, limit = MAX_DISCOVERY_PEERS): DiscoveryPeer[] {
  return discoveryPeerEntries()
    .map(([, peer]) => peer)
    .sort((left, right) => {
      const leftDistance = xorDistance(key, left.relayId);
      const rightDistance = xorDistance(key, right.relayId);
      if (leftDistance < rightDistance) return -1;
      if (leftDistance > rightDistance) return 1;
      return left.relayId.localeCompare(right.relayId);
    })
    .slice(0, Math.min(MAX_DISCOVERY_PEERS, Math.max(1, limit)))
    .map(clone);
}

function publishBundle(bundle: DiscoveryBundle) {
  const canonicalAddress = bundle?.identityManifest?.payload?.canonicalAddress;
  const pinned = typeof canonicalAddress === "string"
    ? {
        identityManifest: getStandaloneManifest(canonicalAddress),
        routeManifest: getRouteManifest(canonicalAddress),
      }
    : {};

  let accepted: {
    canonicalAddress: string;
    identityManifest: QuanticIdentityManifest;
    cryptoProfile: unknown;
    routeManifest: QuanticRouteManifest;
  };
  try {
    accepted = validateDiscoveryBundle(bundle, pinned, { nowMs: Date.now() });
  } catch (error) {
    throw new DiscoveryHttpError(
      error instanceof Error ? error.message : "Bundle Discovery invalide.",
      400,
    );
  }

  publishStandaloneManifest(accepted.identityManifest);
  acceptRouteManifest(accepted.routeManifest, accepted.identityManifest);
  return accepted;
}

async function findOnPeer(peer: DiscoveryPeer, key: string) {
  const response = await fetch(`${peer.endpoint}/api/quantic/discovery/find`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key }),
    signal: AbortSignal.timeout(DISCOVERY_FETCH_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`Lookup Discovery refusé par ${peer.endpoint} (${response.status}).`);
  const payload = await response.json() as {
    bundle?: DiscoveryBundle | null;
    peers?: DiscoveryPeer[];
  };
  return {
    bundle: payload.bundle ?? null,
    peers: Array.isArray(payload.peers) ? payload.peers : [],
  };
}

async function publishOnPeer(peer: DiscoveryPeer, bundle: DiscoveryBundle) {
  const response = await fetch(`${peer.endpoint}/api/quantic/discovery/publish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ bundle, replicate: false }),
    signal: AbortSignal.timeout(DISCOVERY_FETCH_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`Réplication Discovery refusée par ${peer.endpoint} (${response.status}).`);
}

function statusFromError(error: unknown) {
  if (error instanceof DiscoveryHttpError) return error.status;
  if (error && typeof error === "object" && "status" in error) {
    const status = Number((error as { status?: unknown }).status);
    if (Number.isInteger(status) && status >= 400 && status <= 599) return status;
  }
  return 500;
}

export function createDiscoveryRequestHandler(
  runtime: RelayRuntime,
  options: { localRelayId?: string } = {},
) {
  return async function discoveryRequestHandler(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<boolean> {
    const url = new URL(request.url ?? "/", "http://quantic-relay.local");
    const path = url.pathname;
    if (!path.startsWith("/api/quantic/discovery/")) return false;

    response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    try {
      if ((request.method ?? "GET") === "OPTIONS") {
        response.statusCode = 204;
        response.end();
        return true;
      }

      if (path === "/api/quantic/discovery/publish") {
        if (request.method !== "POST") throw new DiscoveryHttpError("Méthode Discovery non autorisée.", 405);
        const body = await readJsonBody(request);
        if (!body.bundle || typeof body.bundle !== "object") {
          throw new DiscoveryHttpError("Bundle Discovery signé requis.", 400);
        }
        const incomingBundle = body.bundle as DiscoveryBundle;
        const accepted = await runtime.mutate(() => publishBundle(incomingBundle));
        let replication = { attempted: 0, succeeded: 0, failed: 0 };
        if (body.replicate !== false && options.localRelayId) {
          const canonicalAddress = accepted.canonicalAddress;
          const peerSnapshot = await runtime.read(() => discoveryPeerEntries().map(([, peer]) => peer));
          const pinned = await runtime.read(() => localBundle(canonicalAddress));
          const service = createDiscoveryService({
            localRelayId: options.localRelayId,
            peers: () => peerSnapshot,
            pinnedBundle: () => pinned,
            acceptLocal: (bundle) => bundle,
            transport: {
              publish: publishOnPeer,
              find: findOnPeer,
            },
          });
          const result = await service.replicate(incomingBundle);
          replication = {
            attempted: result.attempted,
            succeeded: result.succeeded,
            failed: result.failed,
          };
        }
        json(response, 201, {
          accepted: true,
          canonicalAddress: accepted.canonicalAddress,
          identitySequence: accepted.identityManifest.payload.sequence,
          routeSequence: accepted.routeManifest.payload.sequence,
          replication,
        });
        return true;
      }

      if (path === "/api/quantic/discovery/find") {
        if (request.method !== "POST") throw new DiscoveryHttpError("Méthode Discovery non autorisée.", 405);
        const body = await readJsonBody(request);
        const key = requireKey(body.key);
        const bundle = await runtime.read(() => findLocalBundle(key));
        const peers = await runtime.read(() => nearestPeers(key));
        json(response, 200, { bundle, peers });
        return true;
      }

      if (path === "/api/quantic/discovery/lookup") {
        if (request.method !== "POST") throw new DiscoveryHttpError("Méthode Discovery non autorisée.", 405);
        if (!options.localRelayId) throw new DiscoveryHttpError("Discovery Mesh non initialisé.", 503);
        const body = await readJsonBody(request);
        const canonicalAddress = requireCanonicalAddress(body.canonicalAddress);
        const peerSnapshot = await runtime.read(() => discoveryPeerEntries().map(([, peer]) => peer));
        const pinned = await runtime.read(() => localBundle(canonicalAddress));
        const service = createDiscoveryService({
          localRelayId: options.localRelayId,
          peers: () => peerSnapshot,
          pinnedBundle: () => pinned,
          acceptLocal: async (bundle) => {
            const accepted = await runtime.mutate(() => publishBundle(bundle));
            return {
              identityManifest: accepted.identityManifest,
              ...(accepted.cryptoProfile ? { cryptoProfile: accepted.cryptoProfile } : {}),
              routeManifest: accepted.routeManifest,
            };
          },
          transport: {
            publish: publishOnPeer,
            find: findOnPeer,
          },
        });
        const bundle = await service.lookup(canonicalAddress);
        json(response, 200, { bundle });
        return true;
      }

      if (path === "/api/quantic/discovery/peers") {
        if (request.method !== "GET") throw new DiscoveryHttpError("Méthode Discovery non autorisée.", 405);
        const key = requireKey(url.searchParams.get("key"));
        const peers = await runtime.read(() => nearestPeers(key));
        json(response, 200, { peers });
        return true;
      }

      json(response, 404, { error: "Route Discovery introuvable." });
      return true;
    } catch (error) {
      const status = statusFromError(error);
      json(response, status, {
        error: error instanceof Error ? error.message : "Erreur Discovery interne.",
      });
      return true;
    }
  };
}
