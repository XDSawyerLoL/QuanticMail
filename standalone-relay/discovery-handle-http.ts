import type { IncomingMessage, ServerResponse } from "node:http";

import { discoveryHandleKey, normalizeDiscoveryHandle } from "../lib/quantic/discovery-core.mjs";
import { getCryptoProfile } from "../lib/quantic/crypto-profile-state.ts";
import { getRouteManifest } from "../lib/quantic/route-manifest-state.ts";
import { getStandaloneManifestStore } from "../lib/quantic/standalone-v11-state.ts";
import type { DiscoveryBundle } from "./discovery-service.ts";
import { discoveryPeerEntries, type DiscoveryPeer } from "./discovery-state.ts";
import { xorDistance } from "./kademlia.ts";
import { RelayRuntime } from "./runtime.ts";

const MAX_REQUEST_BYTES = 32 * 1024;
const MAX_HANDLE_BUNDLES = 16;
const MAX_PEERS = 20;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function json(response: ServerResponse, status: number, payload: unknown) {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
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
    if (bytes > MAX_REQUEST_BYTES) throw Object.assign(new Error("Requête Discovery handle trop volumineuse."), { status: 413 });
    chunks.push(buffer);
  }
  if (!bytes) throw Object.assign(new Error("Corps JSON requis."), { status: 400 });
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch {
    throw Object.assign(new Error("JSON Discovery handle invalide."), { status: 400 });
  }
}

function localBundlesForHandle(handle: string) {
  const bundles: DiscoveryBundle[] = [];
  for (const [, manifest] of getStandaloneManifestStore()) {
    if (manifest.payload.handle !== handle) continue;
    const canonicalAddress = manifest.payload.canonicalAddress;
    const routeManifest = getRouteManifest(canonicalAddress);
    if (!routeManifest) continue;
    const cryptoProfile = getCryptoProfile(canonicalAddress);
    bundles.push(clone({
      identityManifest: manifest,
      ...(cryptoProfile ? { cryptoProfile } : {}),
      routeManifest,
    }));
    if (bundles.length >= MAX_HANDLE_BUNDLES) break;
  }
  return bundles;
}

function nearestPeers(key: string): DiscoveryPeer[] {
  return discoveryPeerEntries()
    .map(([, peer]) => peer)
    .sort((left, right) => {
      const leftDistance = xorDistance(key, left.relayId);
      const rightDistance = xorDistance(key, right.relayId);
      if (leftDistance < rightDistance) return -1;
      if (leftDistance > rightDistance) return 1;
      return left.relayId.localeCompare(right.relayId);
    })
    .slice(0, MAX_PEERS)
    .map(clone);
}

export function createDiscoveryHandleRequestHandler(runtime: RelayRuntime) {
  return async function discoveryHandleRequestHandler(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<boolean> {
    const url = new URL(request.url ?? "/", "http://quantic-relay.local");
    if (url.pathname !== "/api/quantic/discovery/find-handle") return false;

    try {
      if (request.method === "OPTIONS") {
        response.statusCode = 204;
        response.end();
        return true;
      }
      if (request.method !== "POST") {
        json(response, 405, { error: "Méthode Discovery handle non autorisée." });
        return true;
      }
      const body = await readJson(request);
      const handle = normalizeDiscoveryHandle(body.handle);
      const expectedKey = discoveryHandleKey(handle);
      if (body.key !== expectedKey) {
        json(response, 400, { error: "Clé Discovery handle incohérente." });
        return true;
      }
      const { bundles, peers } = await runtime.read(() => ({
        bundles: localBundlesForHandle(handle),
        peers: nearestPeers(expectedKey),
      }));
      json(response, 200, { bundles, peers });
      return true;
    } catch (error) {
      const status = Number((error as { status?: unknown })?.status);
      json(response, Number.isInteger(status) ? status : 400, {
        error: error instanceof Error ? error.message : "Erreur Discovery handle.",
      });
      return true;
    }
  };
}
