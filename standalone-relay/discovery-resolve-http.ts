import type { IncomingMessage, ServerResponse } from "node:http";

import { getCryptoProfile, acceptCryptoProfile } from "../lib/quantic/crypto-profile-state.ts";
import { verifyDiscoveryCryptoProfile } from "../lib/quantic/discovery-crypto-node.ts";
import { normalizeDiscoveryHandle, validateDiscoveryBundle } from "../lib/quantic/discovery-core.mjs";
import { activeDevices } from "../lib/quantic/manifest-core.mjs";
import { RelayError, resolveIdentity } from "../lib/quantic/relay.ts";
import { getRouteManifest, acceptRouteManifest } from "../lib/quantic/route-manifest-state.ts";
import { publishStandaloneManifest } from "../lib/quantic/standalone-manifest.ts";
import { getStandaloneManifest, getStandaloneManifestStore } from "../lib/quantic/standalone-v11-state.ts";
import { createDiscoveryService, type DiscoveryBundle } from "./discovery-service.ts";
import { discoveryPeerEntries, type DiscoveryPeer } from "./discovery-state.ts";
import { RelayRuntime } from "./runtime.ts";

const CANONICAL = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;
const DISCOVERY_TIMEOUT_MS = 5_000;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function json(response: ServerResponse, status: number, payload: unknown) {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.end(`${JSON.stringify(payload)}\n`);
}

function resolvedFromManifest(manifest: ReturnType<typeof getStandaloneManifest>) {
  if (!manifest) return null;
  const payload = manifest.payload;
  const devices = activeDevices(manifest).map((device) => ({
    deviceId: device.deviceId,
    label: device.label,
    publicKey: device.publicKey,
    deviceSigningPublicKey: device.deviceSigningPublicKey,
    kind: device.kind,
  }));
  const root = devices.find((device) => device.kind === "root");
  return {
    address: `${payload.handle}@quantic`,
    canonicalAddress: payload.canonicalAddress,
    fingerprint: payload.fingerprint,
    publicKey: payload.identityPublicKey,
    signingPublicKey: payload.identitySigningPublicKey,
    rootDeviceId: root?.deviceId,
    deviceId: root?.deviceId,
    devices,
    manifest,
  };
}

function bundleFor(canonicalAddress: string): DiscoveryBundle | null {
  const identityManifest = getStandaloneManifest(canonicalAddress);
  const routeManifest = getRouteManifest(canonicalAddress);
  if (!identityManifest || !routeManifest) return null;
  const cryptoProfile = getCryptoProfile(canonicalAddress);
  return clone({
    identityManifest,
    ...(cryptoProfile ? { cryptoProfile } : {}),
    routeManifest,
  });
}

function acceptBundle(candidate: DiscoveryBundle) {
  const canonicalAddress = candidate.identityManifest.payload.canonicalAddress;
  const pinned = bundleFor(canonicalAddress);
  const accepted = validateDiscoveryBundle(
    candidate,
    pinned
      ? {
          identityManifest: pinned.identityManifest,
          cryptoProfile: pinned.cryptoProfile ?? null,
          routeManifest: pinned.routeManifest,
        }
      : {},
    { nowMs: Date.now(), verifyCryptoProfile: verifyDiscoveryCryptoProfile },
  );
  publishStandaloneManifest(accepted.identityManifest);
  if (accepted.cryptoProfile) acceptCryptoProfile(accepted.cryptoProfile, accepted.identityManifest);
  acceptRouteManifest(accepted.routeManifest, accepted.identityManifest);
  return clone({
    identityManifest: accepted.identityManifest,
    ...(accepted.cryptoProfile ? { cryptoProfile: accepted.cryptoProfile } : {}),
    routeManifest: accepted.routeManifest,
  }) as DiscoveryBundle;
}

async function postDiscovery(peer: DiscoveryPeer, path: string, body: unknown) {
  const response = await fetch(`${peer.endpoint}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`Discovery refusé par ${peer.endpoint} (${response.status}).`);
  return response.json() as Promise<Record<string, unknown>>;
}

function createTransport() {
  return {
    publish: async (peer: DiscoveryPeer, bundle: DiscoveryBundle) => {
      await postDiscovery(peer, "/api/quantic/discovery/publish", { bundle, replicate: false });
    },
    find: async (peer: DiscoveryPeer, key: string) => {
      const value = await postDiscovery(peer, "/api/quantic/discovery/find", { key }) as {
        bundle?: DiscoveryBundle | null;
        bundles?: DiscoveryBundle[];
        peers?: DiscoveryPeer[];
      };
      return {
        bundle: value.bundle ?? null,
        ...(Array.isArray(value.bundles) ? { bundles: value.bundles } : {}),
        peers: Array.isArray(value.peers) ? value.peers : [],
      };
    },
    findHandle: async (peer: DiscoveryPeer, key: string, handle: string) => {
      const value = await postDiscovery(peer, "/api/quantic/discovery/find-handle", { key, handle }) as {
        bundles?: DiscoveryBundle[];
        peers?: DiscoveryPeer[];
      };
      return {
        bundles: Array.isArray(value.bundles) ? value.bundles : [],
        peers: Array.isArray(value.peers) ? value.peers : [],
      };
    },
  };
}

function localShortHandleManifests(handle: string) {
  return [...getStandaloneManifestStore().values()]
    .filter((manifest) => manifest.payload.handle === handle)
    .map(clone);
}

export function createDiscoveryResolveRequestHandler(
  runtime: RelayRuntime,
  localRelayId: string,
) {
  return async function discoveryResolveRequestHandler(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<boolean> {
    const url = new URL(request.url ?? "/", "http://quantic-relay.local");
    if (url.pathname !== "/api/quantic/resolve") return false;

    if (request.method === "OPTIONS") {
      response.statusCode = 204;
      response.end();
      return true;
    }
    if (request.method !== "GET") {
      json(response, 405, { error: "Méthode Quantic non autorisée." });
      return true;
    }

    const locator = (url.searchParams.get("handle") ?? "").trim().toLowerCase();
    try {
      try {
        const live = await runtime.read(() => resolveIdentity(locator));
        const manifest = await runtime.read(() => getStandaloneManifest(live.canonicalAddress));
        json(response, 200, manifest ? { ...live, manifest } : live);
        return true;
      } catch (error) {
        if (!(error instanceof RelayError) || error.status !== 404) throw error;
      }

      if (CANONICAL.test(locator)) {
        const local = await runtime.read(() => getStandaloneManifest(locator));
        if (local) {
          json(response, 200, resolvedFromManifest(local));
          return true;
        }
        // Preserve canonical-resolution semantics: callers that already know the
        // cryptographic address use the explicit Discovery lookup endpoint when
        // it is not cached locally. Automatic mesh lookup is reserved for the
        // human short-handle alias that otherwise cannot identify a canonical key.
        json(response, 404, { error: "Identité Quantic introuvable localement." });
        return true;
      }

      const handle = normalizeDiscoveryHandle(locator);
      const localCandidates = await runtime.read(() => localShortHandleManifests(handle));
      if (localCandidates.length > 1) {
        json(response, 409, {
          error: `${handle}@quantic est ambigu. Utilisez l’adresse canonique avec son empreinte.`,
          canonicalAddresses: localCandidates.map((manifest) => manifest.payload.canonicalAddress).sort(),
        });
        return true;
      }
      if (localCandidates.length === 1) {
        json(response, 200, resolvedFromManifest(localCandidates[0]));
        return true;
      }

      const peerSnapshot = await runtime.read(() => discoveryPeerEntries().map(([, peer]) => peer));
      const service = createDiscoveryService({
        localRelayId,
        peers: () => peerSnapshot,
        pinnedBundle: bundleFor,
        acceptLocal: (bundle) => runtime.mutate(() => acceptBundle(bundle)),
        transport: createTransport(),
      });

      const result = await service.lookupHandle(locator);
      if (result.status === "ambiguous") {
        json(response, 409, {
          error: `${handle}@quantic est ambigu. Utilisez l’adresse canonique avec son empreinte.`,
          canonicalAddresses: result.canonicalAddresses,
        });
        return true;
      }
      if (result.status === "unique") {
        json(response, 200, resolvedFromManifest(result.bundle.identityManifest));
        return true;
      }
      json(response, 404, { error: "Identité Quantic introuvable." });
      return true;
    } catch (error) {
      if (error instanceof RelayError) {
        json(response, error.status, { error: error.message });
        return true;
      }
      json(response, 400, { error: error instanceof Error ? error.message : "Requête Quantic invalide." });
      return true;
    }
  };
}
