import { discoveryKey, validateDiscoveryBundle } from "../lib/quantic/discovery-core.mjs";
import { canonicalRouteManifestText } from "../lib/quantic/federation-core.mjs";
import type { QuanticRouteManifest } from "../lib/quantic/federation-types.ts";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import type { QuanticIdentityManifest } from "../lib/quantic/manifest-types.ts";
import type { DiscoveryPeer } from "./discovery-state.ts";
import { iterativeFindRecord, xorDistance } from "./kademlia.ts";

export type DiscoveryBundle = {
  identityManifest: QuanticIdentityManifest;
  cryptoProfile?: unknown;
  routeManifest: QuanticRouteManifest;
};

export type DiscoveryTransport = {
  publish(peer: DiscoveryPeer, bundle: DiscoveryBundle): Promise<void>;
  find(
    peer: DiscoveryPeer,
    key: string,
  ): Promise<{ bundle: DiscoveryBundle | null; peers: DiscoveryPeer[] }>;
};

export type DiscoveryServiceOptions = {
  localRelayId: string;
  peers(): DiscoveryPeer[];
  pinnedBundle(canonicalAddress: string): DiscoveryBundle | null;
  acceptLocal(bundle: DiscoveryBundle): DiscoveryBundle | Promise<DiscoveryBundle>;
  transport: DiscoveryTransport;
};

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function payloadFingerprint(bundle: DiscoveryBundle) {
  return {
    identity: canonicalManifestText(bundle.identityManifest.payload),
    route: canonicalRouteManifestText(bundle.routeManifest.payload),
  };
}

function newestBundle(records: DiscoveryBundle[]) {
  if (records.length === 0) return null;
  const ordered = [...records].sort((left, right) => {
    const identityDelta = right.identityManifest.payload.sequence - left.identityManifest.payload.sequence;
    if (identityDelta !== 0) return identityDelta;
    return right.routeManifest.payload.sequence - left.routeManifest.payload.sequence;
  });
  const best = ordered[0];
  const bestIdentitySequence = best.identityManifest.payload.sequence;
  const bestRouteSequence = best.routeManifest.payload.sequence;
  const bestFingerprint = payloadFingerprint(best);

  for (const candidate of ordered.slice(1)) {
    if (candidate.identityManifest.payload.sequence !== bestIdentitySequence) break;
    const fingerprint = payloadFingerprint(candidate);
    if (fingerprint.identity !== bestFingerprint.identity) return null;
    if (
      candidate.routeManifest.payload.sequence === bestRouteSequence &&
      fingerprint.route !== bestFingerprint.route
    ) {
      return null;
    }
  }
  return clone(best);
}

function nearestPeers(key: string, peers: DiscoveryPeer[], localRelayId: string, limit: number) {
  const unique = new Map<string, DiscoveryPeer>();
  for (const peer of peers) {
    if (peer.relayId === localRelayId) continue;
    unique.set(peer.relayId, clone(peer));
  }
  return [...unique.values()]
    .sort((left, right) => {
      const leftDistance = xorDistance(key, left.relayId);
      const rightDistance = xorDistance(key, right.relayId);
      if (leftDistance < rightDistance) return -1;
      if (leftDistance > rightDistance) return 1;
      return left.relayId.localeCompare(right.relayId);
    })
    .slice(0, limit);
}

function validateAgainstPinned(bundle: DiscoveryBundle, pinned: DiscoveryBundle | null) {
  return validateDiscoveryBundle(
    bundle,
    pinned
      ? {
          identityManifest: pinned.identityManifest,
          cryptoProfile: pinned.cryptoProfile ?? null,
          routeManifest: pinned.routeManifest,
        }
      : {},
    { nowMs: Date.now() },
  ) as DiscoveryBundle & { canonicalAddress: string };
}

export function createDiscoveryService(options: DiscoveryServiceOptions) {
  async function replicate(bundle: DiscoveryBundle, config: { k?: number } = {}) {
    const canonicalAddress = bundle.identityManifest.payload.canonicalAddress;
    const pinned = options.pinnedBundle(canonicalAddress);
    const accepted = validateAgainstPinned(bundle, pinned);
    const k = config.k ?? 8;
    if (!Number.isSafeInteger(k) || k < 1 || k > 64) throw new Error("Facteur de réplication Discovery invalide.");

    const key = discoveryKey("identity", canonicalAddress);
    const targets = nearestPeers(key, options.peers(), options.localRelayId, k);
    const results = await Promise.allSettled(
      targets.map((peer) => options.transport.publish(peer, accepted)),
    );
    return {
      attempted: targets.length,
      succeeded: results.filter((item) => item.status === "fulfilled").length,
      failed: results.filter((item) => item.status === "rejected").length,
      targets: targets.map((peer) => peer.relayId),
    };
  }

  async function lookup(
    canonicalAddress: string,
    config: { maxQueries?: number; k?: number; alpha?: number; paths?: number } = {},
  ) {
    const pinned = options.pinnedBundle(canonicalAddress);
    const key = discoveryKey("identity", canonicalAddress);
    const seeds = nearestPeers(
      key,
      options.peers(),
      options.localRelayId,
      Math.max(config.k ?? 20, config.paths ?? 3),
    );

    if (seeds.length === 0) return pinned ? clone(pinned) : null;

    const result = await iterativeFindRecord<DiscoveryBundle>(
      key,
      async (peer) => {
        const response = await options.transport.find(peer, key);
        return { record: response.bundle, peers: response.peers };
      },
      {
        seeds,
        alpha: config.alpha ?? 3,
        paths: config.paths ?? 3,
        maxQueries: config.maxQueries ?? 24,
        k: config.k ?? 20,
        validateRecord: (candidate) => {
          try {
            validateAgainstPinned(candidate, pinned);
            return candidate.identityManifest.payload.canonicalAddress === canonicalAddress;
          } catch {
            return false;
          }
        },
        selectRecord: newestBundle,
      },
    );

    if (!result.record) return pinned ? clone(pinned) : null;

    try {
      const accepted = validateAgainstPinned(result.record, pinned);
      const cached = await options.acceptLocal(accepted);
      return clone(cached);
    } catch {
      return pinned ? clone(pinned) : null;
    }
  }

  return { replicate, lookup };
}
