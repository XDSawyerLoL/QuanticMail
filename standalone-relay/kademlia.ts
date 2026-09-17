import type { DiscoveryPeer } from "./discovery-state.ts";

const RELAY_ID = /^[0-9a-f]{64}$/;

function requireRelayId(value: string, label = "Relay ID") {
  if (typeof value !== "string" || !RELAY_ID.test(value)) {
    throw new Error(`${label} doit être un identifiant hexadécimal 256 bits.`);
  }
  return value;
}

function clonePeer(peer: DiscoveryPeer): DiscoveryPeer {
  return JSON.parse(JSON.stringify(peer)) as DiscoveryPeer;
}

function compareDistance(target: string, left: DiscoveryPeer, right: DiscoveryPeer) {
  const leftDistance = xorDistance(target, left.relayId);
  const rightDistance = xorDistance(target, right.relayId);
  if (leftDistance < rightDistance) return -1;
  if (leftDistance > rightDistance) return 1;
  return left.relayId.localeCompare(right.relayId);
}

function bucketIndex(localRelayId: string, remoteRelayId: string) {
  const distance = xorDistance(localRelayId, remoteRelayId);
  if (distance === BigInt(0)) return -1;
  return distance.toString(2).length - 1;
}

function validatePeer(peer: DiscoveryPeer) {
  requireRelayId(peer.relayId);
  if (typeof peer.endpoint !== "string" || peer.endpoint.length === 0) {
    throw new Error("Endpoint Discovery invalide.");
  }
  if (typeof peer.lastSeenAt !== "string" || !Number.isFinite(Date.parse(peer.lastSeenAt))) {
    throw new Error("Date Discovery invalide.");
  }
  if (!Number.isSafeInteger(peer.failures) || peer.failures < 0) {
    throw new Error("Compteur d’échecs Discovery invalide.");
  }
  return clonePeer(peer);
}

export function xorDistance(a: string, b: string) {
  requireRelayId(a, "Relay ID gauche");
  requireRelayId(b, "Relay ID droit");
  return BigInt(`0x${a}`) ^ BigInt(`0x${b}`);
}

export class KBucketTable {
  readonly localRelayId: string;
  readonly bucketSize: number;
  private buckets = new Map<number, DiscoveryPeer[]>();

  constructor(localRelayId: string, options: { bucketSize?: number } = {}) {
    this.localRelayId = requireRelayId(localRelayId, "Relay ID local");
    this.bucketSize = options.bucketSize ?? 20;
    if (!Number.isSafeInteger(this.bucketSize) || this.bucketSize < 1 || this.bucketSize > 256) {
      throw new Error("Capacité Kademlia invalide.");
    }
  }

  get size() {
    let total = 0;
    for (const bucket of this.buckets.values()) total += bucket.length;
    return total;
  }

  upsert(input: DiscoveryPeer) {
    const peer = validatePeer(input);
    if (peer.relayId === this.localRelayId) return false;

    const index = bucketIndex(this.localRelayId, peer.relayId);
    peer.bucketIndex = index;
    const bucket = this.buckets.get(index) ?? [];
    const existingIndex = bucket.findIndex((item) => item.relayId === peer.relayId);

    if (existingIndex >= 0) {
      bucket.splice(existingIndex, 1);
      bucket.push(peer);
      this.buckets.set(index, bucket);
      return true;
    }

    if (bucket.length < this.bucketSize) {
      bucket.push(peer);
      this.buckets.set(index, bucket);
      return true;
    }

    const unhealthy = bucket
      .map((item, position) => ({ item, position }))
      .filter(({ item }) => item.failures > 0)
      .sort((left, right) => {
        if (left.item.failures !== right.item.failures) return right.item.failures - left.item.failures;
        return Date.parse(left.item.lastSeenAt) - Date.parse(right.item.lastSeenAt);
      })[0];

    if (!unhealthy) return false;
    bucket.splice(unhealthy.position, 1);
    bucket.push(peer);
    this.buckets.set(index, bucket);
    return true;
  }

  noteSuccess(relayId: string, at = new Date().toISOString()) {
    requireRelayId(relayId);
    const index = bucketIndex(this.localRelayId, relayId);
    const bucket = this.buckets.get(index);
    if (!bucket) return false;
    const currentIndex = bucket.findIndex((item) => item.relayId === relayId);
    if (currentIndex < 0) return false;
    const current = bucket[currentIndex];
    bucket.splice(currentIndex, 1);
    bucket.push({ ...current, failures: 0, lastSeenAt: at });
    return true;
  }

  noteFailure(relayId: string) {
    requireRelayId(relayId);
    const index = bucketIndex(this.localRelayId, relayId);
    const bucket = this.buckets.get(index);
    if (!bucket) return false;
    const current = bucket.find((item) => item.relayId === relayId);
    if (!current) return false;
    current.failures += 1;
    return true;
  }

  all() {
    return [...this.buckets.entries()]
      .sort(([left], [right]) => left - right)
      .flatMap(([, bucket]) => bucket.map(clonePeer));
  }

  nearest(targetRelayId: string, limit = this.bucketSize) {
    requireRelayId(targetRelayId, "Cible Kademlia");
    if (!Number.isSafeInteger(limit) || limit < 1) throw new Error("Limite Kademlia invalide.");
    return this.all().sort((left, right) => compareDistance(targetRelayId, left, right)).slice(0, limit);
  }
}

type QueryReply<T> = {
  record?: T | null;
  peers?: DiscoveryPeer[];
};

type IterativeOptions<T> = {
  seeds?: DiscoveryPeer[];
  table?: KBucketTable;
  alpha?: number;
  paths?: number;
  maxQueries?: number;
  k?: number;
  validateRecord?: (record: T) => boolean;
  selectRecord?: (records: T[]) => T | null;
};

export async function iterativeFindRecord<T>(
  key: string,
  queryPeer: (peer: DiscoveryPeer, key: string) => Promise<QueryReply<T>>,
  options: IterativeOptions<T> = {},
) {
  requireRelayId(key, "Clé Discovery");
  const alpha = options.alpha ?? 3;
  const paths = options.paths ?? 3;
  const maxQueries = options.maxQueries ?? 24;
  const k = options.k ?? 20;
  for (const [label, value] of [["alpha", alpha], ["paths", paths], ["maxQueries", maxQueries], ["k", k]] as const) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${label} Kademlia invalide.`);
  }

  const candidates = new Map<string, DiscoveryPeer>();
  const seedSource = options.seeds ?? options.table?.nearest(key, Math.max(k, paths)) ?? [];
  for (const seed of seedSource) {
    const validated = validatePeer(seed);
    candidates.set(validated.relayId, validated);
    options.table?.upsert(validated);
  }

  const independentSeeds = [...candidates.values()]
    .sort((left, right) => compareDistance(key, left, right))
    .slice(0, Math.min(paths, candidates.size))
    .map((peer) => peer.relayId);
  const queried = new Set<string>();
  const queriedOrder: string[] = [];
  const records: T[] = [];

  while (queried.size < maxQueries) {
    const remainingIndependent = independentSeeds
      .filter((relayId) => !queried.has(relayId))
      .map((relayId) => candidates.get(relayId))
      .filter((peer): peer is DiscoveryPeer => Boolean(peer));

    const nearestUnqueried = [...candidates.values()]
      .filter((peer) => !queried.has(peer.relayId))
      .sort((left, right) => compareDistance(key, left, right));

    const batch: DiscoveryPeer[] = [];
    const seenBatch = new Set<string>();
    for (const peer of [...remainingIndependent, ...nearestUnqueried]) {
      if (seenBatch.has(peer.relayId)) continue;
      seenBatch.add(peer.relayId);
      batch.push(peer);
      if (batch.length >= alpha || queried.size + batch.length >= maxQueries) break;
    }

    if (batch.length === 0) break;

    for (const peer of batch) {
      queried.add(peer.relayId);
      queriedOrder.push(peer.relayId);
    }

    const replies = await Promise.allSettled(batch.map((peer) => queryPeer(clonePeer(peer), key)));
    for (let index = 0; index < replies.length; index += 1) {
      const outcome = replies[index];
      const peer = batch[index];
      if (outcome.status === "rejected") {
        options.table?.noteFailure(peer.relayId);
        continue;
      }

      options.table?.noteSuccess(peer.relayId);
      const reply = outcome.value ?? {};
      for (const discovered of reply.peers ?? []) {
        try {
          const validated = validatePeer(discovered);
          if (!candidates.has(validated.relayId)) candidates.set(validated.relayId, validated);
          options.table?.upsert(validated);
        } catch {
          // Ignore malformed peer hints. They are routing hints, never authority.
        }
      }

      if (reply.record !== undefined && reply.record !== null) {
        if (!options.validateRecord || options.validateRecord(reply.record)) records.push(reply.record);
      }
    }

    if (records.length > 0) {
      const record = options.selectRecord ? options.selectRecord(records) : records[0];
      return {
        record,
        queried: [...queriedOrder],
        closestPeers: [...candidates.values()].sort((left, right) => compareDistance(key, left, right)).slice(0, k).map(clonePeer),
      };
    }
  }

  return {
    record: null,
    queried: [...queriedOrder],
    closestPeers: [...candidates.values()].sort((left, right) => compareDistance(key, left, right)).slice(0, k).map(clonePeer),
  };
}
