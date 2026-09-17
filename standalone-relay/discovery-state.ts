export type DiscoveryPeer = {
  relayId: string;
  endpoint: string;
  lastSeenAt: string;
  failures: number;
  bucketIndex: number;
};

export type DiscoveryPeerEntries = Array<[string, DiscoveryPeer]>;

type DiscoveryPeerState = {
  peers: Map<string, DiscoveryPeer>;
};

declare global {
  var __quanticDiscoveryPeerState: DiscoveryPeerState | undefined;
}

const RELAY_ID = /^[0-9a-f]{64}$/;
const STALE_PEER_MS = 30 * 24 * 60 * 60 * 1000;
const FAILURE_PRUNE_THRESHOLD = 3;

const state: DiscoveryPeerState = globalThis.__quanticDiscoveryPeerState ?? {
  peers: new Map(),
};
globalThis.__quanticDiscoveryPeerState = state;

function clonePeer(peer: DiscoveryPeer): DiscoveryPeer {
  return JSON.parse(JSON.stringify(peer)) as DiscoveryPeer;
}

function normalizeEndpoint(endpoint: string) {
  const parsed = new URL(endpoint);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Endpoint Discovery invalide.");
  }
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/$/, "");
}

function validatePeer(peer: DiscoveryPeer) {
  if (!peer || !RELAY_ID.test(peer.relayId)) throw new Error("Relay ID Discovery invalide.");
  if (typeof peer.endpoint !== "string") throw new Error("Endpoint Discovery invalide.");
  if (typeof peer.lastSeenAt !== "string" || !Number.isFinite(Date.parse(peer.lastSeenAt))) {
    throw new Error("Date Discovery invalide.");
  }
  if (!Number.isSafeInteger(peer.failures) || peer.failures < 0) {
    throw new Error("Compteur d’échecs Discovery invalide.");
  }
  if (!Number.isSafeInteger(peer.bucketIndex) || peer.bucketIndex < 0 || peer.bucketIndex > 255) {
    throw new Error("Bucket Discovery invalide.");
  }
  return {
    ...peer,
    endpoint: normalizeEndpoint(peer.endpoint),
  };
}

function shouldPrune(peer: DiscoveryPeer, nowMs: number) {
  return peer.failures >= FAILURE_PRUNE_THRESHOLD && Date.parse(peer.lastSeenAt) < nowMs - STALE_PEER_MS;
}

export function normalizeDiscoveryPeerEntries(entries: DiscoveryPeerEntries, nowMs = Date.now()): DiscoveryPeerEntries {
  const next = new Map<string, DiscoveryPeer>();
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string") {
      throw new Error("Entrée Discovery invalide.");
    }
    const peer = validatePeer(entry[1]);
    if (entry[0] !== peer.relayId) throw new Error("Clé Discovery incohérente avec relayId.");
    if (!shouldPrune(peer, nowMs)) next.set(peer.relayId, clonePeer(peer));
  }
  return [...next.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([relayId, peer]) => [relayId, clonePeer(peer)] as [string, DiscoveryPeer]);
}

function prune(nowMs = Date.now()) {
  for (const [relayId, peer] of state.peers) {
    if (shouldPrune(peer, nowMs)) state.peers.delete(relayId);
  }
}

export function rememberDiscoveryPeer(peer: DiscoveryPeer, nowMs = Date.now()) {
  const validated = validatePeer(peer);
  if (shouldPrune(validated, nowMs)) {
    state.peers.delete(validated.relayId);
    return null;
  }
  state.peers.set(validated.relayId, clonePeer(validated));
  return clonePeer(validated);
}

export function discoveryPeerEntries(nowMs = Date.now()): DiscoveryPeerEntries {
  prune(nowMs);
  return [...state.peers.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([relayId, peer]) => [relayId, clonePeer(peer)] as [string, DiscoveryPeer]);
}

export function replaceDiscoveryPeerEntries(entries: DiscoveryPeerEntries, nowMs = Date.now()) {
  state.peers = new Map(normalizeDiscoveryPeerEntries(entries, nowMs));
}
