import { randomBytes } from "node:crypto";

import { rememberDiscoveryPeer, type DiscoveryPeer } from "./discovery-state.ts";
import { verifyRelayHello } from "./identity.ts";
import { xorDistance } from "./kademlia.ts";
import { RelayRuntime } from "./runtime.ts";

const BOOTSTRAP_TIMEOUT_MS = 5_000;

function normalizeEndpoint(value: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Endpoint bootstrap Quantic invalide.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Endpoint bootstrap Quantic invalide.");
  }
  if (url.username || url.password) {
    throw new Error("Endpoint bootstrap Quantic invalide.");
  }
  return url.origin;
}

function peerBucketIndex(localRelayId: string, remoteRelayId: string) {
  const distance = xorDistance(localRelayId, remoteRelayId);
  if (distance === BigInt(0)) return -1;
  return distance.toString(2).length - 1;
}

export function parseRelayBootstrap(value: string | undefined) {
  if (!value?.trim()) return [];
  const unique = new Set<string>();
  for (const raw of value.split(",")) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    unique.add(normalizeEndpoint(trimmed));
  }
  return [...unique];
}

async function helloForEndpoint(endpoint: string) {
  const nonce = `bootstrap-${randomBytes(18).toString("base64url")}`;
  const response = await fetch(`${endpoint}/api/quantic/federation/hello`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce }),
    signal: AbortSignal.timeout(BOOTSTRAP_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`Bootstrap Quantic refusé par ${endpoint} (${response.status}).`);
  }
  return verifyRelayHello(await response.json(), nonce);
}

export async function bootstrapDiscoveryPeers(
  runtime: RelayRuntime,
  localRelayId: string,
  endpoints: string[],
) {
  const normalized = [...new Set(endpoints.map(normalizeEndpoint))];
  const connected: DiscoveryPeer[] = [];
  const failed: string[] = [];

  for (const endpoint of normalized) {
    try {
      const hello = await helloForEndpoint(endpoint);
      if (hello.relayId === localRelayId) continue;
      const bucketIndex = peerBucketIndex(localRelayId, hello.relayId);
      if (bucketIndex < 0) continue;
      const peer: DiscoveryPeer = {
        relayId: hello.relayId,
        endpoint: hello.endpoint,
        lastSeenAt: new Date().toISOString(),
        failures: 0,
        bucketIndex,
      };
      const remembered = await runtime.mutate(() => rememberDiscoveryPeer(peer));
      if (remembered) connected.push(remembered);
    } catch {
      failed.push(endpoint);
    }
  }

  return { connected, failed };
}
