import assert from "node:assert/strict";
import test from "node:test";

import {
  createEmptyRelayState,
  exportRelayState,
  restoreRelayState,
} from "../lib/quantic/relay-state.ts";

async function discoveryState() {
  try {
    return await import("../standalone-relay/discovery-state.ts");
  } catch (error) {
    assert.fail(`Discovery peer state is not implemented yet: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const RELAY_A = "a".repeat(64);
const RELAY_B = "b".repeat(64);

function peer(overrides: Record<string, unknown> = {}) {
  return {
    relayId: RELAY_A,
    endpoint: "https://relay-a.example",
    lastSeenAt: "2026-09-17T09:00:00.000Z",
    failures: 0,
    bucketIndex: 17,
    ...overrides,
  };
}

test("discovery peers round-trip through their dedicated durable state", async () => {
  const {
    rememberDiscoveryPeer,
    discoveryPeerEntries,
    replaceDiscoveryPeerEntries,
  } = await discoveryState();

  replaceDiscoveryPeerEntries([], Date.parse("2026-09-17T09:00:00.000Z"));
  rememberDiscoveryPeer(peer());
  const saved = discoveryPeerEntries(Date.parse("2026-09-17T09:01:00.000Z"));
  assert.equal(saved.length, 1);
  assert.deepEqual(saved[0], [RELAY_A, peer()]);

  replaceDiscoveryPeerEntries([], Date.parse("2026-09-17T09:01:00.000Z"));
  assert.deepEqual(discoveryPeerEntries(Date.parse("2026-09-17T09:01:00.000Z")), []);
  replaceDiscoveryPeerEntries(saved, Date.parse("2026-09-17T09:01:00.000Z"));
  assert.deepEqual(discoveryPeerEntries(Date.parse("2026-09-17T09:01:00.000Z")), saved);
});

test("stale failing discovery peers are pruned on restore", async () => {
  const {
    discoveryPeerEntries,
    replaceDiscoveryPeerEntries,
  } = await discoveryState();
  const now = Date.parse("2026-09-17T09:00:00.000Z");
  const veryOld = new Date(now - 31 * 24 * 60 * 60 * 1000).toISOString();

  replaceDiscoveryPeerEntries([
    [RELAY_A, peer({ lastSeenAt: veryOld, failures: 5 })],
    [RELAY_B, peer({ relayId: RELAY_B, endpoint: "https://relay-b.example", failures: 0 })],
  ], now);

  const entries = discoveryPeerEntries(now);
  assert.equal(entries.length, 1);
  assert.equal(entries[0][0], RELAY_B);
});

test("relay snapshot V3 persists Discovery peers and restores them atomically", async () => {
  const {
    rememberDiscoveryPeer,
    discoveryPeerEntries,
    replaceDiscoveryPeerEntries,
  } = await discoveryState();
  const now = Date.parse("2026-09-17T09:00:00.000Z");
  restoreRelayState(createEmptyRelayState(new Date(now).toISOString()), now);
  rememberDiscoveryPeer(peer());

  const snapshot = exportRelayState(new Date(now + 1000).toISOString());
  assert.equal(snapshot.version, 3);
  assert.deepEqual(snapshot.discoveryPeers, [[RELAY_A, peer()]]);

  replaceDiscoveryPeerEntries([], now);
  restoreRelayState(JSON.parse(JSON.stringify(snapshot)), now);
  assert.deepEqual(discoveryPeerEntries(now), [[RELAY_A, peer()]]);
});

test("legacy V2 snapshots restore with an empty Discovery peer table", async () => {
  const { discoveryPeerEntries, replaceDiscoveryPeerEntries } = await discoveryState();
  const now = Date.parse("2026-09-17T09:00:00.000Z");
  const current = createEmptyRelayState(new Date(now).toISOString()) as Record<string, unknown>;
  const legacyV2: Record<string, unknown> = { ...current, version: 2 };
  delete legacyV2.discoveryPeers;

  replaceDiscoveryPeerEntries([[RELAY_A, peer()]], now);
  restoreRelayState(legacyV2, now);
  assert.deepEqual(discoveryPeerEntries(now), []);
});
