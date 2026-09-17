import assert from "node:assert/strict";
import test from "node:test";

import {
  createEmptyRelayState,
  exportRelayState,
  restoreRelayState,
} from "../lib/quantic/relay-state.ts";
import {
  getStandaloneManifest,
  getStandalonePreKeyStore,
} from "../lib/quantic/standalone-v11-state.ts";

const savedAt = "2026-09-16T20:00:00.000Z";

function legacyV1State() {
  return {
    format: "quantic-relay-state" as const,
    version: 1 as const,
    savedAt,
    identities: [],
    aliases: [],
    challenges: [],
    devices: [],
    queues: [],
    receipts: [],
    sendWindows: [],
  };
}

test("empty relay state is emitted as V3 with durable protocol stores", () => {
  restoreRelayState(createEmptyRelayState(savedAt));
  const snapshot = exportRelayState(savedAt);

  assert.equal(snapshot.version, 3);
  assert.deepEqual(snapshot.manifests, []);
  assert.deepEqual(snapshot.preKeyPools, []);
  assert.deepEqual(snapshot.consumedPreKeys, []);
  assert.deepEqual(snapshot.discoveryPeers, []);
});

test("legacy V1 relay state migrates to V3 with empty durable protocol stores", () => {
  restoreRelayState(legacyV1State());
  const migrated = exportRelayState(savedAt);

  assert.equal(migrated.version, 3);
  assert.deepEqual(migrated.manifests, []);
  assert.deepEqual(migrated.preKeyPools, []);
  assert.deepEqual(migrated.consumedPreKeys, []);
  assert.deepEqual(migrated.discoveryPeers, []);
  assert.equal(getStandaloneManifest("alice~0123456789@quantic"), null);
  assert.equal(getStandalonePreKeyStore().pools.size, 0);
  assert.equal(getStandalonePreKeyStore().consumed.size, 0);
});

test("future relay state versions remain rejected", () => {
  assert.throws(
    () => restoreRelayState({ ...legacyV1State(), version: 4 }),
    /version/i,
  );
});
