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

test("empty relay state is emitted as V2 with durable V1.1 stores", () => {
  restoreRelayState(createEmptyRelayState(savedAt));
  const snapshot = exportRelayState(savedAt);

  assert.equal(snapshot.version, 2);
  assert.deepEqual(snapshot.manifests, []);
  assert.deepEqual(snapshot.preKeyPools, []);
  assert.deepEqual(snapshot.consumedPreKeys, []);
});

test("legacy V1 relay state migrates to V2 with empty manifest and prekey stores", () => {
  restoreRelayState(legacyV1State());
  const migrated = exportRelayState(savedAt);

  assert.equal(migrated.version, 2);
  assert.deepEqual(migrated.manifests, []);
  assert.deepEqual(migrated.preKeyPools, []);
  assert.deepEqual(migrated.consumedPreKeys, []);
  assert.equal(getStandaloneManifest("alice~0123456789@quantic"), null);
  assert.equal(getStandalonePreKeyStore().pools.size, 0);
  assert.equal(getStandalonePreKeyStore().consumed.size, 0);
});

test("future relay state versions remain rejected", () => {
  assert.throws(
    () => restoreRelayState({ ...legacyV1State(), version: 3 }),
    /version/i,
  );
});
