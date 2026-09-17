import assert from "node:assert/strict";
import test from "node:test";

import {
  createEmptyRelayState,
  exportRelayState,
  restoreRelayState,
  type RelayPersistentState,
} from "../lib/quantic/relay-state.ts";
import { getStandalonePreKeyStore } from "../lib/quantic/standalone-v11-state.ts";
import { RelayRuntime, type RelayStateStore } from "../standalone-relay/runtime.ts";

const PREKEY_ID = "e".repeat(32);

test("disk failure rolls back V1.1 prekey state with the rest of the relay", async () => {
  const now = Date.parse("2026-09-16T21:00:00.000Z");
  restoreRelayState(createEmptyRelayState(new Date(now).toISOString()), now);
  const store: RelayStateStore = {
    async load() {
      return null;
    },
    async save(_state: RelayPersistentState) {
      throw new Error("disk unavailable");
    },
  };
  const runtime = new RelayRuntime(store);
  await runtime.initialize();
  const before = exportRelayState(new Date(now).toISOString());

  await assert.rejects(
    () => runtime.mutate(() => {
      getStandalonePreKeyStore().consumed.set(PREKEY_ID, now + 60_000);
      return { mutated: true };
    }),
    /disk unavailable/i,
  );

  assert.equal(getStandalonePreKeyStore().consumed.has(PREKEY_ID), false);
  assert.deepEqual(exportRelayState(new Date(now).toISOString()), before);
});
