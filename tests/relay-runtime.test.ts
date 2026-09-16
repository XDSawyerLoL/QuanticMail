import assert from "node:assert/strict";
import test from "node:test";

import { createIdentityChallenge } from "../lib/quantic/relay.ts";
import {
  createEmptyRelayState,
  exportRelayState,
  restoreRelayState,
  type RelayPersistentState,
} from "../lib/quantic/relay-state.ts";
import { RelayRuntime, type RelayStateStore } from "../standalone-relay/runtime.ts";

const fakeKey = { kty: "EC", crv: "P-256", x: "x", y: "y" };

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test("mutations are durably serialized in request order", async () => {
  restoreRelayState(createEmptyRelayState());
  const firstSave = deferred();
  const saved: RelayPersistentState[] = [];
  let saveCount = 0;
  const store: RelayStateStore = {
    async load() {
      return null;
    },
    async save(state) {
      saveCount += 1;
      saved.push(state);
      if (saveCount === 1) await firstSave.promise;
    },
  };
  const runtime = new RelayRuntime(store);
  await runtime.initialize();
  const executed: string[] = [];

  const a = runtime.mutate(() => {
    executed.push("alice");
    return createIdentityChallenge({ handle: "alice", publicKey: fakeKey, signingPublicKey: fakeKey });
  });
  const b = runtime.mutate(() => {
    executed.push("bob");
    return createIdentityChallenge({ handle: "bob", publicKey: fakeKey, signingPublicKey: fakeKey });
  });

  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(executed, ["alice"]);
  firstSave.resolve();
  await Promise.all([a, b]);

  assert.deepEqual(executed, ["alice", "bob"]);
  assert.equal(saved.length, 2);
  assert.equal(saved[0].challenges.length, 1);
  assert.equal(saved[1].challenges.length, 2);
});

test("disk failure restores the pre-mutation relay state", async () => {
  restoreRelayState(createEmptyRelayState());
  const store: RelayStateStore = {
    async load() {
      return null;
    },
    async save() {
      throw new Error("disk unavailable");
    },
  };
  const runtime = new RelayRuntime(store);
  await runtime.initialize();
  const before = exportRelayState("2026-09-16T00:00:00.000Z");

  await assert.rejects(
    () =>
      runtime.mutate(() =>
        createIdentityChallenge({ handle: "alice", publicKey: fakeKey, signingPublicKey: fakeKey }),
      ),
    /disk unavailable/i,
  );

  assert.deepEqual(exportRelayState("2026-09-16T00:00:00.000Z"), before);
});

test("a protocol error after a mutation is persisted before it is rethrown", async () => {
  restoreRelayState(createEmptyRelayState());
  const saved: RelayPersistentState[] = [];
  const store: RelayStateStore = {
    async load() {
      return null;
    },
    async save(state) {
      saved.push(state);
    },
  };
  const runtime = new RelayRuntime(store);
  await runtime.initialize();

  await assert.rejects(
    () =>
      runtime.mutate(() => {
        createIdentityChallenge({ handle: "alice", publicKey: fakeKey, signingPublicKey: fakeKey });
        throw new Error("protocol rejected after mutation");
      }),
    /protocol rejected/i,
  );

  assert.equal(saved.length, 1);
  assert.equal(saved[0].challenges.length, 1);
  assert.equal(exportRelayState().challenges.length, 1);
});
