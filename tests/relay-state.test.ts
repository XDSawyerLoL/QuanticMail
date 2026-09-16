import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { createIdentityChallenge, registerIdentity } from "../lib/quantic/relay.ts";
import {
  createEmptyRelayState,
  exportRelayState,
  restoreRelayState,
} from "../lib/quantic/relay-state.ts";

function emptySavedAt() {
  return "2026-09-16T00:00:00.000Z";
}

test("empty relay state is explicit and versioned", () => {
  restoreRelayState(createEmptyRelayState(emptySavedAt()));

  const snapshot = exportRelayState("2026-09-16T00:00:01.000Z");

  assert.equal(snapshot.format, "quantic-relay-state");
  assert.equal(snapshot.version, 2);
  assert.equal(snapshot.savedAt, "2026-09-16T00:00:01.000Z");
  assert.deepEqual(snapshot.identities, []);
  assert.deepEqual(snapshot.aliases, []);
  assert.deepEqual(snapshot.challenges, []);
  assert.deepEqual(snapshot.devices, []);
  assert.deepEqual(snapshot.queues, []);
  assert.deepEqual(snapshot.receipts, []);
  assert.deepEqual(snapshot.sendWindows, []);
  assert.deepEqual(snapshot.manifests, []);
  assert.deepEqual(snapshot.preKeyPools, []);
  assert.deepEqual(snapshot.consumedPreKeys, []);
});

test("relay aliases round-trip through JSON without Set loss", () => {
  const state = createEmptyRelayState(emptySavedAt());
  state.aliases = [["alice", ["alice~0123456789@quantic"]]];

  restoreRelayState(JSON.parse(JSON.stringify(state)));

  assert.deepEqual(exportRelayState(emptySavedAt()).aliases, state.aliases);
});

test("persistent snapshots never contain raw device auth tokens", () => {
  restoreRelayState(createEmptyRelayState(emptySavedAt()));
  const encryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = encryption.publicKey.export({ format: "jwk" });
  const signingPublicKey = signing.publicKey.export({ format: "jwk" });
  const authToken = "test-auth-token-that-must-never-be-persisted-000001";
  const challenge = createIdentityChallenge({
    handle: "alice",
    publicKey,
    signingPublicKey,
  });
  const signature = sign(
    "sha256",
    Buffer.from(challenge.challenge, "utf8"),
    { key: signing.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");

  registerIdentity({
    handle: "alice",
    publicKey,
    signingPublicKey,
    authToken,
    challenge: challenge.challenge,
    signature,
  });

  const snapshot = exportRelayState(emptySavedAt());
  const serialized = JSON.stringify(snapshot);
  assert.equal(serialized.includes(authToken), false);
  assert.equal(snapshot.identities.length, 1);
  assert.match(snapshot.identities[0][1].authTokenHash, /^[0-9a-f]{64}$/);
});

test("unknown state format or future version is rejected", () => {
  assert.throws(
    () => restoreRelayState({ format: "wrong", version: 2 }),
    /format/i,
  );
  assert.throws(
    () => restoreRelayState({ format: "quantic-relay-state", version: 3 }),
    /version/i,
  );
});

test("a rejected restore leaves the previous state untouched", () => {
  const state = createEmptyRelayState(emptySavedAt());
  state.aliases = [["bob", ["bob~fedcba9876@quantic"]]];
  restoreRelayState(state);
  const before = exportRelayState(emptySavedAt());

  assert.throws(
    () =>
      restoreRelayState({
        ...state,
        identities: "not-an-array",
      }),
    /identities/i,
  );

  assert.deepEqual(exportRelayState(emptySavedAt()), before);
});

test("restore prunes expired challenges and stale rate-limit timestamps", () => {
  const now = Date.parse("2026-09-16T12:00:00.000Z");
  const state = createEmptyRelayState(emptySavedAt());
  const fakeKey = { kty: "EC", crv: "P-256", x: "x", y: "y" };
  state.challenges = [
    [
      "alice~0123456789@quantic",
      {
        challenge: "expired",
        handle: "alice",
        canonicalAddress: "alice~0123456789@quantic",
        fingerprint: "0123456789",
        publicKey: fakeKey,
        signingPublicKey: fakeKey,
        expiresAt: now - 1,
      },
    ],
  ];
  state.sendWindows = [["alice~0123456789@quantic", [now - 60_001, now - 10_000]]];

  restoreRelayState(state, now);
  const restored = exportRelayState(emptySavedAt());

  assert.deepEqual(restored.challenges, []);
  assert.deepEqual(restored.sendWindows, [["alice~0123456789@quantic", [now - 10_000]]]);
});
