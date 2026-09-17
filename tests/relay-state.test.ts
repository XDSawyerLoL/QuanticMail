import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import type { QuanticCryptoProfileV2 } from "../lib/quantic/crypto-profile-core.mjs";
import {
  cryptoProfileEntries,
  replaceCryptoProfileEntries,
} from "../lib/quantic/crypto-profile-state.ts";
import type { QuanticRouteManifest } from "../lib/quantic/federation-types.ts";
import { createIdentityChallenge, registerIdentity } from "../lib/quantic/relay.ts";
import { createEmptyRelayState, exportRelayState, restoreRelayState } from "../lib/quantic/relay-state.ts";
import { replaceRouteManifestEntries, routeManifestEntries } from "../lib/quantic/route-manifest-state.ts";
import { checkFederationReplay, recordFederationAccepted, replaceFederationStateEntries } from "../standalone-relay/federation-state.ts";

function emptySavedAt() { return "2026-09-16T00:00:00.000Z"; }
function emptyFederationState() { return { seen: [], inbound: [], outbound: [], pendingReceipts: [] }; }

test("empty relay state is explicit and versioned", () => {
  restoreRelayState(createEmptyRelayState(emptySavedAt()));
  const snapshot = exportRelayState("2026-09-16T00:00:01.000Z");
  assert.equal(snapshot.format, "quantic-relay-state");
  assert.equal(snapshot.version, 3);
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
  assert.deepEqual(snapshot.routeManifests, []);
  assert.deepEqual(snapshot.cryptoProfiles, []);
  assert.deepEqual(snapshot.federation, emptyFederationState());
  assert.deepEqual(snapshot.discoveryPeers, []);
});

test("relay aliases round-trip through JSON without Set loss", () => {
  const state = createEmptyRelayState(emptySavedAt());
  state.aliases = [["alice", ["alice~0123456789@quantic"]]];
  restoreRelayState(JSON.parse(JSON.stringify(state)));
  assert.deepEqual(exportRelayState(emptySavedAt()).aliases, state.aliases);
});

test("route manifest cache round-trips through relay durable state", () => {
  const route: QuanticRouteManifest = {
    format: "quantic-route-manifest", version: 1,
    payload: { version: 1, sequence: 4, canonicalAddress: "bob~abcdef0123@quantic", identitySigningPublicKey: { kty: "EC", crv: "P-256", x: "ix", y: "iy" }, identityManifestSequence: 3, cryptoProfileSequence: null, cryptoProfileDigest: null, relays: [], issuedAt: "2026-09-16T00:00:00.000Z", expiresAt: "2026-10-16T00:00:00.000Z" },
    signatures: { p256: "signature" },
  };
  replaceRouteManifestEntries([[route.payload.canonicalAddress, route]]);
  const snapshot = exportRelayState(emptySavedAt());
  assert.deepEqual(snapshot.routeManifests, [[route.payload.canonicalAddress, route]]);
  replaceRouteManifestEntries([]);
  restoreRelayState(JSON.parse(JSON.stringify(snapshot)));
  assert.deepEqual(routeManifestEntries(), [[route.payload.canonicalAddress, route]]);
});

test("Crypto Profile public cache round-trips without private PQ material", () => {
  const profile: QuanticCryptoProfileV2 = {
    format: "quantic-crypto-profile", version: 2,
    payload: { version: 2, sequence: 3, canonicalAddress: "bob~abcdef0123@quantic", identitySigningPublicKey: { kty: "EC", crv: "P-256", x: "ix", y: "iy" }, identityManifestSequence: 2, policy: "hybrid-required", identityMlDsaAlgorithm: "ML-DSA-65", identityMlDsaPublicKeySpki: "A".repeat(64), devices: [{ deviceId: "d-abcdef0123", mlKemAlgorithm: "ML-KEM-768", mlKemPublicKeySpki: "B".repeat(64), mlDsaAlgorithm: "ML-DSA-65", mlDsaPublicKeySpki: "C".repeat(64) }], issuedAt: "2026-09-17T08:00:00.000Z" },
    signatures: { p256: "dGVzdC1zaWduYXR1cmU=", mlDsa65Self: "D".repeat(64) },
  };
  replaceCryptoProfileEntries([[profile.payload.canonicalAddress, profile]]);
  const snapshot = exportRelayState(emptySavedAt());
  assert.deepEqual(snapshot.cryptoProfiles, [[profile.payload.canonicalAddress, profile]]);
  assert.equal(JSON.stringify(snapshot).includes("privateKeyPkcs8"), false);
  replaceCryptoProfileEntries([]);
  restoreRelayState(JSON.parse(JSON.stringify(snapshot)));
  assert.deepEqual(cryptoProfileEntries(), [[profile.payload.canonicalAddress, profile]]);
});

test("federation replay state round-trips through relay durable state", () => {
  restoreRelayState(createEmptyRelayState(emptySavedAt()));
  const federationId = "fed-state-000000000001"; const digest = "a".repeat(64);
  recordFederationAccepted({ federationId, envelopeDigest: digest, expiresAt: "2026-10-16T00:00:00.000Z" });
  const snapshot = exportRelayState(emptySavedAt());
  assert.equal(snapshot.federation.seen.length, 1);
  replaceFederationStateEntries(emptyFederationState());
  restoreRelayState(JSON.parse(JSON.stringify(snapshot)), Date.parse("2026-09-17T00:00:00.000Z"));
  assert.deepEqual(checkFederationReplay(federationId, digest, Date.parse("2026-09-17T00:01:00.000Z")), { duplicate: true });
});

test("legacy version-1 relay snapshots without V1.2, route, Crypto Profile, federation or discovery state still restore", () => {
  const state = createEmptyRelayState(emptySavedAt());
  const legacy: Record<string, unknown> = { ...state, version: 1 };
  delete legacy.manifests; delete legacy.preKeyPools; delete legacy.consumedPreKeys; delete legacy.routeManifests; delete legacy.cryptoProfiles; delete legacy.federation; delete legacy.discoveryPeers;
  restoreRelayState(legacy);
  const restored = exportRelayState(emptySavedAt());
  assert.deepEqual(restored.manifests, []); assert.deepEqual(restored.preKeyPools, []); assert.deepEqual(restored.consumedPreKeys, []); assert.deepEqual(restored.routeManifests, []); assert.deepEqual(restored.cryptoProfiles, []); assert.deepEqual(restored.federation, emptyFederationState()); assert.deepEqual(restored.discoveryPeers, []);
});

test("persistent snapshots never contain raw device auth tokens", () => {
  restoreRelayState(createEmptyRelayState(emptySavedAt()));
  const encryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" }); const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = encryption.publicKey.export({ format: "jwk" }); const signingPublicKey = signing.publicKey.export({ format: "jwk" });
  const authToken = "test-auth-token-that-must-never-be-persisted-000001";
  const challenge = createIdentityChallenge({ handle: "alice", publicKey, signingPublicKey });
  const signature = sign("sha256", Buffer.from(challenge.challenge, "utf8"), { key: signing.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
  registerIdentity({ handle: "alice", publicKey, signingPublicKey, authToken, challenge: challenge.challenge, signature });
  const snapshot = exportRelayState(emptySavedAt()); const serialized = JSON.stringify(snapshot);
  assert.equal(serialized.includes(authToken), false); assert.equal(snapshot.identities.length, 1); assert.match(snapshot.identities[0][1].authTokenHash, /^[0-9a-f]{64}$/);
});

test("unknown state format or future version is rejected", () => {
  assert.throws(() => restoreRelayState({ format: "wrong", version: 3 }), /format/i);
  assert.throws(() => restoreRelayState({ format: "quantic-relay-state", version: 4 }), /version/i);
});

test("a rejected restore leaves the previous state untouched", () => {
  const state = createEmptyRelayState(emptySavedAt()); state.aliases = [["bob", ["bob~fedcba9876@quantic"]]]; restoreRelayState(state); const before = exportRelayState(emptySavedAt());
  assert.throws(() => restoreRelayState({ ...state, identities: "not-an-array" }), /identities/i);
  assert.deepEqual(exportRelayState(emptySavedAt()), before);
});

test("restore prunes expired challenges and stale rate-limit timestamps", () => {
  const now = Date.parse("2026-09-16T12:00:00.000Z"); const state = createEmptyRelayState(emptySavedAt()); const fakeKey = { kty: "EC", crv: "P-256", x: "x", y: "y" };
  state.challenges = [["alice~0123456789@quantic", { challenge: "expired", handle: "alice", canonicalAddress: "alice~0123456789@quantic", fingerprint: "0123456789", publicKey: fakeKey, signingPublicKey: fakeKey, expiresAt: now - 1 }]];
  state.sendWindows = [["alice~0123456789@quantic", [now - 60_001, now - 10_000]]];
  restoreRelayState(state, now); const restored = exportRelayState(emptySavedAt());
  assert.deepEqual(restored.challenges, []); assert.deepEqual(restored.sendWindows, [["alice~0123456789@quantic", [now - 10_000]]]);
});
