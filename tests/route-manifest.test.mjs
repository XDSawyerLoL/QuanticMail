import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import test from "node:test";

import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { canonicalRouteManifestText } from "../lib/quantic/federation-core.mjs";
import {
  assertVerifiedRouteManifest,
  mergeRouteManifestState,
} from "../lib/quantic/route-manifest-node.mjs";

function keys() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    publicKey: pair.publicKey.export({ format: "jwk" }),
    privateKey: pair.privateKey,
  };
}

function fingerprint(key) {
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex").slice(0, 10);
}

function deviceId(key) {
  return `d-${createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex").slice(0, 10)}`;
}

function spkiRelayId(publicKeyObject) {
  return createHash("sha256")
    .update(publicKeyObject.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function signedIdentity() {
  const owner = keys();
  const encryption = keys();
  const fp = fingerprint(owner.publicKey);
  const canonicalAddress = `bob~${fp}@quantic`;
  const payload = {
    version: 1,
    sequence: 3,
    canonicalAddress,
    handle: "bob",
    fingerprint: fp,
    identityPublicKey: encryption.publicKey,
    identitySigningPublicKey: owner.publicKey,
    devices: [{
      deviceId: deviceId(encryption.publicKey),
      label: "Bob root",
      publicKey: encryption.publicKey,
      deviceSigningPublicKey: owner.publicKey,
      kind: "root",
      issuedAt: "2026-09-17T00:00:00.000Z",
    }],
    revocations: [],
    issuedAt: "2026-09-17T00:00:00.000Z",
  };
  const signature = sign("sha256", Buffer.from(canonicalManifestText(payload)), {
    key: owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return {
    owner,
    manifest: { format: "quantic-identity-manifest", version: 1, payload, signature },
  };
}

function signedRoute(identity, sequence = 1, endpoint = "https://relay.example") {
  const relayPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const relayPublic = relayPair.publicKey.export({ format: "jwk" });
  const payload = {
    version: 1,
    sequence,
    canonicalAddress: identity.manifest.payload.canonicalAddress,
    identitySigningPublicKey: identity.manifest.payload.identitySigningPublicKey,
    identityManifestSequence: identity.manifest.payload.sequence,
    cryptoProfileSequence: null,
    cryptoProfileDigest: null,
    relays: [{
      relayId: spkiRelayId(relayPair.publicKey),
      endpoint,
      priority: 10,
      protocols: ["quantic-federation/1"],
      classicalSigningPublicKey: relayPublic,
      expiresAt: "2026-10-17T00:00:00.000Z",
    }],
    issuedAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-10-17T00:00:00.000Z",
  };
  const signature = sign("sha256", Buffer.from(canonicalRouteManifestText(payload)), {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return {
    format: "quantic-route-manifest",
    version: 1,
    payload,
    signatures: { p256: signature },
  };
}

test("valid route manifest verifies against the signed identity manifest", () => {
  const identity = signedIdentity();
  const route = signedRoute(identity);
  assert.equal(assertVerifiedRouteManifest(route, identity.manifest).payload.sequence, 1);
});

test("route verification rejects endpoint/key relayId mismatch", () => {
  const identity = signedIdentity();
  const route = signedRoute(identity);
  route.payload.relays[0].relayId = "f".repeat(64);
  route.signatures.p256 = sign("sha256", Buffer.from(canonicalRouteManifestText(route.payload)), {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  assert.throws(() => assertVerifiedRouteManifest(route, identity.manifest), /relay id|relais/i);
});

test("route verification rejects a signature from another identity", () => {
  const identity = signedIdentity();
  const attacker = keys();
  const route = signedRoute(identity);
  route.signatures.p256 = sign("sha256", Buffer.from(canonicalRouteManifestText(route.payload)), {
    key: attacker.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  assert.throws(() => assertVerifiedRouteManifest(route, identity.manifest), /signature/i);
});

test("route state rejects rollback and same-sequence forks", () => {
  const identity = signedIdentity();
  const first = signedRoute(identity, 2, "https://relay-a.example");
  const newer = signedRoute(identity, 3, "https://relay-b.example");
  assert.equal(mergeRouteManifestState(null, first).payload.sequence, 2);
  assert.equal(mergeRouteManifestState(first, newer).payload.sequence, 3);
  assert.throws(() => mergeRouteManifestState(newer, first), /rollback|ancienne/i);

  const fork = signedRoute(identity, 3, "https://relay-c.example");
  assert.throws(() => mergeRouteManifestState(newer, fork), /conflit|fork/i);
});

test("route cannot claim an unavailable future identity manifest sequence", () => {
  const identity = signedIdentity();
  const route = signedRoute(identity);
  route.payload.identityManifestSequence = identity.manifest.payload.sequence + 1;
  route.signatures.p256 = sign("sha256", Buffer.from(canonicalRouteManifestText(route.payload)), {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  assert.throws(() => assertVerifiedRouteManifest(route, identity.manifest), /sequence|séquence/i);
});
