import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import test from "node:test";

import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { canonicalRouteManifestText } from "../lib/quantic/federation-core.mjs";

async function discoveryCore() {
  try {
    return await import("../lib/quantic/discovery-core.mjs");
  } catch (error) {
    assert.fail(`Discovery core is not implemented yet: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function keys() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    publicKey: pair.publicKey.export({ format: "jwk" }),
    privateKey: pair.privateKey,
    publicKeyObject: pair.publicKey,
  };
}

function fingerprint(key, length = 32) {
  return createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, length);
}

function deviceId(key, length = 32) {
  return `d-${createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, length)}`;
}

function relayId(publicKeyObject) {
  return createHash("sha256")
    .update(publicKeyObject.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function signedIdentity(handle = "bobmesh", sequence = 3) {
  const owner = keys();
  const encryption = keys();
  const fp = fingerprint(owner.publicKey);
  const canonicalAddress = `${handle}~${fp}@quantic`;
  const payload = {
    version: 1,
    sequence,
    canonicalAddress,
    handle,
    fingerprint: fp,
    identityPublicKey: encryption.publicKey,
    identitySigningPublicKey: owner.publicKey,
    devices: [{
      deviceId: deviceId(encryption.publicKey),
      label: `${handle} root`,
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
    encryption,
    manifest: {
      format: "quantic-identity-manifest",
      version: 1,
      payload,
      signature,
    },
  };
}

function resignIdentity(identity, sequence) {
  const payload = {
    ...identity.manifest.payload,
    sequence,
    issuedAt: new Date(Date.parse(identity.manifest.payload.issuedAt) + sequence * 1000).toISOString(),
  };
  const signature = sign("sha256", Buffer.from(canonicalManifestText(payload)), {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return { ...identity.manifest, payload, signature };
}

function signedRoute(identity, sequence = 2, endpoint = "https://relay.mesh.example") {
  const relay = keys();
  const payload = {
    version: 1,
    sequence,
    canonicalAddress: identity.manifest.payload.canonicalAddress,
    identitySigningPublicKey: identity.manifest.payload.identitySigningPublicKey,
    identityManifestSequence: identity.manifest.payload.sequence,
    cryptoProfileSequence: null,
    cryptoProfileDigest: null,
    relays: [{
      relayId: relayId(relay.publicKeyObject),
      endpoint,
      priority: 10,
      protocols: ["quantic-federation/1"],
      classicalSigningPublicKey: relay.publicKey,
      expiresAt: "2026-10-17T00:00:00.000Z",
    }],
    issuedAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-10-17T00:00:00.000Z",
  };
  const p256 = sign("sha256", Buffer.from(canonicalRouteManifestText(payload)), {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return {
    format: "quantic-route-manifest",
    version: 1,
    payload,
    signatures: { p256 },
  };
}

test("discovery keys are deterministic, namespaced SHA-256 hashes", async () => {
  const { discoveryKey } = await discoveryCore();
  const address = "BobMesh~0123456789abcdef0123456789abcdef@Quantic";
  const normalized = address.toLowerCase();
  const expectedIdentity = createHash("sha256").update(`quantic-identity:${normalized}`).digest("hex");
  const expectedRoute = createHash("sha256").update(`quantic-route:${normalized}`).digest("hex");

  assert.equal(discoveryKey("identity", `  ${address}  `), expectedIdentity);
  assert.equal(discoveryKey("route", address), expectedRoute);
  assert.notEqual(discoveryKey("identity", address), discoveryKey("route", address));
  assert.match(discoveryKey("crypto", address), /^[0-9a-f]{64}$/);
});

test("a valid identity plus route bundle is cross-checked and accepted", async () => {
  const { validateDiscoveryBundle } = await discoveryCore();
  const identity = signedIdentity();
  const route = signedRoute(identity);

  const accepted = validateDiscoveryBundle(
    { identityManifest: identity.manifest, routeManifest: route },
    {},
    { nowMs: Date.parse("2026-09-18T00:00:00.000Z") },
  );

  assert.equal(accepted.canonicalAddress, identity.manifest.payload.canonicalAddress);
  assert.equal(accepted.identityManifest.payload.sequence, 3);
  assert.equal(accepted.routeManifest.payload.sequence, 2);
  assert.equal(accepted.cryptoProfile, null);
});

test("bundle validation rejects identity and route rollback against pinned state", async () => {
  const { validateDiscoveryBundle } = await discoveryCore();
  const identity = signedIdentity();
  const route = signedRoute(identity, 2);
  const newerIdentity = resignIdentity(identity, 4);
  const newerRoute = signedRoute({ ...identity, manifest: newerIdentity }, 3, "https://newer.mesh.example");

  assert.throws(
    () => validateDiscoveryBundle(
      { identityManifest: identity.manifest, routeManifest: route },
      { identityManifest: newerIdentity, routeManifest: newerRoute },
      { nowMs: Date.parse("2026-09-18T00:00:00.000Z") },
    ),
    /rollback|ancienne|séquence|sequence/i,
  );
});

test("bundle validation refuses a referenced Crypto Profile when the exact profile is absent", async () => {
  const { validateDiscoveryBundle } = await discoveryCore();
  const identity = signedIdentity();
  const route = signedRoute(identity);
  route.payload.cryptoProfileSequence = 7;
  route.payload.cryptoProfileDigest = "a".repeat(64);
  route.signatures.p256 = sign("sha256", Buffer.from(canonicalRouteManifestText(route.payload)), {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");

  assert.throws(
    () => validateDiscoveryBundle(
      { identityManifest: identity.manifest, routeManifest: route },
      {},
      { nowMs: Date.parse("2026-09-18T00:00:00.000Z") },
    ),
    /crypto|profil|profile/i,
  );
});

test("newest record selection rejects same-sequence forks", async () => {
  const { selectNewestValidRecord } = await discoveryCore();
  const base = {
    kind: "route",
    canonicalAddress: "bobmesh~0123456789abcdef0123456789abcdef@quantic",
  };
  const oldRecord = { ...base, sequence: 2, digest: "1".repeat(64), value: { sequence: 2 } };
  const newest = { ...base, sequence: 3, digest: "2".repeat(64), value: { sequence: 3 } };

  assert.deepEqual(selectNewestValidRecord([oldRecord, newest]), newest);
  assert.deepEqual(selectNewestValidRecord([newest, { ...newest }]), newest);
  assert.throws(
    () => selectNewestValidRecord([newest, { ...newest, digest: "3".repeat(64) }]),
    /fork|conflit/i,
  );
});
