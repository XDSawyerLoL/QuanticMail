import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  discoveryHandleKey,
  normalizeDiscoveryHandle,
} from "../lib/quantic/discovery-core.mjs";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { canonicalRouteManifestText } from "../lib/quantic/federation-core.mjs";
import { createDiscoveryService, type DiscoveryBundle } from "../standalone-relay/discovery-service.ts";
import type { DiscoveryPeer } from "../standalone-relay/discovery-state.ts";

function keys() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    publicKey: pair.publicKey.export({ format: "jwk" }),
    privateKey: pair.privateKey,
    publicKeyObject: pair.publicKey,
  };
}

function fingerprint(key: JsonWebKey, length = 32) {
  return createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, length);
}

function deviceId(key: JsonWebKey, length = 32) {
  return `d-${createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, length)}`;
}

function relayId(publicKeyObject: ReturnType<typeof generateKeyPairSync>["publicKey"]) {
  return createHash("sha256")
    .update(publicKeyObject.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function signedBundle(handle: string): DiscoveryBundle {
  const owner = keys();
  const encryption = keys();
  const relay = keys();
  const fp = fingerprint(owner.publicKey);
  const canonicalAddress = `${handle}~${fp}@quantic`;
  const identityPayload = {
    version: 1 as const,
    sequence: 3,
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
      kind: "root" as const,
      issuedAt: "2026-09-17T00:00:00.000Z",
    }],
    revocations: [],
    issuedAt: "2026-09-17T00:00:00.000Z",
  };
  const identityManifest = {
    format: "quantic-identity-manifest" as const,
    version: 1 as const,
    payload: identityPayload,
    signature: sign("sha256", Buffer.from(canonicalManifestText(identityPayload)), {
      key: owner.privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64"),
  };
  const routePayload = {
    version: 1 as const,
    sequence: 2,
    canonicalAddress,
    identitySigningPublicKey: owner.publicKey,
    identityManifestSequence: identityPayload.sequence,
    cryptoProfileSequence: null,
    cryptoProfileDigest: null,
    relays: [{
      relayId: relayId(relay.publicKeyObject),
      endpoint: "https://relay.handle.example",
      priority: 10,
      protocols: ["quantic-federation/1"],
      classicalSigningPublicKey: relay.publicKey,
      expiresAt: "2026-10-17T00:00:00.000Z",
    }],
    issuedAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-10-17T00:00:00.000Z",
  };
  const routeManifest = {
    format: "quantic-route-manifest" as const,
    version: 1 as const,
    payload: routePayload,
    signatures: {
      p256: sign("sha256", Buffer.from(canonicalRouteManifestText(routePayload)), {
        key: owner.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64"),
    },
  };
  return { identityManifest, routeManifest };
}

function peer(hex: string, endpoint: string): DiscoveryPeer {
  return {
    relayId: hex.repeat(64),
    endpoint,
    lastSeenAt: "2026-09-17T12:00:00.000Z",
    failures: 0,
    bucketIndex: 0,
  };
}

test("Discovery handle keys normalize short @quantic aliases and reject canonical locators", () => {
  assert.equal(normalizeDiscoveryHandle("  Benoit.V3@Quantic "), "benoit.v3");
  assert.match(discoveryHandleKey("benoit.v3@quantic"), /^[0-9a-f]{64}$/);
  assert.throws(
    () => discoveryHandleKey("benoit.v3~0123456789abcdef0123456789abcdef@quantic"),
    /handle|court/i,
  );
});

test("Discovery handle lookup follows peer hints after the first valid record to detect ambiguity", async () => {
  const first = signedBundle("benoit.v3");
  const second = signedBundle("benoit.v3");
  assert.notEqual(
    first.identityManifest.payload.canonicalAddress,
    second.identityManifest.payload.canonicalAddress,
  );

  const firstPeer = peer("1", "https://one.example");
  const secondPeer = peer("2", "https://two.example");
  const service = createDiscoveryService({
    localRelayId: "f".repeat(64),
    peers: () => [firstPeer],
    pinnedBundle: () => null,
    acceptLocal: (bundle) => bundle,
    transport: {
      publish: async () => undefined,
      find: async (target) => {
        if (target.relayId === firstPeer.relayId) {
          return { bundle: first, peers: [secondPeer] };
        }
        return { bundle: second, peers: [] };
      },
    },
  });

  const result = await service.lookupHandle("benoit.v3@quantic", {
    alpha: 1,
    paths: 1,
    maxQueries: 4,
  });
  assert.equal(result.status, "ambiguous");
  assert.deepEqual(
    [...(result.canonicalAddresses ?? [])].sort(),
    [
      first.identityManifest.payload.canonicalAddress,
      second.identityManifest.payload.canonicalAddress,
    ].sort(),
  );
});

test("Discovery handle lookup returns a unique cryptographically valid bundle", async () => {
  const bundle = signedBundle("unique.handle");
  const onlyPeer = peer("3", "https://only.example");
  const service = createDiscoveryService({
    localRelayId: "e".repeat(64),
    peers: () => [onlyPeer],
    pinnedBundle: () => null,
    acceptLocal: (candidate) => candidate,
    transport: {
      publish: async () => undefined,
      find: async () => ({ bundle, peers: [] }),
    },
  });

  const result = await service.lookupHandle("unique.handle@quantic");
  assert.equal(result.status, "unique");
  assert.equal(
    result.bundle?.identityManifest.payload.canonicalAddress,
    bundle.identityManifest.payload.canonicalAddress,
  );
});
