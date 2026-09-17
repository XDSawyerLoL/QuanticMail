import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import {
  createEmptyRelayState,
  exportRelayState,
  restoreRelayState,
} from "../lib/quantic/relay-state.ts";
import {
  getStandaloneManifest,
  getStandaloneManifestStore,
  getStandalonePreKeyStore,
} from "../lib/quantic/standalone-v11-state.ts";

const NOW = Date.parse("2026-09-16T20:30:00.000Z");

function digest(key: JsonWebKey) {
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex");
}

function signedManifest() {
  const owner = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const identityEncryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const deviceEncryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const deviceSigning = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const ownerPublic = owner.publicKey.export({ format: "jwk" });
  const identityPublic = identityEncryption.publicKey.export({ format: "jwk" });
  const devicePublic = deviceEncryption.publicKey.export({ format: "jwk" });
  const deviceSigningPublic = deviceSigning.publicKey.export({ format: "jwk" });
  const fp = digest(ownerPublic).slice(0, 32);
  const canonicalAddress = `alice~${fp}@quantic`;
  const payload = {
    version: 1 as const,
    sequence: 3,
    canonicalAddress,
    handle: "alice",
    fingerprint: fp,
    identityPublicKey: identityPublic,
    identitySigningPublicKey: ownerPublic,
    devices: [{
      deviceId: `d-${digest(devicePublic).slice(0, 32)}`,
      label: "PC principal",
      publicKey: devicePublic,
      deviceSigningPublicKey: deviceSigningPublic,
      kind: "root" as const,
      issuedAt: "2026-09-16T20:00:00.000Z",
    }],
    revocations: [],
    issuedAt: "2026-09-16T20:00:00.000Z",
  };
  const signature = sign(
    "sha256",
    Buffer.from(canonicalManifestText(payload), "utf8"),
    { key: owner.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  return {
    manifest: {
      format: "quantic-identity-manifest" as const,
      version: 1 as const,
      payload,
      signature,
    },
    deviceId: payload.devices[0].deviceId,
    deviceSigningPublic,
  };
}

test("manifest, available prekeys, and consumed tombstones survive V2 restore", () => {
  restoreRelayState(createEmptyRelayState(), NOW);
  const { manifest, deviceId } = signedManifest();
  getStandaloneManifestStore().set(manifest.payload.canonicalAddress, manifest);
  const preKey = {
    version: 1 as const,
    canonicalAddress: manifest.payload.canonicalAddress,
    deviceId,
    preKeyId: "a".repeat(32),
    publicKey: { kty: "EC", crv: "P-256", x: "prekey-x", y: "prekey-y" },
    createdAt: "2026-09-16T20:20:00.000Z",
    expiresAt: "2026-09-17T20:20:00.000Z",
    signature: "s".repeat(64),
  };
  const poolKey = `${manifest.payload.canonicalAddress}#${deviceId}`;
  getStandalonePreKeyStore().pools.set(poolKey, [preKey]);
  getStandalonePreKeyStore().consumed.set("b".repeat(32), NOW + 60_000);

  const snapshot = exportRelayState(new Date(NOW).toISOString());
  restoreRelayState(createEmptyRelayState(), NOW);
  restoreRelayState(JSON.parse(JSON.stringify(snapshot)), NOW);

  assert.equal(getStandaloneManifest(manifest.payload.canonicalAddress)?.payload.sequence, 3);
  assert.equal(getStandalonePreKeyStore().pools.get(poolKey)?.[0].preKeyId, preKey.preKeyId);
  assert.equal(getStandalonePreKeyStore().consumed.get("b".repeat(32)), NOW + 60_000);
});

test("restore prunes expired prekeys and tombstones", () => {
  const { manifest, deviceId } = signedManifest();
  const poolKey = `${manifest.payload.canonicalAddress}#${deviceId}`;
  const snapshot = createEmptyRelayState(new Date(NOW).toISOString());
  snapshot.manifests = [[manifest.payload.canonicalAddress, manifest]];
  snapshot.preKeyPools = [[poolKey, [{
    version: 1,
    canonicalAddress: manifest.payload.canonicalAddress,
    deviceId,
    preKeyId: "c".repeat(32),
    publicKey: { kty: "EC", crv: "P-256", x: "expired-x", y: "expired-y" },
    createdAt: "2026-09-15T20:00:00.000Z",
    expiresAt: "2026-09-16T20:00:00.000Z",
    signature: "s".repeat(64),
  }]]];
  snapshot.consumedPreKeys = [["d".repeat(32), NOW - 1]];

  restoreRelayState(snapshot, NOW);

  assert.equal(getStandalonePreKeyStore().pools.size, 0);
  assert.equal(getStandalonePreKeyStore().consumed.size, 0);
});

test("invalid persisted manifest is rejected without replacing current V1.1 state", () => {
  restoreRelayState(createEmptyRelayState(), NOW);
  const { manifest } = signedManifest();
  getStandaloneManifestStore().set(manifest.payload.canonicalAddress, manifest);
  const before = exportRelayState(new Date(NOW).toISOString());
  const invalid = JSON.parse(JSON.stringify(before));
  invalid.manifests[0][1].payload.sequence += 1;

  assert.throws(() => restoreRelayState(invalid, NOW), /signature|manifeste/i);
  assert.deepEqual(exportRelayState(new Date(NOW).toISOString()), before);
});
