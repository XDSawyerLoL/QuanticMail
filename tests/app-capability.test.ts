import assert from "node:assert/strict";
import test from "node:test";

import {
  fingerprintPublicKeyStrong,
  generateIdentityKeys,
  generateSigningKeys,
  randomToken,
} from "../lib/quantic/crypto.ts";
import { createInitialManifest } from "../lib/quantic/manifest.ts";
import type { LocalIdentity } from "../lib/quantic/local-db.ts";
import {
  createAppCapability,
  verifyAppCapability,
} from "../lib/quantic-core/app-capability.ts";

async function identity(): Promise<{ local: LocalIdentity; manifest: Awaited<ReturnType<typeof createInitialManifest>> }> {
  const encryption = await generateIdentityKeys();
  const signing = await generateSigningKeys();
  const fingerprint = await fingerprintPublicKeyStrong(signing.signingPublicKey);
  const createdAt = "2026-09-17T12:00:00.000Z";
  const local: LocalIdentity = {
    handle: "sansa.core",
    address: "sansa.core@quantic",
    canonicalAddress: `sansa.core~${fingerprint}@quantic`,
    fingerprint,
    publicKey: encryption.publicKey,
    privateKey: encryption.privateKey,
    signingPublicKey: signing.signingPublicKey,
    signingPrivateKey: signing.signingPrivateKey,
    deviceSigningPublicKey: signing.signingPublicKey,
    deviceSigningPrivateKey: signing.signingPrivateKey,
    role: "root",
    authToken: randomToken(),
    createdAt,
  };
  return { local, manifest: await createInitialManifest(local) };
}

test("Quantic Core app capability verifies a product-scoped app key without exporting the root private key", async () => {
  const { local, manifest } = await identity();
  const app = await generateSigningKeys();
  const capability = await createAppCapability(
    local,
    "providence",
    app.signingPublicKey,
    ["identity:prove", "profile:read"],
    "2026-09-18T12:00:00.000Z",
    { now: "2026-09-17T12:30:00.000Z", nonce: "n-0123456789abcdef0123456789abcdef" },
  );

  assert.equal(await verifyAppCapability(capability, manifest, Date.parse("2026-09-17T13:00:00.000Z")), true);
  assert.equal("privateKey" in capability.payload, false);
  assert.equal("identityPrivateKey" in capability.payload, false);
});

test("Quantic Core app capability rejects a tampered application key", async () => {
  const { local, manifest } = await identity();
  const app = await generateSigningKeys();
  const attacker = await generateSigningKeys();
  const capability = await createAppCapability(
    local,
    "mail",
    app.signingPublicKey,
    ["identity:prove"],
    "2026-09-18T12:00:00.000Z",
    { now: "2026-09-17T12:30:00.000Z", nonce: "n-fedcba9876543210fedcba9876543210" },
  );
  capability.payload.appSigningPublicKey = attacker.signingPublicKey;
  assert.equal(await verifyAppCapability(capability, manifest, Date.parse("2026-09-17T13:00:00.000Z")), false);
});

test("Quantic Core app capability rejects expiry and a different canonical identity", async () => {
  const first = await identity();
  const second = await identity();
  const app = await generateSigningKeys();
  const capability = await createAppCapability(
    first.local,
    "glide",
    app.signingPublicKey,
    ["identity:prove"],
    "2026-09-17T13:00:00.000Z",
    { now: "2026-09-17T12:30:00.000Z", nonce: "n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
  );

  assert.equal(await verifyAppCapability(capability, first.manifest, Date.parse("2026-09-17T13:00:01.000Z")), false);
  assert.equal(await verifyAppCapability(capability, second.manifest, Date.parse("2026-09-17T12:45:00.000Z")), false);
});
