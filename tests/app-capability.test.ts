import assert from "node:assert/strict";
import test from "node:test";

import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import type { QuanticIdentityManifest } from "../lib/quantic/manifest-types.ts";
import type { LocalIdentity } from "../lib/quantic/local-db.ts";
import {
  createAppCapability,
  verifyAppCapability,
} from "../lib/quantic-core/app-capability.ts";

function toBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function signingKeys() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    publicKey: await crypto.subtle.exportKey("jwk", pair.publicKey),
    privateKey: await crypto.subtle.exportKey("jwk", pair.privateKey),
  };
}

async function encryptionKeys() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"],
  );
  return {
    publicKey: await crypto.subtle.exportKey("jwk", pair.publicKey),
    privateKey: await crypto.subtle.exportKey("jwk", pair.privateKey),
  };
}

async function digestPoint(key: JsonWebKey) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`P-256:${key.x}:${key.y}`),
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function signText(privateJwk: JsonWebKey, text: string) {
  const key = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(text),
  );
  return toBase64(new Uint8Array(signature));
}

async function identity(): Promise<{ local: LocalIdentity; manifest: QuanticIdentityManifest }> {
  const encryption = await encryptionKeys();
  const signing = await signingKeys();
  const fingerprint = (await digestPoint(signing.publicKey)).slice(0, 32);
  const deviceId = `d-${(await digestPoint(encryption.publicKey)).slice(0, 32)}`;
  const createdAt = "2026-09-17T12:00:00.000Z";
  const canonicalAddress = `sansa.core~${fingerprint}@quantic`;
  const payload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress,
    handle: "sansa.core",
    fingerprint,
    identityPublicKey: encryption.publicKey,
    identitySigningPublicKey: signing.publicKey,
    devices: [{
      deviceId,
      label: "Sansa root",
      publicKey: encryption.publicKey,
      deviceSigningPublicKey: signing.publicKey,
      kind: "root" as const,
      issuedAt: createdAt,
    }],
    revocations: [],
    issuedAt: createdAt,
  };
  const manifest: QuanticIdentityManifest = {
    format: "quantic-identity-manifest",
    version: 1,
    payload,
    signature: await signText(signing.privateKey, canonicalManifestText(payload)),
  };
  const local: LocalIdentity = {
    handle: "sansa.core",
    address: "sansa.core@quantic",
    canonicalAddress,
    fingerprint,
    publicKey: encryption.publicKey,
    privateKey: encryption.privateKey,
    signingPublicKey: signing.publicKey,
    signingPrivateKey: signing.privateKey,
    deviceSigningPublicKey: signing.publicKey,
    deviceSigningPrivateKey: signing.privateKey,
    deviceId,
    role: "root",
    authToken: "test-auth-token-that-never-leaves-this-unit-test",
    createdAt,
    manifest,
  };
  return { local, manifest };
}

test("Quantic Core app capability verifies a product-scoped app key without exporting the root private key", async () => {
  const { local, manifest } = await identity();
  const app = await signingKeys();
  const capability = await createAppCapability(
    local,
    "providence",
    app.publicKey,
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
  const app = await signingKeys();
  const attacker = await signingKeys();
  const capability = await createAppCapability(
    local,
    "mail",
    app.publicKey,
    ["identity:prove"],
    "2026-09-18T12:00:00.000Z",
    { now: "2026-09-17T12:30:00.000Z", nonce: "n-fedcba9876543210fedcba9876543210" },
  );
  capability.payload.appSigningPublicKey = attacker.publicKey;
  assert.equal(await verifyAppCapability(capability, manifest, Date.parse("2026-09-17T13:00:00.000Z")), false);
});

test("Quantic Core app capability rejects expiry and a different canonical identity", async () => {
  const first = await identity();
  const second = await identity();
  const app = await signingKeys();
  const capability = await createAppCapability(
    first.local,
    "glide",
    app.publicKey,
    ["identity:prove"],
    "2026-09-17T13:00:00.000Z",
    { now: "2026-09-17T12:30:00.000Z", nonce: "n-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
  );

  assert.equal(await verifyAppCapability(capability, first.manifest, Date.parse("2026-09-17T13:00:01.000Z")), false);
  assert.equal(await verifyAppCapability(capability, second.manifest, Date.parse("2026-09-17T12:45:00.000Z")), false);
});
