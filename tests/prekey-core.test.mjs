import test from "node:test";
import assert from "node:assert/strict";
import {
  canonicalPreKeyText,
  isPreKeyExpired,
  verifyPreKeySignature,
} from "../lib/quantic/prekey-core.mjs";

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

async function signingPair() {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}

async function ecdhPublicJwk() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"],
  );
  return crypto.subtle.exportKey("jwk", pair.publicKey);
}

async function signedRecord({ expiresAt = "2026-09-23T17:30:00.000Z" } = {}) {
  const pair = await signingPair();
  const publicSigningKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const record = {
    version: 1,
    canonicalAddress: "alice~0123456789abcdef0123456789abcdef@quantic",
    deviceId: "d-0123456789",
    preKeyId: "0123456789abcdef0123456789abcdef",
    publicKey: await ecdhPublicJwk(),
    createdAt: "2026-09-16T17:30:00.000Z",
    expiresAt,
    signature: "",
  };
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    pair.privateKey,
    new TextEncoder().encode(canonicalPreKeyText(record)),
  );
  record.signature = toBase64(new Uint8Array(signature));
  return { record, publicSigningKey };
}

test("signed one-time prekey verifies against its device signing key", async () => {
  const { record, publicSigningKey } = await signedRecord();
  assert.equal(await verifyPreKeySignature(record, publicSigningKey), true);
});

test("tampering with a signed prekey invalidates the signature", async () => {
  const { record, publicSigningKey } = await signedRecord();
  const tampered = { ...record, preKeyId: "ffffffffffffffffffffffffffffffff" };
  assert.equal(await verifyPreKeySignature(tampered, publicSigningKey), false);
});

test("canonical prekey text is deterministic", async () => {
  const { record } = await signedRecord();
  assert.equal(canonicalPreKeyText({ ...record }), canonicalPreKeyText(record));
});

test("prekey expiry uses an explicit comparison time", async () => {
  const { record } = await signedRecord({ expiresAt: "2026-09-20T00:00:00.000Z" });
  assert.equal(isPreKeyExpired(record, Date.parse("2026-09-19T23:59:59.000Z")), false);
  assert.equal(isPreKeyExpired(record, Date.parse("2026-09-20T00:00:00.000Z")), true);
});

test("invalid prekey identifiers are rejected", async () => {
  const { record } = await signedRecord();
  assert.throws(
    () => canonicalPreKeyText({ ...record, preKeyId: "too-short" }),
    /prekey/i,
  );
});
