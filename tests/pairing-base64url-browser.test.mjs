import { test } from "node:test";
import assert from "node:assert/strict";
import { randomPairingSecret, encryptPairingPackage, decryptPairingPackage } from "../lib/quantic/pairing-crypto.mjs";

test("pairing QR crypto roundtrip with native Web APIs", async () => {
  const secret = randomPairingSecret();
  assert.match(secret, /^[A-Za-z0-9_-]{43}$/);
  const payload = { address: "example@quantic", accented: "éà", ready: true };
  const encrypted = await encryptPairingPackage(secret, "invite-test-123", payload);
  assert.match(encrypted.iv, /^[A-Za-z0-9_-]+$/);
  assert.match(encrypted.ciphertext, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(await decryptPairingPackage(secret, "invite-test-123", encrypted), payload);
});

test("pairing supports Buffer polyfills that reject base64url encoding", async () => {
  const originalBuffer = globalThis.Buffer;
  try {
    globalThis.Buffer = {
      from() { throw new Error("Unknown encoding: base64url"); },
    };
    const secret = randomPairingSecret();
    const payload = { message: "Appareil lié" };
    const encrypted = await encryptPairingPackage(secret, "invite-test-456", payload);
    assert.deepEqual(await decryptPairingPackage(secret, "invite-test-456", encrypted), payload);
  } finally {
    globalThis.Buffer = originalBuffer;
  }
});

test("pairing rejects invalid Base64URL secrets", async () => {
  await assert.rejects(() => encryptPairingPackage("wrong+chars", "invite-test-789", {}), /Base64URL invalide/);
});
