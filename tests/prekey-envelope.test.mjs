import test from "node:test";
import assert from "node:assert/strict";
import {
  encryptForRecipientCore,
  decryptEnvelopeCore,
} from "../lib/quantic/envelope-crypto.mjs";
import { selectEnvelopePrivateKey } from "../lib/quantic/envelope-core.mjs";

async function ecdhPair() {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"],
  );
  return {
    publicKey: await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey),
    privateKey: await globalThis.crypto.subtle.exportKey("jwk", pair.privateKey),
  };
}

test("one-time prekey envelope decrypts with the claimed prekey", async () => {
  const staticPair = await ecdhPair();
  const prekeyPair = await ecdhPair();
  const preKeyId = "a".repeat(32);
  const encrypted = await encryptForRecipientCore(prekeyPair.publicKey, { body: "secret" });
  const envelope = { ...encrypted, keyMode: "one-time-prekey", preKeyId };
  const selected = selectEnvelopePrivateKey(envelope, staticPair.privateKey, {
    preKeyId,
    privateKey: prekeyPair.privateKey,
    state: "unused",
  });
  assert.equal(selected.consumePreKeyId, preKeyId);
  assert.deepEqual(await decryptEnvelopeCore(selected.privateKey, envelope), { body: "secret" });
});

test("a consumed prekey cannot be selected again", async () => {
  const staticPair = await ecdhPair();
  const prekeyPair = await ecdhPair();
  const preKeyId = "b".repeat(32);
  const encrypted = await encryptForRecipientCore(prekeyPair.publicKey, { body: "once" });
  const envelope = { ...encrypted, keyMode: "one-time-prekey", preKeyId };
  assert.throws(
    () => selectEnvelopePrivateKey(envelope, staticPair.privateKey, null),
    /prekey.*introuvable|prekey.*consomm/i,
  );
});

test("static fallback still decrypts with the device static key", async () => {
  const staticPair = await ecdhPair();
  const encrypted = await encryptForRecipientCore(staticPair.publicKey, { body: "fallback" });
  const envelope = { ...encrypted, keyMode: "static-fallback" };
  const selected = selectEnvelopePrivateKey(envelope, staticPair.privateKey, null);
  assert.equal(selected.consumePreKeyId, null);
  assert.deepEqual(await decryptEnvelopeCore(selected.privateKey, envelope), { body: "fallback" });
});
