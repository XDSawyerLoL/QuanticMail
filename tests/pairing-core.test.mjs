import test from "node:test";
import assert from "node:assert/strict";
import {
  encryptPairingPackage,
  decryptPairingPackage,
  randomPairingSecret,
} from "../lib/quantic/pairing-crypto.mjs";
import {
  createPairingStore,
  createInvite,
  submitPairingRequest,
  attachPairingPackage,
  takePairingPackage,
  getPairingRequest,
} from "../lib/quantic/pairing-store.mjs";

const startedAt = Date.parse("2026-09-16T18:30:00.000Z");
const root = {
  canonicalAddress: "alice~0123456789abcdef0123456789abcdef@quantic",
  rootDeviceId: "d-0123456789",
};

test("pairing package encrypts and decrypts with HKDF/AES-GCM", async () => {
  const secret = randomPairingSecret();
  const payload = { certificate: { ok: true }, manifest: { sequence: 4 }, history: [{ id: "m1" }] };
  const encrypted = await encryptPairingPackage(secret, "invite-123", payload);
  assert.deepEqual(await decryptPairingPackage(secret, "invite-123", encrypted), payload);
});

test("tampered encrypted pairing package is rejected", async () => {
  const secret = randomPairingSecret();
  const encrypted = await encryptPairingPackage(secret, "invite-123", { ok: true });
  const tampered = { ...encrypted, ciphertext: encrypted.ciphertext.slice(0, -4) + "AAAA" };
  await assert.rejects(() => decryptPairingPackage(secret, "invite-123", tampered));
});

test("wrong pairing secret cannot decrypt package", async () => {
  const first = randomPairingSecret();
  const second = randomPairingSecret();
  const encrypted = await encryptPairingPackage(first, "invite-123", { ok: true });
  await assert.rejects(() => decryptPairingPackage(second, "invite-123", encrypted));
});

test("pairing invite expires after its deadline", () => {
  const store = createPairingStore();
  const invite = createInvite(store, root, "secret-value", startedAt, 10 * 60 * 1000);
  assert.throws(
    () => submitPairingRequest(store, invite.inviteId, "secret-value", { deviceId: "d-1111111111" }, startedAt + 10 * 60 * 1000),
    /expir/i,
  );
});

test("wrong pairing secret is rejected before request storage", () => {
  const store = createPairingStore();
  const invite = createInvite(store, root, "correct-secret", startedAt);
  assert.throws(
    () => submitPairingRequest(store, invite.inviteId, "wrong-secret", { deviceId: "d-1111111111" }, startedAt + 1000),
    /secret/i,
  );
  assert.equal(getPairingRequest(store, invite.inviteId, "correct-secret", startedAt + 1000), null);
});

test("approved pairing package can be picked up only once", () => {
  const store = createPairingStore();
  const invite = createInvite(store, root, "secret-value", startedAt);
  submitPairingRequest(store, invite.inviteId, "secret-value", { deviceId: "d-1111111111" }, startedAt + 1000);
  attachPairingPackage(store, invite.inviteId, "secret-value", { ciphertext: "abc", iv: "iv" }, startedAt + 2000);
  assert.deepEqual(takePairingPackage(store, invite.inviteId, "secret-value", startedAt + 3000), { ciphertext: "abc", iv: "iv" });
  assert.throws(
    () => takePairingPackage(store, invite.inviteId, "secret-value", startedAt + 4000),
    /introuvable|consomm/i,
  );
});
