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
const VALID_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const WRONG_SECRET = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

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

test("pairing store rejects secrets weaker than 256 bits", () => {
  const store = createPairingStore();
  assert.throws(
    () => createInvite(store, root, "AAAAAAAAAAAAAAAA", startedAt),
    /secret/i,
  );
});

test("pairing invite expires after its deadline", () => {
  const store = createPairingStore();
  const invite = createInvite(store, root, VALID_SECRET, startedAt, 10 * 60 * 1000);
  assert.throws(
    () => submitPairingRequest(store, invite.inviteId, VALID_SECRET, { deviceId: "d-1111111111" }, startedAt + 10 * 60 * 1000),
    /expir/i,
  );
});

test("wrong pairing secret is rejected before request storage", () => {
  const store = createPairingStore();
  const invite = createInvite(store, root, VALID_SECRET, startedAt);
  assert.throws(
    () => submitPairingRequest(store, invite.inviteId, WRONG_SECRET, { deviceId: "d-1111111111" }, startedAt + 1000),
    /secret/i,
  );
  assert.equal(getPairingRequest(store, invite.inviteId, VALID_SECRET, startedAt + 1000), null);
});

test("approved pairing package can be picked up only once", () => {
  const store = createPairingStore();
  const invite = createInvite(store, root, VALID_SECRET, startedAt);
  submitPairingRequest(store, invite.inviteId, VALID_SECRET, { deviceId: "d-1111111111" }, startedAt + 1000);
  attachPairingPackage(store, invite.inviteId, VALID_SECRET, { ciphertext: "abc", iv: "iv" }, startedAt + 2000);
  assert.deepEqual(takePairingPackage(store, invite.inviteId, VALID_SECRET, startedAt + 3000), { ciphertext: "abc", iv: "iv" });
  assert.throws(
    () => takePairingPackage(store, invite.inviteId, VALID_SECRET, startedAt + 4000),
    /introuvable|consomm/i,
  );
});
