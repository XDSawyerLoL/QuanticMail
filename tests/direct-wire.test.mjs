import assert from "node:assert/strict";
import test from "node:test";

import {
  createDirectEnvelopeFrame,
  createDirectReceiptFrame,
  parseDirectFrame,
} from "../lib/quantic-network/direct-wire.mjs";

const publicKey = { kty: "EC", crv: "P-256", x: "x", y: "y" };

const encryptedEnvelope = {
  id: "dmsg-01234567-89ab-cdef-0123-456789abcdef",
  clientMessageId: "client-message-0001",
  from: "alice~0123456789abcdef0123456789abcdef@quantic",
  fromDeviceId: "d-0123456789abcdef0123456789abcdef",
  to: "bob~abcdef0123456789abcdef0123456789@quantic",
  toDeviceId: "d-abcdef0123456789abcdef0123456789",
  ciphertext: "ciphertext-only",
  iv: "iv-only",
  ephemeralPublicKey: publicKey,
  createdAt: "2026-09-17T12:00:00.000Z",
  cryptoProfileSequence: 3,
  pqc: { algorithm: "ML-KEM-768", encapsulation: "opaque-pq-ciphertext" },
};

test("direct envelope frame preserves encrypted and post-quantum transport metadata unchanged", () => {
  const frame = createDirectEnvelopeFrame(encryptedEnvelope);
  const parsed = parseDirectFrame(JSON.stringify(frame));
  assert.equal(parsed.type, "envelope");
  assert.deepEqual(parsed.payload, encryptedEnvelope);
  assert.equal(JSON.stringify(parsed).includes("ML-KEM-768"), true);
});

test("direct wire rejects plaintext-like message fields and private key material", () => {
  assert.throws(
    () => createDirectEnvelopeFrame({ ...encryptedEnvelope, subject: "secret subject" }),
    /plaintext|interdit|clair/i,
  );
  assert.throws(
    () => createDirectEnvelopeFrame({ ...encryptedEnvelope, privateKey: { d: "secret" } }),
    /priv|interdit|secret/i,
  );
});

test("direct receipt frame retains normal Quantic delivery receipt semantics", () => {
  const receipt = {
    id: "dreceipt-01234567-89ab-cdef-0123-456789abcdef",
    clientMessageId: encryptedEnvelope.clientMessageId,
    from: encryptedEnvelope.to,
    fromDeviceId: encryptedEnvelope.toDeviceId,
    to: encryptedEnvelope.from,
    toDeviceId: encryptedEnvelope.fromDeviceId,
    deliveredAt: "2026-09-17T12:00:02.000Z",
  };
  const parsed = parseDirectFrame(JSON.stringify(createDirectReceiptFrame(receipt)));
  assert.equal(parsed.type, "receipt");
  assert.deepEqual(parsed.payload, receipt);
});
