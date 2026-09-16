import test from "node:test";
import assert from "node:assert/strict";

import {
  canonicalPortableEnvelopeText,
  canonicalRouteManifestText,
  envelopeDigest,
  validatePortableEnvelopeShape,
  validateRouteManifestShape,
} from "../lib/quantic/federation-core.mjs";

const ALICE = "alice~0123456789abcdef0123456789abcdef@quantic";
const BOB = "bob~abcdef0123456789abcdef0123456789@quantic";

function p256(x, y) {
  return { kty: "EC", crv: "P-256", x, y };
}

function envelope(overrides = {}) {
  return {
    format: "quantic-envelope",
    version: 2,
    clientMessageId: "msg-federation-0001",
    from: ALICE,
    fromDeviceId: "d-0123456789",
    to: BOB,
    toDeviceId: "d-abcdef0123",
    keyMode: "v1-static-fallback",
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: p256("eX", "eY"),
    iv: "aXY=",
    ciphertext: "Y2lwaGVy",
    createdAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-09-18T00:00:00.000Z",
    signatures: { p256Device: "sig-one" },
    ...overrides,
  };
}

function routePayload(overrides = {}) {
  return {
    version: 1,
    sequence: 1,
    canonicalAddress: BOB,
    identitySigningPublicKey: p256("iX", "iY"),
    identityManifestSequence: 2,
    cryptoProfileSequence: null,
    cryptoProfileDigest: null,
    relays: [
      {
        relayId: "b".repeat(64),
        endpoint: "https://b.example",
        priority: 20,
        protocols: ["quantic-federation/1"],
        classicalSigningPublicKey: p256("bX", "bY"),
        expiresAt: "2026-10-01T00:00:00.000Z",
      },
      {
        relayId: "a".repeat(64),
        endpoint: "https://a.example",
        priority: 10,
        protocols: ["quantic-federation/1"],
        classicalSigningPublicKey: p256("aX", "aY"),
        expiresAt: "2026-10-01T00:00:00.000Z",
      },
    ],
    issuedAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-10-01T00:00:00.000Z",
    ...overrides,
  };
}

test("portable envelope canonicalization ignores signature values and is deterministic", async () => {
  const first = envelope();
  const second = envelope({ signatures: { p256Device: "sig-two" } });

  assert.equal(canonicalPortableEnvelopeText(first), canonicalPortableEnvelopeText(second));
  assert.equal(await envelopeDigest(first), await envelopeDigest(second));
});

test("portable envelope canonicalization changes when protected routing data changes", async () => {
  const first = envelope();
  const second = envelope({ toDeviceId: "d-1111111111" });

  assert.notEqual(canonicalPortableEnvelopeText(first), canonicalPortableEnvelopeText(second));
  assert.notEqual(await envelopeDigest(first), await envelopeDigest(second));
});

test("route manifest canonicalization sorts relays by priority, relayId and endpoint", () => {
  const text = canonicalRouteManifestText(routePayload());
  assert.ok(text.indexOf("https://a.example") < text.indexOf("https://b.example"));
});

test("shape validators accept valid federation objects", () => {
  assert.equal(validatePortableEnvelopeShape(envelope()).format, "quantic-envelope");
  assert.equal(validateRouteManifestShape({
    format: "quantic-route-manifest",
    version: 1,
    payload: routePayload(),
    signatures: { p256: "signature" },
  }).format, "quantic-route-manifest");
});

test("shape validators reject malformed federation objects", () => {
  assert.throws(() => validatePortableEnvelopeShape({}), /enveloppe/i);
  assert.throws(() => validateRouteManifestShape({}), /route/i);
  assert.throws(() => validatePortableEnvelopeShape(envelope({ expiresAt: "not-a-date" })), /expiration/i);
  assert.throws(() => validateRouteManifestShape({
    format: "quantic-route-manifest",
    version: 1,
    payload: routePayload({ sequence: 0 }),
    signatures: { p256: "signature" },
  }), /séquence/i);
});
