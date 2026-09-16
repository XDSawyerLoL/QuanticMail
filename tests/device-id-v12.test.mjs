import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  deviceIdForPublicKey,
  isValidDeviceId,
  assertDeviceIdMatchesKey,
} from "../lib/quantic/device-id-core.mjs";
import { validateManifestShape } from "../lib/quantic/manifest-core.mjs";

const key = {
  kty: "EC",
  crv: "P-256",
  x: "v12-device-x",
  y: "v12-device-y",
};

function expectedHex() {
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex");
}

function manifest(deviceId) {
  return {
    format: "quantic-identity-manifest",
    version: 1,
    payload: {
      version: 1,
      sequence: 1,
      canonicalAddress: "sansa~12345678901234567890123456789012@quantic",
      handle: "sansa",
      fingerprint: "12345678901234567890123456789012",
      identityPublicKey: { kty: "EC", crv: "P-256", x: "identity-x", y: "identity-y" },
      identitySigningPublicKey: { kty: "EC", crv: "P-256", x: "sign-x", y: "sign-y" },
      devices: [{
        deviceId,
        label: "PC principal",
        publicKey: key,
        deviceSigningPublicKey: { kty: "EC", crv: "P-256", x: "device-sign-x", y: "device-sign-y" },
        kind: "root",
        issuedAt: "2026-09-16T20:00:00.000Z",
      }],
      revocations: [],
      issuedAt: "2026-09-16T20:00:00.000Z",
    },
    signature: "signed-placeholder",
  };
}

test("strong device id is deterministic d- plus 32 lowercase hex", () => {
  const expected = `d-${expectedHex().slice(0, 32)}`;
  assert.equal(deviceIdForPublicKey(key), expected);
  assert.match(deviceIdForPublicKey(key), /^d-[0-9a-f]{32}$/);
});

test("legacy device id remains the historical 10-hex prefix", () => {
  const expected = `d-${expectedHex().slice(0, 10)}`;
  assert.equal(deviceIdForPublicKey(key, 10), expected);
  assert.equal(isValidDeviceId(expected), true);
});

test("device id validator accepts legacy and strong forms only", () => {
  assert.equal(isValidDeviceId(`d-${expectedHex().slice(0, 10)}`), true);
  assert.equal(isValidDeviceId(`d-${expectedHex().slice(0, 32)}`), true);
  assert.equal(isValidDeviceId("d-1234"), false);
  assert.equal(isValidDeviceId(`d-${"a".repeat(31)}`), false);
  assert.equal(isValidDeviceId(`d-${"a".repeat(33)}`), false);
});

test("device id must match the corresponding public-key digest prefix", () => {
  assert.doesNotThrow(() => assertDeviceIdMatchesKey(`d-${expectedHex().slice(0, 10)}`, key));
  assert.doesNotThrow(() => assertDeviceIdMatchesKey(`d-${expectedHex().slice(0, 32)}`, key));
  assert.throws(() => assertDeviceIdMatchesKey(`d-${"f".repeat(10)}`, key), /correspond/i);
  assert.throws(() => assertDeviceIdMatchesKey(`d-${"f".repeat(32)}`, key), /correspond/i);
});

test("manifest shape accepts legacy and strong device ids", () => {
  assert.doesNotThrow(() => validateManifestShape(manifest(`d-${expectedHex().slice(0, 10)}`)));
  assert.doesNotThrow(() => validateManifestShape(manifest(`d-${expectedHex().slice(0, 32)}`)));
});
