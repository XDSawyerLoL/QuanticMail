import test from "node:test";
import assert from "node:assert/strict";
import { validateManifestShape } from "../lib/quantic/manifest-core.mjs";

const signingKey = {
  kty: "EC",
  crv: "P-256",
  x: "v11-signing-x",
  y: "v11-signing-y",
};

const encryptionKey = {
  kty: "EC",
  crv: "P-256",
  x: "v11-encryption-x",
  y: "v11-encryption-y",
};

function strongManifest() {
  const fingerprint = "0123456789abcdef0123456789abcdef";
  return {
    format: "quantic-identity-manifest",
    version: 1,
    payload: {
      version: 1,
      sequence: 1,
      canonicalAddress: `alice~${fingerprint}@quantic`,
      handle: "alice",
      fingerprint,
      identityPublicKey: encryptionKey,
      identitySigningPublicKey: signingKey,
      devices: [{
        deviceId: "d-1111111111",
        label: "PC principal",
        publicKey: encryptionKey,
        deviceSigningPublicKey: signingKey,
        kind: "root",
        issuedAt: "2026-09-16T17:00:00.000Z",
      }],
      revocations: [],
      issuedAt: "2026-09-16T17:00:00.000Z",
    },
    signature: "signed-placeholder",
  };
}

test("V1.1 manifest accepts a 128-bit canonical fingerprint", () => {
  assert.doesNotThrow(() => validateManifestShape(strongManifest()));
});

test("legacy 40-bit canonical fingerprints remain valid", () => {
  const candidate = strongManifest();
  candidate.payload.fingerprint = "0123456789";
  candidate.payload.canonicalAddress = "alice~0123456789@quantic";
  assert.doesNotThrow(() => validateManifestShape(candidate));
});

test("strong fingerprint helper returns 32 deterministic lowercase hex characters", async () => {
  let helper;
  await assert.doesNotReject(async () => {
    const fingerprintModule = await import("../lib/quantic/identity-fingerprint.mjs");
    helper = fingerprintModule.fingerprintPublicKeyStrong;
  });
  assert.equal(typeof helper, "function");
  const first = await helper(signingKey);
  const second = await helper(signingKey);
  assert.equal(first, second);
  assert.match(first, /^[0-9a-f]{32}$/);
});
