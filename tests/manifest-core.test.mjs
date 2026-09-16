import test from "node:test";
import assert from "node:assert/strict";
import {
  activeDevices,
  canonicalManifestText,
  mergeManifestState,
  validateManifestShape,
} from "../lib/quantic/manifest-core.mjs";

const ROOT = "d-1111111111";
const ROOT2 = "d-2222222222";
const LINKED_A = "d-aaaaaaaaaa";
const LINKED_B = "d-bbbbbbbbbb";
const OLD_A = "d-0a0a0a0a0a";
const OLD_Z = "d-0f0f0f0f0f";

const identitySigningPublicKey = {
  kty: "EC",
  crv: "P-256",
  x: "root-x",
  y: "root-y",
};

const identityPublicKey = {
  kty: "EC",
  crv: "P-256",
  x: "identity-x",
  y: "identity-y",
};

function device(deviceId, kind = "linked") {
  return {
    deviceId,
    label: kind === "root" ? "PC principal" : `Device ${deviceId}`,
    publicKey: { kty: "EC", crv: "P-256", x: `${deviceId}-x`, y: `${deviceId}-y` },
    deviceSigningPublicKey: {
      kty: "EC",
      crv: "P-256",
      x: `${deviceId}-sign-x`,
      y: `${deviceId}-sign-y`,
    },
    kind,
    issuedAt: "2026-09-16T15:00:00.000Z",
  };
}

function manifest({ sequence = 1, devices = [device(ROOT, "root")], revocations = [] } = {}) {
  return {
    format: "quantic-identity-manifest",
    version: 1,
    payload: {
      version: 1,
      sequence,
      canonicalAddress: "sansa~1234567890@quantic",
      handle: "sansa",
      fingerprint: "1234567890",
      identityPublicKey,
      identitySigningPublicKey,
      devices,
      revocations,
      issuedAt: "2026-09-16T15:00:00.000Z",
    },
    signature: "signed-placeholder",
  };
}

test("canonical manifest text is deterministic across device and revocation ordering", () => {
  const left = manifest({
    sequence: 4,
    devices: [device(LINKED_B), device(ROOT, "root"), device(LINKED_A)],
    revocations: [
      { deviceId: OLD_Z, revokedAt: "2026-09-16T14:00:00.000Z", reason: "lost" },
      { deviceId: OLD_A, revokedAt: "2026-09-16T13:00:00.000Z", reason: "replaced" },
    ],
  });
  const right = manifest({
    sequence: 4,
    devices: [device(LINKED_A), device(LINKED_B), device(ROOT, "root")],
    revocations: [
      { deviceId: OLD_A, revokedAt: "2026-09-16T13:00:00.000Z", reason: "replaced" },
      { deviceId: OLD_Z, revokedAt: "2026-09-16T14:00:00.000Z", reason: "lost" },
    ],
  });

  assert.equal(canonicalManifestText(left.payload), canonicalManifestText(right.payload));
});

test("manifest requires exactly one root device", () => {
  assert.throws(
    () => validateManifestShape(manifest({ devices: [device(LINKED_A)] })),
    /exactement un appareil maître/i,
  );
  assert.throws(
    () => validateManifestShape(manifest({ devices: [device(ROOT, "root"), device(ROOT2, "root")] })),
    /exactement un appareil maître/i,
  );
  assert.doesNotThrow(() => validateManifestShape(manifest()));
});

test("revoked devices are never active", () => {
  const candidate = manifest({
    sequence: 2,
    devices: [device(ROOT, "root"), device(LINKED_A), device(LINKED_B)],
    revocations: [
      { deviceId: LINKED_B, revokedAt: "2026-09-16T15:10:00.000Z", reason: "lost" },
    ],
  });

  assert.deepEqual(activeDevices(candidate).map((item) => item.deviceId), [ROOT, LINKED_A].sort());
});

test("manifest rejects a device present in both active devices and revocations", () => {
  const candidate = manifest({
    sequence: 2,
    devices: [device(ROOT, "root"), device(LINKED_B)],
    revocations: [
      { deviceId: LINKED_B, revokedAt: "2026-09-16T15:10:00.000Z", reason: "compromised" },
    ],
  });

  assert.throws(() => validateManifestShape(candidate), /révoqué.*actif/i);
});

test("manifest state rejects sequence rollback", () => {
  const current = manifest({
    sequence: 3,
    devices: [device(ROOT, "root")],
    revocations: [
      { deviceId: LINKED_B, revokedAt: "2026-09-16T15:10:00.000Z", reason: "lost" },
    ],
  });
  const stale = manifest({
    sequence: 2,
    devices: [device(ROOT, "root"), device(LINKED_B)],
  });

  assert.throws(() => mergeManifestState(current, stale), /rollback/i);
});

test("same sequence is idempotent only when manifest content is identical", () => {
  const current = manifest({ sequence: 5, devices: [device(ROOT, "root"), device(LINKED_A)] });
  const identical = manifest({ sequence: 5, devices: [device(LINKED_A), device(ROOT, "root")] });
  const conflicting = manifest({ sequence: 5, devices: [device(ROOT, "root"), device(LINKED_B)] });

  assert.equal(mergeManifestState(current, identical), current);
  assert.throws(() => mergeManifestState(current, conflicting), /conflit.*séquence/i);
});

test("a later manifest cannot reactivate a previously revoked device", () => {
  const current = manifest({
    sequence: 6,
    devices: [device(ROOT, "root")],
    revocations: [
      { deviceId: LINKED_B, revokedAt: "2026-09-16T15:10:00.000Z", reason: "compromised" },
    ],
  });
  const reactivated = manifest({
    sequence: 7,
    devices: [device(ROOT, "root"), device(LINKED_B)],
    revocations: [],
  });

  assert.throws(() => mergeManifestState(current, reactivated), /réactiv|révoqué/i);
});

test("a later manifest must preserve the complete revocation history", () => {
  const current = manifest({
    sequence: 8,
    devices: [device(ROOT, "root"), device(LINKED_A)],
    revocations: [
      { deviceId: LINKED_B, revokedAt: "2026-09-16T15:10:00.000Z", reason: "lost" },
    ],
  });
  const forgotRevocation = manifest({
    sequence: 9,
    devices: [device(ROOT, "root"), device(LINKED_A)],
    revocations: [],
  });

  assert.throws(() => mergeManifestState(current, forgotRevocation), /révocation.*historique|historique.*révocation/i);
});
