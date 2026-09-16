import test from "node:test";
import assert from "node:assert/strict";
import {
  activeDevices,
  canonicalManifestText,
  mergeManifestState,
  validateManifestShape,
} from "../lib/quantic/manifest-core.mjs";

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
    label: deviceId === "root-1" ? "PC principal" : `Device ${deviceId}`,
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

function manifest({ sequence = 1, devices = [device("root-1", "root")], revocations = [] } = {}) {
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
    devices: [device("linked-b"), device("root-1", "root"), device("linked-a")],
    revocations: [
      { deviceId: "old-z", revokedAt: "2026-09-16T14:00:00.000Z", reason: "lost" },
      { deviceId: "old-a", revokedAt: "2026-09-16T13:00:00.000Z", reason: "replaced" },
    ],
  });
  const right = manifest({
    sequence: 4,
    devices: [device("linked-a"), device("linked-b"), device("root-1", "root")],
    revocations: [
      { deviceId: "old-a", revokedAt: "2026-09-16T13:00:00.000Z", reason: "replaced" },
      { deviceId: "old-z", revokedAt: "2026-09-16T14:00:00.000Z", reason: "lost" },
    ],
  });

  assert.equal(canonicalManifestText(left.payload), canonicalManifestText(right.payload));
});

test("manifest requires exactly one root device", () => {
  assert.throws(
    () => validateManifestShape(manifest({ devices: [device("linked-a")] })),
    /exactement un appareil maître/i,
  );
  assert.throws(
    () => validateManifestShape(manifest({ devices: [device("root-1", "root"), device("root-2", "root")] })),
    /exactement un appareil maître/i,
  );
  assert.doesNotThrow(() => validateManifestShape(manifest()));
});

test("revoked devices are never active", () => {
  const candidate = manifest({
    sequence: 2,
    devices: [device("root-1", "root"), device("linked-a"), device("linked-b")],
    revocations: [
      { deviceId: "linked-b", revokedAt: "2026-09-16T15:10:00.000Z", reason: "lost" },
    ],
  });

  assert.deepEqual(activeDevices(candidate).map((item) => item.deviceId), ["linked-a", "root-1"]);
});

test("manifest rejects a device present in both active devices and revocations", () => {
  const candidate = manifest({
    sequence: 2,
    devices: [device("root-1", "root"), device("linked-b")],
    revocations: [
      { deviceId: "linked-b", revokedAt: "2026-09-16T15:10:00.000Z", reason: "compromised" },
    ],
  });

  assert.throws(() => validateManifestShape(candidate), /révoqué.*actif/i);
});

test("manifest state rejects sequence rollback", () => {
  const current = manifest({
    sequence: 3,
    devices: [device("root-1", "root")],
    revocations: [
      { deviceId: "linked-b", revokedAt: "2026-09-16T15:10:00.000Z", reason: "lost" },
    ],
  });
  const stale = manifest({
    sequence: 2,
    devices: [device("root-1", "root"), device("linked-b")],
  });

  assert.throws(() => mergeManifestState(current, stale), /rollback/i);
});

test("same sequence is idempotent only when manifest content is identical", () => {
  const current = manifest({ sequence: 5, devices: [device("root-1", "root"), device("linked-a")] });
  const identical = manifest({ sequence: 5, devices: [device("linked-a"), device("root-1", "root")] });
  const conflicting = manifest({ sequence: 5, devices: [device("root-1", "root"), device("linked-b")] });

  assert.equal(mergeManifestState(current, identical), current);
  assert.throws(() => mergeManifestState(current, conflicting), /conflit.*séquence/i);
});
