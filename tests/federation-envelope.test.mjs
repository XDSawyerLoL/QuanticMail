import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { canonicalPortableEnvelopeText } from "../lib/quantic/federation-core.mjs";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { verifyPortableEnvelope } from "../lib/quantic/federation-node.mjs";

function keyPair() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicJwk(pair) {
  return pair.publicKey.export({ format: "jwk" });
}

function fingerprint(key, length = 32) {
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex").slice(0, length);
}

function deviceId(key) {
  return `d-${fingerprint(key, 10)}`;
}

function signIdentity(payload, ownerPrivateKey) {
  return {
    format: "quantic-identity-manifest",
    version: 1,
    payload,
    signature: sign("sha256", Buffer.from(canonicalManifestText(payload), "utf8"), {
      key: ownerPrivateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64"),
  };
}

function fixture() {
  const owner = keyPair();
  const identityEncryption = keyPair();
  const rootEncryption = keyPair();
  const rootSigning = keyPair();
  const linkedEncryption = keyPair();
  const linkedSigning = keyPair();
  const ephemeral = keyPair();

  const identitySigningPublicKey = publicJwk(owner);
  const fp = fingerprint(identitySigningPublicKey, 32);
  const canonicalAddress = `alice~${fp}@quantic`;
  const rootPublicKey = publicJwk(rootEncryption);
  const linkedPublicKey = publicJwk(linkedEncryption);
  const linkedId = deviceId(linkedPublicKey);

  const payload = {
    version: 1,
    sequence: 4,
    canonicalAddress,
    handle: "alice",
    fingerprint: fp,
    identityPublicKey: publicJwk(identityEncryption),
    identitySigningPublicKey,
    devices: [
      {
        deviceId: deviceId(rootPublicKey),
        label: "Alice root",
        publicKey: rootPublicKey,
        deviceSigningPublicKey: publicJwk(rootSigning),
        kind: "root",
        issuedAt: "2026-09-17T00:00:00.000Z",
      },
      {
        deviceId: linkedId,
        label: "Alice laptop",
        publicKey: linkedPublicKey,
        deviceSigningPublicKey: publicJwk(linkedSigning),
        kind: "linked",
        issuedAt: "2026-09-17T00:01:00.000Z",
      },
    ],
    revocations: [],
    issuedAt: "2026-09-17T00:01:00.000Z",
  };
  const manifest = signIdentity(payload, owner.privateKey);

  const envelope = {
    format: "quantic-envelope",
    version: 2,
    clientMessageId: "msg-federation-1001",
    from: canonicalAddress,
    fromDeviceId: linkedId,
    to: "bob~abcdef0123456789abcdef0123456789@quantic",
    toDeviceId: "d-abcdef0123",
    keyMode: "v1-static-fallback",
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: publicJwk(ephemeral),
    iv: "aXYtbm9uY2U=",
    ciphertext: "Y2lwaGVydGV4dA==",
    createdAt: "2026-09-17T00:02:00.000Z",
    expiresAt: "2026-09-18T00:02:00.000Z",
    signatures: { p256Device: "" },
  };
  envelope.signatures.p256Device = sign(
    "sha256",
    Buffer.from(canonicalPortableEnvelopeText({ ...envelope, signatures: { p256Device: "placeholder" } }), "utf8"),
    { key: linkedSigning.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");

  return { owner, linkedSigning, manifest, envelope, linkedId };
}

test("portable envelope verifies against an active sender device", () => {
  const { manifest, envelope } = fixture();
  assert.doesNotThrow(() => verifyPortableEnvelope(envelope, manifest, null, Date.parse("2026-09-17T12:00:00.000Z")));
});

test("portable envelope signature covers recipient and ciphertext", () => {
  const { manifest, envelope } = fixture();
  assert.throws(
    () => verifyPortableEnvelope({ ...envelope, ciphertext: "dGFtcGVyZWQ=" }, manifest, null, Date.parse("2026-09-17T12:00:00.000Z")),
    /signature/i,
  );
  assert.throws(
    () => verifyPortableEnvelope({ ...envelope, toDeviceId: "d-1111111111" }, manifest, null, Date.parse("2026-09-17T12:00:00.000Z")),
    /signature/i,
  );
});

test("unknown sender device is rejected", () => {
  const { manifest, envelope } = fixture();
  const unknown = { ...envelope, fromDeviceId: "d-1111111111" };
  assert.throws(() => verifyPortableEnvelope(unknown, manifest, null, Date.parse("2026-09-17T12:00:00.000Z")), /appareil|device/i);
});

test("revoked sender device is rejected even with its former valid signature", () => {
  const { owner, manifest, envelope, linkedId } = fixture();
  const payload = {
    ...manifest.payload,
    sequence: manifest.payload.sequence + 1,
    devices: manifest.payload.devices.filter((device) => device.deviceId !== linkedId),
    revocations: [{ deviceId: linkedId, revokedAt: "2026-09-17T01:00:00.000Z", reason: "compromised" }],
    issuedAt: "2026-09-17T01:00:00.000Z",
  };
  const revokedManifest = signIdentity(payload, owner.privateKey);
  assert.throws(() => verifyPortableEnvelope(envelope, revokedManifest, null, Date.parse("2026-09-17T12:00:00.000Z")), /révoqué|revoked|appareil/i);
});

test("expired portable envelope is rejected", () => {
  const { manifest, envelope } = fixture();
  assert.throws(() => verifyPortableEnvelope(envelope, manifest, null, Date.parse("2026-09-19T00:00:00.000Z")), /expir/i);
});
