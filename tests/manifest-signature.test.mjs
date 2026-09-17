import test from "node:test";
import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import {
  assertVerifiedManifest,
  verifyManifestSignature,
} from "../lib/quantic/manifest-node.mjs";

function keyPair() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function digest(publicJwk) {
  return createHash("sha256")
    .update(`P-256:${publicJwk.x}:${publicJwk.y}`)
    .digest("hex");
}

function fingerprint(publicJwk, length = 10) {
  return digest(publicJwk).slice(0, length);
}

function deviceId(publicJwk, length = 10) {
  return `d-${digest(publicJwk).slice(0, length)}`;
}

function makeSignedManifest(length = 10) {
  const rootSigning = keyPair();
  const identityEncryption = keyPair();
  const rootDeviceEncryption = keyPair();
  const rootDeviceSigning = keyPair();

  const identitySigningPublicKey = rootSigning.publicKey.export({ format: "jwk" });
  const identityPublicKey = identityEncryption.publicKey.export({ format: "jwk" });
  const rootPublicKey = rootDeviceEncryption.publicKey.export({ format: "jwk" });
  const rootDeviceSigningPublicKey = rootDeviceSigning.publicKey.export({ format: "jwk" });
  const fp = fingerprint(identitySigningPublicKey, length);
  const handle = "sansa";

  const payload = {
    version: 1,
    sequence: 1,
    canonicalAddress: `${handle}~${fp}@quantic`,
    handle,
    fingerprint: fp,
    identityPublicKey,
    identitySigningPublicKey,
    devices: [
      {
        deviceId: deviceId(rootPublicKey, length),
        label: "PC principal",
        publicKey: rootPublicKey,
        deviceSigningPublicKey: rootDeviceSigningPublicKey,
        kind: "root",
        issuedAt: "2026-09-16T16:00:00.000Z",
      },
    ],
    revocations: [],
    issuedAt: "2026-09-16T16:00:00.000Z",
  };

  const signature = sign(
    "sha256",
    Buffer.from(canonicalManifestText(payload), "utf8"),
    { key: rootSigning.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");

  return {
    manifest: {
      format: "quantic-identity-manifest",
      version: 1,
      payload,
      signature,
    },
  };
}

test("valid legacy root-signed manifest verifies", () => {
  const { manifest } = makeSignedManifest(10);
  assert.equal(verifyManifestSignature(manifest), true);
  assert.doesNotThrow(() => assertVerifiedManifest(manifest));
});

test("valid strong root-signed manifest verifies on Node", () => {
  const { manifest } = makeSignedManifest(32);
  assert.equal(verifyManifestSignature(manifest), true);
  assert.doesNotThrow(() => assertVerifiedManifest(manifest));
});

test("manifest signature fails after payload tampering", () => {
  const { manifest } = makeSignedManifest();
  manifest.payload.sequence = 2;
  assert.equal(verifyManifestSignature(manifest), false);
  assert.throws(() => assertVerifiedManifest(manifest), /signature/i);
});

test("manifest identity fingerprint must match root signing key", () => {
  const { manifest } = makeSignedManifest();
  manifest.payload.fingerprint = "0000000000";
  manifest.payload.canonicalAddress = `${manifest.payload.handle}~0000000000@quantic`;
  assert.throws(() => assertVerifiedManifest(manifest), /empreinte/i);
});
