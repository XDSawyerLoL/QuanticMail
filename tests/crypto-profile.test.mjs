import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import {
  canonicalCryptoProfileText,
  mergeCryptoProfileState,
} from "../lib/quantic/crypto-profile-core.mjs";
import { verifyCryptoProfile } from "../lib/quantic/crypto-profile-node.mjs";
import {
  generateMlDsa65KeyPair,
  generateMlKem768KeyPair,
  mlDsaSign,
} from "../lib/quantic/pqc-runtime-node.ts";

function p256Pair() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicJwk(pair) {
  return pair.publicKey.export({ format: "jwk" });
}

function signedIdentity(handle = "alicepqc") {
  const owner = p256Pair();
  const encryption = p256Pair();
  const ownerPublic = publicJwk(owner);
  const encryptionPublic = publicJwk(encryption);
  const fingerprint = createHash("sha256")
    .update(`P-256:${ownerPublic.x}:${ownerPublic.y}`)
    .digest("hex")
    .slice(0, 32);
  const canonicalAddress = `${handle}~${fingerprint}@quantic`;
  const issuedAt = "2026-09-17T08:00:00.000Z";
  const deviceId = `d-${createHash("sha256").update(`P-256:${encryptionPublic.x}:${encryptionPublic.y}`).digest("hex").slice(0, 10)}`;
  const payload = {
    version: 1,
    sequence: 1,
    canonicalAddress,
    handle,
    fingerprint,
    identityPublicKey: encryptionPublic,
    identitySigningPublicKey: ownerPublic,
    devices: [{
      deviceId,
      label: "Alice root",
      publicKey: encryptionPublic,
      deviceSigningPublicKey: ownerPublic,
      kind: "root",
      issuedAt,
    }],
    revocations: [],
    issuedAt,
  };
  const signature = sign("sha256", Buffer.from(canonicalManifestText(payload)), {
    key: owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return {
    owner,
    deviceId,
    canonicalAddress,
    manifest: { format: "quantic-identity-manifest", version: 1, payload, signature },
  };
}

function makeProfile(identity, sequence, identityPq, devicePq, previousIdentityPq = null, policy = "transition") {
  const payload = {
    version: 2,
    sequence,
    canonicalAddress: identity.canonicalAddress,
    identitySigningPublicKey: identity.manifest.payload.identitySigningPublicKey,
    identityManifestSequence: identity.manifest.payload.sequence,
    policy,
    identityMlDsaAlgorithm: "ML-DSA-65",
    identityMlDsaPublicKeySpki: identityPq.publicKeySpki,
    devices: [{
      deviceId: identity.deviceId,
      mlKemAlgorithm: "ML-KEM-768",
      mlKemPublicKeySpki: devicePq.kem.publicKeySpki,
      mlDsaAlgorithm: "ML-DSA-65",
      mlDsaPublicKeySpki: devicePq.dsa.publicKeySpki,
    }],
    issuedAt: `2026-09-17T08:0${sequence}:00.000Z`,
  };
  const text = Buffer.from(canonicalCryptoProfileText(payload));
  const p256 = sign("sha256", text, {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  const mlDsa65Self = mlDsaSign(identityPq.privateKeyPkcs8, text);
  const mlDsa65Continuity = previousIdentityPq
    ? mlDsaSign(previousIdentityPq.privateKeyPkcs8, text)
    : undefined;
  return {
    format: "quantic-crypto-profile",
    version: 2,
    payload,
    signatures: { p256, mlDsa65Self, ...(mlDsa65Continuity ? { mlDsa65Continuity } : {}) },
  };
}

const caps = (() => {
  try {
    generateMlKem768KeyPair();
    generateMlDsa65KeyPair();
    return true;
  } catch {
    return false;
  }
})();
const skip = caps ? false : "native PQ runtime unavailable";

test("first Crypto Profile activation requires valid P-256 and ML-DSA self proof", { skip }, () => {
  const identity = signedIdentity();
  const rootPq = generateMlDsa65KeyPair();
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const profile = makeProfile(identity, 1, rootPq, devicePq);

  assert.equal(verifyCryptoProfile(profile, identity.manifest, null).payload.sequence, 1);

  const tampered = structuredClone(profile);
  tampered.payload.policy = "hybrid-required";
  assert.throws(() => verifyCryptoProfile(tampered, identity.manifest, null), /signature|ML-DSA|P-256/i);
});

test("Crypto Profile update requires continuity from the previously pinned ML-DSA root", { skip }, () => {
  const identity = signedIdentity("continuity");
  const oldPq = generateMlDsa65KeyPair();
  const newPq = generateMlDsa65KeyPair();
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const previous = makeProfile(identity, 1, oldPq, devicePq);
  const next = makeProfile(identity, 2, newPq, devicePq, oldPq, "hybrid-required");

  assert.equal(verifyCryptoProfile(next, identity.manifest, previous).payload.sequence, 2);

  const attacker = generateMlDsa65KeyPair();
  const missingContinuity = makeProfile(identity, 2, attacker, devicePq, null, "hybrid-required");
  assert.throws(() => verifyCryptoProfile(missingContinuity, identity.manifest, previous), /continuity/i);
});

test("Crypto Profile state rejects rollback and same-sequence forks", { skip }, () => {
  const identity = signedIdentity("state");
  const pq = generateMlDsa65KeyPair();
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const first = makeProfile(identity, 1, pq, devicePq);
  const second = makeProfile(identity, 2, pq, devicePq, pq, "hybrid-required");

  assert.equal(mergeCryptoProfileState(first, second).payload.sequence, 2);
  assert.throws(() => mergeCryptoProfileState(second, first), /rollback/i);

  const fork = structuredClone(second);
  fork.payload.issuedAt = "2026-09-17T09:00:00.000Z";
  assert.throws(() => mergeCryptoProfileState(second, fork), /fork|conflit/i);
});
