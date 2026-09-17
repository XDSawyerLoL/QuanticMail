import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { canonicalCryptoProfileText } from "../lib/quantic/crypto-profile-core.mjs";
import { canonicalPortableEnvelopeText } from "../lib/quantic/federation-core.mjs";
import { verifyPortableEnvelope } from "../lib/quantic/federation-node.mjs";
import { HYBRID_CRYPTO_SUITE } from "../lib/quantic/hybrid-crypto.ts";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { resolveCryptoPolicy } from "../lib/quantic/pqc-policy.mjs";
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

function fingerprint(key, length = 32) {
  return createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, length);
}

function signedIdentity(handle = "alicepolicy") {
  const owner = p256Pair();
  const encryption = p256Pair();
  const ownerPublic = publicJwk(owner);
  const encryptionPublic = publicJwk(encryption);
  const fp = fingerprint(ownerPublic, 32);
  const canonicalAddress = `${handle}~${fp}@quantic`;
  const deviceId = `d-${fingerprint(encryptionPublic, 10)}`;
  const issuedAt = "2026-09-17T08:00:00.000Z";
  const payload = {
    version: 1,
    sequence: 1,
    canonicalAddress,
    handle,
    fingerprint: fp,
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
  const signature = sign("sha256", Buffer.from(canonicalManifestText(payload), "utf8"), {
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

function makeProfile(identity, policy, devicePq) {
  const identityPq = generateMlDsa65KeyPair();
  const payload = {
    version: 2,
    sequence: 1,
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
    issuedAt: "2026-09-17T08:01:00.000Z",
  };
  const text = Buffer.from(canonicalCryptoProfileText(payload), "utf8");
  return {
    format: "quantic-crypto-profile",
    version: 2,
    payload,
    signatures: {
      p256: sign("sha256", text, {
        key: identity.owner.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64"),
      mlDsa65Self: mlDsaSign(identityPq.privateKeyPkcs8, text),
    },
  };
}

function signEnvelope(identity, envelope, devicePq = null) {
  const text = Buffer.from(canonicalPortableEnvelopeText(envelope), "utf8");
  return {
    ...envelope,
    signatures: {
      p256Device: sign("sha256", text, {
        key: identity.owner.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64"),
      ...(devicePq ? { mlDsa65Device: mlDsaSign(devicePq.dsa.privateKeyPkcs8, text) } : {}),
    },
  };
}

function classicalEnvelope(identity) {
  const ephemeral = p256Pair();
  const unsigned = {
    format: "quantic-envelope",
    version: 2,
    clientMessageId: "msg-policy-classical-0001",
    from: identity.canonicalAddress,
    fromDeviceId: identity.deviceId,
    to: `bob~${"b".repeat(32)}@quantic`,
    toDeviceId: "d-abcdef0123",
    keyMode: "v1-static-fallback",
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: publicJwk(ephemeral),
    iv: "aXYtbm9uY2U=",
    ciphertext: "Y2lwaGVydGV4dA==",
    createdAt: "2026-09-17T08:02:00.000Z",
    expiresAt: "2026-09-18T08:02:00.000Z",
    signatures: { p256Device: "placeholder" },
  };
  return signEnvelope(identity, unsigned);
}

function hybridEnvelope(identity, devicePq) {
  const ephemeral = p256Pair();
  const unsigned = {
    format: "quantic-envelope",
    version: 2,
    clientMessageId: "msg-policy-hybrid-0001",
    from: identity.canonicalAddress,
    fromDeviceId: identity.deviceId,
    to: `bob~${"b".repeat(32)}@quantic`,
    toDeviceId: "d-abcdef0123",
    keyMode: "hybrid-static-fallback",
    cryptoSuite: HYBRID_CRYPTO_SUITE,
    classicalEphemeralPublicKey: publicJwk(ephemeral),
    pqKemCiphertext: "pqKemCiphertextForPolicyTest_0123456789",
    iv: "aHlicmlkLWl2",
    ciphertext: "aHlicmlkLWNpcGhlcnRleHQ",
    createdAt: "2026-09-17T08:02:00.000Z",
    expiresAt: "2026-09-18T08:02:00.000Z",
    signatures: { p256Device: "placeholder" },
  };
  return signEnvelope(identity, unsigned, devicePq);
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
const now = Date.parse("2026-09-17T12:00:00.000Z");

test("crypto policy keeps V1 compatible before PQ activation", { skip }, () => {
  const identity = signedIdentity();
  assert.equal(resolveCryptoPolicy(null).mode, "classical-allowed");
  assert.doesNotThrow(() => verifyPortableEnvelope(classicalEnvelope(identity), identity.manifest, null, now));
});

test("transition profile permits classical delivery but advertises PQ capability", { skip }, () => {
  const identity = signedIdentity("transitionpolicy");
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const profile = makeProfile(identity, "transition", devicePq);
  const policy = resolveCryptoPolicy(profile);
  assert.equal(policy.mode, "transition");
  assert.equal(policy.requireHybrid, false);
  assert.doesNotThrow(() => verifyPortableEnvelope(classicalEnvelope(identity), identity.manifest, profile, now));
});

test("hybrid-required rejects silent classical downgrade", { skip }, () => {
  const identity = signedIdentity("requiredpolicy");
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const profile = makeProfile(identity, "hybrid-required", devicePq);
  assert.equal(resolveCryptoPolicy(profile).requireHybrid, true);
  assert.throws(
    () => verifyPortableEnvelope(classicalEnvelope(identity), identity.manifest, profile, now),
    /downgrade|hybrid|post-quant/i,
  );
});

test("hybrid-required accepts a dual-signed hybrid envelope", { skip }, () => {
  const identity = signedIdentity("hybridpolicy");
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const profile = makeProfile(identity, "hybrid-required", devicePq);
  const envelope = hybridEnvelope(identity, devicePq);
  assert.doesNotThrow(() => verifyPortableEnvelope(envelope, identity.manifest, profile, now));
});

test("hybrid-required rejects missing or invalid ML-DSA device proof", { skip }, () => {
  const identity = signedIdentity("signaturepolicy");
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const profile = makeProfile(identity, "hybrid-required", devicePq);
  const valid = hybridEnvelope(identity, devicePq);
  const missing = { ...valid, signatures: { p256Device: valid.signatures.p256Device } };
  assert.throws(() => verifyPortableEnvelope(missing, identity.manifest, profile, now), /ML-DSA|post-quant|signature/i);

  const tampered = { ...valid, pqKemCiphertext: `${valid.pqKemCiphertext}tamper` };
  assert.throws(() => verifyPortableEnvelope(tampered, identity.manifest, profile, now), /signature|ML-DSA|P-256/i);
});

test("hybrid envelope without a trusted Crypto Profile is rejected", { skip }, () => {
  const identity = signedIdentity("untrustedhybrid");
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const envelope = hybridEnvelope(identity, devicePq);
  assert.throws(() => verifyPortableEnvelope(envelope, identity.manifest, null, now), /profil|profile|post-quant|hybrid/i);
});
