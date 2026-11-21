import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  decryptHybridEnvelopeNode,
  encryptHybridEnvelopeNode,
  HYBRID_CRYPTO_SUITE,
} from "../lib/quantic/hybrid-envelope-node.ts";
import { generateMlKem768KeyPair } from "../lib/quantic/pqc-runtime-node.ts";

function p256Pair() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicJwk(pair: ReturnType<typeof p256Pair>) {
  return pair.publicKey.export({ format: "jwk" });
}

function privateJwk(pair: ReturnType<typeof p256Pair>) {
  return pair.privateKey.export({ format: "jwk" });
}

const context = {
  clientMessageId: "msg-hybrid-envelope-0001",
  from: `alice~${"a".repeat(32)}@quantic`,
  fromDeviceId: "d-0123456789",
  to: `bob~${"b".repeat(32)}@quantic`,
  toDeviceId: "d-abcdef0123",
};

test("hybrid P-256 + ML-KEM envelope round-trips through HKDF and AES-256-GCM", () => {
  const recipientClassical = p256Pair();
  const recipientPq = generateMlKem768KeyPair();
  const payload = { subject: "Quantic Crypto V2", body: "hybrid secret", marker: 42 };

  const envelope = encryptHybridEnvelopeNode({
    recipientClassicalPublicKey: publicJwk(recipientClassical),
    recipientMlKemPublicKeySpki: recipientPq.publicKeySpki,
    context,
    payload,
  });

  assert.equal(envelope.cryptoSuite, HYBRID_CRYPTO_SUITE);
  assert.equal(envelope.keyMode, "hybrid-static-fallback");
  assert.equal(envelope.classicalEphemeralPublicKey.kty, "EC");
  assert.match(envelope.pqKemCiphertext, /^[A-Za-z0-9_-]+$/);
  assert.match(envelope.iv, /^[A-Za-z0-9_-]+$/);
  assert.match(envelope.ciphertext, /^[A-Za-z0-9_-]+$/);

  const decrypted = decryptHybridEnvelopeNode({
    recipientClassicalPrivateKey: privateJwk(recipientClassical),
    recipientMlKemPrivateKeyPkcs8: recipientPq.privateKeyPkcs8,
    context,
    envelope,
  });
  assert.deepEqual(decrypted, payload);
});

test("hybrid envelope fails if the ML-KEM private key is wrong", () => {
  const recipientClassical = p256Pair();
  const recipientPq = generateMlKem768KeyPair();
  const attackerPq = generateMlKem768KeyPair();
  const envelope = encryptHybridEnvelopeNode({
    recipientClassicalPublicKey: publicJwk(recipientClassical),
    recipientMlKemPublicKeySpki: recipientPq.publicKeySpki,
    context,
    payload: { body: "secret" },
  });

  assert.throws(() => decryptHybridEnvelopeNode({
    recipientClassicalPrivateKey: privateJwk(recipientClassical),
    recipientMlKemPrivateKeyPkcs8: attackerPq.privateKeyPkcs8,
    context,
    envelope,
  }));
});

test("hybrid envelope fails if the classical P-256 private key is wrong", () => {
  const recipientClassical = p256Pair();
  const attackerClassical = p256Pair();
  const recipientPq = generateMlKem768KeyPair();
  const envelope = encryptHybridEnvelopeNode({
    recipientClassicalPublicKey: publicJwk(recipientClassical),
    recipientMlKemPublicKeySpki: recipientPq.publicKeySpki,
    context,
    payload: { body: "secret" },
  });

  assert.throws(() => decryptHybridEnvelopeNode({
    recipientClassicalPrivateKey: privateJwk(attackerClassical),
    recipientMlKemPrivateKeyPkcs8: recipientPq.privateKeyPkcs8,
    context,
    envelope,
  }));
});

test("hybrid envelope authenticates its routing context as AES-GCM additional data", () => {
  const recipientClassical = p256Pair();
  const recipientPq = generateMlKem768KeyPair();
  const envelope = encryptHybridEnvelopeNode({
    recipientClassicalPublicKey: publicJwk(recipientClassical),
    recipientMlKemPublicKeySpki: recipientPq.publicKeySpki,
    context,
    payload: { body: "secret" },
  });

  assert.throws(() => decryptHybridEnvelopeNode({
    recipientClassicalPrivateKey: privateJwk(recipientClassical),
    recipientMlKemPrivateKeyPkcs8: recipientPq.privateKeyPkcs8,
    context: { ...context, toDeviceId: "d-1111111111" },
    envelope,
  }));
});

test("hybrid envelope binds strong device identifiers in the cryptographic context", () => {
  const recipient = p256Pair(), pq = generateMlKem768KeyPair();
  const routing = {...context,fromDeviceId:"d-"+"a".repeat(32),toDeviceId:"d-"+"b".repeat(32)};
  const envelope = encryptHybridEnvelopeNode({recipientClassicalPublicKey:publicJwk(recipient),recipientMlKemPublicKeySpki:pq.publicKeySpki,context:routing,payload:{body:"synthetic strong ID"}});
  const open = (ctx:typeof routing)=>decryptHybridEnvelopeNode({recipientClassicalPrivateKey:privateJwk(recipient),recipientMlKemPrivateKeyPkcs8:pq.privateKeyPkcs8,context:ctx,envelope});
  assert.deepEqual(open(routing),{body:"synthetic strong ID"});
  assert.throws(()=>open({...routing,toDeviceId:"d-"+"b".repeat(10)}));
});
