import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  createIdentityChallenge,
  enqueueEnvelope,
  pullEnvelopes,
  registerIdentity,
} from "../lib/quantic/relay.ts";
import { registerIdentityCompat } from "../lib/quantic/register-compat.ts";
import { createEmptyRelayState, restoreRelayState } from "../lib/quantic/relay-state.ts";

function keyMaterial() {
  const encryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    encryption,
    signing,
    publicKey: encryption.publicKey.export({ format: "jwk" }) as JsonWebKey,
    signingPublicKey: signing.publicKey.export({ format: "jwk" }) as JsonWebKey,
  };
}

function deviceIds(publicKey: JsonWebKey) {
  const digest = createHash("sha256")
    .update(`P-256:${publicKey.x}:${publicKey.y}`)
    .digest("hex");
  return { legacy: `d-${digest.slice(0, 10)}`, strong: `d-${digest.slice(0, 32)}` };
}

function firstRegistration(handle: string, authToken: string, requestedDeviceId?: string) {
  const keys = keyMaterial();
  const challenge = createIdentityChallenge({
    handle,
    publicKey: keys.publicKey,
    signingPublicKey: keys.signingPublicKey,
  });
  const signature = sign(
    "sha256",
    Buffer.from(challenge.challenge, "utf8"),
    { key: keys.signing.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  const registered = registerIdentity({
    handle,
    publicKey: keys.publicKey,
    signingPublicKey: keys.signingPublicKey,
    authToken,
    deviceId: requestedDeviceId,
    challenge: challenge.challenge,
    signature,
  });
  return { keys, registered };
}

test("same root key can migrate strong id back to legacy id without losing queued delivery", () => {
  restoreRelayState(createEmptyRelayState());

  const aliceToken = "alice-root-token".padEnd(48, "a");
  const aliceKeys = keyMaterial();
  const aliceIds = deviceIds(aliceKeys.publicKey);
  const aliceChallenge = createIdentityChallenge({
    handle: "alice",
    publicKey: aliceKeys.publicKey,
    signingPublicKey: aliceKeys.signingPublicKey,
  });
  const aliceSignature = sign(
    "sha256",
    Buffer.from(aliceChallenge.challenge, "utf8"),
    { key: aliceKeys.signing.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  const alice = registerIdentity({
    handle: "alice",
    publicKey: aliceKeys.publicKey,
    signingPublicKey: aliceKeys.signingPublicKey,
    authToken: aliceToken,
    deviceId: aliceIds.strong,
    challenge: aliceChallenge.challenge,
    signature: aliceSignature,
  });
  assert.equal(alice.rootDeviceId, aliceIds.strong);

  const bobToken = "bob-root-token".padEnd(48, "b");
  const { keys: bobKeys, registered: bob } = firstRegistration("bobby", bobToken);

  enqueueEnvelope({
    clientMessageId: "msg-root-migrate-001",
    from: bob.canonicalAddress,
    fromDeviceId: bob.rootDeviceId,
    to: alice.canonicalAddress,
    toDeviceId: aliceIds.strong,
    ciphertext: "opaque-ciphertext",
    iv: "opaque-iv",
    ephemeralPublicKey: bobKeys.publicKey,
    authToken: bobToken,
  });

  const migrated = registerIdentityCompat({
    handle: "alice",
    publicKey: aliceKeys.publicKey,
    signingPublicKey: aliceKeys.signingPublicKey,
    authToken: aliceToken,
    deviceId: aliceIds.legacy,
  });

  assert.equal(migrated.rootDeviceId, aliceIds.legacy);
  const pulled = pullEnvelopes(alice.canonicalAddress, aliceToken, aliceIds.legacy);
  assert.equal(pulled.length, 1);
  assert.equal(pulled[0].clientMessageId, "msg-root-migrate-001");
  assert.equal(pulled[0].toDeviceId, aliceIds.legacy);
});
