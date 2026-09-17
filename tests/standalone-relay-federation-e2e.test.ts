import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  canonicalPortableEnvelopeText,
  canonicalRouteManifestText,
} from "../lib/quantic/federation-core.mjs";
import {
  decryptEnvelopeCore,
  encryptForRecipientCore,
} from "../lib/quantic/envelope-crypto.mjs";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { verifyRelayHello } from "../standalone-relay/identity.ts";
import { startRelayServer, type RunningRelayServer } from "../standalone-relay/server.ts";

function keys() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicJwk(pair: ReturnType<typeof keys>) {
  return pair.publicKey.export({ format: "jwk" });
}

function privateJwk(pair: ReturnType<typeof keys>) {
  return pair.privateKey.export({ format: "jwk" });
}

function fingerprint(key: JsonWebKey, length = 32) {
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex").slice(0, length);
}

function deviceId(key: JsonWebKey) {
  return `d-${fingerprint(key, 10)}`;
}

function signedIdentity(handle: string) {
  const owner = keys();
  const encryption = keys();
  const ownerPublic = publicJwk(owner);
  const encryptionPublic = publicJwk(encryption);
  const fp = fingerprint(ownerPublic, 32);
  const canonicalAddress = `${handle}~${fp}@quantic`;
  const issuedAt = new Date(Date.now() - 60_000).toISOString();
  const payload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress,
    handle,
    fingerprint: fp,
    identityPublicKey: encryptionPublic,
    identitySigningPublicKey: ownerPublic,
    devices: [{
      deviceId: deviceId(encryptionPublic),
      label: `${handle} root`,
      publicKey: encryptionPublic,
      deviceSigningPublicKey: ownerPublic,
      kind: "root" as const,
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
    encryption,
    deviceId: deviceId(encryptionPublic),
    canonicalAddress,
    manifest: { format: "quantic-identity-manifest" as const, version: 1 as const, payload, signature },
  };
}

async function registerIdentityOnRelay(
  relayUrl: string,
  identity: ReturnType<typeof signedIdentity>,
  authToken: string,
) {
  const challengeResponse = await fetch(`${relayUrl}/api/quantic/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      handle: identity.canonicalAddress,
      publicKey: identity.manifest.payload.identityPublicKey,
      signingPublicKey: identity.manifest.payload.identitySigningPublicKey,
    }),
  });
  assert.equal(challengeResponse.status, 201);
  const challenge = await challengeResponse.json() as { challenge: string };
  const ownershipSignature = sign("sha256", Buffer.from(challenge.challenge, "utf8"), {
    key: identity.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  const registerResponse = await fetch(`${relayUrl}/api/quantic/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      handle: identity.canonicalAddress,
      publicKey: identity.manifest.payload.identityPublicKey,
      signingPublicKey: identity.manifest.payload.identitySigningPublicKey,
      authToken,
      challenge: challenge.challenge,
      signature: ownershipSignature,
    }),
  });
  assert.equal(registerResponse.status, 201);
}

async function relayHello(relay: RunningRelayServer) {
  const nonce = `route-${createHash("sha256").update(relay.url).digest("hex").slice(0, 24)}`;
  const response = await fetch(`${relay.url}/api/quantic/federation/hello`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce }),
  });
  assert.equal(response.status, 200);
  return verifyRelayHello(await response.json(), nonce, relay.relayId);
}

function signedRoute(
  recipient: ReturnType<typeof signedIdentity>,
  relay: Awaited<ReturnType<typeof relayHello>>,
) {
  const issuedAt = new Date(Date.now() - 60_000).toISOString();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const payload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress: recipient.canonicalAddress,
    identitySigningPublicKey: recipient.manifest.payload.identitySigningPublicKey,
    identityManifestSequence: recipient.manifest.payload.sequence,
    cryptoProfileSequence: null,
    cryptoProfileDigest: null,
    relays: [{
      relayId: relay.relayId,
      endpoint: relay.endpoint,
      priority: 10,
      protocols: ["quantic-federation/1"],
      classicalSigningPublicKey: relay.classicalSigningPublicKey,
      expiresAt,
    }],
    issuedAt,
    expiresAt,
  };
  const p256 = sign("sha256", Buffer.from(canonicalRouteManifestText(payload), "utf8"), {
    key: recipient.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return { format: "quantic-route-manifest" as const, version: 1 as const, payload, signatures: { p256 } };
}

async function signedEncryptedEnvelope(
  sender: ReturnType<typeof signedIdentity>,
  recipient: ReturnType<typeof signedIdentity>,
  plaintext: Record<string, unknown>,
) {
  const encrypted = await encryptForRecipientCore(
    recipient.manifest.payload.identityPublicKey,
    plaintext,
  );
  const createdAt = new Date().toISOString();
  const envelope = {
    format: "quantic-envelope" as const,
    version: 2 as const,
    clientMessageId: "msg-federation-e2e-0001",
    from: sender.canonicalAddress,
    fromDeviceId: sender.deviceId,
    to: recipient.canonicalAddress,
    toDeviceId: recipient.deviceId,
    keyMode: "v1-static-fallback" as const,
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: encrypted.ephemeralPublicKey,
    iv: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    createdAt,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    signatures: { p256Device: "placeholder" },
  };
  envelope.signatures.p256Device = sign(
    "sha256",
    Buffer.from(canonicalPortableEnvelopeText(envelope), "utf8"),
    { key: sender.owner.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  return envelope;
}

test("Alice on relay A sends an encrypted message to Bob on relay B and receives Bob's delivery receipt", async () => {
  const dataDirA = await fs.mkdtemp(join(tmpdir(), "quantic-relay-a-e2e-"));
  const dataDirB = await fs.mkdtemp(join(tmpdir(), "quantic-relay-b-e2e-"));
  const relayA = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir: dataDirA });
  const relayB = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir: dataDirB });
  const alice = signedIdentity("alicee2e");
  const bob = signedIdentity("bobe2e");
  const aliceToken = "alice-e2e-local-device-auth-token-000000000000000000001";
  const bobToken = "bob-e2e-local-device-auth-token-00000000000000000000001";
  const plaintext = {
    subject: "Federation V1",
    body: "Quantic relay A to relay B acceptance proof",
    marker: "federation-e2e-0001",
  };

  try {
    await registerIdentityOnRelay(relayA.url, alice, aliceToken);
    await registerIdentityOnRelay(relayB.url, bob, bobToken);

    const route = signedRoute(bob, await relayHello(relayB));
    const envelope = await signedEncryptedEnvelope(alice, bob, plaintext);

    const sendResponse = await fetch(`${relayA.url}/api/quantic/federation/send`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${aliceToken}`,
      },
      body: JSON.stringify({
        senderIdentityManifest: alice.manifest,
        recipientIdentityManifest: bob.manifest,
        recipientRouteManifest: route,
        envelope,
      }),
    });
    assert.equal(sendResponse.status, 202, await sendResponse.text());
    const sent = await sendResponse.json() as { federationId: string; relayId: string; duplicate: boolean };
    assert.equal(sent.relayId, relayB.relayId);
    assert.equal(sent.duplicate, false);
    assert.match(sent.federationId, /^fed-[0-9a-f]{32}$/);

    const bobPullResponse = await fetch(
      `${relayB.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.deviceId)}`,
      { headers: { authorization: `Bearer ${bobToken}` } },
    );
    assert.equal(bobPullResponse.status, 200);
    const bobPull = await bobPullResponse.json() as {
      envelopes: Array<{
        id: string;
        clientMessageId: string;
        ciphertext: string;
        iv: string;
        ephemeralPublicKey: JsonWebKey;
      }>;
    };
    assert.equal(bobPull.envelopes.length, 1);
    assert.equal(bobPull.envelopes[0].clientMessageId, envelope.clientMessageId);

    const decrypted = await decryptEnvelopeCore(privateJwk(bob.encryption), bobPull.envelopes[0]);
    assert.deepEqual(decrypted, plaintext);

    const ackResponse = await fetch(`${relayB.url}/api/quantic/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${bobToken}`,
      },
      body: JSON.stringify({
        handle: bob.canonicalAddress,
        deviceId: bob.deviceId,
        ids: [bobPull.envelopes[0].id],
      }),
    });
    assert.equal(ackResponse.status, 200);
    const ack = await ackResponse.json() as { acknowledged: number; federationReceipts: number };
    assert.equal(ack.acknowledged, 1);
    assert.equal(ack.federationReceipts, 1);

    const aliceReceiptsResponse = await fetch(
      `${relayA.url}/api/quantic/receipts?handle=${encodeURIComponent(alice.canonicalAddress)}&deviceId=${encodeURIComponent(alice.deviceId)}`,
      { headers: { authorization: `Bearer ${aliceToken}` } },
    );
    assert.equal(aliceReceiptsResponse.status, 200);
    const aliceReceipts = await aliceReceiptsResponse.json() as {
      receipts: Array<{
        clientMessageId: string;
        from: string;
        fromDeviceId: string;
        to: string;
        toDeviceId: string;
      }>;
    };
    assert.equal(aliceReceipts.receipts.length, 1);
    assert.equal(aliceReceipts.receipts[0].clientMessageId, envelope.clientMessageId);
    assert.equal(aliceReceipts.receipts[0].from, alice.canonicalAddress);
    assert.equal(aliceReceipts.receipts[0].fromDeviceId, alice.deviceId);
    assert.equal(aliceReceipts.receipts[0].to, bob.canonicalAddress);
    assert.equal(aliceReceipts.receipts[0].toDeviceId, bob.deviceId);
  } finally {
    await relayA.close();
    await relayB.close();
    await fs.rm(dataDirA, { recursive: true, force: true });
    await fs.rm(dataDirB, { recursive: true, force: true });
  }
});
