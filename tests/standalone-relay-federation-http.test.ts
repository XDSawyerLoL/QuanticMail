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
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { verifyRelayHello } from "../standalone-relay/identity.ts";
import { startRelayServer } from "../standalone-relay/server.ts";

async function tempDir() {
  return fs.mkdtemp(join(tmpdir(), "quantic-relay-federation-http-"));
}

function keys() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicJwk(pair: ReturnType<typeof keys>) {
  return pair.publicKey.export({ format: "jwk" });
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
      issuedAt: "2026-09-17T00:00:00.000Z",
    }],
    revocations: [],
    issuedAt: "2026-09-17T00:00:00.000Z",
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

async function relayHello(relayUrl: string, relayId: string) {
  const nonce = `nonce-${"a".repeat(24)}`;
  const response = await fetch(`${relayUrl}/api/quantic/federation/hello`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce }),
  });
  assert.equal(response.status, 200);
  return verifyRelayHello(await response.json(), nonce, relayId);
}

function signedRoute(
  recipient: ReturnType<typeof signedIdentity>,
  relay: Awaited<ReturnType<typeof relayHello>>,
) {
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
      expiresAt: "2026-10-17T00:00:00.000Z",
    }],
    issuedAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-10-17T00:00:00.000Z",
  };
  const p256 = sign("sha256", Buffer.from(canonicalRouteManifestText(payload), "utf8"), {
    key: recipient.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  return { format: "quantic-route-manifest" as const, version: 1 as const, payload, signatures: { p256 } };
}

function signedEnvelope(
  sender: ReturnType<typeof signedIdentity>,
  recipient: ReturnType<typeof signedIdentity>,
) {
  const ephemeral = keys();
  const envelope = {
    format: "quantic-envelope" as const,
    version: 2 as const,
    clientMessageId: "msg-federation-http-0001",
    from: sender.canonicalAddress,
    fromDeviceId: sender.deviceId,
    to: recipient.canonicalAddress,
    toDeviceId: recipient.deviceId,
    keyMode: "v1-static-fallback" as const,
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: publicJwk(ephemeral),
    iv: "aXYtbm9uY2U=",
    ciphertext: "ZmVkZXJhdGVkLWNpcGhlcnRleHQ=",
    createdAt: "2026-09-17T00:10:00.000Z",
    expiresAt: "2026-09-18T00:10:00.000Z",
    signatures: { p256Device: "placeholder" },
  };
  envelope.signatures.p256Device = sign(
    "sha256",
    Buffer.from(canonicalPortableEnvelopeText(envelope), "utf8"),
    { key: sender.owner.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  return envelope;
}

test("standalone relay exposes a signed nonce-bound federation hello", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const nonce = "nonce-0123456789abcdef";
    const response = await fetch(`${relay.url}/api/quantic/federation/hello`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce }),
    });
    assert.equal(response.status, 200);
    const hello = await response.json();
    const verified = verifyRelayHello(hello, nonce, relay.relayId);
    assert.equal(verified.relayId, relay.relayId);
    assert.equal(verified.endpoint, relay.url);
    assert.ok(verified.protocols.includes("quantic-federation/1"));
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("federation hello rejects a weak nonce", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const response = await fetch(`${relay.url}/api/quantic/federation/hello`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce: "tiny" }),
    });
    assert.equal(response.status, 400);
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("destination relay accepts a sender-signed federation envelope without the sender auth token", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  const bob = signedIdentity("bob");
  const alice = signedIdentity("alice");
  const bobToken = "bob-local-device-auth-token-000000000000000000000001";
  try {
    await registerIdentityOnRelay(relay.url, bob, bobToken);
    const hello = await relayHello(relay.url, relay.relayId);
    const route = signedRoute(bob, hello);
    const envelope = signedEnvelope(alice, bob);

    const response = await fetch(`${relay.url}/api/quantic/federation/forward`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        format: "quantic-federation-forward",
        version: 1,
        federationId: "fed-http-0000000000000001",
        originRelay: hello,
        previousRelayId: "0".repeat(64),
        hopLimit: 4,
        visitedRelayIds: [],
        expiresAt: "2026-09-18T00:10:00.000Z",
        senderIdentityManifest: alice.manifest,
        recipientIdentityManifest: bob.manifest,
        recipientRouteManifest: route,
        envelope,
        previousRelayAttestation: "task-5-placeholder",
      }),
    });
    assert.equal(response.status, 202);
    const forwarded = await response.json() as { duplicate: boolean };
    assert.equal(forwarded.duplicate, false);

    const pull = await fetch(
      `${relay.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.deviceId)}`,
      { headers: { authorization: `Bearer ${bobToken}` } },
    );
    assert.equal(pull.status, 200);
    const body = await pull.json() as { envelopes: Array<{ clientMessageId: string; ciphertext: string }> };
    assert.equal(body.envelopes.length, 1);
    assert.equal(body.envelopes[0].clientMessageId, envelope.clientMessageId);
    assert.equal(body.envelopes[0].ciphertext, envelope.ciphertext);
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("destination relay rejects a route that does not authorize itself", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  const bob = signedIdentity("bobby");
  const alice = signedIdentity("alicia");
  const bobToken = "bob-route-local-auth-token-000000000000000000000001";
  try {
    await registerIdentityOnRelay(relay.url, bob, bobToken);
    const hello = await relayHello(relay.url, relay.relayId);
    const route = signedRoute(bob, { ...hello, relayId: "f".repeat(64) });
    const envelope = signedEnvelope(alice, bob);
    const response = await fetch(`${relay.url}/api/quantic/federation/forward`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        format: "quantic-federation-forward",
        version: 1,
        federationId: "fed-http-0000000000000002",
        originRelay: hello,
        previousRelayId: "0".repeat(64),
        hopLimit: 4,
        visitedRelayIds: [],
        expiresAt: "2026-09-18T00:10:00.000Z",
        senderIdentityManifest: alice.manifest,
        recipientIdentityManifest: bob.manifest,
        recipientRouteManifest: route,
        envelope,
        previousRelayAttestation: "task-5-placeholder",
      }),
    });
    assert.notEqual(response.status, 202);
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
