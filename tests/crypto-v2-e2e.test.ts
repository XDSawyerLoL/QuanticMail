import assert from "node:assert/strict";
import { fork, type ChildProcess } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalCryptoProfileText } from "../lib/quantic/crypto-profile-core.mjs";
import { verifyCryptoProfile } from "../lib/quantic/crypto-profile-node.mjs";
import {
  canonicalPortableEnvelopeText,
  canonicalRouteManifestText,
} from "../lib/quantic/federation-core.mjs";
import {
  decryptHybridEnvelopeNode,
  encryptHybridEnvelopeNode,
} from "../lib/quantic/hybrid-envelope-node.ts";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import {
  generateMlDsa65KeyPair,
  generateMlKem768KeyPair,
  mlDsaSign,
} from "../lib/quantic/pqc-runtime-node.ts";
import { verifyRelayHello } from "../standalone-relay/identity.ts";

type IsolatedRelay = {
  url: string;
  relayId: string;
  close(): Promise<void>;
};

async function startIsolatedRelay(dataDir: string): Promise<IsolatedRelay> {
  const childPath = fileURLToPath(new URL("./helpers/standalone-relay-child.ts", import.meta.url));
  const child = fork(childPath, [], {
    execArgv: ["--experimental-transform-types"],
    env: { ...process.env, QUANTIC_TEST_RELAY_DATA_DIR: dataDir },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
  });
  let stderr = "";
  child.stderr?.on("data", (chunk) => { stderr += String(chunk); });

  const ready = await new Promise<{ url: string; relayId: string }>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`Démarrage du relais Crypto V2 expiré.${stderr ? `\n${stderr}` : ""}`));
    }, 10_000);
    timer.unref();
    const cleanup = () => {
      clearTimeout(timer);
      child.off("error", onError);
      child.off("exit", onExit);
      child.off("message", onMessage);
    };
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onExit = () => { cleanup(); reject(new Error(`Relais Crypto V2 interrompu.${stderr ? `\n${stderr}` : ""}`)); };
    const onMessage = (message: unknown) => {
      const value = message as { type?: string; url?: string; relayId?: string } | null;
      if (value?.type !== "ready" || typeof value.url !== "string" || typeof value.relayId !== "string") return;
      cleanup();
      resolve({ url: value.url, relayId: value.relayId });
    };
    child.once("error", onError);
    child.once("exit", onExit);
    child.on("message", onMessage);
  });

  return {
    ...ready,
    async close() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      await new Promise<void>((resolve) => {
        const forceTimer = setTimeout(() => child.kill("SIGKILL"), 5_000);
        forceTimer.unref();
        child.once("exit", () => { clearTimeout(forceTimer); resolve(); });
        child.send({ type: "shutdown" });
      });
    },
  };
}

function p256Pair() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicJwk(pair: ReturnType<typeof p256Pair>) {
  return pair.publicKey.export({ format: "jwk" });
}

function privateJwk(pair: ReturnType<typeof p256Pair>) {
  return pair.privateKey.export({ format: "jwk" });
}

function fingerprint(key: JsonWebKey, length = 32) {
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex").slice(0, length);
}

function deviceId(key: JsonWebKey) {
  return `d-${fingerprint(key, 10)}`;
}

function signedIdentity(handle: string) {
  const owner = p256Pair();
  const encryption = p256Pair();
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

function cryptoProfile(identity: ReturnType<typeof signedIdentity>) {
  const identityPq = generateMlDsa65KeyPair();
  const devicePq = { kem: generateMlKem768KeyPair(), dsa: generateMlDsa65KeyPair() };
  const payload = {
    version: 2 as const,
    sequence: 1,
    canonicalAddress: identity.canonicalAddress,
    identitySigningPublicKey: identity.manifest.payload.identitySigningPublicKey,
    identityManifestSequence: identity.manifest.payload.sequence,
    policy: "hybrid-required" as const,
    identityMlDsaAlgorithm: "ML-DSA-65" as const,
    identityMlDsaPublicKeySpki: identityPq.publicKeySpki,
    devices: [{
      deviceId: identity.deviceId,
      mlKemAlgorithm: "ML-KEM-768" as const,
      mlKemPublicKeySpki: devicePq.kem.publicKeySpki,
      mlDsaAlgorithm: "ML-DSA-65" as const,
      mlDsaPublicKeySpki: devicePq.dsa.publicKeySpki,
    }],
    issuedAt: new Date(Date.now() - 30_000).toISOString(),
  };
  const text = Buffer.from(canonicalCryptoProfileText(payload), "utf8");
  const profile = {
    format: "quantic-crypto-profile" as const,
    version: 2 as const,
    payload,
    signatures: {
      p256: sign("sha256", text, {
        key: identity.owner.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64"),
      mlDsa65Self: mlDsaSign(identityPq.privateKeyPkcs8, text),
    },
  };
  verifyCryptoProfile(profile, identity.manifest, null);
  return { profile, identityPq, devicePq };
}

async function registerIdentityOnRelay(relayUrl: string, identity: ReturnType<typeof signedIdentity>, authToken: string) {
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

async function relayHello(relay: IsolatedRelay) {
  const nonce = `crypto-v2-${createHash("sha256").update(relay.url).digest("hex").slice(0, 24)}`;
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
  recipientProfile: ReturnType<typeof cryptoProfile>["profile"],
  relay: Awaited<ReturnType<typeof relayHello>>,
) {
  const issuedAt = new Date(Date.now() - 30_000).toISOString();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const cryptoProfileDigest = createHash("sha256")
    .update(canonicalCryptoProfileText(recipientProfile.payload), "utf8")
    .digest("hex");
  const payload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress: recipient.canonicalAddress,
    identitySigningPublicKey: recipient.manifest.payload.identitySigningPublicKey,
    identityManifestSequence: recipient.manifest.payload.sequence,
    cryptoProfileSequence: recipientProfile.payload.sequence,
    cryptoProfileDigest,
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

function signedHybridEnvelope(
  sender: ReturnType<typeof signedIdentity>,
  senderPq: ReturnType<typeof cryptoProfile>,
  recipient: ReturnType<typeof signedIdentity>,
  recipientPq: ReturnType<typeof cryptoProfile>,
  plaintext: Record<string, unknown>,
) {
  const context = {
    clientMessageId: "msg-crypto-v2-e2e-0001",
    from: sender.canonicalAddress,
    fromDeviceId: sender.deviceId,
    to: recipient.canonicalAddress,
    toDeviceId: recipient.deviceId,
  };
  const encrypted = encryptHybridEnvelopeNode({
    recipientClassicalPublicKey: recipient.manifest.payload.identityPublicKey,
    recipientMlKemPublicKeySpki: recipientPq.devicePq.kem.publicKeySpki,
    context,
    payload: plaintext,
  });
  const envelope = {
    format: "quantic-envelope" as const,
    version: 2 as const,
    clientMessageId: context.clientMessageId,
    from: context.from,
    fromDeviceId: context.fromDeviceId,
    to: context.to,
    toDeviceId: context.toDeviceId,
    ...encrypted,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    signatures: { p256Device: "placeholder", mlDsa65Device: "placeholder" },
  };
  const text = Buffer.from(canonicalPortableEnvelopeText(envelope), "utf8");
  envelope.signatures.p256Device = sign("sha256", text, {
    key: sender.owner.privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64");
  envelope.signatures.mlDsa65Device = mlDsaSign(senderPq.devicePq.dsa.privateKeyPkcs8, text);
  return { envelope, context };
}

test("Crypto V2 hybrid delivery survives A→B federation, decrypts on Bob, returns a receipt, and rejects PQ tampering", async () => {
  const dataDirA = await fs.mkdtemp(join(tmpdir(), "quantic-crypto-v2-a-"));
  const dataDirB = await fs.mkdtemp(join(tmpdir(), "quantic-crypto-v2-b-"));
  const relayA = await startIsolatedRelay(dataDirA);
  const relayB = await startIsolatedRelay(dataDirB);
  const alice = signedIdentity("alicecryptov2");
  const bob = signedIdentity("bobcryptov2");
  const alicePq = cryptoProfile(alice);
  const bobPq = cryptoProfile(bob);
  const aliceToken = "alice-crypto-v2-local-device-auth-token-00000000000000001";
  const bobToken = "bob-crypto-v2-local-device-auth-token-0000000000000000001";
  const plaintext = {
    subject: "Quantic Crypto V2",
    body: "P-256 + ML-KEM-768 + ML-DSA-65",
    marker: "crypto-v2-federation-proof",
  };

  try {
    await registerIdentityOnRelay(relayA.url, alice, aliceToken);
    await registerIdentityOnRelay(relayB.url, bob, bobToken);

    const route = signedRoute(bob, bobPq.profile, await relayHello(relayB));
    const { envelope, context } = signedHybridEnvelope(alice, alicePq, bob, bobPq, plaintext);

    const tampered = { ...envelope, pqKemCiphertext: `${envelope.pqKemCiphertext}tamper` };
    const rejected = await fetch(`${relayA.url}/api/quantic/federation/send`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${aliceToken}` },
      body: JSON.stringify({
        senderIdentityManifest: alice.manifest,
        senderCryptoProfile: alicePq.profile,
        recipientIdentityManifest: bob.manifest,
        recipientRouteManifest: route,
        envelope: tampered,
      }),
    });
    assert.equal(rejected.status, 401);

    const sendResponse = await fetch(`${relayA.url}/api/quantic/federation/send`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${aliceToken}` },
      body: JSON.stringify({
        senderIdentityManifest: alice.manifest,
        senderCryptoProfile: alicePq.profile,
        recipientIdentityManifest: bob.manifest,
        recipientRouteManifest: route,
        envelope,
      }),
    });
    const sendBody = await sendResponse.text();
    assert.equal(sendResponse.status, 202, sendBody);

    const pullResponse = await fetch(
      `${relayB.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.deviceId)}`,
      { headers: { authorization: `Bearer ${bobToken}` } },
    );
    assert.equal(pullResponse.status, 200);
    const pulled = await pullResponse.json() as {
      envelopes: Array<{
        id: string;
        clientMessageId: string;
        keyMode?: string;
        cryptoSuite?: string;
        ciphertext: string;
        iv: string;
        ephemeralPublicKey: JsonWebKey;
        pqKemCiphertext?: string;
      }>;
    };
    assert.equal(pulled.envelopes.length, 1);
    const received = pulled.envelopes[0];
    assert.equal(received.clientMessageId, envelope.clientMessageId);
    assert.equal(received.keyMode, envelope.keyMode);
    assert.equal(received.cryptoSuite, envelope.cryptoSuite);
    assert.equal(received.pqKemCiphertext, envelope.pqKemCiphertext);

    const decrypted = decryptHybridEnvelopeNode({
      recipientClassicalPrivateKey: privateJwk(bob.encryption),
      recipientMlKemPrivateKeyPkcs8: bobPq.devicePq.kem.privateKeyPkcs8,
      context,
      envelope: {
        keyMode: received.keyMode as "hybrid-static-fallback",
        cryptoSuite: received.cryptoSuite as typeof envelope.cryptoSuite,
        classicalEphemeralPublicKey: received.ephemeralPublicKey,
        pqKemCiphertext: received.pqKemCiphertext as string,
        iv: received.iv,
        ciphertext: received.ciphertext,
      },
    });
    assert.deepEqual(decrypted, plaintext);

    const ackResponse = await fetch(`${relayB.url}/api/quantic/ack`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bobToken}` },
      body: JSON.stringify({ handle: bob.canonicalAddress, deviceId: bob.deviceId, ids: [received.id] }),
    });
    assert.equal(ackResponse.status, 200);

    const receiptResponse = await fetch(
      `${relayA.url}/api/quantic/receipts?handle=${encodeURIComponent(alice.canonicalAddress)}&deviceId=${encodeURIComponent(alice.deviceId)}`,
      { headers: { authorization: `Bearer ${aliceToken}` } },
    );
    assert.equal(receiptResponse.status, 200);
    const receipts = await receiptResponse.json() as { receipts: Array<{ clientMessageId: string }> };
    assert.equal(receipts.receipts.length, 1);
    assert.equal(receipts.receipts[0].clientMessageId, envelope.clientMessageId);
  } finally {
    await relayA.close();
    await relayB.close();
    await fs.rm(dataDirA, { recursive: true, force: true });
    await fs.rm(dataDirB, { recursive: true, force: true });
  }
});
