import assert from "node:assert/strict";
import { fork, type ChildProcess } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  canonicalPortableEnvelopeText,
  canonicalRouteManifestText,
} from "../lib/quantic/federation-core.mjs";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { verifyRelayHello } from "../standalone-relay/identity.ts";

type IsolatedRelay = {
  url: string;
  relayId: string;
  close(): Promise<void>;
};

async function startIsolatedRelay(dataDir: string, port = 0): Promise<IsolatedRelay> {
  const childPath = fileURLToPath(new URL("./helpers/standalone-relay-child.ts", import.meta.url));
  const child = fork(childPath, [], {
    execArgv: ["--experimental-transform-types"],
    env: {
      ...process.env,
      QUANTIC_TEST_RELAY_DATA_DIR: dataDir,
      QUANTIC_TEST_RELAY_PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
  });
  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr += String(chunk);
  });

  const ready = await new Promise<{ url: string; relayId: string }>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`Démarrage du relais isolé expiré.${stderr ? `\n${stderr}` : ""}`));
    }, 10_000);
    timer.unref();

    const cleanup = () => {
      clearTimeout(timer);
      child.off("error", onError);
      child.off("exit", onExit);
      child.off("message", onMessage);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onExit = () => {
      cleanup();
      reject(new Error(`Processus Quantic Relay interrompu.${stderr ? `\n${stderr}` : ""}`));
    };
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
        child.once("exit", () => {
          clearTimeout(forceTimer);
          resolve();
        });
        child.send({ type: "shutdown" });
      });
    },
  };
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

async function relayHello(relay: IsolatedRelay) {
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

function signedEnvelope(
  sender: ReturnType<typeof signedIdentity>,
  recipient: ReturnType<typeof signedIdentity>,
) {
  const ephemeral = keys();
  const createdAt = new Date().toISOString();
  const envelope = {
    format: "quantic-envelope" as const,
    version: 2 as const,
    clientMessageId: "msg-federation-retry-0001",
    from: sender.canonicalAddress,
    fromDeviceId: sender.deviceId,
    to: recipient.canonicalAddress,
    toDeviceId: recipient.deviceId,
    keyMode: "v1-static-fallback" as const,
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: publicJwk(ephemeral),
    iv: "cmV0cnktaXY=",
    ciphertext: "cmV0cnktY2lwaGVydGV4dA==",
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

async function fetchReceipts(relayUrl: string, identity: ReturnType<typeof signedIdentity>, token: string) {
  const response = await fetch(
    `${relayUrl}/api/quantic/receipts?handle=${encodeURIComponent(identity.canonicalAddress)}&deviceId=${encodeURIComponent(identity.deviceId)}`,
    { headers: { authorization: `Bearer ${token}` } },
  );
  assert.equal(response.status, 200);
  return (await response.json() as { receipts: Array<{ clientMessageId: string }> }).receipts;
}

async function eventuallyReceivesReceipt(
  relayUrl: string,
  identity: ReturnType<typeof signedIdentity>,
  token: string,
  timeoutMs = 7_000,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const receipts = await fetchReceipts(relayUrl, identity, token);
    if (receipts.length > 0) return receipts;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return [];
}

test("pending federation receipt retries after relay restart without duplicating Bob's message", async () => {
  const dataDirA = await fs.mkdtemp(join(tmpdir(), "quantic-relay-a-retry-"));
  const dataDirB = await fs.mkdtemp(join(tmpdir(), "quantic-relay-b-retry-"));
  let relayA: IsolatedRelay | null = await startIsolatedRelay(dataDirA);
  let relayB: IsolatedRelay | null = await startIsolatedRelay(dataDirB);
  const alice = signedIdentity("aliceretry");
  const bob = signedIdentity("bobretry");
  const aliceToken = "alice-retry-device-auth-token-0000000000000000000000001";
  const bobToken = "bob-retry-device-auth-token-000000000000000000000000001";

  try {
    await registerIdentityOnRelay(relayA.url, alice, aliceToken);
    await registerIdentityOnRelay(relayB.url, bob, bobToken);
    const route = signedRoute(bob, await relayHello(relayB));
    const envelope = signedEnvelope(alice, bob);

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

    const pullResponse = await fetch(
      `${relayB.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.deviceId)}`,
      { headers: { authorization: `Bearer ${bobToken}` } },
    );
    assert.equal(pullResponse.status, 200);
    const pull = await pullResponse.json() as { envelopes: Array<{ id: string }> };
    assert.equal(pull.envelopes.length, 1);

    const relayAId = relayA.relayId;
    const relayBId = relayB.relayId;
    const relayAPort = Number(new URL(relayA.url).port);
    const relayBPort = Number(new URL(relayB.url).port);

    await relayA.close();
    relayA = null;

    const ackResponse = await fetch(`${relayB.url}/api/quantic/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${bobToken}`,
      },
      body: JSON.stringify({
        handle: bob.canonicalAddress,
        deviceId: bob.deviceId,
        ids: [pull.envelopes[0].id],
      }),
    });
    assert.equal(ackResponse.status, 200);
    const ack = await ackResponse.json() as { acknowledged: number; federationReceipts: number };
    assert.equal(ack.acknowledged, 1);
    assert.equal(ack.federationReceipts, 1);

    await relayB.close();
    relayB = null;

    relayA = await startIsolatedRelay(dataDirA, relayAPort);
    relayB = await startIsolatedRelay(dataDirB, relayBPort);
    assert.equal(relayA.relayId, relayAId);
    assert.equal(relayB.relayId, relayBId);

    const retryResponse = await fetch(`${relayA.url}/api/quantic/federation/send`, {
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
    const retryBody = await retryResponse.text();
    assert.equal(retryResponse.status, 202, retryBody);
    assert.equal((JSON.parse(retryBody) as { duplicate: boolean }).duplicate, true);

    const bobAfterRestart = await fetch(
      `${relayB.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.deviceId)}`,
      { headers: { authorization: `Bearer ${bobToken}` } },
    );
    assert.equal(bobAfterRestart.status, 200);
    assert.deepEqual((await bobAfterRestart.json() as { envelopes: unknown[] }).envelopes, []);

    const receipts = await eventuallyReceivesReceipt(relayA.url, alice, aliceToken);
    assert.equal(receipts.length, 1, "le reçu fédéré durable n'a pas été rejoué après redémarrage");
    assert.equal(receipts[0].clientMessageId, envelope.clientMessageId);
  } finally {
    if (relayA) await relayA.close();
    if (relayB) await relayB.close();
    await fs.rm(dataDirA, { recursive: true, force: true });
    await fs.rm(dataDirB, { recursive: true, force: true });
  }
});
