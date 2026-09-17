import assert from "node:assert/strict";
import { fork, type ChildProcess } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { discoveryKey } from "../lib/quantic/discovery-core.mjs";
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

type IsolatedRelay = {
  url: string;
  relayId: string;
  close(): Promise<void>;
};

function childError(child: ChildProcess, stderr: string) {
  return new Error(`Processus Quantic Relay interrompu.${stderr ? `\n${stderr}` : ""}`);
}

async function startIsolatedRelay(dataDir: string, bootstrap: string[] = []): Promise<IsolatedRelay> {
  const childPath = fileURLToPath(new URL("./helpers/standalone-relay-child.ts", import.meta.url));
  const env = { ...process.env };
  delete env.QUANTIC_GITHUB_TOKEN;
  delete env.QUANTIC_GITHUB_OWNER;
  delete env.QUANTIC_GITHUB_REPO;
  delete env.QUANTIC_GITHUB_BRANCH;
  delete env.NEXT_PUBLIC_QUANTIC_BOOTSTRAP_URL;
  const child = fork(childPath, [], {
    execArgv: ["--experimental-transform-types"],
    env: {
      ...env,
      QUANTIC_TEST_RELAY_DATA_DIR: dataDir,
      QUANTIC_TEST_RELAY_BOOTSTRAP: bootstrap.join(","),
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
      reject(childError(child, stderr));
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
  const response = await fetch(`${relayUrl}/api/quantic/register`, {
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
  const text = await response.text();
  assert.equal(response.status, 201, text);
}

async function relayHello(relay: IsolatedRelay) {
  const nonce = `mesh-${createHash("sha256").update(relay.url).digest("hex").slice(0, 24)}`;
  const response = await fetch(`${relay.url}/api/quantic/federation/hello`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce }),
  });
  assert.equal(response.status, 200);
  return verifyRelayHello(await response.json(), nonce, relay.relayId);
}

function signedRoute(recipient: ReturnType<typeof signedIdentity>, relay: Awaited<ReturnType<typeof relayHello>>) {
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

async function signedEncryptedEnvelope(sender: ReturnType<typeof signedIdentity>, recipient: ReturnType<typeof signedIdentity>) {
  const plaintext = {
    subject: "Discovery Mesh",
    body: "A found B through C without Render or GitHub",
    marker: "offline-central-e2e-0001",
  };
  const encrypted = await encryptForRecipientCore(recipient.manifest.payload.identityPublicKey, plaintext);
  const envelope = {
    format: "quantic-envelope" as const,
    version: 2 as const,
    clientMessageId: "msg-discovery-offline-central-0001",
    from: sender.canonicalAddress,
    fromDeviceId: sender.deviceId,
    to: recipient.canonicalAddress,
    toDeviceId: recipient.deviceId,
    keyMode: "v1-static-fallback" as const,
    cryptoSuite: "QNT-P256-AES256GCM-1",
    classicalEphemeralPublicKey: encrypted.ephemeralPublicKey,
    iv: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    signatures: { p256Device: "placeholder" },
  };
  envelope.signatures.p256Device = sign(
    "sha256",
    Buffer.from(canonicalPortableEnvelopeText(envelope), "utf8"),
    { key: sender.owner.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  return { envelope, plaintext };
}

async function peersFor(relayUrl: string, key: string) {
  const response = await fetch(`${relayUrl}/api/quantic/discovery/peers?key=${key}`);
  const text = await response.text();
  assert.equal(response.status, 200, text);
  return JSON.parse(text) as { peers: Array<{ relayId: string; endpoint: string }> };
}

test("A discovers Bob on B through bootstrap C and Federation delivers without Render or GitHub", async () => {
  const dirs = await Promise.all(["a", "b", "c"].map((name) => fs.mkdtemp(join(tmpdir(), `quantic-mesh-${name}-`))));
  let relayA: IsolatedRelay | null = null;
  let relayB: IsolatedRelay | null = null;
  let relayC: IsolatedRelay | null = null;
  try {
    relayB = await startIsolatedRelay(dirs[1]);
    relayC = await startIsolatedRelay(dirs[2], [relayB.url]);
    relayA = await startIsolatedRelay(dirs[0], [relayC.url]);

    const alice = signedIdentity("aliceoffline");
    const bob = signedIdentity("boboffline");
    const aliceToken = "alice-offline-device-auth-token-0000000000000000000001";
    const bobToken = "bob-offline-device-auth-token-00000000000000000000001";
    await registerIdentityOnRelay(relayA.url, alice, aliceToken);
    await registerIdentityOnRelay(relayB.url, bob, bobToken);

    const route = signedRoute(bob, await relayHello(relayB));
    const publishResponse = await fetch(`${relayB.url}/api/quantic/discovery/publish`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ bundle: { identityManifest: bob.manifest, routeManifest: route } }),
    });
    const publishText = await publishResponse.text();
    assert.equal(publishResponse.status, 201, publishText);

    const key = discoveryKey("identity", bob.canonicalAddress);
    const peersA = await peersFor(relayA.url, key);
    const peersC = await peersFor(relayC.url, key);
    assert.deepEqual(peersA.peers.map((peer) => peer.relayId), [relayC.relayId]);
    assert.deepEqual(peersC.peers.map((peer) => peer.relayId), [relayB.relayId]);

    const directOnA = await fetch(`${relayA.url}/api/quantic/resolve?handle=${encodeURIComponent(bob.canonicalAddress)}`);
    assert.equal(directOnA.status, 404);

    const lookupResponse = await fetch(`${relayA.url}/api/quantic/discovery/lookup`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ canonicalAddress: bob.canonicalAddress }),
    });
    const lookupText = await lookupResponse.text();
    assert.equal(lookupResponse.status, 200, lookupText);
    const discovered = JSON.parse(lookupText) as {
      bundle: { identityManifest: typeof bob.manifest; routeManifest: typeof route } | null;
    };
    assert.equal(discovered.bundle?.identityManifest.payload.canonicalAddress, bob.canonicalAddress);
    assert.equal(discovered.bundle?.routeManifest.payload.relays[0].relayId, relayB.relayId);

    const { envelope, plaintext } = await signedEncryptedEnvelope(alice, bob);
    const sendResponse = await fetch(`${relayA.url}/api/quantic/federation/send`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${aliceToken}`,
      },
      body: JSON.stringify({
        senderIdentityManifest: alice.manifest,
        recipientIdentityManifest: discovered.bundle!.identityManifest,
        recipientRouteManifest: discovered.bundle!.routeManifest,
        envelope,
      }),
    });
    const sendText = await sendResponse.text();
    assert.equal(sendResponse.status, 202, sendText);

    const pullResponse = await fetch(
      `${relayB.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.deviceId)}`,
      { headers: { authorization: `Bearer ${bobToken}` } },
    );
    assert.equal(pullResponse.status, 200);
    const pull = await pullResponse.json() as {
      envelopes: Array<{ id: string; clientMessageId: string; ciphertext: string; iv: string; ephemeralPublicKey: JsonWebKey }>;
    };
    assert.equal(pull.envelopes.length, 1);
    const decrypted = await decryptEnvelopeCore(privateJwk(bob.encryption), pull.envelopes[0]);
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
        ids: [pull.envelopes[0].id],
      }),
    });
    const ackText = await ackResponse.text();
    assert.equal(ackResponse.status, 200, ackText);

    const receiptsResponse = await fetch(
      `${relayA.url}/api/quantic/receipts?handle=${encodeURIComponent(alice.canonicalAddress)}&deviceId=${encodeURIComponent(alice.deviceId)}`,
      { headers: { authorization: `Bearer ${aliceToken}` } },
    );
    assert.equal(receiptsResponse.status, 200);
    const receipts = await receiptsResponse.json() as { receipts: Array<{ clientMessageId: string }> };
    assert.equal(receipts.receipts.length, 1);
    assert.equal(receipts.receipts[0].clientMessageId, envelope.clientMessageId);
  } finally {
    await Promise.allSettled([relayA?.close(), relayC?.close(), relayB?.close()].filter(Boolean) as Promise<void>[]);
    await Promise.all(dirs.map((dir) => fs.rm(dir, { recursive: true, force: true })));
  }
});
