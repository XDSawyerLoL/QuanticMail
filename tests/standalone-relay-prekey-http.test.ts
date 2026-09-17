import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";

import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { canonicalPreKeyText } from "../lib/quantic/prekey-core.mjs";
import { createEmptyRelayState, restoreRelayState, type RelayPersistentState } from "../lib/quantic/relay-state.ts";
import { createRelayRequestHandler } from "../standalone-relay/http.ts";
import { RelayRuntime, type RelayStateStore } from "../standalone-relay/runtime.ts";

function memoryStore(): RelayStateStore {
  let durable: RelayPersistentState | null = null;
  return {
    async load() { return durable ? JSON.parse(JSON.stringify(durable)) : null; },
    async save(state) { durable = JSON.parse(JSON.stringify(state)); },
  };
}

async function withRelay(run: (baseUrl: string) => Promise<void>) {
  restoreRelayState(createEmptyRelayState());
  const runtime = new RelayRuntime(memoryStore());
  await runtime.initialize();
  const handler = createRelayRequestHandler(runtime);
  const server = createServer((request, response) => void handler(request, response));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

async function body(response: Response) {
  return response.json() as Promise<Record<string, unknown>>;
}

async function register(baseUrl: string, handle: string) {
  const encryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = encryption.publicKey.export({ format: "jwk" });
  const signingPublicKey = signing.publicKey.export({ format: "jwk" });
  const authToken = `${handle}-token`.padEnd(48, "x");
  const challengeResponse = await fetch(`${baseUrl}/api/quantic/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle, publicKey, signingPublicKey }),
  });
  const challenge = await body(challengeResponse);
  const signature = sign(
    "sha256",
    Buffer.from(String(challenge.challenge), "utf8"),
    { key: signing.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  const registeredResponse = await fetch(`${baseUrl}/api/quantic/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle, publicKey, signingPublicKey, authToken, challenge: challenge.challenge, signature }),
  });
  assert.equal(registeredResponse.status, 201);
  const registered = await body(registeredResponse);
  return {
    signing,
    publicKey,
    signingPublicKey,
    authToken,
    canonicalAddress: String(registered.canonicalAddress),
    fingerprint: String(registered.fingerprint),
    rootDeviceId: String(registered.rootDeviceId),
  };
}

async function publishManifest(baseUrl: string, user: Awaited<ReturnType<typeof register>>) {
  const payload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress: user.canonicalAddress,
    handle: user.canonicalAddress.split("~")[0],
    fingerprint: user.fingerprint,
    identityPublicKey: user.publicKey,
    identitySigningPublicKey: user.signingPublicKey,
    devices: [{
      deviceId: user.rootDeviceId,
      label: "Root",
      publicKey: user.publicKey,
      deviceSigningPublicKey: user.signingPublicKey,
      kind: "root" as const,
      issuedAt: "2026-09-16T20:00:00.000Z",
    }],
    revocations: [],
    issuedAt: "2026-09-16T20:00:00.000Z",
  };
  const manifest = {
    format: "quantic-identity-manifest" as const,
    version: 1 as const,
    payload,
    signature: sign(
      "sha256",
      Buffer.from(canonicalManifestText(payload), "utf8"),
      { key: user.signing.privateKey, dsaEncoding: "ieee-p1363" },
    ).toString("base64"),
  };
  const response = await fetch(`${baseUrl}/api/quantic/manifest`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ manifest }),
  });
  assert.equal(response.status, 200);
}

test("standalone relay publishes, counts, and atomically claims one-time prekeys", async () => {
  await withRelay(async (baseUrl) => {
    const alice = await register(baseUrl, "alice");
    const bob = await register(baseUrl, "bob");
    await publishManifest(baseUrl, alice);
    await publishManifest(baseUrl, bob);

    const prekeyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const unsigned = {
      version: 1 as const,
      canonicalAddress: alice.canonicalAddress,
      deviceId: alice.rootDeviceId,
      preKeyId: "a1".repeat(16),
      publicKey: prekeyPair.publicKey.export({ format: "jwk" }),
      createdAt: "2026-09-16T20:00:00.000Z",
      expiresAt: "2027-09-16T20:00:00.000Z",
    };
    const record = {
      ...unsigned,
      signature: sign(
        "sha256",
        Buffer.from(canonicalPreKeyText(unsigned), "utf8"),
        { key: alice.signing.privateKey, dsaEncoding: "ieee-p1363" },
      ).toString("base64"),
    };

    const publish = await fetch(`${baseUrl}/api/quantic/prekeys/publish`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${alice.authToken}`,
      },
      body: JSON.stringify({ handle: alice.canonicalAddress, deviceId: alice.rootDeviceId, records: [record] }),
    });
    assert.equal(publish.status, 200);
    assert.equal((await body(publish)).available, 1);

    const status = await fetch(
      `${baseUrl}/api/quantic/prekeys/status?handle=${encodeURIComponent(alice.canonicalAddress)}&deviceId=${encodeURIComponent(alice.rootDeviceId)}`,
      { headers: { authorization: `Bearer ${alice.authToken}` } },
    );
    assert.equal(status.status, 200);
    assert.equal((await body(status)).available, 1);

    const claim = await fetch(`${baseUrl}/api/quantic/prekeys/claim`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${bob.authToken}`,
      },
      body: JSON.stringify({
        from: bob.canonicalAddress,
        fromDeviceId: bob.rootDeviceId,
        to: alice.canonicalAddress,
        toDeviceId: alice.rootDeviceId,
      }),
    });
    assert.equal(claim.status, 200);
    assert.equal(((await body(claim)).prekey as { preKeyId: string }).preKeyId, record.preKeyId);

    const secondClaim = await fetch(`${baseUrl}/api/quantic/prekeys/claim`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${bob.authToken}`,
      },
      body: JSON.stringify({
        from: bob.canonicalAddress,
        fromDeviceId: bob.rootDeviceId,
        to: alice.canonicalAddress,
        toDeviceId: alice.rootDeviceId,
      }),
    });
    assert.equal(secondClaim.status, 404);

    const republish = await fetch(`${baseUrl}/api/quantic/prekeys/publish`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${alice.authToken}`,
      },
      body: JSON.stringify({ handle: alice.canonicalAddress, deviceId: alice.rootDeviceId, records: [record] }),
    });
    assert.equal(republish.status, 200);
    const republished = await body(republish);
    assert.equal(republished.accepted, 0);
    assert.equal(republished.consumedRejected, 1);
  });
});
