import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";

import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { createEmptyRelayState, restoreRelayState, type RelayPersistentState } from "../lib/quantic/relay-state.ts";
import { createRelayRequestHandler } from "../standalone-relay/http.ts";
import { RelayRuntime, type RelayStateStore } from "../standalone-relay/runtime.ts";

function memoryStore(): RelayStateStore {
  let durable: RelayPersistentState | null = null;
  return {
    async load() {
      return durable ? JSON.parse(JSON.stringify(durable)) : null;
    },
    async save(state) {
      durable = JSON.parse(JSON.stringify(state));
    },
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

async function json(response: Response) {
  return response.json() as Promise<Record<string, unknown>>;
}

async function registerUser(baseUrl: string, handle: string) {
  const encryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = encryption.publicKey.export({ format: "jwk" });
  const signingPublicKey = signing.publicKey.export({ format: "jwk" });
  const authToken = `${handle}-auth-token`.padEnd(48, "x");
  const challengeResponse = await fetch(`${baseUrl}/api/quantic/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle, publicKey, signingPublicKey }),
  });
  assert.equal(challengeResponse.status, 201);
  const challenge = await json(challengeResponse);
  const proof = sign(
    "sha256",
    Buffer.from(String(challenge.challenge), "utf8"),
    { key: signing.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");
  const response = await fetch(`${baseUrl}/api/quantic/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      handle,
      publicKey,
      signingPublicKey,
      authToken,
      challenge: challenge.challenge,
      signature: proof,
    }),
  });
  assert.equal(response.status, 201);
  const registered = await json(response);
  return {
    encryption,
    signing,
    publicKey,
    signingPublicKey,
    authToken,
    canonicalAddress: String(registered.canonicalAddress),
    fingerprint: String(registered.fingerprint),
    rootDeviceId: String(registered.rootDeviceId),
  };
}

function signedManifest(user: Awaited<ReturnType<typeof registerUser>>, sequence: number, label = "Root") {
  const payload = {
    version: 1 as const,
    sequence,
    canonicalAddress: user.canonicalAddress,
    handle: user.canonicalAddress.split("~")[0],
    fingerprint: user.fingerprint,
    identityPublicKey: user.publicKey,
    identitySigningPublicKey: user.signingPublicKey,
    devices: [{
      deviceId: user.rootDeviceId,
      label,
      publicKey: user.publicKey,
      deviceSigningPublicKey: user.signingPublicKey,
      kind: "root" as const,
      issuedAt: "2026-09-16T20:00:00.000Z",
    }],
    revocations: [],
    issuedAt: `2026-09-16T20:0${Math.min(sequence, 9)}:00.000Z`,
  };
  return {
    format: "quantic-identity-manifest" as const,
    version: 1 as const,
    payload,
    signature: sign(
      "sha256",
      Buffer.from(canonicalManifestText(payload), "utf8"),
      { key: user.signing.privateKey, dsaEncoding: "ieee-p1363" },
    ).toString("base64"),
  };
}

test("standalone relay publishes and reads a signed manifest durably", async () => {
  await withRelay(async (baseUrl) => {
    const alice = await registerUser(baseUrl, "alice");
    const manifest = signedManifest(alice, 1);
    const publish = await fetch(`${baseUrl}/api/quantic/manifest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest }),
    });
    assert.equal(publish.status, 200);

    const get = await fetch(`${baseUrl}/api/quantic/manifest?canonical=${encodeURIComponent(alice.canonicalAddress)}`);
    assert.equal(get.status, 200);
    const body = await json(get);
    assert.equal((body.manifest as { payload: { sequence: number } }).payload.sequence, 1);
  });
});

test("standalone manifest API rejects rollback and same-sequence forks", async () => {
  await withRelay(async (baseUrl) => {
    const alice = await registerUser(baseUrl, "alice");
    const initial = signedManifest(alice, 2);
    assert.equal((await fetch(`${baseUrl}/api/quantic/manifest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest: initial }),
    })).status, 200);

    const rollback = signedManifest(alice, 1);
    const rollbackResponse = await fetch(`${baseUrl}/api/quantic/manifest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest: rollback }),
    });
    assert.equal(rollbackResponse.status, 409);

    const fork = signedManifest(alice, 2, "Forked root label");
    const forkResponse = await fetch(`${baseUrl}/api/quantic/manifest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ manifest: fork }),
    });
    assert.equal(forkResponse.status, 409);
  });
});
