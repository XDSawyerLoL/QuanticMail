import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";

import {
  createEmptyRelayState,
  restoreRelayState,
  type RelayPersistentState,
} from "../lib/quantic/relay-state.ts";
import { createRelayRequestHandler, MAX_REQUEST_BYTES } from "../standalone-relay/http.ts";
import { RelayRuntime, type RelayStateStore } from "../standalone-relay/runtime.ts";

type DeviceCertificatePayloadFixture = {
  canonicalAddress: string;
  handle: string;
  fingerprint: string;
  identityPublicKey: JsonWebKey;
  identitySigningPublicKey: JsonWebKey;
  deviceId: string;
  deviceLabel: string;
  devicePublicKey: JsonWebKey;
  deviceSigningPublicKey: JsonWebKey;
  issuedAt: string;
};

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
  const server = createServer((request, response) => {
    void handler(request, response);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const baseUrl = `http://127.0.0.1:${address.port}`;
  try {
    await run(baseUrl);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

function jsonHeaders(token?: string) {
  return {
    "content-type": "application/json",
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

async function json(response: Response) {
  return response.json() as Promise<Record<string, unknown>>;
}

function identityKeys() {
  const encryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    encryption,
    signing,
    publicKey: encryption.publicKey.export({ format: "jwk" }),
    signingPublicKey: signing.publicKey.export({ format: "jwk" }),
  };
}

async function registerUser(baseUrl: string, handle: string) {
  const keys = identityKeys();
  const authToken = `${handle}-token-`.padEnd(48, handle[0] ?? "x");
  const challengeResponse = await fetch(`${baseUrl}/api/quantic/challenge`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      handle,
      publicKey: keys.publicKey,
      signingPublicKey: keys.signingPublicKey,
    }),
  });
  assert.equal(challengeResponse.status, 201);
  const challengeBody = await json(challengeResponse);
  const signature = sign(
    "sha256",
    Buffer.from(String(challengeBody.challenge), "utf8"),
    { key: keys.signing.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");

  const registerResponse = await fetch(`${baseUrl}/api/quantic/register`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      handle,
      publicKey: keys.publicKey,
      signingPublicKey: keys.signingPublicKey,
      authToken,
      challenge: challengeBody.challenge,
      signature,
    }),
  });
  assert.equal(registerResponse.status, 201);
  const registered = await json(registerResponse);
  return {
    keys,
    authToken,
    canonicalAddress: String(registered.canonicalAddress),
    fingerprint: String(registered.fingerprint),
    rootDeviceId: String(registered.rootDeviceId),
  };
}

function certificateMessage(payload: DeviceCertificatePayloadFixture) {
  return [
    "quantic-device-certificate-v1",
    payload.canonicalAddress,
    payload.handle,
    payload.fingerprint,
    `P-256:${payload.identityPublicKey.x}:${payload.identityPublicKey.y}`,
    `P-256:${payload.identitySigningPublicKey.x}:${payload.identitySigningPublicKey.y}`,
    payload.deviceId,
    payload.deviceLabel,
    `P-256:${payload.devicePublicKey.x}:${payload.devicePublicKey.y}`,
    `P-256:${payload.deviceSigningPublicKey.x}:${payload.deviceSigningPublicKey.y}`,
    payload.issuedAt,
  ].join("\n");
}

test("health and CORS expose Quantic Relay V1", async () => {
  await withRelay(async (baseUrl) => {
    const health = await fetch(`${baseUrl}/api/quantic/health`);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get("access-control-allow-origin"), "*");
    const body = await json(health);
    assert.equal(body.ok, true);
    assert.equal(body.protocol, "quantic-relay/1");
    assert.equal(body.service, "Quantic Network Relay");
    assert.ok(Number.isFinite(Date.parse(String(body.time))));

    const preflight = await fetch(`${baseUrl}/api/quantic/send`, { method: "OPTIONS" });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-methods"), "GET, POST, OPTIONS");
    assert.equal(preflight.headers.get("access-control-allow-headers"), "Content-Type, Authorization");

    assert.equal((await fetch(`${baseUrl}/api/quantic/unknown`)).status, 404);
    assert.equal((await fetch(`${baseUrl}/api/quantic/send`)).status, 405);
  });
});

test("standalone adapter preserves the complete current Relay V1 HTTP flow", async () => {
  await withRelay(async (baseUrl) => {
    const alice = await registerUser(baseUrl, "alice");
    const bob = await registerUser(baseUrl, "bob");

    const resolved = await fetch(
      `${baseUrl}/api/quantic/resolve?handle=${encodeURIComponent(bob.canonicalAddress)}`,
    );
    assert.equal(resolved.status, 200);
    const resolvedBob = await json(resolved);
    assert.equal(resolvedBob.canonicalAddress, bob.canonicalAddress);

    const linkedEncryption = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const linkedSigning = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const linkedPublicKey = linkedEncryption.publicKey.export({ format: "jwk" });
    const linkedSigningPublicKey = linkedSigning.publicKey.export({ format: "jwk" });
    const deviceId = `d-${createHash("sha256")
      .update(`P-256:${linkedPublicKey.x}:${linkedPublicKey.y}`)
      .digest("hex")
      .slice(0, 10)}`;
    const payload: DeviceCertificatePayloadFixture = {
      canonicalAddress: alice.canonicalAddress,
      handle: "alice",
      fingerprint: alice.fingerprint,
      identityPublicKey: alice.keys.publicKey,
      identitySigningPublicKey: alice.keys.signingPublicKey,
      deviceId,
      deviceLabel: "Alice laptop",
      devicePublicKey: linkedPublicKey,
      deviceSigningPublicKey: linkedSigningPublicKey,
      issuedAt: new Date().toISOString(),
    };
    const certificate = {
      format: "quantic-device-certificate",
      version: 1,
      payload: { version: 1, ...payload },
      signature: sign(
        "sha256",
        Buffer.from(certificateMessage(payload), "utf8"),
        { key: alice.keys.signing.privateKey, dsaEncoding: "ieee-p1363" },
      ).toString("base64"),
    };
    const deviceResponse = await fetch(`${baseUrl}/api/quantic/devices/register`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ certificate, authToken: "linked-device-token".padEnd(48, "x") }),
    });
    assert.equal(deviceResponse.status, 201);
    assert.equal((await json(deviceResponse)).deviceId, deviceId);

    const sendResponse = await fetch(`${baseUrl}/api/quantic/send`, {
      method: "POST",
      headers: jsonHeaders(alice.authToken),
      body: JSON.stringify({
        clientMessageId: "msg-http-0001",
        from: alice.canonicalAddress,
        fromDeviceId: alice.rootDeviceId,
        to: bob.canonicalAddress,
        toDeviceId: bob.rootDeviceId,
        ciphertext: "opaque-http-ciphertext",
        iv: "opaque-http-iv",
        ephemeralPublicKey: alice.keys.publicKey,
      }),
    });
    assert.equal(sendResponse.status, 202);

    const pullResponse = await fetch(
      `${baseUrl}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.rootDeviceId)}`,
      { headers: { authorization: `Bearer ${bob.authToken}` } },
    );
    assert.equal(pullResponse.status, 200);
    const envelopes = (await json(pullResponse)).envelopes as Array<Record<string, unknown>>;
    assert.equal(envelopes.length, 1);
    assert.equal(envelopes[0].clientMessageId, "msg-http-0001");

    const ackResponse = await fetch(`${baseUrl}/api/quantic/ack`, {
      method: "POST",
      headers: jsonHeaders(bob.authToken),
      body: JSON.stringify({
        handle: bob.canonicalAddress,
        deviceId: bob.rootDeviceId,
        ids: [envelopes[0].id],
      }),
    });
    assert.equal(ackResponse.status, 200);
    assert.equal((await json(ackResponse)).acknowledged, 1);

    const receiptsResponse = await fetch(
      `${baseUrl}/api/quantic/receipts?handle=${encodeURIComponent(alice.canonicalAddress)}&deviceId=${encodeURIComponent(alice.rootDeviceId)}`,
      { headers: { authorization: `Bearer ${alice.authToken}` } },
    );
    assert.equal(receiptsResponse.status, 200);
    const receipts = (await json(receiptsResponse)).receipts as Array<Record<string, unknown>>;
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].clientMessageId, "msg-http-0001");

    const receiptAck = await fetch(`${baseUrl}/api/quantic/receipts`, {
      method: "POST",
      headers: jsonHeaders(alice.authToken),
      body: JSON.stringify({
        handle: alice.canonicalAddress,
        deviceId: alice.rootDeviceId,
        ids: [receipts[0].id],
      }),
    });
    assert.equal(receiptAck.status, 200);
    assert.equal((await json(receiptAck)).acknowledged, 1);
  });
});

test("HTTP adapter preserves RelayError status and rejects malformed or oversized JSON", async () => {
  await withRelay(async (baseUrl) => {
    const unauthorized = await fetch(`${baseUrl}/api/quantic/pull?handle=missing@quantic`);
    assert.equal(unauthorized.status, 401);

    const malformed = await fetch(`${baseUrl}/api/quantic/challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{bad-json",
    });
    assert.equal(malformed.status, 400);

    const oversized = await fetch(`${baseUrl}/api/quantic/challenge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(MAX_REQUEST_BYTES + 1) }),
    });
    assert.equal(oversized.status, 413);
  });
});
