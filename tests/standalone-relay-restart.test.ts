import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  startRelayServer,
  type RunningRelayServer,
} from "../standalone-relay/server.ts";

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
    signing,
    publicKey: encryption.publicKey.export({ format: "jwk" }),
    signingPublicKey: signing.publicKey.export({ format: "jwk" }),
  };
}

async function registerUser(baseUrl: string, handle: string) {
  const keys = identityKeys();
  const authToken = `${handle}-restart-token-`.padEnd(56, handle[0] ?? "x");
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
  const challenge = await json(challengeResponse);
  const signature = sign(
    "sha256",
    Buffer.from(String(challenge.challenge), "utf8"),
    { key: keys.signing.privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64");

  const registrationResponse = await fetch(`${baseUrl}/api/quantic/register`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({
      handle,
      publicKey: keys.publicKey,
      signingPublicKey: keys.signingPublicKey,
      authToken,
      challenge: challenge.challenge,
      signature,
    }),
  });
  assert.equal(registrationResponse.status, 201);
  const registered = await json(registrationResponse);

  return {
    authToken,
    publicKey: keys.publicKey,
    canonicalAddress: String(registered.canonicalAddress),
    rootDeviceId: String(registered.rootDeviceId),
  };
}

async function startOn(dataDir: string) {
  return startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
}

test("encrypted queue, acknowledgement, and receipt survive complete relay restarts", async () => {
  const dataDir = await fs.mkdtemp(join(tmpdir(), "quantic-relay-restart-"));
  let relay: RunningRelayServer | null = null;

  try {
    relay = await startOn(dataDir);
    const alice = await registerUser(relay.url, "alice");
    const bob = await registerUser(relay.url, "bob");

    const sendResponse = await fetch(`${relay.url}/api/quantic/send`, {
      method: "POST",
      headers: jsonHeaders(alice.authToken),
      body: JSON.stringify({
        clientMessageId: "msg-restart-0001",
        from: alice.canonicalAddress,
        fromDeviceId: alice.rootDeviceId,
        to: bob.canonicalAddress,
        toDeviceId: bob.rootDeviceId,
        ciphertext: "opaque-test-ciphertext",
        iv: "opaque-test-iv",
        ephemeralPublicKey: alice.publicKey,
      }),
    });
    assert.equal(sendResponse.status, 202);

    await relay.close();
    relay = null;

    relay = await startOn(dataDir);
    const bobPull = await fetch(
      `${relay.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.rootDeviceId)}`,
      { headers: { authorization: `Bearer ${bob.authToken}` } },
    );
    assert.equal(bobPull.status, 200);
    const bobPullBody = await json(bobPull);
    const envelopes = bobPullBody.envelopes as Array<Record<string, unknown>>;
    assert.equal(envelopes.length, 1);
    assert.equal(envelopes[0].clientMessageId, "msg-restart-0001");
    const envelopeId = String(envelopes[0].id);

    const ackResponse = await fetch(`${relay.url}/api/quantic/ack`, {
      method: "POST",
      headers: jsonHeaders(bob.authToken),
      body: JSON.stringify({
        handle: bob.canonicalAddress,
        deviceId: bob.rootDeviceId,
        ids: [envelopeId],
      }),
    });
    assert.equal(ackResponse.status, 200);
    assert.equal((await json(ackResponse)).acknowledged, 1);

    await relay.close();
    relay = null;

    relay = await startOn(dataDir);
    const bobAfterAck = await fetch(
      `${relay.url}/api/quantic/pull?handle=${encodeURIComponent(bob.canonicalAddress)}&deviceId=${encodeURIComponent(bob.rootDeviceId)}`,
      { headers: { authorization: `Bearer ${bob.authToken}` } },
    );
    assert.equal(bobAfterAck.status, 200);
    assert.deepEqual((await json(bobAfterAck)).envelopes, []);

    const aliceReceipts = await fetch(
      `${relay.url}/api/quantic/receipts?handle=${encodeURIComponent(alice.canonicalAddress)}&deviceId=${encodeURIComponent(alice.rootDeviceId)}`,
      { headers: { authorization: `Bearer ${alice.authToken}` } },
    );
    assert.equal(aliceReceipts.status, 200);
    const receiptBody = await json(aliceReceipts);
    const receipts = receiptBody.receipts as Array<Record<string, unknown>>;
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].clientMessageId, "msg-restart-0001");
    const receiptId = String(receipts[0].id);

    const receiptAck = await fetch(`${relay.url}/api/quantic/receipts`, {
      method: "POST",
      headers: jsonHeaders(alice.authToken),
      body: JSON.stringify({
        handle: alice.canonicalAddress,
        deviceId: alice.rootDeviceId,
        ids: [receiptId],
      }),
    });
    assert.equal(receiptAck.status, 200);
    assert.equal((await json(receiptAck)).acknowledged, 1);

    await relay.close();
    relay = null;

    relay = await startOn(dataDir);
    const finalReceipts = await fetch(
      `${relay.url}/api/quantic/receipts?handle=${encodeURIComponent(alice.canonicalAddress)}&deviceId=${encodeURIComponent(alice.rootDeviceId)}`,
      { headers: { authorization: `Bearer ${alice.authToken}` } },
    );
    assert.equal(finalReceipts.status, 200);
    assert.deepEqual((await json(finalReceipts)).receipts, []);
  } finally {
    if (relay) await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
