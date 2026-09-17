import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { RelayError } from "../lib/quantic/relay.ts";
import { createDirectSignalingRequestHandler } from "../standalone-relay/direct-signaling.ts";

const ALICE = "alice.direct~0123456789abcdef0123456789abcdef@quantic";
const BOB = "bob.direct~abcdef0123456789abcdef0123456789@quantic";
const ALICE_DEVICE = "d-0123456789abcdef0123456789abcdef";
const BOB_DEVICE = "d-abcdef0123456789abcdef0123456789";

function auth(locator: string, token: string | null, deviceId?: string | null) {
  const expected = locator === ALICE
    ? { token: "alice-token", deviceId: ALICE_DEVICE }
    : locator === BOB
      ? { token: "bob-token", deviceId: BOB_DEVICE }
      : null;
  if (!expected || token !== expected.token || deviceId !== expected.deviceId) {
    throw new RelayError("Authentification directe invalide.", 401);
  }
  return { canonicalAddress: locator, deviceId: expected.deviceId };
}

async function withServer(
  run: (baseUrl: string, advance: (ms: number) => void) => Promise<void>,
  options: { maxQueue?: number } = {},
) {
  let now = Date.parse("2026-09-17T12:00:00.000Z");
  const handler = createDirectSignalingRequestHandler({
    authenticate: auth,
    now: () => now,
    maxQueue: options.maxQueue,
  });
  const server = createServer((request, response) => { void handler(request, response); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No test port");
  try {
    await run(`http://127.0.0.1:${address.port}`, (ms) => { now += ms; });
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

function encryptedSignal() {
  return {
    ciphertext: "Y2lwaGVydGV4dA==",
    iv: "MDEyMzQ1Njc4OWFi",
    ephemeralPublicKey: { kty: "EC", crv: "P-256", x: "x-value", y: "y-value" },
  };
}

async function post(baseUrl: string, path: string, token: string | null, body: unknown) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

test("direct signaling rejects unauthenticated and cross-device polling", async () => {
  await withServer(async (baseUrl) => {
    const unauthorized = await post(baseUrl, "/api/quantic/direct/send", null, {
      from: ALICE,
      fromDeviceId: ALICE_DEVICE,
      to: BOB,
      toDeviceId: BOB_DEVICE,
      type: "offer",
      encrypted: encryptedSignal(),
    });
    assert.equal(unauthorized.status, 401);

    const crossPoll = await fetch(
      `${baseUrl}/api/quantic/direct/poll?handle=${encodeURIComponent(ALICE)}&deviceId=${encodeURIComponent(ALICE_DEVICE)}`,
      { headers: { authorization: "Bearer bob-token" } },
    );
    assert.equal(crossPoll.status, 401);
  });
});

test("direct signaling carries only bounded encrypted rendezvous payloads and expires them", async () => {
  await withServer(async (baseUrl, advance) => {
    const sent = await post(baseUrl, "/api/quantic/direct/send", "alice-token", {
      from: ALICE,
      fromDeviceId: ALICE_DEVICE,
      to: BOB,
      toDeviceId: BOB_DEVICE,
      type: "offer",
      encrypted: encryptedSignal(),
    });
    assert.equal(sent.status, 202, await sent.text());

    const poll = await fetch(
      `${baseUrl}/api/quantic/direct/poll?handle=${encodeURIComponent(BOB)}&deviceId=${encodeURIComponent(BOB_DEVICE)}`,
      { headers: { authorization: "Bearer bob-token" } },
    );
    assert.equal(poll.status, 200);
    const first = await poll.json() as { signals: Array<{ type: string; encrypted: unknown }> };
    assert.equal(first.signals.length, 1);
    assert.equal(first.signals[0].type, "offer");
    assert.equal("sdp" in (first.signals[0] as object), false);

    await post(baseUrl, "/api/quantic/direct/send", "alice-token", {
      from: ALICE,
      fromDeviceId: ALICE_DEVICE,
      to: BOB,
      toDeviceId: BOB_DEVICE,
      type: "ice",
      encrypted: encryptedSignal(),
    });
    advance(61_000);
    const expired = await fetch(
      `${baseUrl}/api/quantic/direct/poll?handle=${encodeURIComponent(BOB)}&deviceId=${encodeURIComponent(BOB_DEVICE)}`,
      { headers: { authorization: "Bearer bob-token" } },
    );
    const empty = await expired.json() as { signals: unknown[] };
    assert.deepEqual(empty.signals, []);
  });
});

test("direct signaling bounds each device queue to prevent relay flooding", async () => {
  await withServer(async (baseUrl) => {
    for (let index = 0; index < 2; index += 1) {
      const response = await post(baseUrl, "/api/quantic/direct/send", "alice-token", {
        from: ALICE,
        fromDeviceId: ALICE_DEVICE,
        to: BOB,
        toDeviceId: BOB_DEVICE,
        type: "ice",
        encrypted: encryptedSignal(),
      });
      assert.equal(response.status, 202);
    }
    const flooded = await post(baseUrl, "/api/quantic/direct/send", "alice-token", {
      from: ALICE,
      fromDeviceId: ALICE_DEVICE,
      to: BOB,
      toDeviceId: BOB_DEVICE,
      type: "ice",
      encrypted: encryptedSignal(),
    });
    assert.equal(flooded.status, 429);
  }, { maxQueue: 2 });
});
