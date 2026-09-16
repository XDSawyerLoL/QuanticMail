import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { verifyRelayHello } from "../standalone-relay/identity.ts";
import { startRelayServer } from "../standalone-relay/server.ts";

async function tempDir() {
  return fs.mkdtemp(join(tmpdir(), "quantic-relay-federation-http-"));
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
