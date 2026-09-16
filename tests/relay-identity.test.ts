import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  loadOrCreateRelayIdentity,
  signRelayHello,
  verifyRelayHello,
} from "../standalone-relay/identity.ts";

async function tempDir(prefix: string) {
  return fs.mkdtemp(join(tmpdir(), prefix));
}

test("relay identity is stable across loads from the same data directory", async () => {
  const dataDir = await tempDir("quantic-relay-id-");
  try {
    const first = await loadOrCreateRelayIdentity(dataDir);
    const second = await loadOrCreateRelayIdentity(dataDir);

    assert.match(first.relayId, /^[0-9a-f]{64}$/);
    assert.equal(second.relayId, first.relayId);
    assert.deepEqual(second.publicKeyJwk, first.publicKeyJwk);
    assert.equal(second.privateKeyPem, first.privateKeyPem);

    const stat = await fs.stat(join(dataDir, "relay-identity.json"));
    if (process.platform !== "win32") assert.equal(stat.mode & 0o777, 0o600);
  } finally {
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("different relay data directories produce different relay identities", async () => {
  const firstDir = await tempDir("quantic-relay-id-a-");
  const secondDir = await tempDir("quantic-relay-id-b-");
  try {
    const first = await loadOrCreateRelayIdentity(firstDir);
    const second = await loadOrCreateRelayIdentity(secondDir);
    assert.notEqual(first.relayId, second.relayId);
  } finally {
    await fs.rm(firstDir, { recursive: true, force: true });
    await fs.rm(secondDir, { recursive: true, force: true });
  }
});

test("signed relay hello binds endpoint and caller nonce", async () => {
  const dataDir = await tempDir("quantic-relay-hello-");
  try {
    const identity = await loadOrCreateRelayIdentity(dataDir);
    const hello = signRelayHello(identity, "https://relay.example", "nonce-0123456789abcdef");

    assert.equal(verifyRelayHello(hello, "nonce-0123456789abcdef").relayId, identity.relayId);
    assert.throws(() => verifyRelayHello(hello, "nonce-wrong-0123456789"), /nonce/i);
    assert.throws(
      () => verifyRelayHello({ ...hello, endpoint: "https://evil.example" }, "nonce-0123456789abcdef"),
      /signature|preuve/i,
    );
  } finally {
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
