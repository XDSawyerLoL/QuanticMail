import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { startRelayServer } from "../standalone-relay/server.ts";

async function tempDir() {
  return fs.mkdtemp(join(tmpdir(), "quantic-relay-server-"));
}

test("standalone server binds a free port, serves health, and flushes state on close", async () => {
  const dataDir = await tempDir();
  try {
    const relay = await startRelayServer({
      host: "127.0.0.1",
      port: 0,
      dataDir,
    });

    assert.equal(relay.host, "127.0.0.1");
    assert.ok(Number.isInteger(relay.port));
    assert.ok(relay.port > 0);
    assert.equal(relay.url, `http://127.0.0.1:${relay.port}`);

    const health = await fetch(`${relay.url}/api/quantic/health`);
    assert.equal(health.status, 200);
    const body = (await health.json()) as Record<string, unknown>;
    assert.equal(body.protocol, "quantic-relay/1");

    await relay.close();

    const durable = JSON.parse(
      await fs.readFile(join(dataDir, "relay-state.json"), "utf8"),
    ) as Record<string, unknown>;
    assert.equal(durable.format, "quantic-relay-state");
    assert.equal(durable.version, 2);
  } finally {
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("server refuses to start when durable relay state is corrupt", async () => {
  const dataDir = await tempDir();
  try {
    await fs.writeFile(join(dataDir, "relay-state.json"), "{not-json", "utf8");

    await assert.rejects(
      () => startRelayServer({ host: "127.0.0.1", port: 0, dataDir }),
      /relay-state\.json/i,
    );
  } finally {
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("close is idempotent and never performs a second concurrent shutdown", async () => {
  const dataDir = await tempDir();
  try {
    const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
    await Promise.all([relay.close(), relay.close()]);

    const durable = JSON.parse(
      await fs.readFile(join(dataDir, "relay-state.json"), "utf8"),
    ) as Record<string, unknown>;
    assert.equal(durable.version, 2);
  } finally {
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
