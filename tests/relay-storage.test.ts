import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { createEmptyRelayState } from "../lib/quantic/relay-state.ts";
import { createFileRelayStateStore } from "../standalone-relay/storage.ts";

async function tempDir() {
  return fs.mkdtemp(join(tmpdir(), "quantic-relay-"));
}

test("file store returns null when no state file exists", async () => {
  const dir = await tempDir();
  try {
    const store = createFileRelayStateStore(dir);
    assert.equal(await store.load(), null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("file store persists and reloads versioned state", async () => {
  const dir = await tempDir();
  try {
    const store = createFileRelayStateStore(dir);
    const state = createEmptyRelayState("2026-09-16T00:00:00.000Z");

    await store.save(state);

    assert.deepEqual(await store.load(), state);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("relay state file is owner-only on POSIX", { skip: process.platform === "win32" }, async () => {
  const dir = await tempDir();
  try {
    const store = createFileRelayStateStore(dir);
    await store.save(createEmptyRelayState("2026-09-16T00:00:00.000Z"));

    const stat = await fs.stat(join(dir, "relay-state.json"));
    assert.equal(stat.mode & 0o777, 0o600);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("invalid JSON is rejected instead of treated as an empty relay", async () => {
  const dir = await tempDir();
  try {
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(join(dir, "relay-state.json"), "{ definitely-not-json", "utf8");
    const store = createFileRelayStateStore(dir);

    await assert.rejects(() => store.load(), /relay-state\.json/i);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("failed atomic replace preserves the previous durable state", async () => {
  const dir = await tempDir();
  try {
    const store = createFileRelayStateStore(dir);
    const first = createEmptyRelayState("2026-09-16T00:00:00.000Z");
    await store.save(first);

    const failingFs = {
      mkdir: fs.mkdir,
      open: fs.open,
      readFile: fs.readFile,
      rm: fs.rm,
      rename: async () => {
        throw new Error("simulated rename failure");
      },
    };
    const failingStore = createFileRelayStateStore(dir, failingFs);
    const second = createEmptyRelayState("2026-09-16T01:00:00.000Z");

    await assert.rejects(() => failingStore.save(second), /rename failure/i);
    assert.deepEqual(await store.load(), first);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
