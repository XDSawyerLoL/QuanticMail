import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import * as registryPath from "../lib/quantic/registry-path.mjs";

type MinimalManifest = {
  payload: {
    handle: string;
    canonicalAddress: string;
  };
};

function manifest(handle: string, fingerprint: string): MinimalManifest {
  return {
    payload: {
      handle,
      canonicalAddress: `${handle}~${fingerprint}@quantic`,
    },
  };
}

test("normalizes a short @quantic handle without accepting canonical locators", () => {
  assert.equal(typeof registryPath.normalizeRegistryHandle, "function");
  assert.equal(registryPath.normalizeRegistryHandle("  Benoit.V3@Quantic  "), "benoit.v3");
  assert.throws(
    () => registryPath.normalizeRegistryHandle("benoit.v3~0123456789abcdef0123456789abcdef@quantic"),
    /court|handle/i,
  );
});

test("filters durable manifests by short handle and preserves ambiguity", () => {
  assert.equal(typeof registryPath.filterRegistryManifestsByHandle, "function");
  const first = manifest("benoit.v3", "0123456789abcdef0123456789abcdef");
  const second = manifest("benoit.v3", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  const other = manifest("alice", "fedcba9876543210fedcba9876543210");

  const matches = registryPath.filterRegistryManifestsByHandle("benoit.v3@quantic", [first, other, second]);
  assert.deepEqual(matches, [first, second]);
});

test("resolve API is wired to durable short-handle fallback", async () => {
  const source = await readFile(new URL("../app/api/quantic/resolve/route.ts", import.meta.url), "utf8");
  assert.match(source, /loadRegistryManifestsByHandle/);
  assert.match(source, /ambig/i);
});

test("mail client resolves recipients across configured relays and retries logical 404", async () => {
  const source = await readFile(new URL("../components/quantic-network-v11-app.tsx", import.meta.url), "utf8");
  assert.match(source, /relayFetchJson/);
  assert.match(source, /getRelayEndpoints/);
  assert.match(source, /retryStatuses:\s*\[404\]/);
});
