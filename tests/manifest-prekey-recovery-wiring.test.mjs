import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../components/quantic-network-v11-app.tsx", import.meta.url), "utf8");

test("V1.1 client wires automatic root manifest recovery", () => {
  assert.match(source, /shouldBootstrapRootManifest\(local\.role, err\.status\)/);
  assert.match(source, /const manifest = await createInitialManifest\(local\)/);
  assert.match(source, /return publishManifest\(local, manifest\)/);
});

test("V1.1 client wires static fallback for missing prekey manifest", () => {
  assert.match(source, /shouldUseStaticFallbackForPreKeyError\(err\.status, err\.message\)/);
  assert.match(source, /keyMode: "static-fallback"/);
});
