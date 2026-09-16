import test from "node:test";
import assert from "node:assert/strict";
import { registryFilePath } from "../lib/quantic/registry-path.mjs";

test("registry path is deterministic and does not expose the address", () => {
  const address = "sansa~1234567890@quantic";
  const first = registryFilePath(address);
  const second = registryFilePath(address);

  assert.equal(first, second);
  assert.match(first, /^registry\/identities\/[0-9a-f]{64}\.json$/);
  assert.equal(first.includes("sansa"), false);
  assert.equal(first.includes("@"), false);
});

test("registry path normalizes canonical address case and whitespace", () => {
  assert.equal(
    registryFilePath("  Sansa~1234567890@Quantic  "),
    registryFilePath("sansa~1234567890@quantic"),
  );
});

test("registry path rejects non-canonical Quantic locators", () => {
  assert.throws(() => registryFilePath("sansa@quantic"), /canonique/i);
  assert.throws(() => registryFilePath("https://example.com"), /canonique/i);
});
