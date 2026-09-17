import test from "node:test";
import assert from "node:assert/strict";

import { registryCheckpointMessage } from "../lib/quantic/registry-commit.mjs";

test("registry checkpoint commit message never exposes canonical address", () => {
  const canonicalAddress = "alice~12345678901234567890123456789012@quantic";
  const path = "registry/identities/abcdef0123456789.json";
  const message = registryCheckpointMessage(path, 42);

  assert.equal(message.includes(canonicalAddress), false);
  assert.equal(message.includes("alice"), false);
  assert.match(message, /^registry: checkpoint [0-9a-f]+ #42$/);
});
