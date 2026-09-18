import test from "node:test";
import assert from "node:assert/strict";
import {
  shouldBootstrapRootManifest,
  shouldUseStaticFallbackForPreKeyError,
} from "../lib/quantic/recovery-policy.mjs";

test("root identity bootstraps a missing manifest after a 404", () => {
  assert.equal(shouldBootstrapRootManifest("root", 404), true);
  assert.equal(shouldBootstrapRootManifest("secondary", 404), false);
  assert.equal(shouldBootstrapRootManifest("root", 409), false);
});

test("prekey claim falls back only for absence/unavailability compatible with static delivery", () => {
  assert.equal(shouldUseStaticFallbackForPreKeyError(404, "not found"), true);
  assert.equal(
    shouldUseStaticFallbackForPreKeyError(
      409,
      "Les one-time prekeys nécessitent un manifeste V1 actif.",
    ),
    true,
  );
  assert.equal(shouldUseStaticFallbackForPreKeyError(409, "Conflit de manifeste."), false);
  assert.equal(shouldUseStaticFallbackForPreKeyError(401, "unauthorized"), false);
});
