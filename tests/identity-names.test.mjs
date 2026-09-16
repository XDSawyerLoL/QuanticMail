import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const key = { kty: "EC", crv: "P-256", x: "server-x", y: "server-y" };
const digest = createHash("sha256").update("P-256:server-x:server-y").digest("hex");

async function loadHelper() {
  let helper;
  await assert.doesNotReject(async () => {
    helper = (await import("../lib/quantic/identity-names.mjs")).identityNamesForKey;
  });
  return helper;
}

test("server defaults to legacy 10-hex identity when no fingerprint is requested", async () => {
  const identityNamesForKey = await loadHelper();
  const result = identityNamesForKey("alice", key);
  assert.equal(result.fingerprint, digest.slice(0, 10));
  assert.equal(result.canonicalAddress, `alice~${digest.slice(0, 10)}@quantic`);
});

test("server accepts a matching strong 32-hex requested fingerprint", async () => {
  const identityNamesForKey = await loadHelper();
  const strong = digest.slice(0, 32);
  const result = identityNamesForKey("alice", key, strong);
  assert.equal(result.fingerprint, strong);
  assert.equal(result.canonicalAddress, `alice~${strong}@quantic`);
});

test("server accepts a matching legacy requested fingerprint", async () => {
  const identityNamesForKey = await loadHelper();
  const legacy = digest.slice(0, 10);
  assert.equal(identityNamesForKey("alice", key, legacy).fingerprint, legacy);
});

test("server rejects a requested fingerprint that does not match the signing key", async () => {
  const identityNamesForKey = await loadHelper();
  assert.throws(
    () => identityNamesForKey("alice", key, "ffffffffffffffffffffffffffffffff"),
    /empreinte.*correspond/i,
  );
});
