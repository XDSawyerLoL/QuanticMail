import test from "node:test";
import assert from "node:assert/strict";
import { decideRegistryWrite } from "../lib/quantic/registry-write-core.mjs";

const ADDRESS = "alice~0123456789abcdef0123456789abcdef@quantic";
function manifest(sequence, label = "Root", signature = `sig-${sequence}`) {
  return {
    format: "quantic-identity-manifest",
    version: 1,
    payload: {
      version: 1,
      sequence,
      canonicalAddress: ADDRESS,
      handle: "alice",
      fingerprint: "0123456789abcdef0123456789abcdef",
      identityPublicKey: { kty: "EC", crv: "P-256", x: "enc-x", y: "enc-y" },
      identitySigningPublicKey: { kty: "EC", crv: "P-256", x: "sign-x", y: "sign-y" },
      devices: [{ deviceId: "d-1111111111", label, publicKey: { kty: "EC", crv: "P-256", x: "enc-x", y: "enc-y" }, deviceSigningPublicKey: { kty: "EC", crv: "P-256", x: "sign-x", y: "sign-y" }, kind: "root", issuedAt: "2026-09-16T18:00:00.000Z" }],
      revocations: [],
      issuedAt: "2026-09-16T18:00:00.000Z",
    },
    signature,
  };
}

test("registry refuses to overwrite a newer checkpoint", () => {
  assert.throws(() => decideRegistryWrite(manifest(5), manifest(4)), /newer|ancien|sequence/i);
});

test("registry refuses a fork at the same sequence", () => {
  assert.throws(() => decideRegistryWrite(manifest(5, "Root A"), manifest(5, "Root B")), /conflit|fork|sequence/i);
});

test("same manifest payload with another valid signature is unchanged", () => {
  assert.equal(decideRegistryWrite(manifest(5, "Root", "sig-a"), manifest(5, "Root", "sig-b")), "unchanged");
});

test("higher sequence is writable", () => {
  assert.equal(decideRegistryWrite(manifest(5), manifest(6)), "write");
});
