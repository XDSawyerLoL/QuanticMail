import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const ADDRESS = "alice~0123456789abcdef0123456789abcdef@quantic";

function manifest(sequence, marker = "same") {
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
      devices: [{
        deviceId: "d-1111111111",
        label: marker,
        publicKey: { kty: "EC", crv: "P-256", x: "enc-x", y: "enc-y" },
        deviceSigningPublicKey: { kty: "EC", crv: "P-256", x: "sign-x", y: "sign-y" },
        kind: "root",
        issuedAt: "2026-09-16T18:00:00.000Z",
      }],
      revocations: [],
      issuedAt: "2026-09-16T18:00:00.000Z",
    },
    signature: `sig-${sequence}-${marker}`,
  };
}

test("manifest GET route uses the shared canonical validator supporting V1.1 addresses", async () => {
  const source = await readFile(new URL("../app/api/quantic/manifest/route.ts", import.meta.url), "utf8");
  assert.match(source, /normalizeCanonicalAddress/);
  assert.doesNotMatch(source, /\[0-9a-f\]\{10\}@quantic/);
});

test("client sync chooses a newer remote manifest instead of republishing stale local state", async () => {
  const { decideManifestSync } = await import("../lib/quantic/manifest-sync-core.mjs");
  const result = decideManifestSync(manifest(2), manifest(3));
  assert.equal(result.action, "adopt-remote");
  assert.equal(result.manifest.payload.sequence, 3);
});

test("client sync publishes local state only when it is newer or remote is absent", async () => {
  const { decideManifestSync } = await import("../lib/quantic/manifest-sync-core.mjs");
  assert.equal(decideManifestSync(manifest(4), manifest(3)).action, "publish-local");
  assert.equal(decideManifestSync(manifest(4), null).action, "publish-local");
});

test("equal manifest sequence with different content is rejected as a fork", async () => {
  const { decideManifestSync } = await import("../lib/quantic/manifest-sync-core.mjs");
  assert.throws(() => decideManifestSync(manifest(4, "left"), manifest(4, "right")), /conflit|fork/i);
});

test("server authority helper rejects an incoming manifest older than durable state", async () => {
  const { reconcileManifestAuthority } = await import("../lib/quantic/manifest-authority-core.mjs");
  assert.throws(() => reconcileManifestAuthority(null, manifest(5), manifest(4)), /ancien|rollback|sequence/i);
});

test("server authority helper advances cached state to durable state before accepting incoming", async () => {
  const { reconcileManifestAuthority } = await import("../lib/quantic/manifest-authority-core.mjs");
  const accepted = reconcileManifestAuthority(manifest(2), manifest(5), manifest(6));
  assert.equal(accepted.payload.sequence, 6);
});
