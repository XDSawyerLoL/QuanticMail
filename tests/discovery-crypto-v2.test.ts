import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalCryptoProfileText } from "../lib/quantic/crypto-profile-core.mjs";
import { discoveryKey } from "../lib/quantic/discovery-core.mjs";
import { canonicalRouteManifestText } from "../lib/quantic/federation-core.mjs";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import {
  generateMlDsa65KeyPair,
  generateMlKem768KeyPair,
  mlDsaSign,
} from "../lib/quantic/pqc-runtime-node.ts";
import { startRelayServer } from "../standalone-relay/server.ts";

function p256Pair() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicJwk(pair: ReturnType<typeof p256Pair>) {
  return pair.publicKey.export({ format: "jwk" });
}

function fingerprint(key: JsonWebKey, length = 32) {
  return createHash("sha256").update(`P-256:${key.x}:${key.y}`).digest("hex").slice(0, length);
}

function makeBundle(relayId: string, endpoint: string) {
  const owner = p256Pair();
  const encryption = p256Pair();
  const ownerPublic = publicJwk(owner);
  const encryptionPublic = publicJwk(encryption);
  const fp = fingerprint(ownerPublic);
  const canonicalAddress = `pqcmesh~${fp}@quantic`;
  const deviceId = `d-${fingerprint(encryptionPublic, 10)}`;
  const issuedAt = new Date(Date.now() - 60_000).toISOString();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  const identityPayload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress,
    handle: "pqcmesh",
    fingerprint: fp,
    identityPublicKey: encryptionPublic,
    identitySigningPublicKey: ownerPublic,
    devices: [{
      deviceId,
      label: "PQC root",
      publicKey: encryptionPublic,
      deviceSigningPublicKey: ownerPublic,
      kind: "root" as const,
      issuedAt,
    }],
    revocations: [],
    issuedAt,
  };
  const identityManifest = {
    format: "quantic-identity-manifest" as const,
    version: 1 as const,
    payload: identityPayload,
    signature: sign("sha256", Buffer.from(canonicalManifestText(identityPayload), "utf8"), {
      key: owner.privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64"),
  };

  const identityPq = generateMlDsa65KeyPair();
  const deviceKem = generateMlKem768KeyPair();
  const deviceDsa = generateMlDsa65KeyPair();
  const cryptoPayload = {
    version: 2 as const,
    sequence: 1,
    canonicalAddress,
    identitySigningPublicKey: ownerPublic,
    identityManifestSequence: 1,
    policy: "hybrid-required" as const,
    identityMlDsaAlgorithm: "ML-DSA-65" as const,
    identityMlDsaPublicKeySpki: identityPq.publicKeySpki,
    devices: [{
      deviceId,
      mlKemAlgorithm: "ML-KEM-768" as const,
      mlKemPublicKeySpki: deviceKem.publicKeySpki,
      mlDsaAlgorithm: "ML-DSA-65" as const,
      mlDsaPublicKeySpki: deviceDsa.publicKeySpki,
    }],
    issuedAt,
  };
  const cryptoText = Buffer.from(canonicalCryptoProfileText(cryptoPayload), "utf8");
  const cryptoProfile = {
    format: "quantic-crypto-profile" as const,
    version: 2 as const,
    payload: cryptoPayload,
    signatures: {
      p256: sign("sha256", cryptoText, {
        key: owner.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64"),
      mlDsa65Self: mlDsaSign(identityPq.privateKeyPkcs8, cryptoText),
    },
  };
  const cryptoProfileDigest = createHash("sha256")
    .update(canonicalCryptoProfileText(cryptoPayload), "utf8")
    .digest("hex");

  const relayKey = p256Pair();
  const relayPublic = publicJwk(relayKey);
  const routePayload = {
    version: 1 as const,
    sequence: 1,
    canonicalAddress,
    identitySigningPublicKey: ownerPublic,
    identityManifestSequence: 1,
    cryptoProfileSequence: 1,
    cryptoProfileDigest,
    relays: [{
      relayId,
      endpoint,
      priority: 10,
      protocols: ["quantic-federation/1"],
      classicalSigningPublicKey: relayPublic,
      expiresAt,
    }],
    issuedAt,
    expiresAt,
  };
  // The route relayId must match the signing key, so replace the caller hint with the real key digest.
  routePayload.relays[0].relayId = createHash("sha256")
    .update(relayKey.publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  const routeManifest = {
    format: "quantic-route-manifest" as const,
    version: 1 as const,
    payload: routePayload,
    signatures: {
      p256: sign("sha256", Buffer.from(canonicalRouteManifestText(routePayload), "utf8"), {
        key: owner.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64"),
    },
  };

  return { canonicalAddress, identityManifest, cryptoProfile, routeManifest };
}

const pqAvailable = (() => {
  try {
    generateMlKem768KeyPair();
    generateMlDsa65KeyPair();
    return true;
  } catch {
    return false;
  }
})();
const skip = pqAvailable ? false : "native PQ runtime unavailable";

test("Discovery Mesh publishes, persists, and returns a verified hybrid-required Crypto Profile V2", { skip }, async () => {
  const dataDir = await fs.mkdtemp(join(tmpdir(), "quantic-discovery-pqc-"));
  let relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const bundle = makeBundle(relay.relayId, relay.url);
    const publish = await fetch(`${relay.url}/api/quantic/discovery/publish`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ bundle }),
    });
    assert.equal(publish.status, 201);

    const found = await fetch(`${relay.url}/api/quantic/discovery/find`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key: discoveryKey("identity", bundle.canonicalAddress) }),
    });
    assert.equal(found.status, 200);
    const first = await found.json() as { bundle?: { cryptoProfile?: typeof bundle.cryptoProfile } | null };
    assert.equal(first.bundle?.cryptoProfile?.payload.policy, "hybrid-required");
    assert.equal(first.bundle?.cryptoProfile?.payload.sequence, 1);

    await relay.close();
    relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
    const afterRestart = await fetch(`${relay.url}/api/quantic/discovery/find`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key: discoveryKey("identity", bundle.canonicalAddress) }),
    });
    assert.equal(afterRestart.status, 200);
    const restored = await afterRestart.json() as { bundle?: { cryptoProfile?: typeof bundle.cryptoProfile } | null };
    assert.equal(restored.bundle?.cryptoProfile?.payload.policy, "hybrid-required");
    assert.equal(restored.bundle?.cryptoProfile?.payload.sequence, 1);
  } finally {
    await relay.close().catch(() => undefined);
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
