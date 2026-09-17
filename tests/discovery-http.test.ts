import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { discoveryKey } from "../lib/quantic/discovery-core.mjs";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import { canonicalRouteManifestText } from "../lib/quantic/federation-core.mjs";
import { replaceDiscoveryPeerEntries } from "../standalone-relay/discovery-state.ts";
import { startRelayServer } from "../standalone-relay/server.ts";

async function tempDir() {
  return fs.mkdtemp(join(tmpdir(), "quantic-discovery-http-"));
}

function keys() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    publicKey: pair.publicKey.export({ format: "jwk" }),
    privateKey: pair.privateKey,
    publicKeyObject: pair.publicKey,
  };
}

function fingerprint(key: JsonWebKey, length = 32) {
  return createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, length);
}

function deviceId(key: JsonWebKey, length = 32) {
  return `d-${createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, length)}`;
}

function relayId(publicKeyObject: ReturnType<typeof generateKeyPairSync>["publicKey"]) {
  return createHash("sha256")
    .update(publicKeyObject.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function signedBundle(handle = "bobmesh") {
  const owner = keys();
  const encryption = keys();
  const relay = keys();
  const fp = fingerprint(owner.publicKey);
  const canonicalAddress = `${handle}~${fp}@quantic`;
  const identityPayload = {
    version: 1,
    sequence: 3,
    canonicalAddress,
    handle,
    fingerprint: fp,
    identityPublicKey: encryption.publicKey,
    identitySigningPublicKey: owner.publicKey,
    devices: [{
      deviceId: deviceId(encryption.publicKey),
      label: `${handle} root`,
      publicKey: encryption.publicKey,
      deviceSigningPublicKey: owner.publicKey,
      kind: "root",
      issuedAt: "2026-09-17T00:00:00.000Z",
    }],
    revocations: [],
    issuedAt: "2026-09-17T00:00:00.000Z",
  };
  const identityManifest = {
    format: "quantic-identity-manifest",
    version: 1,
    payload: identityPayload,
    signature: sign("sha256", Buffer.from(canonicalManifestText(identityPayload)), {
      key: owner.privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64"),
  };
  const routePayload = {
    version: 1,
    sequence: 2,
    canonicalAddress,
    identitySigningPublicKey: owner.publicKey,
    identityManifestSequence: identityPayload.sequence,
    cryptoProfileSequence: null,
    cryptoProfileDigest: null,
    relays: [{
      relayId: relayId(relay.publicKeyObject),
      endpoint: "https://relay.mesh.example",
      priority: 10,
      protocols: ["quantic-federation/1"],
      classicalSigningPublicKey: relay.publicKey,
      expiresAt: "2026-10-17T00:00:00.000Z",
    }],
    issuedAt: "2026-09-17T00:00:00.000Z",
    expiresAt: "2026-10-17T00:00:00.000Z",
  };
  const routeManifest = {
    format: "quantic-route-manifest",
    version: 1,
    payload: routePayload,
    signatures: {
      p256: sign("sha256", Buffer.from(canonicalRouteManifestText(routePayload)), {
        key: owner.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64"),
    },
  };
  return { identityManifest, routeManifest };
}

async function postJson(url: string, body: unknown) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("Discovery HTTP publishes only a cryptographically valid bundle and finds it by namespaced key", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const bundle = signedBundle();
    const canonical = bundle.identityManifest.payload.canonicalAddress;
    const publish = await postJson(`${relay.url}/api/quantic/discovery/publish`, { bundle });
    assert.equal(publish.status, 201);
    const accepted = await publish.json() as Record<string, unknown>;
    assert.equal(accepted.accepted, true);
    assert.equal(accepted.canonicalAddress, canonical);

    const find = await postJson(`${relay.url}/api/quantic/discovery/find`, {
      key: discoveryKey("identity", canonical),
    });
    assert.equal(find.status, 200);
    const found = await find.json() as { bundle: typeof bundle | null; peers: unknown[] };
    assert.equal(found.bundle?.identityManifest.payload.canonicalAddress, canonical);
    assert.equal(found.bundle?.routeManifest.payload.sequence, 2);
    assert.ok(Array.isArray(found.peers));
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("Discovery HTTP rejects a tampered signed bundle instead of caching it", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const bundle = signedBundle("mallorymesh");
    bundle.routeManifest.payload.sequence = 99;
    const publish = await postJson(`${relay.url}/api/quantic/discovery/publish`, { bundle });
    assert.equal(publish.status, 400);

    const find = await postJson(`${relay.url}/api/quantic/discovery/find`, {
      key: discoveryKey("identity", bundle.identityManifest.payload.canonicalAddress),
    });
    assert.equal(find.status, 200);
    const found = await find.json() as { bundle: unknown };
    assert.equal(found.bundle, null);
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("Discovery find falls back to at most 20 nearest durable peers and keeps responses bounded", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const now = "2026-09-17T11:00:00.000Z";
    const entries = Array.from({ length: 30 }, (_, index) => {
      const relayId = (index + 1).toString(16).padStart(64, "0");
      return [relayId, {
        relayId,
        endpoint: `https://peer-${index + 1}.example`,
        lastSeenAt: now,
        failures: 0,
        bucketIndex: 0,
      }] as const;
    });
    replaceDiscoveryPeerEntries(entries as never, Date.parse(now));

    const key = "f".repeat(64);
    const response = await postJson(`${relay.url}/api/quantic/discovery/find`, { key });
    assert.equal(response.status, 200);
    const text = await response.text();
    assert.ok(Buffer.byteLength(text, "utf8") < 64 * 1024);
    const body = JSON.parse(text) as { bundle: null; peers: Array<{ relayId: string }> };
    assert.equal(body.bundle, null);
    assert.ok(body.peers.length > 0);
    assert.ok(body.peers.length <= 20);
    assert.equal(new Set(body.peers.map((item) => item.relayId)).size, body.peers.length);

    const peersResponse = await fetch(`${relay.url}/api/quantic/discovery/peers?key=${key}`);
    assert.equal(peersResponse.status, 200);
    const peerBody = await peersResponse.json() as { peers: unknown[] };
    assert.ok(peerBody.peers.length <= 20);
  } finally {
    replaceDiscoveryPeerEntries([]);
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});

test("Discovery publish inherits the relay request-size ceiling", async () => {
  const dataDir = await tempDir();
  const relay = await startRelayServer({ host: "127.0.0.1", port: 0, dataDir });
  try {
    const response = await postJson(`${relay.url}/api/quantic/discovery/publish`, {
      padding: "x".repeat(600 * 1024),
    });
    assert.equal(response.status, 413);
  } finally {
    await relay.close();
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
