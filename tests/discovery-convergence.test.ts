import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { canonicalRouteManifestText } from "../lib/quantic/federation-core.mjs";
import type { QuanticRouteManifest } from "../lib/quantic/federation-types.ts";
import { canonicalManifestText } from "../lib/quantic/manifest-core.mjs";
import type { QuanticIdentityManifest } from "../lib/quantic/manifest-types.ts";
import type { DiscoveryPeer } from "../standalone-relay/discovery-state.ts";

async function discoveryService() {
  try {
    return await import("../standalone-relay/discovery-service.ts");
  } catch (error) {
    assert.fail(`Discovery service is not implemented yet: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function keyPair() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    publicKey: pair.publicKey.export({ format: "jwk" }),
    privateKey: pair.privateKey,
  };
}

function fingerprint(key: JsonWebKey) {
  return createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, 32);
}

function deviceId(key: JsonWebKey) {
  return `d-${createHash("sha256")
    .update(`P-256:${key.x}:${key.y}`)
    .digest("hex")
    .slice(0, 32)}`;
}

function relayId(index: number) {
  return index.toString(16).padStart(64, "0");
}

function peer(index: number): DiscoveryPeer {
  return {
    relayId: relayId(index),
    endpoint: `https://relay-${index}.mesh.example`,
    lastSeenAt: "2026-09-17T11:30:00.000Z",
    failures: 0,
    bucketIndex: 0,
  };
}

function bundleFactory(handle = "converge") {
  const owner = keyPair();
  const encryption = keyPair();
  const fp = fingerprint(owner.publicKey);
  const canonicalAddress = `${handle}~${fp}@quantic`;

  function make(identitySequence: number, routeSequence: number, endpoint = "https://home.mesh.example") {
    const identityPayload = {
      version: 1 as const,
      sequence: identitySequence,
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
        kind: "root" as const,
        issuedAt: "2026-09-17T00:00:00.000Z",
      }],
      revocations: [],
      issuedAt: "2026-09-17T00:00:00.000Z",
    };
    const identityManifest: QuanticIdentityManifest = {
      format: "quantic-identity-manifest",
      version: 1,
      payload: identityPayload,
      signature: sign("sha256", Buffer.from(canonicalManifestText(identityPayload)), {
        key: owner.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64"),
    };
    const routePayload = {
      version: 1 as const,
      sequence: routeSequence,
      canonicalAddress,
      identitySigningPublicKey: owner.publicKey,
      identityManifestSequence: identitySequence,
      cryptoProfileSequence: null,
      cryptoProfileDigest: null,
      relays: [{
        relayId: relayId(99),
        endpoint,
        priority: 10,
        protocols: ["quantic-federation/1"],
        classicalSigningPublicKey: owner.publicKey,
        expiresAt: "2026-10-17T00:00:00.000Z",
      }],
      issuedAt: "2026-09-17T00:00:00.000Z",
      expiresAt: "2026-10-17T00:00:00.000Z",
    };
    const routeManifest: QuanticRouteManifest = {
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

  return { canonicalAddress, make };
}

type Bundle = ReturnType<ReturnType<typeof bundleFactory>["make"]>;

type NodeState = {
  peer: DiscoveryPeer;
  peers: DiscoveryPeer[];
  bundle: Bundle | null;
};

function createFiveNodes() {
  const nodes = new Map<string, NodeState>();
  for (let index = 1; index <= 5; index += 1) {
    const current = peer(index);
    nodes.set(current.relayId, { peer: current, peers: [], bundle: null });
  }
  return nodes;
}

test("five-node Discovery replication targets only the K closest relays and lookup converges", async () => {
  const { createDiscoveryService } = await discoveryService();
  const factory = bundleFactory();
  const bundle = factory.make(1, 1);
  const nodes = createFiveNodes();
  const source = nodes.get(relayId(5))!;
  source.bundle = bundle;
  source.peers = [...nodes.values()].filter((node) => node !== source).map((node) => node.peer);
  const publishedTo: string[] = [];

  const service = createDiscoveryService({
    localRelayId: source.peer.relayId,
    peers: () => source.peers,
    pinnedBundle: () => source.bundle,
    acceptLocal: (accepted: Bundle) => {
      source.bundle = accepted;
      return accepted;
    },
    transport: {
      publish: async (target: DiscoveryPeer, record: Bundle) => {
        publishedTo.push(target.relayId);
        nodes.get(target.relayId)!.bundle = record;
      },
      find: async (target: DiscoveryPeer) => {
        const node = nodes.get(target.relayId)!;
        return { bundle: node.bundle, peers: node.peers };
      },
    },
  });

  const replicated = await service.replicate(bundle, { k: 2 });
  assert.equal(replicated.attempted, 2);
  assert.equal(replicated.succeeded, 2);
  assert.equal(new Set(publishedTo).size, 2);
  assert.equal([...nodes.values()].filter((node) => node.bundle !== null).length, 3);

  const seeker = nodes.get(relayId(1))!;
  seeker.peers = [nodes.get(relayId(2))!.peer, nodes.get(relayId(3))!.peer, nodes.get(relayId(4))!.peer];
  for (const candidate of seeker.peers) {
    const state = nodes.get(candidate.relayId)!;
    state.peers = source.peers.filter((item) => item.relayId !== candidate.relayId);
  }
  const seekerService = createDiscoveryService({
    localRelayId: seeker.peer.relayId,
    peers: () => seeker.peers,
    pinnedBundle: () => seeker.bundle,
    acceptLocal: (accepted: Bundle) => {
      seeker.bundle = accepted;
      return accepted;
    },
    transport: {
      publish: async () => undefined,
      find: async (target: DiscoveryPeer) => {
        const node = nodes.get(target.relayId)!;
        return { bundle: node.bundle, peers: node.peers };
      },
    },
  });

  const found = await seekerService.lookup(factory.canonicalAddress, { maxQueries: 5 });
  assert.equal(found?.identityManifest.payload.canonicalAddress, factory.canonicalAddress);
  assert.equal(seeker.bundle?.routeManifest.payload.sequence, 1);
});

test("partition rejoin caches a newer valid route but ignores rollback and same-sequence fork", async () => {
  const { createDiscoveryService } = await discoveryService();
  const factory = bundleFactory("rejoin");
  const oldBundle = factory.make(1, 1, "https://old.mesh.example");
  const newerBundle = factory.make(1, 2, "https://new.mesh.example");
  const forkBundle = factory.make(1, 2, "https://fork.mesh.example");
  let local: Bundle | null = oldBundle;
  let remote: Bundle | null = newerBundle;
  const remotePeer = peer(2);

  const service = createDiscoveryService({
    localRelayId: relayId(1),
    peers: () => [remotePeer],
    pinnedBundle: () => local,
    acceptLocal: (accepted: Bundle) => {
      local = accepted;
      return accepted;
    },
    transport: {
      publish: async () => undefined,
      find: async () => ({ bundle: remote, peers: [] }),
    },
  });

  const refreshed = await service.lookup(factory.canonicalAddress, { maxQueries: 2 });
  assert.equal(refreshed?.routeManifest.payload.sequence, 2);
  assert.equal(local?.routeManifest.payload.relays[0].endpoint, "https://new.mesh.example");

  remote = oldBundle;
  const rollback = await service.lookup(factory.canonicalAddress, { maxQueries: 2 });
  assert.equal(rollback?.routeManifest.payload.sequence, 2);
  assert.equal(local?.routeManifest.payload.relays[0].endpoint, "https://new.mesh.example");

  remote = forkBundle;
  const fork = await service.lookup(factory.canonicalAddress, { maxQueries: 2 });
  assert.equal(fork?.routeManifest.payload.sequence, 2);
  assert.equal(local?.routeManifest.payload.relays[0].endpoint, "https://new.mesh.example");
});
