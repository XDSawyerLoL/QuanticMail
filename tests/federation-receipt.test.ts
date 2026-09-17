import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { QuanticRouteManifest } from "../lib/quantic/federation-types.ts";
import {
  checkFederationReplay,
  federationStateEntries,
  recordFederationAccepted,
  replaceFederationStateEntries,
} from "../standalone-relay/federation-state.ts";
import {
  signFederationReceipt,
  verifyFederationReceipt,
} from "../standalone-relay/federation-receipt.ts";
import {
  loadOrCreateRelayIdentity,
  relayIdForPublicKey,
} from "../standalone-relay/identity.ts";

function emptyFederationState() {
  return {
    seen: [],
    inbound: [],
    outbound: [],
    pendingReceipts: [],
  };
}

test("federation replay state is idempotent for the same digest and rejects conflicting reuse", () => {
  replaceFederationStateEntries(emptyFederationState());
  const expiresAt = "2026-09-18T12:00:00.000Z";
  const now = Date.parse("2026-09-17T12:00:00.000Z");
  const federationId = "fed-replay-000000000001";
  const digest = "a".repeat(64);

  assert.deepEqual(checkFederationReplay(federationId, digest, now), { duplicate: false });
  recordFederationAccepted({ federationId, envelopeDigest: digest, expiresAt });
  assert.deepEqual(checkFederationReplay(federationId, digest, now), { duplicate: true });
  assert.throws(
    () => checkFederationReplay(federationId, "b".repeat(64), now),
    /replay|conflit|digest|federation/i,
  );
  assert.equal(federationStateEntries(now).seen.length, 1);
});

test("expired replay records are pruned and no longer block a new federation id", () => {
  replaceFederationStateEntries({
    ...emptyFederationState(),
    seen: [[
      "fed-expired-0000000001",
      {
        federationId: "fed-expired-0000000001",
        envelopeDigest: "c".repeat(64),
        expiresAt: "2026-09-16T00:00:00.000Z",
        result: "accepted",
      },
    ]],
  });
  const now = Date.parse("2026-09-17T12:00:00.000Z");
  assert.deepEqual(checkFederationReplay("fed-expired-0000000001", "c".repeat(64), now), { duplicate: false });
  assert.deepEqual(federationStateEntries(now).seen, []);
});

test("destination relay signs a receipt that the authorized route can verify", async () => {
  const dataDir = await fs.mkdtemp(join(tmpdir(), "quantic-federation-receipt-"));
  try {
    const relay = await loadOrCreateRelayIdentity(dataDir);
    const route: QuanticRouteManifest = {
      format: "quantic-route-manifest",
      version: 1,
      payload: {
        version: 1,
        sequence: 7,
        canonicalAddress: "bob~abcdef0123456789abcdef0123456789@quantic",
        identitySigningPublicKey: { kty: "EC", crv: "P-256", x: "owner-x", y: "owner-y" },
        identityManifestSequence: 4,
        cryptoProfileSequence: null,
        cryptoProfileDigest: null,
        relays: [{
          relayId: relay.relayId,
          endpoint: "http://127.0.0.1:8787",
          priority: 10,
          protocols: ["quantic-federation/1"],
          classicalSigningPublicKey: relay.publicKeyJwk,
          expiresAt: "2026-10-17T00:00:00.000Z",
        }],
        issuedAt: "2026-09-17T00:00:00.000Z",
        expiresAt: "2026-10-17T00:00:00.000Z",
      },
      signatures: { p256: "already-verified-route-signature" },
    };

    assert.equal(relayIdForPublicKey(relay.publicKeyJwk), relay.relayId);
    const receipt = signFederationReceipt(relay, {
      federationId: "fed-receipt-0000000001",
      envelopeDigest: "d".repeat(64),
      clientMessageId: "msg-receipt-0001",
      from: "alice~11111111111111111111111111111111@quantic",
      fromDeviceId: "d-1111111111",
      to: route.payload.canonicalAddress,
      toDeviceId: "d-2222222222",
      routeSequence: route.payload.sequence,
      deliveredAt: "2026-09-17T12:00:00.000Z",
      expiresAt: "2026-09-18T12:00:00.000Z",
    });
    assert.equal(
      verifyFederationReceipt(receipt, route, Date.parse("2026-09-17T12:01:00.000Z")).payload.destinationRelayId,
      relay.relayId,
    );

    const tampered = {
      ...receipt,
      payload: { ...receipt.payload, deliveredAt: "2026-09-17T12:02:00.000Z" },
    };
    assert.throws(
      () => verifyFederationReceipt(tampered, route, Date.parse("2026-09-17T12:03:00.000Z")),
      /signature/i,
    );
  } finally {
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
