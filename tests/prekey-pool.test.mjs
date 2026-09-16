import test from "node:test";
import assert from "node:assert/strict";
import {
  createPreKeyPoolStore,
  publishToPreKeyPool,
  claimFromPreKeyPool,
  countPreKeyPool,
} from "../lib/quantic/prekey-pool.mjs";

function record(id, expiresAt = "2026-09-23T18:00:00.000Z") {
  return {
    version: 1,
    canonicalAddress: "alice~0123456789abcdef0123456789abcdef@quantic",
    deviceId: "d-0123456789",
    preKeyId: id,
    publicKey: { kty: "EC", crv: "P-256", x: `x-${id}`, y: `y-${id}` },
    createdAt: "2026-09-16T18:00:00.000Z",
    expiresAt,
    signature: "signature-placeholder-long-enough",
  };
}

const now = Date.parse("2026-09-16T18:01:00.000Z");

test("claim removes a prekey atomically", () => {
  const store = createPreKeyPoolStore();
  publishToPreKeyPool(store, "alice#device", [record("00000000000000000000000000000001")], now);
  const first = claimFromPreKeyPool(store, "alice#device", now);
  const second = claimFromPreKeyPool(store, "alice#device", now);
  assert.equal(first?.preKeyId, "00000000000000000000000000000001");
  assert.equal(second, null);
});

test("a claimed prekey cannot be republished before its expiry", () => {
  const store = createPreKeyPoolStore();
  const claimed = record("00000000000000000000000000000002");
  publishToPreKeyPool(store, "alice#device", [claimed], now);
  assert.ok(claimFromPreKeyPool(store, "alice#device", now));
  const result = publishToPreKeyPool(store, "alice#device", [claimed], now + 1000);
  assert.equal(result.accepted, 0);
  assert.equal(result.consumedRejected, 1);
});

test("expired prekeys are never counted or claimed", () => {
  const store = createPreKeyPoolStore();
  publishToPreKeyPool(
    store,
    "alice#device",
    [record("00000000000000000000000000000003", "2026-09-16T18:00:30.000Z")],
    now,
  );
  assert.equal(countPreKeyPool(store, "alice#device", now), 0);
  assert.equal(claimFromPreKeyPool(store, "alice#device", now), null);
});

test("pool deduplicates and caps records at 64", () => {
  const store = createPreKeyPoolStore();
  const records = Array.from({ length: 70 }, (_, index) =>
    record(index.toString(16).padStart(32, "0")),
  );
  const result = publishToPreKeyPool(store, "alice#device", [...records, records[0]], now);
  assert.equal(result.available, 64);
  assert.equal(countPreKeyPool(store, "alice#device", now), 64);
});
