import assert from "node:assert/strict";
import test from "node:test";

async function kademlia() {
  try {
    return await import("../standalone-relay/kademlia.ts");
  } catch (error) {
    assert.fail(`Kademlia routing core is not implemented yet: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const LOCAL = "0".repeat(64);

function id(prefix: string) {
  return `${prefix}${"0".repeat(64 - prefix.length)}`;
}

function peer(relayId: string, overrides: Record<string, unknown> = {}) {
  return {
    relayId,
    endpoint: `https://${relayId.slice(0, 8)}.example`,
    lastSeenAt: "2026-09-17T11:00:00.000Z",
    failures: 0,
    bucketIndex: 0,
    ...overrides,
  };
}

test("xorDistance is exact and symmetric over 256-bit relay IDs", async () => {
  const { xorDistance } = await kademlia();
  const a = "0".repeat(64);
  const b = `${"0".repeat(63)}f`;
  const c = `${"f"}${"0".repeat(63)}`;

  assert.equal(xorDistance(a, b), 15n);
  assert.equal(xorDistance(b, a), 15n);
  assert.equal(xorDistance(a, c), 15n << 252n);
  assert.equal(xorDistance(a, a), 0n);
  assert.throws(() => xorDistance("bad", b), /relay id|256|hex/i);
});

test("KBucketTable caps a bucket and replaces an unhealthy least-recent peer before a healthy one", async () => {
  const { KBucketTable } = await kademlia();
  const table = new KBucketTable(LOCAL, { bucketSize: 2 });

  const first = peer(id("8"), { lastSeenAt: "2026-09-17T10:00:00.000Z", failures: 0 });
  const unhealthy = peer(id("9"), { lastSeenAt: "2026-09-17T10:01:00.000Z", failures: 2 });
  const newcomer = peer(id("a"), { lastSeenAt: "2026-09-17T10:02:00.000Z", failures: 0 });

  assert.equal(table.upsert(first), true);
  assert.equal(table.upsert(unhealthy), true);
  assert.equal(table.size, 2);
  assert.equal(table.upsert(newcomer), true);
  assert.equal(table.size, 2);

  const relayIds = table.all().map((item: { relayId: string }) => item.relayId);
  assert.deepEqual(relayIds.sort(), [first.relayId, newcomer.relayId].sort());
});

test("KBucketTable nearest returns peers ordered by XOR distance", async () => {
  const { KBucketTable } = await kademlia();
  const table = new KBucketTable(LOCAL, { bucketSize: 8 });
  const peers = [peer(id("8")), peer(id("4")), peer(id("2")), peer(id("1"))];
  peers.forEach((item) => table.upsert(item));

  const target = id("3");
  const nearest = table.nearest(target, 3).map((item: { relayId: string }) => item.relayId);
  const expected = [...peers]
    .sort((left, right) => {
      const ld = BigInt(`0x${left.relayId}`) ^ BigInt(`0x${target}`);
      const rd = BigInt(`0x${right.relayId}`) ^ BigInt(`0x${target}`);
      return ld < rd ? -1 : ld > rd ? 1 : 0;
    })
    .slice(0, 3)
    .map((item) => item.relayId);

  assert.deepEqual(nearest, expected);
});

test("iterativeFindRecord converges over multiple hops, uses independent seeds, and stays bounded", async () => {
  const { iterativeFindRecord } = await kademlia();
  const targetKey = id("f");
  const a = peer(id("1"));
  const b = peer(id("2"));
  const c = peer(id("4"));
  const d = peer(id("8"));
  const destination = peer(id("e"));
  const calls: string[] = [];

  const graph = new Map<string, { record?: { value: string }; peers?: ReturnType<typeof peer>[] }>([
    [a.relayId, { peers: [d] }],
    [b.relayId, { peers: [c] }],
    [c.relayId, { peers: [destination] }],
    [d.relayId, { peers: [destination] }],
    [destination.relayId, { record: { value: "signed-bundle" }, peers: [] }],
  ]);

  const result = await iterativeFindRecord(
    targetKey,
    async (candidate: ReturnType<typeof peer>) => {
      calls.push(candidate.relayId);
      return graph.get(candidate.relayId) ?? { peers: [] };
    },
    {
      seeds: [a, b, c],
      alpha: 3,
      paths: 3,
      maxQueries: 5,
      k: 8,
    },
  );

  assert.deepEqual(result.record, { value: "signed-bundle" });
  assert.ok(calls.includes(a.relayId));
  assert.ok(calls.includes(b.relayId));
  assert.ok(calls.includes(c.relayId));
  assert.ok(calls.length <= 5);
  assert.equal(new Set(calls).size, calls.length);
  assert.ok(result.closestPeers.some((item: { relayId: string }) => item.relayId === destination.relayId));
});
