import test from "node:test";
import assert from "node:assert/strict";
import {
  buildRelayUrl,
  getRelayEndpoints,
  normalizeRelayBaseUrl,
  orderedRelays,
  relayFetch,
  relayFetchJson,
  saveRelayEndpoints,
  type RelayEndpoint,
  type StorageLike,
} from "../lib/quantic/relay-client.ts";

class MemoryStorage implements StorageLike {
  #data = new Map<string, string>();
  getItem(key: string) { return this.#data.get(key) ?? null; }
  setItem(key: string, value: string) { this.#data.set(key, value); }
  removeItem(key: string) { this.#data.delete(key); }
}

const relay = (id: string, baseUrl: string, priority: number, enabled = true): RelayEndpoint => ({
  id,
  label: id,
  baseUrl,
  priority,
  enabled,
});

test("normalizes relay origins and keeps same-origin bootstrap empty", () => {
  assert.equal(normalizeRelayBaseUrl(""), "");
  assert.equal(normalizeRelayBaseUrl("https://relay.example.com///"), "https://relay.example.com");
  assert.equal(normalizeRelayBaseUrl("http://localhost:3001/"), "http://localhost:3001");
  assert.throws(() => normalizeRelayBaseUrl("ftp://relay.example.com"));
});

test("orders enabled relays by priority and ignores disabled relays", () => {
  assert.deepEqual(
    orderedRelays([
      relay("slow", "https://slow.example", 50),
      relay("off", "https://off.example", 1, false),
      relay("fast", "https://fast.example", 10),
    ]).map((item) => item.id),
    ["fast", "slow"],
  );
});

test("builds relative URLs for same-origin and absolute URLs for external relays", () => {
  assert.equal(buildRelayUrl(relay("local", "", 1), "/api/quantic/health"), "/api/quantic/health");
  assert.equal(
    buildRelayUrl(relay("remote", "https://relay.example.com", 1), "/api/quantic/health"),
    "https://relay.example.com/api/quantic/health",
  );
});

test("persists a local relay list without forcing the bootstrap relay back in", () => {
  const storage = new MemoryStorage();
  saveRelayEndpoints([relay("mine", "https://mine.example", 5)], storage);
  assert.deepEqual(getRelayEndpoints(storage), [relay("mine", "https://mine.example", 5)]);
});

test("falls back after a network failure", async () => {
  const attempts: string[] = [];
  const result = await relayFetchJson<{ ok: boolean }>(
    [relay("one", "https://one.example", 1), relay("two", "https://two.example", 2)],
    "/api/quantic/health",
    undefined,
    {
      fetchImpl: async (input) => {
        attempts.push(String(input));
        if (String(input).startsWith("https://one.example")) throw new TypeError("network down");
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
      },
    },
  );
  assert.equal(result.relay.id, "two");
  assert.deepEqual(attempts, [
    "https://one.example/api/quantic/health",
    "https://two.example/api/quantic/health",
  ]);
});

test("falls back after a retryable 503 but not after a logical 401", async () => {
  const relays = [relay("one", "https://one.example", 1), relay("two", "https://two.example", 2)];
  let count = 0;
  const ok = await relayFetchJson<{ ok: boolean }>(relays, "/x", undefined, {
    fetchImpl: async () => {
      count += 1;
      return count === 1
        ? new Response(JSON.stringify({ error: "down" }), { status: 503 })
        : new Response(JSON.stringify({ ok: true }), { status: 200 });
    },
  });
  assert.equal(ok.relay.id, "two");

  count = 0;
  await assert.rejects(
    relayFetchJson(relays, "/x", undefined, {
      fetchImpl: async () => {
        count += 1;
        return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 });
      },
    }),
    /unauthorized/,
  );
  assert.equal(count, 1);
});

test("can opt into 404 failover for distributed identity lookup", async () => {
  let count = 0;
  const result = await relayFetchJson<{ address: string }>(
    [relay("one", "https://one.example", 1), relay("two", "https://two.example", 2)],
    "/api/quantic/resolve?handle=alice",
    undefined,
    {
      retryStatuses: [404],
      fetchImpl: async () => {
        count += 1;
        return count === 1
          ? new Response(JSON.stringify({ error: "not found" }), { status: 404 })
          : new Response(JSON.stringify({ address: "alice@quantic" }), { status: 200 });
      },
    },
  );
  assert.equal(result.relay.id, "two");
});

test("raw relay fetch preserves logical responses for the existing client flow", async () => {
  let count = 0;
  const result = await relayFetch(
    [relay("one", "https://one.example", 1), relay("two", "https://two.example", 2)],
    "/api/quantic/register",
    { method: "POST" },
    {
      fetchImpl: async () => {
        count += 1;
        return new Response(JSON.stringify({ error: "proof required" }), { status: 428 });
      },
    },
  );
  assert.equal(result.response.status, 428);
  assert.equal(result.relay.id, "one");
  assert.equal(count, 1);
});
