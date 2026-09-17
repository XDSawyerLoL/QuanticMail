import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_RELAY_ENDPOINTS,
  getRelayEndpoints,
  orderedRelays,
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

const legacyBootstrap: RelayEndpoint = {
  id: "quantic-bootstrap",
  label: "Quantic bootstrap",
  baseUrl: "",
  priority: 100,
  enabled: true,
};

test("fresh clients prefer the durable public Quantic relay before same-origin fallback", () => {
  assert.equal(DEFAULT_RELAY_ENDPOINTS[0]?.id, "quantic-public");
  assert.equal(DEFAULT_RELAY_ENDPOINTS[0]?.baseUrl, "https://quanticmail-network-relay.onrender.com");
  assert.equal(DEFAULT_RELAY_ENDPOINTS[1]?.id, "quantic-bootstrap");
});

test("legacy bootstrap-only browser settings are migrated to the durable relay", () => {
  const storage = new MemoryStorage();
  saveRelayEndpoints([legacyBootstrap], storage);
  const relays = getRelayEndpoints(storage);
  assert.deepEqual(relays.map((item) => item.id), ["quantic-public", "quantic-bootstrap"]);
});

test("an old active bootstrap preference cannot pin registration to ephemeral web memory", () => {
  const ordered = orderedRelays(DEFAULT_RELAY_ENDPOINTS, "quantic-bootstrap");
  assert.equal(ordered[0]?.id, "quantic-public");
});

test("an explicitly custom-only relay configuration remains custom-only", () => {
  const storage = new MemoryStorage();
  saveRelayEndpoints([
    { id: "mine", label: "Mine", baseUrl: "https://mine.example", priority: 5, enabled: true },
  ], storage);
  assert.deepEqual(getRelayEndpoints(storage).map((item) => item.id), ["mine"]);
});
