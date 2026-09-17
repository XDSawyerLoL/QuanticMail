import assert from "node:assert/strict";
import test from "node:test";

import {
  DURABLE_PUBLIC_RELAY,
  mergeDefaultRelayEndpoints,
  parseDefaultRelayEndpoints,
} from "../lib/quantic/relay-client.ts";

test("parses multiple HTTPS Quantic bootstrap seeds and removes duplicate origins", () => {
  const relays = parseDefaultRelayEndpoints(
    "https://seed-a.example/, https://seed-b.example, https://seed-a.example",
  );
  assert.deepEqual(relays.map((relay) => relay.baseUrl), [
    "https://seed-a.example",
    "https://seed-b.example",
  ]);
  assert.deepEqual(relays.map((relay) => relay.priority), [20, 30]);
});

test("rejects insecure remote bootstrap endpoints but allows localhost development", () => {
  assert.throws(() => parseDefaultRelayEndpoints("http://seed.example"), /HTTPS/i);
  assert.equal(parseDefaultRelayEndpoints("http://localhost:8787")[0].baseUrl, "http://localhost:8787");
});

test("merges environment seeds with the compatibility public relay without duplicating it", () => {
  const configured = parseDefaultRelayEndpoints(
    `${DURABLE_PUBLIC_RELAY.baseUrl},https://independent.example`,
  );
  const merged = mergeDefaultRelayEndpoints(configured, [DURABLE_PUBLIC_RELAY]);
  assert.equal(merged.filter((relay) => relay.baseUrl === DURABLE_PUBLIC_RELAY.baseUrl).length, 1);
  assert.ok(merged.some((relay) => relay.baseUrl === "https://independent.example"));
});
