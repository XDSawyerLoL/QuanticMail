import test from "node:test";
import assert from "node:assert/strict";

import { createPostgresRelayPersistence } from "../standalone-relay/postgres-storage.ts";

type QueryResult = { rows: Array<{ value?: unknown }>; rowCount?: number };

class FakePostgresClient {
  readonly values = new Map<string, unknown>();

  async query(sql: string, params: unknown[] = []): Promise<QueryResult> {
    const compact = sql.replace(/\s+/g, " ").trim().toLowerCase();
    if (compact.startsWith("create table")) return { rows: [], rowCount: 0 };

    if (compact.startsWith("select value from quantic_relay_kv")) {
      const key = String(params[0] ?? "");
      return this.values.has(key)
        ? { rows: [{ value: structuredClone(this.values.get(key)) }], rowCount: 1 }
        : { rows: [], rowCount: 0 };
    }

    if (compact.startsWith("insert into quantic_relay_kv") && compact.includes("do nothing")) {
      const key = String(params[0] ?? "");
      const value = JSON.parse(String(params[1] ?? "null"));
      if (this.values.has(key)) return { rows: [], rowCount: 0 };
      this.values.set(key, value);
      return { rows: [{ value: structuredClone(value) }], rowCount: 1 };
    }

    if (compact.startsWith("insert into quantic_relay_kv")) {
      const key = String(params[0] ?? "");
      const value = JSON.parse(String(params[1] ?? "null"));
      this.values.set(key, value);
      return { rows: [{ value: structuredClone(value) }], rowCount: 1 };
    }

    throw new Error(`Unexpected SQL in fake client: ${compact}`);
  }
}

test("Postgres relay state survives a fresh persistence adapter", async () => {
  const client = new FakePostgresClient();
  const first = createPostgresRelayPersistence(client);
  await first.initialize();

  const snapshot = {
    version: 3,
    identities: [],
    devices: [],
    envelopes: [],
    receipts: [],
    manifests: [],
    preKeyPools: [],
    consumedPreKeys: [],
    routeManifests: [],
    cryptoProfiles: [],
    federation: { outbound: [], inbound: [], replay: [], pendingReceipts: [] },
    discovery: { peers: [] },
  } as never;

  await first.stateStore.save(snapshot);
  const second = createPostgresRelayPersistence(client);
  await second.initialize();
  assert.deepEqual(await second.stateStore.load(), snapshot);
});

test("Postgres keeps one stable relay identity across process restarts", async () => {
  const client = new FakePostgresClient();
  const first = createPostgresRelayPersistence(client);
  await first.initialize();
  const identityA = await first.loadOrCreateIdentity();

  const second = createPostgresRelayPersistence(client);
  await second.initialize();
  const identityB = await second.loadOrCreateIdentity();

  assert.equal(identityB.relayId, identityA.relayId);
  assert.deepEqual(identityB.publicKeyJwk, identityA.publicKeyJwk);
  assert.equal(identityB.privateKeyPem, identityA.privateKeyPem);
});
