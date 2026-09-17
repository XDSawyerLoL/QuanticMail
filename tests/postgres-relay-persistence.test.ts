import test from "node:test";
import assert from "node:assert/strict";

import {
  createPostgresRelayPersistence,
  RelayStateConflictError,
} from "../standalone-relay/postgres-storage.ts";

type StoredRow = { value: unknown; revision: number };
type QueryResult = { rows: Array<{ value?: unknown; revision?: number }>; rowCount?: number };

class FakePostgresClient {
  readonly rows = new Map<string, StoredRow>();

  async query(sql: string, params: unknown[] = []): Promise<QueryResult> {
    const compact = sql.replace(/\s+/g, " ").trim().toLowerCase();
    if (compact.startsWith("create table") || compact.startsWith("alter table")) {
      return { rows: [], rowCount: 0 };
    }

    if (compact.startsWith("select value, revision from quantic_relay_kv")) {
      const key = String(params[0] ?? "");
      const row = this.rows.get(key);
      return row
        ? { rows: [{ value: structuredClone(row.value), revision: row.revision }], rowCount: 1 }
        : { rows: [], rowCount: 0 };
    }

    if (compact.startsWith("select value from quantic_relay_kv")) {
      const key = String(params[0] ?? "");
      const row = this.rows.get(key);
      return row
        ? { rows: [{ value: structuredClone(row.value) }], rowCount: 1 }
        : { rows: [], rowCount: 0 };
    }

    if (compact.startsWith("update quantic_relay_kv") && compact.includes("revision = revision + 1")) {
      const key = String(params[0] ?? "");
      const value = JSON.parse(String(params[1] ?? "null"));
      const expected = Number(params[2]);
      const row = this.rows.get(key);
      if (!row || row.revision !== expected) return { rows: [], rowCount: 0 };
      row.value = value;
      row.revision += 1;
      return { rows: [{ revision: row.revision }], rowCount: 1 };
    }

    if (compact.startsWith("insert into quantic_relay_kv") && compact.includes("do nothing")) {
      const key = String(params[0] ?? "");
      const value = JSON.parse(String(params[1] ?? "null"));
      if (this.rows.has(key)) return { rows: [], rowCount: 0 };
      const revision = compact.includes("returning revision") ? 1 : 0;
      this.rows.set(key, { value, revision });
      return compact.includes("returning revision")
        ? { rows: [{ revision }], rowCount: 1 }
        : { rows: [{ value: structuredClone(value) }], rowCount: 1 };
    }

    if (compact.startsWith("insert into quantic_relay_kv")) {
      const key = String(params[0] ?? "");
      const value = JSON.parse(String(params[1] ?? "null"));
      const current = this.rows.get(key);
      this.rows.set(key, { value, revision: current?.revision ?? 0 });
      return { rows: [{ value: structuredClone(value) }], rowCount: 1 };
    }

    throw new Error(`Unexpected SQL in fake client: ${compact}`);
  }
}

function snapshot(marker = "base") {
  return {
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
    marker,
  } as never;
}

test("Postgres relay state survives a fresh persistence adapter", async () => {
  const client = new FakePostgresClient();
  const first = createPostgresRelayPersistence(client);
  await first.initialize();
  await first.stateStore.save(snapshot());

  const second = createPostgresRelayPersistence(client);
  await second.initialize();
  assert.deepEqual(await second.stateStore.load(), snapshot());
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

test("Postgres rejects a stale relay snapshot writer instead of overwriting newer state", async () => {
  const client = new FakePostgresClient();
  const first = createPostgresRelayPersistence(client);
  await first.stateStore.save(snapshot("initial"));

  const writerA = createPostgresRelayPersistence(client);
  const writerB = createPostgresRelayPersistence(client);
  assert.deepEqual(await writerA.stateStore.load(), snapshot("initial"));
  assert.deepEqual(await writerB.stateStore.load(), snapshot("initial"));

  await writerA.stateStore.save(snapshot("writer-a"));
  await assert.rejects(
    writerB.stateStore.save(snapshot("writer-b")),
    (error: unknown) => error instanceof RelayStateConflictError,
  );

  const reader = createPostgresRelayPersistence(client);
  assert.deepEqual(await reader.stateStore.load(), snapshot("writer-a"));
});

test("Postgres can encrypt the relay signing identity at rest and rejects the wrong secret", async () => {
  const client = new FakePostgresClient();
  const secret = "correct-horse-battery-staple-quantic-relay-secret-2026";
  const first = createPostgresRelayPersistence(client, { identitySecret: secret });
  const identity = await first.loadOrCreateIdentity();

  const stored = JSON.stringify(client.rows.get("relay-identity")?.value);
  assert.ok(stored.includes("quantic-relay-identity-encrypted"));
  assert.equal(stored.includes("BEGIN PRIVATE KEY"), false);

  const second = createPostgresRelayPersistence(client, { identitySecret: secret });
  assert.equal((await second.loadOrCreateIdentity()).relayId, identity.relayId);

  const wrong = createPostgresRelayPersistence(client, {
    identitySecret: "wrong-secret-that-is-still-long-enough-for-validation-0001",
  });
  await assert.rejects(wrong.loadOrCreateIdentity(), /secret|déchiffr|authent/i);
});
