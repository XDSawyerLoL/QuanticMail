import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
} from "node:crypto";

import type { RelayPersistentState } from "../lib/quantic/relay-state.ts";
import {
  relayIdForPublicKey,
  type RelayIdentity,
} from "./identity.ts";
import type { RelayStateStore } from "./storage.ts";

type QueryRow = { value?: unknown };

type QueryResult = {
  rows: QueryRow[];
  rowCount?: number | null;
};

export type PostgresQueryClient = {
  query(sql: string, params?: unknown[]): Promise<QueryResult>;
};

const STATE_KEY = "relay-state";
const IDENTITY_KEY = "relay-identity";

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS quantic_relay_kv (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`;

function valueFromRow(row: QueryRow | undefined) {
  if (!row || row.value === undefined) return null;
  if (typeof row.value === "string") return JSON.parse(row.value) as unknown;
  return row.value;
}

function createRelayIdentity(): RelayIdentity {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyJwk = pair.publicKey.export({ format: "jwk" }) as JsonWebKey;
  const privateKeyPem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return {
    relayId: relayIdForPublicKey(publicKeyJwk),
    publicKeyJwk,
    privateKeyPem,
  };
}

function assertRelayIdentity(value: unknown): RelayIdentity {
  const identity = value as Partial<RelayIdentity> | null;
  if (
    !identity ||
    typeof identity.relayId !== "string" ||
    !/^[0-9a-f]{64}$/.test(identity.relayId) ||
    !identity.publicKeyJwk ||
    typeof identity.privateKeyPem !== "string"
  ) {
    throw new Error("Identité PostgreSQL Quantic Relay invalide.");
  }

  const expectedRelayId = relayIdForPublicKey(identity.publicKeyJwk);
  if (expectedRelayId !== identity.relayId) {
    throw new Error("Relay ID PostgreSQL incohérent avec sa clé publique.");
  }

  const privatePublic = createPublicKey(createPrivateKey(identity.privateKeyPem)).export({
    format: "jwk",
  }) as JsonWebKey;
  if (
    privatePublic.kty !== identity.publicKeyJwk.kty ||
    privatePublic.crv !== identity.publicKeyJwk.crv ||
    privatePublic.x !== identity.publicKeyJwk.x ||
    privatePublic.y !== identity.publicKeyJwk.y
  ) {
    throw new Error("La clé privée PostgreSQL ne correspond pas au Relay ID.");
  }

  return identity as RelayIdentity;
}

export function createPostgresRelayPersistence(client: PostgresQueryClient) {
  let initialized = false;

  async function initialize() {
    if (initialized) return;
    await client.query(CREATE_TABLE_SQL);
    initialized = true;
  }

  async function readValue(key: string) {
    await initialize();
    const result = await client.query(
      "SELECT value FROM quantic_relay_kv WHERE key = $1",
      [key],
    );
    return valueFromRow(result.rows[0]);
  }

  async function saveValue(key: string, value: unknown) {
    await initialize();
    const serialized = JSON.stringify(value);
    await client.query(
      `INSERT INTO quantic_relay_kv (key, value, updated_at)
       VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (key) DO UPDATE
       SET value = EXCLUDED.value, updated_at = NOW()
       RETURNING value`,
      [key, serialized],
    );
  }

  const stateStore: RelayStateStore = {
    async load() {
      return (await readValue(STATE_KEY)) as RelayPersistentState | null;
    },
    async save(state) {
      await saveValue(STATE_KEY, state);
    },
  };

  async function loadOrCreateIdentity() {
    const existing = await readValue(IDENTITY_KEY);
    if (existing) return assertRelayIdentity(existing);

    const generated = createRelayIdentity();
    const inserted = await client.query(
      `INSERT INTO quantic_relay_kv (key, value, updated_at)
       VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (key) DO NOTHING
       RETURNING value`,
      [IDENTITY_KEY, JSON.stringify(generated)],
    );
    const insertedValue = valueFromRow(inserted.rows[0]);
    if (insertedValue) return assertRelayIdentity(insertedValue);

    const raced = await readValue(IDENTITY_KEY);
    if (!raced) throw new Error("Impossible de relire l’identité PostgreSQL Quantic Relay.");
    return assertRelayIdentity(raced);
  }

  return {
    initialize,
    stateStore,
    loadOrCreateIdentity,
  };
}

export async function createPostgresRelayPersistenceFromUrl(databaseUrl: string) {
  if (!databaseUrl.trim()) throw new Error("URL PostgreSQL Quantic Relay absente.");
  const { Pool } = await import("pg");
  const pool = new Pool({
    connectionString: databaseUrl,
    max: 4,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });
  const persistence = createPostgresRelayPersistence(pool as unknown as PostgresQueryClient);
  await persistence.initialize();
  return {
    ...persistence,
    async close() {
      await pool.end();
    },
  };
}
