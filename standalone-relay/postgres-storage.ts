import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
} from "node:crypto";

import type { RelayPersistentState } from "../lib/quantic/relay-state.ts";
import {
  relayIdForPublicKey,
  type RelayIdentity,
} from "./identity.ts";
import type { RelayStateStore } from "./storage.ts";

type QueryRow = { value?: unknown; revision?: number | string };

type QueryResult = {
  rows: QueryRow[];
  rowCount?: number | null;
};

export type PostgresQueryClient = {
  query(sql: string, params?: unknown[]): Promise<QueryResult>;
};

export type PostgresPersistenceOptions = {
  identitySecret?: string;
};

const STATE_KEY = "relay-state";
const IDENTITY_KEY = "relay-identity";
const IDENTITY_AAD = Buffer.from("quantic-relay-identity-v1", "utf8");

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS quantic_relay_kv (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`;
const ADD_REVISION_SQL = `
  ALTER TABLE quantic_relay_kv
  ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0
`;

type EncryptedRelayIdentity = {
  format: "quantic-relay-identity-encrypted";
  version: 1;
  kdf: "scrypt";
  cipher: "aes-256-gcm";
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
};

export class RelayStateConflictError extends Error {
  constructor() {
    super("Conflit de révision PostgreSQL Quantic Relay : un autre processus a écrit un état plus récent.");
    this.name = "RelayStateConflictError";
  }
}

function valueFromRow(row: QueryRow | undefined) {
  if (!row || row.value === undefined) return null;
  if (typeof row.value === "string") return JSON.parse(row.value) as unknown;
  return row.value;
}

function revisionFromRow(row: QueryRow | undefined) {
  if (!row || row.revision === undefined) return null;
  const value = Number(row.revision);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Révision PostgreSQL Quantic Relay invalide.");
  return value;
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

function requireIdentitySecret(value?: string) {
  if (value === undefined) return null;
  if (value.length < 32) {
    throw new Error("QUANTIC_RELAY_IDENTITY_SECRET doit contenir au moins 32 caractères.");
  }
  return value;
}

function isEncryptedIdentity(value: unknown): value is EncryptedRelayIdentity {
  const record = value as Partial<EncryptedRelayIdentity> | null;
  return Boolean(
    record &&
      record.format === "quantic-relay-identity-encrypted" &&
      record.version === 1 &&
      record.kdf === "scrypt" &&
      record.cipher === "aes-256-gcm" &&
      typeof record.salt === "string" &&
      typeof record.iv === "string" &&
      typeof record.ciphertext === "string" &&
      typeof record.tag === "string"
  );
}

function deriveIdentityKey(secret: string, salt: Buffer) {
  return scryptSync(secret, salt, 32, {
    N: 16_384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
}

function encryptRelayIdentity(identity: RelayIdentity, secret: string): EncryptedRelayIdentity {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveIdentityKey(secret, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(IDENTITY_AAD);
  const plaintext = Buffer.from(JSON.stringify(identity), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    format: "quantic-relay-identity-encrypted",
    version: 1,
    kdf: "scrypt",
    cipher: "aes-256-gcm",
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: tag.toString("base64url"),
  };
}

function decryptRelayIdentity(record: EncryptedRelayIdentity, secret: string): RelayIdentity {
  try {
    const salt = Buffer.from(record.salt, "base64url");
    const iv = Buffer.from(record.iv, "base64url");
    const tag = Buffer.from(record.tag, "base64url");
    const ciphertext = Buffer.from(record.ciphertext, "base64url");
    if (salt.length !== 16 || iv.length !== 12 || tag.length !== 16 || ciphertext.length < 16) {
      throw new Error("format");
    }
    const decipher = createDecipheriv("aes-256-gcm", deriveIdentityKey(secret, salt), iv);
    decipher.setAAD(IDENTITY_AAD);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    return assertRelayIdentity(JSON.parse(plaintext));
  } catch {
    throw new Error("Secret d’identité Quantic Relay incorrect ou identité chiffrée impossible à déchiffrer/authentifier.");
  }
}

export function createPostgresRelayPersistence(
  client: PostgresQueryClient,
  options: PostgresPersistenceOptions = {},
) {
  let initialized = false;
  let stateRevision: number | null = null;
  const identitySecret = requireIdentitySecret(options.identitySecret);

  async function initialize() {
    if (initialized) return;
    await client.query(CREATE_TABLE_SQL);
    await client.query(ADD_REVISION_SQL);
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

  async function loadState() {
    await initialize();
    const result = await client.query(
      "SELECT value, revision FROM quantic_relay_kv WHERE key = $1",
      [STATE_KEY],
    );
    const row = result.rows[0];
    const value = valueFromRow(row);
    stateRevision = value === null ? null : revisionFromRow(row);
    return value as RelayPersistentState | null;
  }

  async function saveState(state: RelayPersistentState) {
    await initialize();
    const serialized = JSON.stringify(state);
    if (stateRevision === null) {
      const inserted = await client.query(
        `INSERT INTO quantic_relay_kv (key, value, revision, updated_at)
         VALUES ($1, $2::jsonb, 1, NOW())
         ON CONFLICT (key) DO NOTHING
         RETURNING revision`,
        [STATE_KEY, serialized],
      );
      const revision = revisionFromRow(inserted.rows[0]);
      if (revision === null) throw new RelayStateConflictError();
      stateRevision = revision;
      return;
    }

    const updated = await client.query(
      `UPDATE quantic_relay_kv
       SET value = $2::jsonb, revision = revision + 1, updated_at = NOW()
       WHERE key = $1 AND revision = $3
       RETURNING revision`,
      [STATE_KEY, serialized, stateRevision],
    );
    const revision = revisionFromRow(updated.rows[0]);
    if (revision === null) throw new RelayStateConflictError();
    stateRevision = revision;
  }

  const stateStore: RelayStateStore = {
    load: loadState,
    save: saveState,
  };

  function decodeStoredIdentity(value: unknown) {
    if (isEncryptedIdentity(value)) {
      if (!identitySecret) {
        throw new Error("QUANTIC_RELAY_IDENTITY_SECRET est requis pour cette identité PostgreSQL chiffrée.");
      }
      return decryptRelayIdentity(value, identitySecret);
    }
    return assertRelayIdentity(value);
  }

  function encodedIdentity(identity: RelayIdentity) {
    return identitySecret ? encryptRelayIdentity(identity, identitySecret) : identity;
  }

  async function loadOrCreateIdentity() {
    const existing = await readValue(IDENTITY_KEY);
    if (existing) {
      const identity = decodeStoredIdentity(existing);
      if (identitySecret && !isEncryptedIdentity(existing)) {
        await saveValue(IDENTITY_KEY, encryptRelayIdentity(identity, identitySecret));
      }
      return identity;
    }

    const generated = createRelayIdentity();
    const inserted = await client.query(
      `INSERT INTO quantic_relay_kv (key, value, updated_at)
       VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (key) DO NOTHING
       RETURNING value`,
      [IDENTITY_KEY, JSON.stringify(encodedIdentity(generated))],
    );
    const insertedValue = valueFromRow(inserted.rows[0]);
    if (insertedValue) return decodeStoredIdentity(insertedValue);

    const raced = await readValue(IDENTITY_KEY);
    if (!raced) throw new Error("Impossible de relire l’identité PostgreSQL Quantic Relay.");
    return decodeStoredIdentity(raced);
  }

  return {
    initialize,
    stateStore,
    loadOrCreateIdentity,
  };
}

export async function createPostgresRelayPersistenceFromUrl(
  databaseUrl: string,
  options: PostgresPersistenceOptions = {},
) {
  if (!databaseUrl.trim()) throw new Error("URL PostgreSQL Quantic Relay absente.");
  const { Pool } = await import("pg");
  const pool = new Pool({
    connectionString: databaseUrl,
    max: 4,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });
  const persistence = createPostgresRelayPersistence(pool as unknown as PostgresQueryClient, options);
  await persistence.initialize();
  return {
    ...persistence,
    async close() {
      await pool.end();
    },
  };
}
