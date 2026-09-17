import { assertVerifiedManifest } from "./manifest-node.mjs";
import type { QuanticIdentityManifest } from "./manifest-types";
import { isPreKeyExpired, validatePreKeyRecord, type SignedPreKeyRecord } from "./prekey-core.mjs";
import { createPreKeyPoolStore, type PreKeyPoolStore } from "./prekey-pool.mjs";

export type StandaloneV11PersistentState = {
  manifests: Array<[string, QuanticIdentityManifest]>;
  preKeyPools: Array<[string, SignedPreKeyRecord[]]>;
  consumedPreKeys: Array<[string, number]>;
};

type StandaloneV11State = {
  manifests: Map<string, QuanticIdentityManifest>;
  preKeys: PreKeyPoolStore;
};

declare global {
  var __quanticStandaloneV11State: StandaloneV11State | undefined;
}

const state: StandaloneV11State = globalThis.__quanticStandaloneV11State ?? {
  manifests: new Map(),
  preKeys: createPreKeyPoolStore(),
};
globalThis.__quanticStandaloneV11State = state;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function requirePairs<T>(value: unknown, label: string): Array<[string, T]> {
  if (!Array.isArray(value)) throw new Error(`${label} doit être un tableau.`);
  const keys = new Set<string>();
  const result: Array<[string, T]> = [];
  for (const entry of value) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string") {
      throw new Error(`${label} contient une entrée invalide.`);
    }
    if (keys.has(entry[0])) throw new Error(`${label} contient une clé dupliquée.`);
    keys.add(entry[0]);
    result.push([entry[0], clone(entry[1] as T)]);
  }
  return result;
}

export function getStandaloneManifest(canonicalAddress: string) {
  return state.manifests.get(canonicalAddress.trim().toLowerCase()) ?? null;
}

export function getStandaloneManifestStore() {
  return state.manifests;
}

export function getStandalonePreKeyStore() {
  return state.preKeys;
}

export function exportStandaloneV11State(now = Date.now()): StandaloneV11PersistentState {
  const preKeyPools: Array<[string, SignedPreKeyRecord[]]> = [];
  for (const [key, records] of state.preKeys.pools) {
    const fresh = records.filter((record) => !isPreKeyExpired(record, now));
    if (fresh.length) preKeyPools.push([key, clone(fresh)]);
  }

  const consumedPreKeys = [...state.preKeys.consumed.entries()]
    .filter(([, expiresAt]) => Number.isFinite(expiresAt) && expiresAt > now);

  return {
    manifests: [...state.manifests.entries()].map(([key, manifest]) => [key, clone(manifest)]),
    preKeyPools,
    consumedPreKeys,
  };
}

export function restoreStandaloneV11State(input: Partial<StandaloneV11PersistentState> | null | undefined, now = Date.now()) {
  const manifestEntries = requirePairs<QuanticIdentityManifest>(input?.manifests ?? [], "manifests");
  const nextManifests = new Map<string, QuanticIdentityManifest>();
  for (const [key, manifest] of manifestEntries) {
    assertVerifiedManifest(manifest);
    const canonical = manifest.payload.canonicalAddress.trim().toLowerCase();
    if (key.trim().toLowerCase() !== canonical) {
      throw new Error("Clé de manifeste persisté incohérente.");
    }
    nextManifests.set(canonical, manifest);
  }

  const poolEntries = requirePairs<SignedPreKeyRecord[]>(input?.preKeyPools ?? [], "preKeyPools");
  const nextPools = new Map<string, SignedPreKeyRecord[]>();
  for (const [key, records] of poolEntries) {
    if (!Array.isArray(records)) throw new Error("preKeyPools contient une valeur invalide.");
    const fresh: SignedPreKeyRecord[] = [];
    for (const record of records) {
      validatePreKeyRecord(record);
      const expectedKey = `${record.canonicalAddress}#${record.deviceId}`;
      if (key !== expectedKey) throw new Error("Clé de pool de prekeys incohérente.");
      if (!isPreKeyExpired(record, now)) fresh.push(record);
    }
    if (fresh.length) nextPools.set(key, fresh);
  }

  const consumedEntries = requirePairs<number>(input?.consumedPreKeys ?? [], "consumedPreKeys");
  const nextConsumed = new Map<string, number>();
  for (const [preKeyId, expiresAt] of consumedEntries) {
    if (!/^[0-9a-f]{32}$/.test(preKeyId) || !Number.isFinite(expiresAt)) {
      throw new Error("Tombstone de prekey invalide.");
    }
    if (expiresAt > now) nextConsumed.set(preKeyId, expiresAt);
  }

  state.manifests = nextManifests;
  state.preKeys = {
    pools: nextPools,
    consumed: nextConsumed,
  };
}
