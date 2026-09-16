const MAX_POOL = 64;

export function createPreKeyPoolStore() {
  return {
    pools: new Map(),
    consumed: new Map(),
  };
}

function pruneConsumed(store, now) {
  for (const [id, expiresAt] of store.consumed) {
    if (expiresAt <= now) store.consumed.delete(id);
  }
}

function prunePool(store, key, now) {
  const pool = store.pools.get(key) ?? [];
  const fresh = pool.filter((record) => Date.parse(record.expiresAt) > now);
  if (fresh.length) store.pools.set(key, fresh);
  else store.pools.delete(key);
  return fresh;
}

export function publishToPreKeyPool(store, key, records, now = Date.now()) {
  pruneConsumed(store, now);
  const pool = prunePool(store, key, now);
  const byId = new Map(pool.map((record) => [record.preKeyId, record]));
  let accepted = 0;
  let consumedRejected = 0;
  let expiredRejected = 0;

  for (const record of records) {
    if (Date.parse(record.expiresAt) <= now) {
      expiredRejected += 1;
      continue;
    }
    if (store.consumed.has(record.preKeyId)) {
      consumedRejected += 1;
      continue;
    }
    if (byId.has(record.preKeyId)) continue;
    if (byId.size >= MAX_POOL) break;
    byId.set(record.preKeyId, record);
    accepted += 1;
  }

  const next = [...byId.values()].slice(0, MAX_POOL);
  if (next.length) store.pools.set(key, next);
  else store.pools.delete(key);
  return {
    accepted,
    consumedRejected,
    expiredRejected,
    available: next.length,
  };
}

export function claimFromPreKeyPool(store, key, now = Date.now()) {
  pruneConsumed(store, now);
  const pool = prunePool(store, key, now);
  const record = pool.shift() ?? null;
  if (!record) return null;
  if (pool.length) store.pools.set(key, pool);
  else store.pools.delete(key);
  store.consumed.set(record.preKeyId, Date.parse(record.expiresAt));
  return record;
}

export function countPreKeyPool(store, key, now = Date.now()) {
  pruneConsumed(store, now);
  return prunePool(store, key, now).length;
}
