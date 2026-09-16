import type { SignedPreKeyRecord } from "./prekey-core.mjs";

export type PreKeyPoolStore = {
  pools: Map<string, SignedPreKeyRecord[]>;
  consumed: Map<string, number>;
};

export function createPreKeyPoolStore(): PreKeyPoolStore;
export function publishToPreKeyPool(
  store: PreKeyPoolStore,
  key: string,
  records: SignedPreKeyRecord[],
  now?: number,
): { accepted: number; consumedRejected: number; expiredRejected: number; available: number };
export function claimFromPreKeyPool(
  store: PreKeyPoolStore,
  key: string,
  now?: number,
): SignedPreKeyRecord | null;
export function countPreKeyPool(store: PreKeyPoolStore, key: string, now?: number): number;
