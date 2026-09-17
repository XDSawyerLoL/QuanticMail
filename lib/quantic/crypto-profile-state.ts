import type { QuanticIdentityManifest } from "./manifest-types.ts";
import type { QuanticCryptoProfileV2 } from "./crypto-profile-core.mjs";
import { mergeCryptoProfileState } from "./crypto-profile-core.mjs";
import { verifyCryptoProfile } from "./crypto-profile-node.mjs";

declare global {
  var __quanticCryptoProfileState: Map<string, QuanticCryptoProfileV2> | undefined;
}

function state() {
  if (!globalThis.__quanticCryptoProfileState) {
    globalThis.__quanticCryptoProfileState = new Map<string, QuanticCryptoProfileV2>();
  }
  return globalThis.__quanticCryptoProfileState;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function getCryptoProfile(canonicalAddress: string) {
  return state().get(canonicalAddress.trim().toLowerCase()) ?? null;
}

export function acceptCryptoProfile(
  profile: QuanticCryptoProfileV2,
  identityManifest: QuanticIdentityManifest,
) {
  const canonical = profile.payload.canonicalAddress.trim().toLowerCase();
  const previous = state().get(canonical) ?? null;
  const verified = verifyCryptoProfile(profile, identityManifest, previous) as QuanticCryptoProfileV2;
  const accepted = mergeCryptoProfileState(previous, verified) as QuanticCryptoProfileV2;
  state().set(canonical, clone(accepted));
  return accepted;
}

export function cryptoProfileEntries(): Array<[string, QuanticCryptoProfileV2]> {
  return clone([...state().entries()]);
}

export function replaceCryptoProfileEntries(entries: Array<[string, QuanticCryptoProfileV2]>) {
  const next = new Map<string, QuanticCryptoProfileV2>();
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string") {
      throw new Error("Entrée Crypto Profile persistante invalide.");
    }
    const [key, profile] = entry;
    const canonical = key.trim().toLowerCase();
    if (
      !profile ||
      profile.format !== "quantic-crypto-profile" ||
      profile.version !== 2 ||
      !profile.payload ||
      profile.payload.version !== 2 ||
      profile.payload.canonicalAddress !== canonical ||
      !Number.isSafeInteger(profile.payload.sequence) ||
      profile.payload.sequence < 1
    ) {
      throw new Error("Crypto Profile persistant invalide.");
    }
    if (next.has(canonical)) throw new Error("Crypto Profile persistant dupliqué.");
    next.set(canonical, clone(profile));
  }
  globalThis.__quanticCryptoProfileState = next;
}
