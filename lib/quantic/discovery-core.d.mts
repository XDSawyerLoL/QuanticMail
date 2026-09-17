import type { QuanticCryptoProfileV2 } from "./crypto-profile-core.mjs";
import type { QuanticRouteManifest } from "./federation-types.ts";
import type { QuanticIdentityManifest } from "./manifest-types.ts";

export type DiscoveryKind = "identity" | "crypto" | "route";

export type DiscoveryRecord<T = unknown> = {
  kind: DiscoveryKind;
  canonicalAddress: string;
  sequence: number;
  digest: string;
  value: T;
};

export type DiscoveryPinnedState = {
  identityManifest?: QuanticIdentityManifest | null;
  cryptoProfile?: QuanticCryptoProfileV2 | null;
  routeManifest?: QuanticRouteManifest | null;
};

export type DiscoveryBundle = {
  identityManifest: QuanticIdentityManifest;
  cryptoProfile?: QuanticCryptoProfileV2;
  routeManifest: QuanticRouteManifest;
};

export type DiscoveryCryptoVerifier = (
  profile: QuanticCryptoProfileV2,
  identityManifest: QuanticIdentityManifest,
  pinnedProfile: QuanticCryptoProfileV2 | null,
) => QuanticCryptoProfileV2 | { profile: QuanticCryptoProfileV2; digest: string };

export function discoveryKey(kind: DiscoveryKind, canonicalAddress: string): string;

export function validateDiscoveryBundle(
  bundle: DiscoveryBundle,
  pinnedState?: DiscoveryPinnedState,
  options?: {
    nowMs?: number;
    verifyCryptoProfile?: DiscoveryCryptoVerifier;
  },
): {
  canonicalAddress: string;
  identityManifest: QuanticIdentityManifest;
  cryptoProfile: QuanticCryptoProfileV2 | null;
  routeManifest: QuanticRouteManifest;
};

export function selectNewestValidRecord<T = unknown>(
  records: Array<DiscoveryRecord<T>>,
): DiscoveryRecord<T> | null;
