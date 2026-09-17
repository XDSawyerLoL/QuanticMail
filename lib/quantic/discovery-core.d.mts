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
  cryptoProfile?: unknown;
  routeManifest?: QuanticRouteManifest | null;
};

export type DiscoveryBundle = {
  identityManifest: QuanticIdentityManifest;
  cryptoProfile?: unknown;
  routeManifest: QuanticRouteManifest;
};

export type DiscoveryCryptoVerifier = (
  profile: unknown,
  identityManifest: QuanticIdentityManifest,
  pinnedProfile: unknown | null,
) => unknown | { profile: unknown; digest: string };

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
  cryptoProfile: unknown | null;
  routeManifest: QuanticRouteManifest;
};

export function selectNewestValidRecord<T = unknown>(
  records: Array<DiscoveryRecord<T>>,
): DiscoveryRecord<T> | null;
