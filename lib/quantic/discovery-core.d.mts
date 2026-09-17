export type DiscoveryKind = "identity" | "crypto" | "route";

export type DiscoveryRecord<T = unknown> = {
  kind: DiscoveryKind;
  canonicalAddress: string;
  sequence: number;
  digest: string;
  value: T;
};

export type DiscoveryPinnedState = {
  identityManifest?: unknown;
  cryptoProfile?: unknown;
  routeManifest?: unknown;
};

export type DiscoveryBundle = {
  identityManifest: unknown;
  cryptoProfile?: unknown;
  routeManifest: unknown;
};

export type DiscoveryCryptoVerifier = (
  profile: unknown,
  identityManifest: unknown,
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
  identityManifest: unknown;
  cryptoProfile: unknown | null;
  routeManifest: unknown;
};

export function selectNewestValidRecord<T = unknown>(
  records: Array<DiscoveryRecord<T>>,
): DiscoveryRecord<T> | null;
