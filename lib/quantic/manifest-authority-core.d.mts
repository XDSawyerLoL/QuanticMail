import type { QuanticIdentityManifest } from "./manifest-types";

export function reconcileManifestAuthority(
  cachedManifest: QuanticIdentityManifest | null | undefined,
  durableManifest: QuanticIdentityManifest | null | undefined,
  incomingManifest: QuanticIdentityManifest,
): QuanticIdentityManifest;
