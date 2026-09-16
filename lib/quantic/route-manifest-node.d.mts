import type { QuanticRouteManifest } from "./federation-types.ts";
import type { QuanticIdentityManifest } from "./manifest-types.ts";

export function relayIdForRouteKey(key: JsonWebKey): string;
export function verifyRouteManifestSignature(manifest: QuanticRouteManifest): boolean;
export function assertVerifiedRouteManifest(
  manifest: QuanticRouteManifest,
  identityManifest: QuanticIdentityManifest,
  nowMs?: number,
): QuanticRouteManifest;
export function mergeRouteManifestState(
  current: QuanticRouteManifest | null,
  incoming: QuanticRouteManifest,
): QuanticRouteManifest;
