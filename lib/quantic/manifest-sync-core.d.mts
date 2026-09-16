import type { QuanticIdentityManifest } from "./manifest-types";

export type ManifestSyncDecision =
  | { action: "none"; manifest: QuanticIdentityManifest | null }
  | { action: "adopt-remote" | "publish-local"; manifest: QuanticIdentityManifest };

export function decideManifestSync(
  localManifest: QuanticIdentityManifest | null | undefined,
  remoteManifest: QuanticIdentityManifest | null | undefined,
): ManifestSyncDecision;
