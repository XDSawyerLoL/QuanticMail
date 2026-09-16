import type { QuanticIdentityManifest } from "./manifest-types";

export function decideRegistryWrite(
  remoteManifest: QuanticIdentityManifest | null | undefined,
  nextManifest: QuanticIdentityManifest,
): "write" | "unchanged";
