import type {
  QuanticIdentityManifest,
  QuanticIdentityManifestPayload,
  QuanticManifestDevice,
} from "./manifest-types";

export function canonicalManifestText(payload: QuanticIdentityManifestPayload): string;
export function activeDevices(manifest: QuanticIdentityManifest): QuanticManifestDevice[];
export function validateManifestShape(manifest: QuanticIdentityManifest): QuanticIdentityManifestPayload;
export function mergeManifestState(
  current: QuanticIdentityManifest | null,
  incoming: QuanticIdentityManifest,
): QuanticIdentityManifest;
