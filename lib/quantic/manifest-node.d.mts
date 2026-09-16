import type { QuanticIdentityManifest } from "./manifest-types";

export function fingerprintPublicKeyNode(key: JsonWebKey): string;
export function deviceIdForPublicKeyNode(key: JsonWebKey): string;
export function verifyManifestSignature(manifest: QuanticIdentityManifest): boolean;
export function assertVerifiedManifest(manifest: QuanticIdentityManifest): QuanticIdentityManifest;
