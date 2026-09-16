import type { QuanticIdentityManifest } from "./manifest-types";

export function fingerprintPublicKeyNode(key: JsonWebKey, length?: 10 | 32): string;
export function deviceIdForPublicKeyNode(key: JsonWebKey, length?: 10 | 32): string;
export function verifyManifestSignature(manifest: QuanticIdentityManifest): boolean;
export function assertVerifiedManifest(manifest: QuanticIdentityManifest): QuanticIdentityManifest;
