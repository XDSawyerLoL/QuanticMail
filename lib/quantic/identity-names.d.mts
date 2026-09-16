export function identityNamesForKey(
  handle: string,
  signingPublicKey: JsonWebKey,
  requestedFingerprint?: string | null,
): {
  fingerprint: string;
  address: string;
  canonicalAddress: string;
};
