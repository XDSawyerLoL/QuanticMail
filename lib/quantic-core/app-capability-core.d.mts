export type NormalizedAppCapabilityPayload = {
  version: 1;
  canonicalAddress: string;
  app: string;
  appSigningPublicKey: JsonWebKey;
  scopes: string[];
  identityManifestSequence: number;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
};

export function normalizeAppId(value: unknown): string;
export function normalizeAppScopes(value: unknown): string[];
export function normalizeAppCapabilityPayload(payload: unknown): NormalizedAppCapabilityPayload;
export function canonicalAppCapabilityText(payload: unknown): string;
