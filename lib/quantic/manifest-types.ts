export type QuanticManifestDevice = {
  deviceId: string;
  label: string;
  publicKey: JsonWebKey;
  deviceSigningPublicKey: JsonWebKey;
  kind: "root" | "linked";
  issuedAt: string;
};

export type QuanticRevocation = {
  deviceId: string;
  revokedAt: string;
  reason: "user" | "lost" | "compromised" | "replaced";
};

export type QuanticIdentityManifestPayload = {
  version: 1;
  sequence: number;
  canonicalAddress: string;
  handle: string;
  fingerprint: string;
  identityPublicKey: JsonWebKey;
  identitySigningPublicKey: JsonWebKey;
  devices: QuanticManifestDevice[];
  revocations: QuanticRevocation[];
  issuedAt: string;
};

export type QuanticIdentityManifest = {
  format: "quantic-identity-manifest";
  version: 1;
  payload: QuanticIdentityManifestPayload;
  signature: string;
};
