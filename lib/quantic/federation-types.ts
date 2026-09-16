export type QuanticRouteRelay = {
  relayId: string;
  endpoint: string;
  priority: number;
  protocols: string[];
  classicalSigningPublicKey: JsonWebKey;
  postQuantumSigningPublicKeySpki?: string;
  expiresAt: string;
};

export type QuanticRouteManifestPayload = {
  version: 1;
  sequence: number;
  canonicalAddress: string;
  identitySigningPublicKey: JsonWebKey;
  identityManifestSequence: number;
  cryptoProfileSequence: number | null;
  cryptoProfileDigest: string | null;
  relays: QuanticRouteRelay[];
  issuedAt: string;
  expiresAt: string;
};

export type QuanticRouteManifest = {
  format: "quantic-route-manifest";
  version: 1;
  payload: QuanticRouteManifestPayload;
  signatures: {
    p256: string;
    mlDsa65?: string;
  };
};

export type QuanticPortableEnvelope = {
  format: "quantic-envelope";
  version: 2;
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
  keyMode:
    | "v1-one-time-prekey"
    | "v1-static-fallback"
    | "hybrid-one-time-prekey"
    | "hybrid-static-fallback";
  cryptoSuite: string;
  preKeyId?: string;
  classicalEphemeralPublicKey?: JsonWebKey;
  pqKemCiphertext?: string;
  iv: string;
  ciphertext: string;
  createdAt: string;
  expiresAt: string;
  signatures: {
    p256Device: string;
    mlDsa65Device?: string;
  };
};
