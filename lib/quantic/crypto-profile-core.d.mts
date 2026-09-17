export type QuanticCryptoDeviceV2 = {
  deviceId: string;
  mlKemAlgorithm: "ML-KEM-768";
  mlKemPublicKeySpki: string;
  mlDsaAlgorithm: "ML-DSA-65";
  mlDsaPublicKeySpki: string;
};

export type QuanticCryptoProfilePayloadV2 = {
  version: 2;
  sequence: number;
  canonicalAddress: string;
  identitySigningPublicKey: JsonWebKey;
  identityManifestSequence: number;
  policy: "transition" | "hybrid-required";
  identityMlDsaAlgorithm: "ML-DSA-65";
  identityMlDsaPublicKeySpki: string;
  devices: QuanticCryptoDeviceV2[];
  issuedAt: string;
};

export type QuanticCryptoProfileV2 = {
  format: "quantic-crypto-profile";
  version: 2;
  payload: QuanticCryptoProfilePayloadV2;
  signatures: {
    p256: string;
    mlDsa65Self: string;
    mlDsa65Continuity?: string;
  };
};

export function canonicalCryptoProfilePayload(payload: unknown): QuanticCryptoProfilePayloadV2;
export function canonicalCryptoProfileText(payload: unknown): string;
export function validateCryptoProfileShape(profile: unknown): QuanticCryptoProfileV2;
export function mergeCryptoProfileState(
  current: QuanticCryptoProfileV2 | null,
  incoming: QuanticCryptoProfileV2,
): QuanticCryptoProfileV2;
