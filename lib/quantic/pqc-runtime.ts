export const ML_KEM_768 = "ML-KEM-768" as const;
export const ML_DSA_65 = "ML-DSA-65" as const;

export type PqcCapabilities = {
  runtime: string;
  mlKem768: boolean;
  mlDsa65: boolean;
};

export type PqcEncodedKeyPair = {
  publicKeySpki: string;
  privateKeyPkcs8: string;
};

export type MlKemEncapsulation = {
  sharedSecret: Buffer;
  ciphertext: string;
};

export function hasModernWebPqc(): boolean {
  const subtle = globalThis.crypto?.subtle as SubtleCrypto & {
    encapsulateBits?: unknown;
    decapsulateBits?: unknown;
  };
  return Boolean(
    subtle &&
      typeof subtle.encapsulateBits === "function" &&
      typeof subtle.decapsulateBits === "function",
  );
}
