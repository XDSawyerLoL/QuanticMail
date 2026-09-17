import {
  createPrivateKey,
  createPublicKey,
  decapsulate,
  encapsulate,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import type {
  MlKemEncapsulation,
  PqcCapabilities,
  PqcEncodedKeyPair,
} from "./pqc-runtime.ts";

function encodeDer(value: Buffer | Uint8Array) {
  return Buffer.from(value).toString("base64url");
}

function decodeDer(value: string) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Clé PQ Quantic base64url invalide.");
  return Buffer.from(value, "base64url");
}

function exportPair(publicKey: KeyObject, privateKey: KeyObject): PqcEncodedKeyPair {
  return {
    publicKeySpki: encodeDer(publicKey.export({ type: "spki", format: "der" })),
    privateKeyPkcs8: encodeDer(privateKey.export({ type: "pkcs8", format: "der" })),
  };
}

function importPublicKey(spki: string) {
  return createPublicKey({ key: decodeDer(spki), format: "der", type: "spki" });
}

function importPrivateKey(pkcs8: string) {
  return createPrivateKey({ key: decodeDer(pkcs8), format: "der", type: "pkcs8" });
}

let cachedCapabilities: PqcCapabilities | null = null;

export function detectPqcCapabilities(): PqcCapabilities {
  if (cachedCapabilities) return cachedCapabilities;

  let mlKem768 = false;
  let mlDsa65 = false;

  try {
    const pair = generateKeyPairSync("ml-kem-768");
    mlKem768 = pair.publicKey.asymmetricKeyType === "ml-kem-768";
  } catch {
    mlKem768 = false;
  }

  try {
    const pair = generateKeyPairSync("ml-dsa-65");
    mlDsa65 = pair.publicKey.asymmetricKeyType === "ml-dsa-65";
  } catch {
    mlDsa65 = false;
  }

  cachedCapabilities = {
    runtime: `node-${process.versions.node}`,
    mlKem768,
    mlDsa65,
  };
  return cachedCapabilities;
}

function requireCapability(name: "mlKem768" | "mlDsa65") {
  const capabilities = detectPqcCapabilities();
  if (!capabilities[name]) {
    const label = name === "mlKem768" ? "ML-KEM-768" : "ML-DSA-65";
    throw new Error(`${label} n’est pas disponible dans ${capabilities.runtime}.`);
  }
}

export function generateMlKem768KeyPair(): PqcEncodedKeyPair {
  requireCapability("mlKem768");
  const pair = generateKeyPairSync("ml-kem-768");
  return exportPair(pair.publicKey, pair.privateKey);
}

export function generateMlDsa65KeyPair(): PqcEncodedKeyPair {
  requireCapability("mlDsa65");
  const pair = generateKeyPairSync("ml-dsa-65");
  return exportPair(pair.publicKey, pair.privateKey);
}

export function mlKemEncapsulate(publicKeySpki: string): MlKemEncapsulation {
  requireCapability("mlKem768");
  const publicKey = importPublicKey(publicKeySpki);
  if (publicKey.asymmetricKeyType !== "ml-kem-768") {
    throw new Error("La clé publique n’est pas une clé ML-KEM-768.");
  }
  const result = encapsulate(publicKey);
  return {
    sharedSecret: Buffer.from(result.sharedKey),
    ciphertext: encodeDer(result.ciphertext),
  };
}

export function mlKemDecapsulate(privateKeyPkcs8: string, ciphertext: string): Buffer {
  requireCapability("mlKem768");
  const privateKey = importPrivateKey(privateKeyPkcs8);
  if (privateKey.asymmetricKeyType !== "ml-kem-768") {
    throw new Error("La clé privée n’est pas une clé ML-KEM-768.");
  }
  return Buffer.from(decapsulate(privateKey, decodeDer(ciphertext)));
}

export function mlDsaSign(privateKeyPkcs8: string, data: Uint8Array): string {
  requireCapability("mlDsa65");
  const privateKey = importPrivateKey(privateKeyPkcs8);
  if (privateKey.asymmetricKeyType !== "ml-dsa-65") {
    throw new Error("La clé privée n’est pas une clé ML-DSA-65.");
  }
  return sign(null, Buffer.from(data), privateKey).toString("base64url");
}

export function mlDsaVerify(publicKeySpki: string, data: Uint8Array, signature: string): boolean {
  requireCapability("mlDsa65");
  try {
    const publicKey = importPublicKey(publicKeySpki);
    if (publicKey.asymmetricKeyType !== "ml-dsa-65") return false;
    return verify(null, Buffer.from(data), publicKey, Buffer.from(signature, "base64url"));
  } catch {
    return false;
  }
}
