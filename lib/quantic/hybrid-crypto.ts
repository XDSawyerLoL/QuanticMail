export const HYBRID_CRYPTO_SUITE = "QNT-HYB-P256-MLKEM768-HKDFSHA256-AES256GCM-1" as const;

export type HybridEnvelopeContext = {
  clientMessageId: string;
  from: string;
  fromDeviceId: string;
  to: string;
  toDeviceId: string;
};

const CANONICAL_ADDRESS = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;
const DEVICE_ID = /^d-[0-9a-f]{10}$/;
const CLIENT_MESSAGE_ID = /^[A-Za-z0-9._:-]{8,100}$/;

export function canonicalHybridContext(context: HybridEnvelopeContext) {
  const normalized = {
    clientMessageId: context.clientMessageId,
    from: context.from.trim().toLowerCase(),
    fromDeviceId: context.fromDeviceId,
    to: context.to.trim().toLowerCase(),
    toDeviceId: context.toDeviceId,
  };
  if (!CLIENT_MESSAGE_ID.test(normalized.clientMessageId)) throw new Error("Identifiant de message hybride invalide.");
  if (!CANONICAL_ADDRESS.test(normalized.from) || !CANONICAL_ADDRESS.test(normalized.to)) {
    throw new Error("Adresse canonique hybride invalide.");
  }
  if (!DEVICE_ID.test(normalized.fromDeviceId) || !DEVICE_ID.test(normalized.toDeviceId)) {
    throw new Error("Identifiant d’appareil hybride invalide.");
  }
  return [
    "quantic-hybrid-envelope-context-v1",
    HYBRID_CRYPTO_SUITE,
    normalized.clientMessageId,
    normalized.from,
    normalized.fromDeviceId,
    normalized.to,
    normalized.toDeviceId,
  ].join("\n");
}

export function hybridKdfInput(classicalSecret: Uint8Array, pqSecret: Uint8Array) {
  if (classicalSecret.byteLength !== 32) throw new Error("Secret ECDH P-256 hybride invalide.");
  if (pqSecret.byteLength !== 32) throw new Error("Secret ML-KEM-768 hybride invalide.");
  const input = new Uint8Array(64);
  input.set(classicalSecret, 0);
  input.set(pqSecret, 32);
  return input;
}

export function hybridKdfInfo(context: HybridEnvelopeContext) {
  return new TextEncoder().encode(canonicalHybridContext(context));
}

export function hybridAad(context: HybridEnvelopeContext) {
  return new TextEncoder().encode(`${canonicalHybridContext(context)}\nquantic-aes-gcm-aad-v1`);
}

export async function deriveHybridAesKey(
  classicalSecret: Uint8Array,
  pqSecret: Uint8Array,
  context: HybridEnvelopeContext,
) {
  const ikm = hybridKdfInput(classicalSecret, pqSecret);
  const info = hybridKdfInfo(context);
  const salt = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`quantic-hybrid-kdf-salt-v1\n${canonicalHybridContext(context)}`),
  );
  const keyMaterial = await globalThis.crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return globalThis.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
