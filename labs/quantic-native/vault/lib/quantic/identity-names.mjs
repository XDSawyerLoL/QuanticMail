import { createHash } from "node:crypto";

const HANDLE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const FINGERPRINT = /^(?:[0-9a-f]{10}|[0-9a-f]{32})$/;

function assertSigningKey(key) {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error("Clé publique de propriété Quantic invalide.");
  }
}

export function identityNamesForKey(handle, signingPublicKey, requestedFingerprint = null) {
  const cleanHandle = String(handle ?? "").trim().toLowerCase();
  if (!HANDLE.test(cleanHandle)) throw new Error("Identifiant Quantic invalide.");
  assertSigningKey(signingPublicKey);

  const digest = createHash("sha256")
    .update(`P-256:${signingPublicKey.x}:${signingPublicKey.y}`)
    .digest("hex");

  let fingerprint = requestedFingerprint == null || requestedFingerprint === ""
    ? digest.slice(0, 10)
    : String(requestedFingerprint).trim().toLowerCase();

  if (!FINGERPRINT.test(fingerprint)) {
    throw new Error("Empreinte Quantic invalide.");
  }
  if (!digest.startsWith(fingerprint)) {
    throw new Error("L’empreinte Quantic ne correspond pas à la clé de propriété.");
  }

  return {
    fingerprint,
    address: `${cleanHandle}@quantic`,
    canonicalAddress: `${cleanHandle}~${fingerprint}@quantic`,
  };
}
