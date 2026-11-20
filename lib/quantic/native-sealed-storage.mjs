export const NATIVE_SEALED_FORMAT = "quantic-windows-dpapi";
export const NATIVE_SEALED_VERSION = 1;

export function isNativeSealedRecord(value) {
  return Boolean(value && typeof value === "object" &&
    value.format === NATIVE_SEALED_FORMAT &&
    value.version === NATIVE_SEALED_VERSION &&
    typeof value.ciphertext === "string" && value.ciphertext.length > 0);
}

export async function sealNativeRecord(value, bridge, index = {}) {
  if (!bridge) return value;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Enregistrement secret Quantic invalide.");
  }
  const ciphertext = await bridge.seal(JSON.stringify(value));
  if (typeof ciphertext !== "string" || ciphertext.length < 8) {
    throw new Error("Le coffre Windows n'a pas chiffré l'enregistrement.");
  }
  return { ...index, format: NATIVE_SEALED_FORMAT, version: NATIVE_SEALED_VERSION, ciphertext };
}

export async function unsealNativeRecord(stored, bridge) {
  if (!isNativeSealedRecord(stored)) {
    if (stored && typeof stored === "object" && stored.format === NATIVE_SEALED_FORMAT) {
      throw new Error("Enveloppe chiffrée Windows non reconnue.");
    }
    return stored;
  }
  if (!bridge) throw new Error("L'enregistrement nécessite le coffre Windows du profil d'origine.");
  const plaintext = await bridge.unseal(stored.ciphertext);
  let payload;
  try { payload = JSON.parse(plaintext); } catch { throw new Error("Enregistrement Windows illisible."); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Enregistrement Windows invalide.");
  }
  return payload;
}
