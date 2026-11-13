// Read-only local bridge plus signature proof from Quantic Identity Vault.
// The bridge identity (qid_...) is NOT a Quantic Mail mailbox key.
export const VAULT_BRIDGE_URL = "http://127.0.0.1:47621";
export const VAULT_AUDIENCE = "quantic-mail-desktop";

function bytesFromBase64url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error("Encodage de preuve Quantic ID invalide.");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function base64url(bytes) {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function validateVaultStatus(status) {
  if (!status || typeof status !== "object" || ![1, 2, 3].includes(Number(status.version)) ||
      status.product !== "Quantic Identity Vault") {
    throw new Error("Réponse du service Quantic ID non reconnue.");
  }
  const available = status.identityAvailable === true;
  const keyId = typeof status.keyId === "string" && /^qid_[0-9a-f]{32}$/.test(status.keyId) ? status.keyId : null;
  if (available && (!keyId || typeof status.publicKey !== "string")) {
    throw new Error("Le service Quantic ID est actif mais son identité publique est invalide.");
  }
  return {
    available,
    keyId,
    label: typeof status.label === "string" ? status.label.slice(0, 120) : "",
    algorithm: typeof status.algorithm === "string" ? status.algorithm : "",
    publicKey: available ? status.publicKey : null,
    hardwareMode: status.hardwareMode === true,
  };
}

export async function readVaultStatus(fetchImpl = fetch) {
  const response = await fetchImpl(VAULT_BRIDGE_URL + "/v1/status", {
    method: "GET",
    cache: "no-store",
    signal: AbortSignal.timeout(3000),
  });
  if (!response.ok) throw new Error("Le service local Quantic ID ne répond pas correctement.");
  return validateVaultStatus(await response.json());
}

export async function verifyVaultProof(status, proof, challenge, cryptoImpl = globalThis.crypto, now = Date.now()) {
  if (!status.available || !status.keyId || !status.publicKey) throw new Error("Quantic ID n'est pas déverrouillé.");
  if (!proof || proof.version !== 1 || typeof proof.payload !== "string" ||
      proof.keyId !== status.keyId || proof.publicKey !== status.publicKey) {
    throw new Error("La preuve ne correspond pas à l’identité Quantic ID déverrouillée.");
  }
  let message;
  try { message = JSON.parse(proof.payload); }
  catch { throw new Error("La preuve Quantic ID contient un message invalide."); }
  if (message?.version !== 1 || message.keyId !== status.keyId ||
      message.challenge !== challenge || message.audience !== VAULT_AUDIENCE ||
      !Number.isFinite(Date.parse(message.issuedAt)) ||
      Math.abs(now - Date.parse(message.issuedAt)) > 5 * 60 * 1000) {
    throw new Error("La preuve Quantic ID est expirée ou ne vise pas cette application.");
  }
  const publicDer = bytesFromBase64url(proof.publicKey);
  const signature = bytesFromBase64url(proof.signature);
  const digest = new Uint8Array(await cryptoImpl.subtle.digest("SHA-256", publicDer));
  const keyId = "qid_" + Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, 32);
  if (keyId !== status.keyId) throw new Error("L'identifiant Quantic ID ne correspond pas à la clé publique.");

  let algorithm;
  let verifyAlgorithm;
  if (proof.algorithm === "ed25519" && status.algorithm === "ed25519") {
    algorithm = { name: "Ed25519" };
    verifyAlgorithm = algorithm;
  } else if (proof.algorithm === "ecdsa-p256-sha256" && status.algorithm === "ecdsa-p256-sha256") {
    algorithm = { name: "ECDSA", namedCurve: "P-256" };
    verifyAlgorithm = { name: "ECDSA", hash: "SHA-256" };
  } else {
    throw new Error("Algorithme de signature Quantic ID incompatible.");
  }
  const verificationKey = await cryptoImpl.subtle.importKey("spki", publicDer, algorithm, false, ["verify"]);
  const valid = await cryptoImpl.subtle.verify(verifyAlgorithm, verificationKey, signature, new TextEncoder().encode(proof.payload));
  if (!valid) throw new Error("La signature Quantic ID n'a pas pu être vérifiée.");
  return { keyId: status.keyId, label: status.label };
}

export async function verifyUnlockedVault(status, fetchImpl = fetch, cryptoImpl = globalThis.crypto) {
  if (!status.available) throw new Error("Déverrouille Quantic ID avant d’ouvrir Quantic Mail.");
  const challenge = base64url(cryptoImpl.getRandomValues(new Uint8Array(32)));
  const response = await fetchImpl(VAULT_BRIDGE_URL + "/v1/assert", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge, audience: VAULT_AUDIENCE }),
    cache: "no-store",
    signal: AbortSignal.timeout(16000),
  });
  if (!response.ok) throw new Error(response.status === 423 ? "Quantic ID est verrouillé." : "Quantic ID n'a pas pu signer sa preuve d'accès.");
  return verifyVaultProof(status, await response.json(), challenge, cryptoImpl);
}
