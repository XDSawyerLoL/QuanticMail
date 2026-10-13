const VERSION = 1;
const SALT_TEXT = "quantic-pairing-salt-v1";

function toBase64Url(bytes) {
  const binary = typeof Buffer !== "undefined" && typeof window === "undefined"
    ? Buffer.from(bytes).toString("base64")
    : btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));
  return binary.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error("Encodage de la clé QR invalide.");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const bytes = typeof Buffer !== "undefined" && typeof window === "undefined"
    ? new Uint8Array(Buffer.from(padded, "base64"))
    : Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  if (toBase64Url(bytes) !== value) throw new Error("Encodage de la clé QR invalide.");
  return bytes;
}

function asArrayBuffer(bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function randomPairingSecret() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

async function deriveKey(secret, inviteId) {
  const secretBytes = fromBase64Url(secret);
  if (secretBytes.byteLength !== 32) throw new Error("Secret de pairing invalide.");
  if (typeof inviteId !== "string" || inviteId.length < 4 || inviteId.length > 128) {
    throw new Error("Identifiant de pairing invalide.");
  }
  const material = await globalThis.crypto.subtle.importKey(
    "raw",
    asArrayBuffer(secretBytes),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return globalThis.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(SALT_TEXT),
      info: new TextEncoder().encode(`quantic-pairing-v1:${inviteId}`),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptPairingPackage(secret, inviteId, payload) {
  const key = await deriveKey(secret, inviteId);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext,
  );
  return {
    version: VERSION,
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
  };
}

export async function decryptPairingPackage(secret, inviteId, encrypted) {
  if (!encrypted || encrypted.version !== VERSION) throw new Error("Paquet de pairing invalide.");
  const key = await deriveKey(secret, inviteId);
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(fromBase64Url(encrypted.iv)) },
    key,
    asArrayBuffer(fromBase64Url(encrypted.ciphertext)),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}
