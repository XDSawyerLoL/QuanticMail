const VERSION = 1;
const SALT_TEXT = "quantic-pairing-salt-v1";

function toBase64Url(bytes) {
  // Prefer Web APIs in browsers, including environments with incomplete Buffer polyfills.
  let base64;
  if (typeof btoa === "function") {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    base64 = btoa(binary);
  } else if (typeof Buffer !== "undefined") {
    base64 = Buffer.from(bytes).toString("base64");
  } else {
    throw new Error("Encodage Base64 indisponible.");
  }
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error("Encodage Base64URL invalide.");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  if (typeof atob === "function") {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(padded, "base64"));
  throw new Error("Décodage Base64 indisponible.");
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
