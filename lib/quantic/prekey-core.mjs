const CANONICAL_ADDRESS = /^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/;
const DEVICE_ID = /^d-[0-9a-f]{10}$/;
const PREKEY_ID = /^[0-9a-f]{32}$/;

function assertPublicKey(key) {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error("Clé publique de prekey invalide.");
  }
}

function publicPoint(key) {
  assertPublicKey(key);
  return `P-256:${key.x}:${key.y}`;
}

function fromBase64(value) {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(value, "base64"));
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function asArrayBuffer(bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function validatePreKeyRecord(record, requireSignature = true) {
  if (!record || record.version !== 1) throw new Error("Version de prekey invalide.");
  if (typeof record.canonicalAddress !== "string" || !CANONICAL_ADDRESS.test(record.canonicalAddress)) {
    throw new Error("Adresse canonique de prekey invalide.");
  }
  if (typeof record.deviceId !== "string" || !DEVICE_ID.test(record.deviceId)) {
    throw new Error("Identifiant d’appareil de prekey invalide.");
  }
  if (typeof record.preKeyId !== "string" || !PREKEY_ID.test(record.preKeyId)) {
    throw new Error("Identifiant prekey invalide.");
  }
  assertPublicKey(record.publicKey);
  if (typeof record.createdAt !== "string" || Number.isNaN(Date.parse(record.createdAt))) {
    throw new Error("Date de création de prekey invalide.");
  }
  if (typeof record.expiresAt !== "string" || Number.isNaN(Date.parse(record.expiresAt))) {
    throw new Error("Date d’expiration de prekey invalide.");
  }
  if (Date.parse(record.expiresAt) <= Date.parse(record.createdAt)) {
    throw new Error("Durée de vie de prekey invalide.");
  }
  if (requireSignature && (typeof record.signature !== "string" || record.signature.length < 20)) {
    throw new Error("Signature de prekey invalide.");
  }
  return record;
}

export function canonicalPreKeyText(record) {
  validatePreKeyRecord(record, false);
  return [
    "quantic-one-time-prekey-v1",
    record.canonicalAddress,
    record.deviceId,
    record.preKeyId,
    publicPoint(record.publicKey),
    record.createdAt,
    record.expiresAt,
  ].join("\n");
}

export function isPreKeyExpired(record, now = Date.now()) {
  validatePreKeyRecord(record, false);
  return Date.parse(record.expiresAt) <= now;
}

export async function verifyPreKeySignature(record, deviceSigningPublicKey) {
  try {
    validatePreKeyRecord(record, true);
    assertPublicKey(deviceSigningPublicKey);
    const key = await globalThis.crypto.subtle.importKey(
      "jwk",
      deviceSigningPublicKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return globalThis.crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      asArrayBuffer(fromBase64(record.signature)),
      asArrayBuffer(new TextEncoder().encode(canonicalPreKeyText(record))),
    );
  } catch {
    return false;
  }
}
