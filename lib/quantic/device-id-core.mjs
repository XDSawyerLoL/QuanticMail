const DEVICE_ID = /^d-(?:[0-9a-f]{10}|[0-9a-f]{32})$/;

function assertPublicKey(key) {
  if (!key || key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error("Clé publique d’appareil invalide.");
  }
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function publicDevicePoint(key) {
  assertPublicKey(key);
  return `P-256:${key.x}:${key.y}`;
}

export async function deviceDigestHex(key) {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(publicDevicePoint(key)),
  );
  return toHex(new Uint8Array(digest));
}

export function deviceIdFromDigestHex(digestHex, length = 32) {
  if (length !== 10 && length !== 32) throw new Error("Longueur d’identifiant d’appareil invalide.");
  if (typeof digestHex !== "string" || !/^[0-9a-f]{64}$/.test(digestHex)) {
    throw new Error("Empreinte d’appareil invalide.");
  }
  return `d-${digestHex.slice(0, length)}`;
}

export async function deviceIdForPublicKey(key, length = 32) {
  return deviceIdFromDigestHex(await deviceDigestHex(key), length);
}

export function isValidDeviceId(value) {
  return typeof value === "string" && DEVICE_ID.test(value);
}

export function assertDeviceIdMatchesDigest(deviceId, digestHex) {
  if (!isValidDeviceId(deviceId)) throw new Error("Identifiant d’appareil invalide.");
  const length = deviceId.length - 2;
  const expected = deviceIdFromDigestHex(digestHex, length);
  if (deviceId !== expected) {
    throw new Error("L’identifiant cryptographique de l’appareil ne correspond pas à sa clé.");
  }
  return deviceId;
}

export async function assertDeviceIdMatchesKey(deviceId, key) {
  return assertDeviceIdMatchesDigest(deviceId, await deviceDigestHex(key));
}
