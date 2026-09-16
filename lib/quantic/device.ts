import {
  fingerprintPublicKey,
  fingerprintPublicKeyStrong,
  generateIdentityKeys,
  randomToken,
  signChallenge,
} from "@/lib/quantic/crypto";
import {
  assertDeviceIdMatchesKey,
  deviceIdForPublicKey,
} from "@/lib/quantic/device-id-core.mjs";
import type {
  DeviceCertificate,
  DeviceCertificatePayload,
  LocalIdentity,
  LocalPendingDevice,
} from "@/lib/quantic/local-db";

export type PublicDeviceRequest = {
  format: "quantic-device-request";
  version: 1;
  canonicalAddress: string;
  deviceId: string;
  deviceLabel: string;
  devicePublicKey: JsonWebKey;
  deviceSigningPublicKey: JsonWebKey;
  createdAt: string;
};

function toBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function asArrayBuffer(bytes: Uint8Array) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function cleanLabel(value: string) {
  const label = value.trim().replace(/\s+/g, " ");
  if (label.length < 2 || label.length > 48) {
    throw new Error("Le nom de l’appareil doit contenir 2 à 48 caractères.");
  }
  return label;
}

function publicPoint(key: JsonWebKey, label: string) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) {
    throw new Error(`${label} invalide.`);
  }
  return `P-256:${key.x}:${key.y}`;
}

export async function deviceIdFromPublicKey(key: JsonWebKey, length: 10 | 32 = 32) {
  return deviceIdForPublicKey(key, length);
}

export function deviceCertificateMessage(payload: DeviceCertificatePayload) {
  return [
    "quantic-device-certificate-v1",
    payload.canonicalAddress,
    payload.handle,
    payload.fingerprint,
    publicPoint(payload.identityPublicKey, "Clé d’identité"),
    publicPoint(payload.identitySigningPublicKey, "Clé de propriété"),
    payload.deviceId,
    payload.deviceLabel,
    publicPoint(payload.devicePublicKey, "Clé d’appareil"),
    publicPoint(payload.deviceSigningPublicKey, "Clé de signature d’appareil"),
    payload.issuedAt,
  ].join("\n");
}

export async function verifyTextSignature(
  publicJwk: JsonWebKey,
  text: string,
  signature: string,
) {
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      asArrayBuffer(fromBase64(signature)),
      asArrayBuffer(new TextEncoder().encode(text)),
    );
  } catch {
    return false;
  }
}

export async function createPendingDevice(
  canonicalAddress: string,
  deviceLabel: string,
): Promise<{ pending: LocalPendingDevice; request: PublicDeviceRequest }> {
  const canonical = canonicalAddress.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,31}~(?:[0-9a-f]{10}|[0-9a-f]{32})@quantic$/.test(canonical)) {
    throw new Error("Saisissez l’adresse canonique complète, par exemple nom~1a2b3c4d5e@quantic.");
  }
  const label = cleanLabel(deviceLabel);
  const keys = await generateIdentityKeys();
  const deviceId = await deviceIdFromPublicKey(keys.publicKey, 32);
  const createdAt = new Date().toISOString();
  const pending: LocalPendingDevice = {
    canonicalAddress: canonical,
    deviceId,
    deviceLabel: label,
    publicKey: keys.publicKey,
    privateKey: keys.privateKey,
    deviceSigningPublicKey: keys.signingPublicKey,
    deviceSigningPrivateKey: keys.signingPrivateKey,
    authToken: randomToken(),
    createdAt,
  };
  return {
    pending,
    request: {
      format: "quantic-device-request",
      version: 1,
      canonicalAddress: canonical,
      deviceId,
      deviceLabel: label,
      devicePublicKey: keys.publicKey,
      deviceSigningPublicKey: keys.signingPublicKey,
      createdAt,
    },
  };
}

export function parseDeviceRequest(text: string): PublicDeviceRequest {
  let request: Partial<PublicDeviceRequest>;
  try {
    request = JSON.parse(text) as Partial<PublicDeviceRequest>;
  } catch {
    throw new Error("Fichier de demande d’appareil invalide.");
  }
  if (
    request.format !== "quantic-device-request" ||
    request.version !== 1 ||
    typeof request.canonicalAddress !== "string" ||
    typeof request.deviceId !== "string" ||
    typeof request.deviceLabel !== "string" ||
    !request.devicePublicKey ||
    !request.deviceSigningPublicKey ||
    typeof request.createdAt !== "string"
  ) {
    throw new Error("Format de demande d’appareil non reconnu.");
  }
  return request as PublicDeviceRequest;
}

export async function createDeviceCertificate(
  identity: LocalIdentity,
  request: PublicDeviceRequest,
): Promise<DeviceCertificate> {
  if (!identity.canonicalAddress || !identity.fingerprint || !identity.signingPublicKey || !identity.signingPrivateKey) {
    throw new Error("Seul l’appareil maître peut autoriser un nouvel appareil.");
  }
  if (request.canonicalAddress !== identity.canonicalAddress) {
    throw new Error("Cette demande vise une autre identité Quantic.");
  }
  await assertDeviceIdMatchesKey(request.deviceId, request.devicePublicKey);
  const payload: DeviceCertificatePayload = {
    version: 1,
    canonicalAddress: identity.canonicalAddress,
    handle: identity.handle,
    fingerprint: identity.fingerprint,
    identityPublicKey: identity.publicKey,
    identitySigningPublicKey: identity.signingPublicKey,
    deviceId: request.deviceId,
    deviceLabel: cleanLabel(request.deviceLabel),
    devicePublicKey: request.devicePublicKey,
    deviceSigningPublicKey: request.deviceSigningPublicKey,
    issuedAt: new Date().toISOString(),
  };
  const signature = await signChallenge(identity.signingPrivateKey, deviceCertificateMessage(payload));
  return {
    format: "quantic-device-certificate",
    version: 1,
    payload,
    signature,
  };
}

export function parseDeviceCertificate(text: string): DeviceCertificate {
  let certificate: Partial<DeviceCertificate>;
  try {
    certificate = JSON.parse(text) as Partial<DeviceCertificate>;
  } catch {
    throw new Error("Fichier de certificat d’appareil invalide.");
  }
  if (
    certificate.format !== "quantic-device-certificate" ||
    certificate.version !== 1 ||
    !certificate.payload ||
    typeof certificate.signature !== "string"
  ) {
    throw new Error("Format de certificat d’appareil non reconnu.");
  }
  return certificate as DeviceCertificate;
}

export async function installDeviceCertificate(
  pending: LocalPendingDevice,
  certificate: DeviceCertificate,
): Promise<LocalIdentity> {
  const payload = certificate.payload;
  if (
    payload.canonicalAddress !== pending.canonicalAddress ||
    payload.deviceId !== pending.deviceId ||
    payload.deviceLabel !== pending.deviceLabel ||
    publicPoint(payload.devicePublicKey, "Clé d’appareil") !== publicPoint(pending.publicKey, "Clé locale") ||
    publicPoint(payload.deviceSigningPublicKey, "Clé de signature d’appareil") !==
      publicPoint(pending.deviceSigningPublicKey, "Clé de signature locale")
  ) {
    throw new Error("Le certificat ne correspond pas à la demande créée sur cet appareil.");
  }
  await assertDeviceIdMatchesKey(payload.deviceId, payload.devicePublicKey);
  const fingerprint = payload.fingerprint.length === 32
    ? await fingerprintPublicKeyStrong(payload.identitySigningPublicKey)
    : await fingerprintPublicKey(payload.identitySigningPublicKey);
  const expectedCanonical = `${payload.handle}~${fingerprint}@quantic`;
  if (fingerprint !== payload.fingerprint || expectedCanonical !== payload.canonicalAddress) {
    throw new Error("L’identité maîtresse du certificat est incohérente.");
  }
  const valid = await verifyTextSignature(
    payload.identitySigningPublicKey,
    deviceCertificateMessage(payload),
    certificate.signature,
  );
  if (!valid) throw new Error("Signature du certificat d’appareil invalide.");

  return {
    handle: payload.handle,
    address: `${payload.handle}@quantic`,
    canonicalAddress: payload.canonicalAddress,
    fingerprint: payload.fingerprint,
    publicKey: pending.publicKey,
    privateKey: pending.privateKey,
    signingPublicKey: payload.identitySigningPublicKey,
    deviceId: pending.deviceId,
    deviceLabel: pending.deviceLabel,
    deviceSigningPublicKey: pending.deviceSigningPublicKey,
    deviceSigningPrivateKey: pending.deviceSigningPrivateKey,
    deviceCertificate: certificate,
    role: "secondary",
    authToken: pending.authToken,
    createdAt: pending.createdAt,
  };
}

export function serializeDeviceRequest(request: PublicDeviceRequest) {
  return JSON.stringify(request, null, 2);
}

export function serializeDeviceCertificate(certificate: DeviceCertificate) {
  return JSON.stringify(certificate, null, 2);
}

export function base64DeviceCertificate(certificate: DeviceCertificate) {
  return toBase64(new TextEncoder().encode(JSON.stringify(certificate)));
}
