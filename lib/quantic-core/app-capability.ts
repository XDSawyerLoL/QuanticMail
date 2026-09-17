import type { LocalIdentity } from "../quantic/local-db";
import {
  canonicalManifestText,
  validateManifestShape,
} from "../quantic/manifest-core.mjs";
import type { QuanticIdentityManifest } from "../quantic/manifest-types";
import {
  canonicalAppCapabilityText,
  normalizeAppCapabilityPayload,
} from "./app-capability-core.mjs";

export type QuanticAppCapabilityPayload = {
  version: 1;
  canonicalAddress: string;
  app: string;
  appSigningPublicKey: JsonWebKey;
  scopes: string[];
  identityManifestSequence: number;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
};

export type QuanticAppCapability = {
  format: "quantic-app-capability";
  version: 1;
  payload: QuanticAppCapabilityPayload;
  signature: string;
};

type CreateCapabilityOptions = {
  now?: string;
  nonce?: string;
  identityManifestSequence?: number;
};

function toBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function randomNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return `n-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

async function signText(privateJwk: JsonWebKey, text: string) {
  const key = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(text),
  );
  return toBase64(new Uint8Array(signature));
}

async function verifyText(publicJwk: JsonWebKey, text: string, signature: string) {
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
      fromBase64(signature),
      new TextEncoder().encode(text),
    );
  } catch {
    return false;
  }
}

async function fingerprintSigningKey(key: JsonWebKey, length: 10 | 32) {
  if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y) return null;
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`P-256:${key.x}:${key.y}`),
  );
  const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return hex.slice(0, length);
}

async function verifyIdentityManifest(manifest: QuanticIdentityManifest) {
  try {
    validateManifestShape(manifest);
    const length: 10 | 32 = manifest.payload.fingerprint.length === 10 ? 10 : 32;
    const fingerprint = await fingerprintSigningKey(manifest.payload.identitySigningPublicKey, length);
    if (!fingerprint || fingerprint !== manifest.payload.fingerprint) return false;
    if (`${manifest.payload.handle}~${fingerprint}@quantic` !== manifest.payload.canonicalAddress) return false;
    return verifyText(
      manifest.payload.identitySigningPublicKey,
      canonicalManifestText(manifest.payload),
      manifest.signature,
    );
  } catch {
    return false;
  }
}

export async function createAppCapability(
  identity: LocalIdentity,
  app: string,
  appSigningPublicKey: JsonWebKey,
  scopes: string[],
  expiresAt: string,
  options: CreateCapabilityOptions = {},
): Promise<QuanticAppCapability> {
  if (
    identity.role === "secondary" ||
    !identity.canonicalAddress ||
    !identity.signingPrivateKey ||
    !identity.signingPublicKey
  ) {
    throw new Error("Seul l’appareil maître peut autoriser une application Quantic.");
  }
  const payload = normalizeAppCapabilityPayload({
    version: 1,
    canonicalAddress: identity.canonicalAddress,
    app,
    appSigningPublicKey,
    scopes,
    identityManifestSequence: options.identityManifestSequence ?? identity.manifest?.payload.sequence ?? 1,
    issuedAt: options.now ?? new Date().toISOString(),
    expiresAt,
    nonce: options.nonce ?? randomNonce(),
  }) as QuanticAppCapabilityPayload;
  const signature = await signText(identity.signingPrivateKey, canonicalAppCapabilityText(payload));
  return {
    format: "quantic-app-capability",
    version: 1,
    payload,
    signature,
  };
}

export async function verifyAppCapability(
  capability: QuanticAppCapability,
  manifest: QuanticIdentityManifest,
  nowMs = Date.now(),
) {
  try {
    if (
      capability?.format !== "quantic-app-capability" ||
      capability.version !== 1 ||
      typeof capability.signature !== "string" ||
      capability.signature.length < 8
    ) {
      return false;
    }
    if (!(await verifyIdentityManifest(manifest))) return false;
    const payload = normalizeAppCapabilityPayload(capability.payload) as QuanticAppCapabilityPayload;
    if (payload.canonicalAddress !== manifest.payload.canonicalAddress) return false;
    if (payload.identityManifestSequence > manifest.payload.sequence) return false;
    if (!Number.isFinite(nowMs) || nowMs < Date.parse(payload.issuedAt) || nowMs >= Date.parse(payload.expiresAt)) {
      return false;
    }
    return verifyText(
      manifest.payload.identitySigningPublicKey,
      canonicalAppCapabilityText(payload),
      capability.signature,
    );
  } catch {
    return false;
  }
}
