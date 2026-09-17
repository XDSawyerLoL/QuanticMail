import { randomToken, signChallenge } from "@/lib/quantic/crypto";
import { verifyTextSignature } from "@/lib/quantic/device";
import type { LocalIdentity } from "@/lib/quantic/local-db";
import { verifyManifestBrowser } from "@/lib/quantic/manifest";
import type { QuanticIdentityManifest } from "@/lib/quantic/manifest-types";
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
    nonce: options.nonce ?? `n-${randomToken()}`,
  }) as QuanticAppCapabilityPayload;
  const signature = await signChallenge(identity.signingPrivateKey, canonicalAppCapabilityText(payload));
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
    if (!(await verifyManifestBrowser(manifest))) return false;
    const payload = normalizeAppCapabilityPayload(capability.payload) as QuanticAppCapabilityPayload;
    if (payload.canonicalAddress !== manifest.payload.canonicalAddress) return false;
    if (payload.identityManifestSequence > manifest.payload.sequence) return false;
    if (!Number.isFinite(nowMs) || nowMs < Date.parse(payload.issuedAt) || nowMs >= Date.parse(payload.expiresAt)) {
      return false;
    }
    return verifyTextSignature(
      manifest.payload.identitySigningPublicKey,
      canonicalAppCapabilityText(payload),
      capability.signature,
    );
  } catch {
    return false;
  }
}
