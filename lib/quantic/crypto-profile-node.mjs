import { createPublicKey, verify } from "node:crypto";

import { assertVerifiedManifest } from "./manifest-node.mjs";
import {
  canonicalCryptoProfileText,
  validateCryptoProfileShape,
} from "./crypto-profile-core.mjs";
import { mlDsaVerify } from "./pqc-runtime-node.ts";

function sameP256Key(first, second) {
  return Boolean(
    first &&
      second &&
      first.kty === "EC" &&
      second.kty === "EC" &&
      first.crv === "P-256" &&
      second.crv === "P-256" &&
      first.x === second.x &&
      first.y === second.y,
  );
}

function verifyP256Signature(publicJwk, text, signature) {
  try {
    return verify(
      "sha256",
      Buffer.from(text, "utf8"),
      {
        key: createPublicKey({ key: publicJwk, format: "jwk" }),
        dsaEncoding: "ieee-p1363",
      },
      Buffer.from(signature, "base64"),
    );
  } catch {
    return false;
  }
}

export function verifyCryptoProfile(profile, identityManifest, previousProfile = null) {
  const validated = validateCryptoProfileShape(profile);
  const identity = assertVerifiedManifest(identityManifest);
  const payload = validated.payload;
  const identityPayload = identity.payload;

  if (payload.canonicalAddress !== identityPayload.canonicalAddress) {
    throw new Error("Le Crypto Profile vise une autre identité Quantic.");
  }
  if (!sameP256Key(payload.identitySigningPublicKey, identityPayload.identitySigningPublicKey)) {
    throw new Error("La clé P-256 du Crypto Profile ne correspond pas à l’identité.");
  }
  if (payload.identityManifestSequence > identityPayload.sequence) {
    throw new Error("Le Crypto Profile référence une séquence d’identité indisponible.");
  }

  const activeDevices = new Set(
    identityPayload.devices
      .filter((device) => !identityPayload.revocations.some((item) => item.deviceId === device.deviceId))
      .map((device) => device.deviceId),
  );
  for (const device of payload.devices) {
    if (!activeDevices.has(device.deviceId)) {
      throw new Error(`Appareil Crypto V2 ${device.deviceId} absent ou révoqué dans l’Identity Manifest.`);
    }
  }

  const text = canonicalCryptoProfileText(payload);
  if (!verifyP256Signature(payload.identitySigningPublicKey, text, validated.signatures.p256)) {
    throw new Error("Signature P-256 du Crypto Profile invalide.");
  }
  if (!mlDsaVerify(
    payload.identityMlDsaPublicKeySpki,
    Buffer.from(text, "utf8"),
    validated.signatures.mlDsa65Self,
  )) {
    throw new Error("Auto-signature ML-DSA-65 du Crypto Profile invalide.");
  }

  if (previousProfile) {
    const previous = validateCryptoProfileShape(previousProfile);
    if (previous.payload.canonicalAddress !== payload.canonicalAddress) {
      throw new Error("Continuité Crypto V2 entre identités différentes refusée.");
    }
    if (payload.sequence <= previous.payload.sequence) {
      throw new Error("Continuité Crypto V2 exige une séquence supérieure.");
    }
    if (!validated.signatures.mlDsa65Continuity) {
      throw new Error("Signature de continuité ML-DSA-65 requise.");
    }
    if (!mlDsaVerify(
      previous.payload.identityMlDsaPublicKeySpki,
      Buffer.from(text, "utf8"),
      validated.signatures.mlDsa65Continuity,
    )) {
      throw new Error("Signature de continuité ML-DSA-65 invalide.");
    }
    if (previous.payload.policy === "hybrid-required" && payload.policy !== "hybrid-required") {
      throw new Error("Downgrade Crypto V2 refusé après hybrid-required.");
    }
  }

  return validated;
}
